package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/testfixture"
)

const prefsXML = `<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="auth_token">eyJhbGciOiJIUzI1NiJ9.c2VjcmV0LXZhbHVlLWRvLW5vdC1sZWFr.x</string>
    <string name="theme">dark</string>
    <string name="refresh_token"></string>
    <boolean name="onboarded" value="true" />
</map>`

const plistXML = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>sessionToken</key><string>abc-secret-value-do-not-leak</string>
<key>launchCount</key><integer>3</integer>
<key>apiKeyEnabled</key><true/>
<key>preferredTheme</key><string>dark</string>
</dict></plist>`

// fakeTools answers like adb, xcrun and plutil would for the given setup.
type fakeTools struct {
	devices string // adb devices output
	qemu    string
	runAs   bool // the package is a debuggable test build
	calls   []string
}

func (f *fakeTools) run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	switch {
	case cmd == "adb devices":
		return []byte("List of devices attached\n" + f.devices + "\n"), nil
	case strings.HasSuffix(cmd, "getprop ro.kernel.qemu"), strings.HasSuffix(cmd, "getprop ro.boot.qemu"):
		return []byte(f.qemu + "\n"), nil
	case strings.Contains(cmd, "run-as") && !f.runAs:
		return nil, errors.New("run-as: package not debuggable: com.acme.shop")
	case strings.HasSuffix(cmd, "ls shared_prefs"):
		return []byte("session.xml\nsettings.txt\n"), nil
	case strings.HasSuffix(cmd, "cat shared_prefs/session.xml"):
		return []byte(prefsXML), nil
	case strings.HasPrefix(cmd, "xcrun simctl get_app_container booted com.acme.shop data"):
		return []byte("/Users/dev/Library/Developer/CoreSimulator/Devices/1F2E/data/Containers/Data/Application/9A8B\n"), nil
	case strings.HasPrefix(cmd, "plutil -convert xml1 -o - "):
		return []byte(plistXML), nil
	}
	return nil, errors.New("unexpected command: " + cmd)
}

func localRuntimeSetup(t *testing.T, f *fakeTools, host string) *Engine {
	t.Helper()
	oldRun, oldOS := RunTool, HostOS
	t.Cleanup(func() { RunTool, HostOS = oldRun, oldOS })
	RunTool, HostOS = f.run, host
	e, _ := scan(t, testfixture.VulnerableRepo(t))
	t.Cleanup(func() { e.Close() })
	e.Cfg.Runtime.AndroidPackage = "com.acme.shop"
	e.Cfg.Runtime.IOSBundleID = "com.acme.shop"
	return e
}

func TestLocalRuntimeFindsPlainCredentialsWithoutValues(t *testing.T) {
	f := &fakeTools{devices: "emulator-5554\tdevice", qemu: "1", runAs: true}
	e := localRuntimeSetup(t, f, "darwin")
	res, err := e.LocalRuntime(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if res.Controls["K-003"] != string(model.StatusFail) || res.Controls["L-002"] != string(model.StatusFail) {
		t.Fatalf("controls %v notes %v", res.Controls, res.Notes)
	}
	fs, _ := e.St.Findings(e.ProjectID)
	keys := map[string]bool{}
	for _, f := range fs {
		if f.Collector == "local-runtime" {
			keys[f.RuleID+" "+f.File+" "+f.Message[strings.Index(f.Message, "under ")+6:strings.Index(f.Message, " in plain")]] = true
		}
	}
	for _, want := range []string{
		"runtime.android-plain-credential emulator:com.acme.shop/shared_prefs/session.xml auth_token",
		"runtime.ios-plain-credential simulator:com.acme.shop/Library/Preferences/com.acme.shop.plist sessionToken",
	} {
		if !keys[want] {
			t.Errorf("missing %q in %v", want, keys)
		}
	}
	if len(keys) != 2 {
		t.Errorf("empty values, non-credential keys and booleans must not be reported: %v", keys)
	}
	assertNoValue(t, e, "c2VjcmV0LXZhbHVlLWRvLW5vdC1sZWFr", "abc-secret-value-do-not-leak")
}

func assertNoValue(t *testing.T, e *Engine, vals ...string) {
	t.Helper()
	filepath.Walk(e.Private(), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		for _, v := range vals {
			if strings.Contains(string(b), v) {
				t.Errorf("stored value %q found in %s", v, p)
			}
		}
		return nil
	})
}

func TestLocalRuntimeBlockedWithoutEmulatorOrSimulator(t *testing.T) {
	for name, tc := range map[string]struct {
		f       fakeTools
		host    string
		android string
		ios     string
	}{
		"real device only": {fakeTools{devices: "R58M123ABC\tdevice", qemu: "", runAs: true}, "linux", "real devices are never used", "need macOS"},
		"no device":        {fakeTools{}, "windows", "no running Android emulator", "need macOS"},
		"emulator lies":    {fakeTools{devices: "emulator-5554\tdevice", qemu: "0", runAs: true}, "linux", "does not report itself as an emulator", "need macOS"},
		"not debuggable":   {fakeTools{devices: "emulator-5554\tdevice", qemu: "1"}, "linux", "debuggable test build", "need macOS"},
	} {
		t.Run(name, func(t *testing.T) {
			f := tc.f
			e := localRuntimeSetup(t, &f, tc.host)
			res, err := e.LocalRuntime(context.Background(), func(string) {})
			if err != nil {
				t.Fatal(err)
			}
			if res.Controls["K-003"] != string(model.StatusBlocked) || res.Controls["L-002"] != string(model.StatusBlocked) {
				t.Fatalf("controls %v, want both BLOCKED", res.Controls)
			}
			notes := strings.Join(res.Notes, " | ")
			if !strings.Contains(notes, tc.android) || !strings.Contains(notes, tc.ios) {
				t.Fatalf("notes %q", notes)
			}
			for _, c := range f.calls {
				if strings.Contains(c, "run-as") && !strings.Contains(c, "emulator-") {
					t.Fatalf("app storage was read on a non-emulator: %s", c)
				}
				if strings.Contains(c, "cat ") && tc.f.qemu != "1" {
					t.Fatalf("storage read although the device is not an emulator: %s", c)
				}
			}
		})
	}
}

func TestLocalRuntimeNeedsConfiguredApp(t *testing.T) {
	f := &fakeTools{devices: "emulator-5554\tdevice", qemu: "1", runAs: true}
	e := localRuntimeSetup(t, f, "darwin")
	e.Cfg.Runtime.AndroidPackage, e.Cfg.Runtime.IOSBundleID = "", ""
	res, err := e.LocalRuntime(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if res.Controls["K-003"] != string(model.StatusBlocked) || res.Controls["L-002"] != string(model.StatusBlocked) || len(f.calls) != 0 {
		t.Fatalf("controls %v, calls %v", res.Controls, f.calls)
	}
}
