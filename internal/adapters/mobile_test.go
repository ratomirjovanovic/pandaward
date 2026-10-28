package adapters

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// When the test binary runs under the name "apktool" it acts like
// `apktool d -o OUT APK`: it writes a decoded manifest with a debuggable
// application. The adapter scrubs the environment, so the name is the
// signal.
func TestMain(m *testing.M) {
	if strings.HasPrefix(filepath.Base(os.Args[0]), "apktool") {
		args := os.Args[1:]
		if len(args) > 0 && args[0] == "--version" {
			io.WriteString(os.Stdout, "2.10.0\n")
			os.Exit(0)
		}
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				os.MkdirAll(args[i+1], 0o755)
				os.WriteFile(filepath.Join(args[i+1], "AndroidManifest.xml"), []byte(`<manifest><application android:debuggable="true"><service android:name=".Sync" android:exported="true"/></application></manifest>`), 0o644)
				os.Exit(0)
			}
		}
		os.Exit(2)
	}
	os.Exit(m.Run())
}

func fakeApktool(t *testing.T) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	name := "apktool"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func apkProject(t *testing.T) *Context {
	t.Helper()
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "release"), 0o755)
	os.WriteFile(filepath.Join(root, "release", "app-release.apk"), []byte("PK\x03\x04\x00binary"), 0o644)
	cfg := config.Default("t")
	inv, err := inventory.Walk(root, inventory.Options{Exclude: cfg.Inventory.Exclude, MaxFileBytes: cfg.Inventory.MaxFileBytes})
	if err != nil {
		t.Fatal(err)
	}
	return &Context{Root: root, Inv: inv, Cfg: cfg, RunDir: t.TempDir(), ToolHome: t.TempDir(), Timeout: time.Minute}
}

func TestApktoolDecodesAPKManifest(t *testing.T) {
	c := apkProject(t)
	if got := c.Inv.Features["apk"]; len(got) != 1 || got[0] != "release/app-release.apk" {
		t.Fatalf("apk feature: %v", got)
	}
	fakeApktool(t)
	res, run := apktoolAdapter{}.Run(context.Background(), c)
	if run.ExitClass != model.ExitOK {
		t.Fatalf("run %s: %s", run.ExitClass, run.Detail)
	}
	rules := map[string]bool{}
	for _, s := range res.Signals {
		if s.ControlID != "K-005" || s.File != "release/app-release.apk" || s.StartLine != 0 || !strings.HasPrefix(s.Message, "Decoded from the built APK") {
			t.Errorf("signal %+v", s)
		}
		rules[s.RuleID] = true
	}
	if !rules["mobile.android-debuggable"] || !rules["mobile.android-exported-component"] {
		t.Fatalf("rules %v", rules)
	}
}

func TestApktoolMissingIsBlocked(t *testing.T) {
	c := apkProject(t)
	t.Setenv("PATH", t.TempDir())
	_, run := apktoolAdapter{}.Run(context.Background(), c)
	if run.ExitClass != model.ExitBlocked {
		t.Fatalf("missing apktool must be BLOCKED, got %s", run.ExitClass)
	}
}

func TestMobileSourceRules(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"ios/App/App.entitlements":     "<plist><dict>\n<key>get-task-allow</key>\n<true/>\n</dict></plist>\n",
		"ios/App/Debug.entitlements":   "<plist><dict>\n<key>get-task-allow</key>\n<true/>\n</dict></plist>\n",
		"ios/App/Store.swift":          "// kSecAttrAccessibleAlways is deprecated\nlet a = kSecAttrAccessibleAlwaysThisDeviceOnly\n",
		"android/src/main/java/a/A.kt": "prefs.edit().putString(\"session_id\", id).apply()\n",
	}
	for p, s := range files {
		os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte(s), 0o644)
	}
	cfg := config.Default("t")
	inv, err := inventory.Walk(root, inventory.Options{Exclude: cfg.Inventory.Exclude, MaxFileBytes: cfg.Inventory.MaxFileBytes})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range mobileSourceSignals(inv, "builtin-mobile") {
		got[s.RuleID] = s.File
	}
	want := map[string]string{"mobile.ios-get-task-allow": "ios/App/App.entitlements", "mobile.ios-keychain-always": "ios/App/Store.swift", "mobile.android-prefs-credential": "android/src/main/java/a/A.kt"}
	for r, f := range want {
		if got[r] != f {
			t.Errorf("%s: got %q, want %q (all: %v)", r, got[r], f, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected signals: %v", got)
	}
}

func TestIsTestPathKeepsMainSourcePackages(t *testing.T) {
	for p, want := range map[string]bool{
		"app/src/main/java/com/example/app/Session.kt": false,
		"src/main/kotlin/com/example/Api.kt":           false,
		"examples/demo.js":                             true,
		"docs/example/app.js":                          true,
		"app/src/test/java/com/example/AppTest.kt":     true,
	} {
		if got := IsTestPath(p); got != want {
			t.Errorf("IsTestPath(%q) = %v, want %v", p, got, want)
		}
	}
}
