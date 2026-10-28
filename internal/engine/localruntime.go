package engine

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pensec/internal/evidence"
	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/redact"
)

// LocalRuntimeResult summarizes a local-runtime run.
type LocalRuntimeResult struct {
	AssessmentID string            `json:"assessment_id"`
	Controls     map[string]string `json:"controls"`
	Findings     int               `json:"findings"`
	Notes        []string          `json:"notes,omitempty"`
}

// RunTool runs a local developer tool (adb, xcrun, plutil) with an argument
// array and a timeout; tests replace it.
var RunTool = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	bin, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%s is not installed", name)
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var out, stderr bytes.Buffer
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		why := strings.TrimSpace(stderr.String())
		if why == "" {
			why = err.Error()
		}
		return out.Bytes(), errors.New(redact.Line(firstLineOf(why)))
	}
	return out.Bytes(), nil
}

// HostOS is runtime.GOOS; tests replace it.
var HostOS = runtime.GOOS

// credKeyRe matches storage keys that name credentials.
var credKeyRe = regexp.MustCompile(`(?i)(token|password|passwd|secret|session|api_?key|credential|refresh|auth)`)

var pkgRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)

// LocalRuntime runs the local-runtime profile: K-003 on an Android emulator
// and L-002 on an iOS simulator, for the test build named in the config. It
// reads only that app's own storage, through run-as on an emulator or the
// simulator's app container, and records key names, never values. Real
// devices are refused. Anything missing makes the control BLOCKED.
func (e *Engine) LocalRuntime(ctx context.Context, progress func(string)) (*LocalRuntimeResult, error) {
	a, err := e.St.LatestAssessment(e.ProjectID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, errors.New("run `pensec scan` first; runtime results attach to the latest assessment")
	}
	res := &LocalRuntimeResult{AssessmentID: a.ID, Controls: map[string]string{}}
	set := func(cid string, st model.Status, reason string) error {
		res.Controls[cid] = string(st)
		if st == model.StatusBlocked {
			res.Notes = append(res.Notes, cid+": "+reason)
		}
		return e.St.SetControlStatus(e.ProjectID, a.ID, cid, st, reason)
	}
	_ = e.St.Event(e.ProjectID, a.ID, "", "LOCAL_RUNTIME_STARTED", "local-runtime on emulator/simulator")
	for _, p := range []struct {
		cid string
		fn  func(context.Context, func(string)) ([]model.Signal, []string, model.Status, string)
	}{{"K-003", e.androidRuntime}, {"L-002", e.iosRuntime}} {
		sigs, files, st, reason := p.fn(ctx, progress)
		if st == model.StatusBlocked || st == model.StatusError {
			if err := set(p.cid, st, reason); err != nil {
				return nil, err
			}
			continue
		}
		ev, err := evidence.Write(e.St, e.Private(), evidence.Record{AssessmentID: a.ID, Kind: "runtime-storage", Collector: "local-runtime",
			Observation: reason, Data: map[string]any{"control": p.cid, "files_checked": files, "credential_keys": keysOf(sigs)}})
		if err != nil {
			return nil, err
		}
		for _, s := range sigs {
			if _, _, err := e.upsertFinding(a.ID, fingerprint(s.RuleID+"|"+s.File+"|"+s.Key, 1), s, ev); err != nil {
				return nil, err
			}
		}
		res.Findings += len(sigs)
		st, why := decide(sigs, p.cid, reason)
		if err := set(p.cid, st, why); err != nil {
			return nil, err
		}
	}
	_ = e.St.Event(e.ProjectID, a.ID, "LOCAL_RUNTIME_STARTED", "LOCAL_RUNTIME_FINISHED", fmt.Sprintf("%d finding signal(s)", res.Findings))
	return res, nil
}

func keysOf(sigs []model.Signal) []string {
	var out []string
	for _, s := range sigs {
		out = append(out, s.File+" "+s.Key)
	}
	return out
}

func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// androidRuntime checks the test app's shared preferences on a running
// emulator. It never touches a real device.
func (e *Engine) androidRuntime(ctx context.Context, progress func(string)) ([]model.Signal, []string, model.Status, string) {
	pkg := e.Cfg.Runtime.AndroidPackage
	if pkg == "" {
		return nil, nil, model.StatusBlocked, "set runtime.android_package in .pensec/config.yaml to the package of a debuggable test build"
	}
	if !pkgRe.MatchString(pkg) {
		return nil, nil, model.StatusError, "runtime.android_package is not a package name"
	}
	out, err := RunTool(ctx, "adb", "devices")
	if err != nil {
		return nil, nil, model.StatusBlocked, "adb is not available: " + err.Error()
	}
	serial := ""
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[1] == "device" && strings.HasPrefix(f[0], "emulator-") {
			serial = f[0]
			break
		}
	}
	if serial == "" {
		return nil, nil, model.StatusBlocked, "no running Android emulator (real devices are never used); start one with the test build installed"
	}
	if q, err := RunTool(ctx, "adb", "-s", serial, "shell", "getprop", "ro.kernel.qemu"); err != nil || strings.TrimSpace(string(q)) != "1" {
		if q2, err2 := RunTool(ctx, "adb", "-s", serial, "shell", "getprop", "ro.boot.qemu"); err2 != nil || strings.TrimSpace(string(q2)) != "1" {
			return nil, nil, model.StatusBlocked, serial + " does not report itself as an emulator (ro.kernel.qemu); real devices are never used"
		}
	}
	progress("Android emulator " + serial + ": " + pkg)
	ls, err := RunTool(ctx, "adb", "-s", serial, "shell", "run-as", pkg, "ls", "shared_prefs")
	if err != nil {
		if strings.Contains(err.Error(), "No such file") {
			return nil, nil, model.StatusPass, "app has no shared_prefs directory on " + serial + "; storage checked, transport not tested"
		}
		return nil, nil, model.StatusBlocked, "run-as " + pkg + " failed (" + err.Error() + "); the package must be installed on the emulator as a debuggable test build"
	}
	var sigs []model.Signal
	var files []string
	for _, name := range strings.Fields(string(ls)) {
		if !strings.HasSuffix(name, ".xml") || strings.ContainsAny(name, "/\\") {
			continue
		}
		rel := "shared_prefs/" + name
		files = append(files, rel)
		b, err := RunTool(ctx, "adb", "-s", serial, "shell", "run-as", pkg, "cat", rel)
		if err != nil {
			return nil, files, model.StatusError, "could not read " + rel + ": " + err.Error()
		}
		for _, k := range prefsCredentialKeys(b) {
			sigs = append(sigs, runtimeSignal("runtime.android-plain-credential", "K-003", "Credential stored in plain SharedPreferences on the emulator", "emulator:"+pkg+"/"+rel, k,
				"Use EncryptedSharedPreferences or the Android Keystore for tokens and exclude them from backups."))
		}
	}
	return sigs, files, model.StatusPass, fmt.Sprintf("%d shared_prefs file(s) of %s checked on %s; storage checked, transport not tested", len(files), pkg, serial)
}

// prefsCredentialKeys returns the names of non-empty string preferences
// whose key names a credential. Values are not returned.
func prefsCredentialKeys(b []byte) []string {
	var doc struct {
		Strings []struct {
			Name  string `xml:"name,attr"`
			Value string `xml:",chardata"`
		} `xml:"string"`
	}
	if xml.Unmarshal(b, &doc) != nil {
		return nil
	}
	var out []string
	for _, s := range doc.Strings {
		if credKeyRe.MatchString(s.Name) && strings.TrimSpace(s.Value) != "" {
			out = append(out, redact.Line(s.Name))
		}
	}
	return out
}

// iosRuntime checks the test app's preferences in a booted simulator.
func (e *Engine) iosRuntime(ctx context.Context, progress func(string)) ([]model.Signal, []string, model.Status, string) {
	id := e.Cfg.Runtime.IOSBundleID
	if HostOS != "darwin" {
		return nil, nil, model.StatusBlocked, "iOS simulator checks need macOS with Xcode; this host is " + HostOS
	}
	if id == "" {
		return nil, nil, model.StatusBlocked, "set runtime.ios_bundle_id in .pensec/config.yaml to the bundle ID of the test build"
	}
	if !pkgRe.MatchString(id) {
		return nil, nil, model.StatusError, "runtime.ios_bundle_id is not a bundle ID"
	}
	out, err := RunTool(ctx, "xcrun", "simctl", "get_app_container", "booted", id, "data")
	if err != nil {
		return nil, nil, model.StatusBlocked, "no booted simulator with " + id + " installed (" + err.Error() + "); real devices are never used"
	}
	container := strings.TrimSpace(string(out))
	if !strings.Contains(container, "/CoreSimulator/Devices/") {
		return nil, nil, model.StatusBlocked, "the app container is not inside a simulator; real devices are never used"
	}
	progress("iOS simulator: " + id)
	rel := "Library/Preferences/" + id + ".plist"
	xmlOut, err := RunTool(ctx, "plutil", "-convert", "xml1", "-o", "-", path.Join(container, rel))
	if err != nil {
		if strings.Contains(err.Error(), "No such file") || strings.Contains(err.Error(), "doesn't exist") {
			return nil, nil, model.StatusPass, "app has no preferences file in the simulator; storage checked, Keychain accessibility not tested"
		}
		return nil, nil, model.StatusError, "could not read " + rel + ": " + err.Error()
	}
	var sigs []model.Signal
	for _, k := range plistCredentialKeys(xmlOut) {
		sigs = append(sigs, runtimeSignal("runtime.ios-plain-credential", "L-002", "Credential stored in UserDefaults in the simulator", "simulator:"+id+"/"+rel, k,
			"Store credentials in the Keychain with a ThisDeviceOnly accessibility class."))
	}
	return sigs, []string{rel}, model.StatusPass, "preferences of " + id + " checked in the booted simulator; storage checked, Keychain accessibility not tested"
}

// plistCredentialKeys returns top-level keys of an XML property list whose
// name looks like a credential and whose value is a non-empty string or data.
func plistCredentialKeys(b []byte) []string {
	dec := xml.NewDecoder(bytes.NewReader(b))
	var out []string
	depth, key, inKey := 0, "", false
	for {
		tok, err := dec.Token()
		if err != nil {
			return out
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			inKey = t.Name.Local == "key" && depth == 3 // plist > dict > key
			if !inKey && t.Name.Local != "string" && t.Name.Local != "data" && depth == 3 {
				key = "" // a value of another type
			}
			if (t.Name.Local == "string" || t.Name.Local == "data") && depth == 3 && key != "" {
				var v string
				if dec.DecodeElement(&v, &t) == nil && strings.TrimSpace(v) != "" && credKeyRe.MatchString(key) {
					out = append(out, redact.Line(key))
				}
				depth--
				key = ""
			}
		case xml.EndElement:
			depth--
			inKey = false
		case xml.CharData:
			if inKey {
				key = string(t)
			}
		}
	}
}

func runtimeSignal(rule, cid, title, file, key, fix string) model.Signal {
	return model.Signal{RuleID: rule, ControlID: cid, Title: title, Severity: model.SevHigh, Confidence: model.Confirmed, CWE: "CWE-312", File: file,
		Message: "The test build stored a non-empty value under " + key + " in plain app storage. The value was not recorded.",
		Fix:     fix, Collector: "local-runtime", Key: key,
		Retest: "Install the fixed test build on the emulator or simulator, run the flow that stores the credential, then `pensec test --profile local-runtime` again."}
}
