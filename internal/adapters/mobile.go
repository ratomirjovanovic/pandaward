package adapters

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
)

// manifestControls names the controls an AndroidManifest.xml check reports
// under: source manifests use K-001 and K-002, decoded APKs K-005.
type manifestControls struct{ config, export string }

// manifestSignals runs the Android manifest checks on one manifest.
func manifestSignals(text, file, collector string, ctl manifestControls) ([]model.Signal, error) {
	var out []model.Signal
	lineOf := func(off int64) int { return strings.Count(text[:min(int(off), len(text))], "\n") + 1 }
	dec := xml.NewDecoder(strings.NewReader(text))
	dec.Strict = false
	type comp struct {
		kind, name string
		line       int
		exported   string
		perm       bool
		launcher   bool
	}
	var cur *comp
	for {
		off := dec.InputOffset()
		tok, err := dec.Token()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "application":
				for _, chk := range []struct {
					attr, bad, id, title string
					sev                  model.Severity
					cwe                  string
				}{
					{"debuggable", "true", "mobile.android-debuggable", "Android app is debuggable", model.SevHigh, "CWE-489"},
					{"allowBackup", "true", "mobile.android-allow-backup", "Android backup enabled", model.SevLow, "CWE-530"},
					{"usesCleartextTraffic", "true", "mobile.android-cleartext", "Android cleartext traffic allowed", model.SevMedium, "CWE-319"},
				} {
					if v, ok := attr(t, chk.attr); ok && v == chk.bad {
						ln := lineOf(off)
						out = append(out, model.Signal{RuleID: chk.id, ControlID: ctl.config, Title: chk.title, Severity: chk.sev, Confidence: model.Confirmed, CWE: chk.cwe,
							File: file, StartLine: ln, EndLine: ln, Snippet: "android:" + chk.attr + "=\"" + chk.bad + "\"",
							Message: "Manifest sets android:" + chk.attr + "=\"" + chk.bad + "\". Static observation; runtime impact depends on build variant.",
							Fix:     "Set android:" + chk.attr + " to false for release builds (use build-type manifest placeholders).", Collector: collector})
					}
				}
			case "activity", "activity-alias", "service", "receiver", "provider":
				name, _ := attr(t, "name")
				exp, _ := attr(t, "exported")
				_, perm := attr(t, "permission")
				cur = &comp{kind: t.Name.Local, name: name, line: lineOf(off), exported: exp, perm: perm}
			case "action":
				if cur != nil {
					if n, _ := attr(t, "name"); n == "android.intent.action.MAIN" {
						cur.launcher = true
					}
				}
			}
		case xml.EndElement:
			if cur != nil && t.Name.Local == cur.kind {
				if cur.exported == "true" && !cur.perm && !cur.launcher {
					out = append(out, model.Signal{RuleID: "mobile.android-exported-component", ControlID: ctl.export, Title: "Exported Android component without permission", Severity: model.SevMedium, Confidence: model.Hypothesis, CWE: "CWE-926",
						File: file, StartLine: cur.line, EndLine: cur.line, Snippet: redact.Line(cur.kind + " " + cur.name + " exported=true"),
						Message: "Any installed app can invoke this " + cur.kind + ". Confirm it validates callers and input.",
						Fix:     "Set android:exported=\"false\" unless required, or protect it with a signature-level permission.", Collector: collector, Key: cur.name})
				}
				cur = nil
			}
		}
	}
}

// credKey matches storage keys that name credentials.
const credKey = `(?i)[^"]*(token|password|passwd|secret|session|api_?key|credential|refresh)[^"]*`

// mobileStorageRules flag credentials kept in plain app storage.
var mobileStorageRules = []lineRule{
	{ID: "mobile.android-world-readable", Control: "K-004", Title: "World-readable or world-writable Android storage", Langs: langs("java", "kotlin"),
		Re: regexp.MustCompile(`\bMODE_WORLD_(READABLE|WRITEABLE)\b`), Severity: model.SevHigh, Confidence: model.Confirmed, CWE: "CWE-276",
		Message: "Files or preferences created with MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE can be read or changed by other apps (and throw on Android 7+).",
		Fix:     "Use MODE_PRIVATE; share data through a ContentProvider with permissions or FileProvider."},
	{ID: "mobile.android-prefs-credential", Control: "K-004", Title: "Credential stored in plain SharedPreferences", Langs: langs("java", "kotlin"),
		Re: regexp.MustCompile(`\.putString\(\s*"` + credKey + `"`), Not: regexp.MustCompile(`(?i)encrypted`), Severity: model.SevMedium, Confidence: model.Hypothesis, CWE: "CWE-312",
		Message: "A value under a credential-like key is written to SharedPreferences, which is stored unencrypted in the app's data directory and included in backups.",
		Fix:     "Keep tokens in EncryptedSharedPreferences or the Android Keystore, and exclude them from backups."},
	{ID: "mobile.ios-keychain-always", Control: "L-004", Title: "Keychain item accessible while the device is locked", Langs: langs("swift", "objc"),
		Re: regexp.MustCompile(`\bkSecAttrAccessibleAlways(ThisDeviceOnly)?\b`), Severity: model.SevMedium, Confidence: model.Confirmed, CWE: "CWE-922",
		Message: "kSecAttrAccessibleAlways keeps the item readable even when the device is locked; Apple deprecated it.",
		Fix:     "Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly, or AfterFirstUnlockThisDeviceOnly for background access."},
	{ID: "mobile.ios-userdefaults-credential", Control: "L-004", Title: "Credential stored in UserDefaults", Langs: langs("swift", "objc"),
		Re: regexp.MustCompile(`(UserDefaults[^\n]*\.set\([^\n]*forKey:\s*"` + credKey + `"|NSUserDefaults[^;]*setObject:[^;]*forKey:\s*@"` + credKey + `")`), Severity: model.SevMedium, Confidence: model.Hypothesis, CWE: "CWE-312",
		Message: "A value under a credential-like key is written to UserDefaults, a plain property list in the app container that is included in backups.",
		Fix:     "Store credentials in the Keychain with a ThisDeviceOnly accessibility class."},
}

// mobileSourceSignals applies the storage rules to Swift, Objective-C,
// Java and Kotlin files and the debugging check to entitlements files.
func mobileSourceSignals(inv *inventory.Inventory, collector string) []model.Signal {
	var out []model.Signal
	for _, f := range inv.Files {
		if IsTestPath(f.Path) {
			continue
		}
		if strings.HasSuffix(strings.ToLower(f.Path), ".entitlements") {
			out = append(out, entitlementSignals(f, collector)...)
			continue
		}
		for i, l := range f.Lines {
			if commentRe.MatchString(l) {
				continue
			}
			for _, r := range mobileStorageRules {
				if r.Langs[f.Lang] && r.Re.MatchString(l) && (r.Not == nil || !r.Not.MatchString(l)) {
					out = append(out, sig(r, f, i+1, collector))
				}
			}
		}
	}
	return out
}

func entitlementSignals(f *inventory.File, collector string) []model.Signal {
	base := strings.ToLower(filepath.Base(f.Path))
	if strings.Contains(base, "debug") || strings.Contains(base, "dev") {
		return nil // a debug-only entitlements file may allow debugging
	}
	for i, l := range f.Lines {
		if !strings.Contains(l, "<key>get-task-allow</key>") {
			continue
		}
		next := l
		if i+1 < len(f.Lines) {
			next += f.Lines[i+1]
		}
		if strings.Contains(next, "<true/>") {
			return []model.Signal{{RuleID: "mobile.ios-get-task-allow", ControlID: "L-003", Title: "iOS entitlements allow debugging (get-task-allow)", Severity: model.SevMedium, Confidence: model.Hypothesis, CWE: "CWE-489",
				File: f.Path, StartLine: i + 1, EndLine: i + 2, Snippet: "get-task-allow = true",
				Message: "get-task-allow lets a debugger attach to the app. It is expected in debug builds; in a release or distribution entitlements file it exposes memory and keychain access.",
				Fix:     "Keep get-task-allow only in the Debug configuration's entitlements; release signing should set it to false.", Collector: collector}}
		}
	}
	return nil
}

// apktoolAdapter decodes APKs found in the project with a user-installed
// apktool (resources only, no smali) and checks the decoded manifest. The
// APK's code is never run.
type apktoolAdapter struct{}

func (apktoolAdapter) Name() string       { return "apktool" }
func (apktoolAdapter) Controls() []string { return []string{"K-005"} }
func (apktoolAdapter) Maturity() string   { return MaturityUnvalidated }
func (apktoolAdapter) Network() bool      { return false }

func (apktoolAdapter) lookup() (string, error) {
	for _, n := range []string{"apktool", "apktool.bat"} {
		if p, err := exec.LookPath(n); err == nil {
			return p, nil
		}
	}
	return "", errors.New("apktool is not installed (optional; needs Java)")
}

func (a apktoolAdapter) version(ctx context.Context, bin string) string {
	cmd := exec.CommandContext(ctx, bin, "--version")
	cmd.Env = inventory.MinimalEnv()
	out, _ := cmd.Output()
	return firstLine(string(out))
}

func (a apktoolAdapter) Run(ctx context.Context, c *Context) (Result, model.Run) {
	res := Result{Decisions: map[string]Decision{}}
	apks := c.Inv.Features["apk"]
	bin, err := a.lookup()
	if err != nil {
		return res, finish(newRun(a.Name(), ""), model.ExitBlocked, err.Error()+"; run `pandaward doctor`", 0)
	}
	run := newRun(a.Name(), a.version(ctx, bin))
	if len(apks) == 0 {
		return res, finish(run, model.ExitUnsupported, "no .apk files in the project", 0)
	}
	if err := os.MkdirAll(c.ToolHome, 0o700); err != nil {
		return res, finish(run, model.ExitError, err.Error(), 0)
	}
	tmp, err := os.MkdirTemp("", "pandaward-")
	if err != nil {
		return res, finish(run, model.ExitError, err.Error(), 0)
	}
	defer os.RemoveAll(tmp)
	for i, rel := range apks {
		out := filepath.Join(c.RunDir, fmt.Sprintf("apktool-%d", i))
		cctx, cancel := context.WithTimeout(ctx, c.Timeout)
		cmd := exec.CommandContext(cctx, bin, "d", "--no-src", "-f", "-o", out, filepath.Join(c.Root, filepath.FromSlash(rel)))
		cmd.Dir = c.RunDir
		cmd.Env = append(toolEnv(c, tmp), javaHome()...)
		var stderr bytes.Buffer
		cmd.Stdout = io.Discard
		cmd.Stderr = &limitedBuffer{b: &stderr, max: 1 << 20}
		err := cmd.Run()
		timedOut := errors.Is(cctx.Err(), context.DeadlineExceeded)
		cancel()
		if timedOut {
			return res, finish(run, model.ExitTimeout, fmt.Sprintf("apktool exceeded %s on %s", c.Timeout, rel), len(res.Signals))
		}
		if err != nil {
			why := firstLine(stderr.String())
			if why == "" {
				why = err.Error()
			}
			return res, finish(run, model.ExitError, "apktool could not decode "+rel+": "+why, len(res.Signals))
		}
		b, err := os.ReadFile(filepath.Join(out, "AndroidManifest.xml"))
		if err != nil {
			return res, finish(run, model.ExitError, "apktool wrote no AndroidManifest.xml for "+rel, len(res.Signals))
		}
		sigs, err := manifestSignals(string(b), rel, a.Name(), manifestControls{"K-005", "K-005"})
		if err != nil {
			return res, finish(run, model.ExitError, "could not parse the decoded manifest of "+rel+": "+err.Error(), len(res.Signals))
		}
		for i := range sigs {
			sigs[i].StartLine, sigs[i].EndLine = 0, 0 // lines refer to the decoded file, not to the APK
			sigs[i].Message = "Decoded from the built APK. " + sigs[i].Message
		}
		res.Signals = append(res.Signals, sigs...)
	}
	return res, finish(run, model.ExitOK, fmt.Sprintf("%d APK(s) decoded (resources only)", len(apks)), len(res.Signals))
}

func javaHome() []string {
	if j := os.Getenv("JAVA_HOME"); j != "" {
		return []string{"JAVA_HOME=" + j}
	}
	return nil
}
