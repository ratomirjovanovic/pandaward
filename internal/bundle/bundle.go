// Package bundle exports one assessment as a zip that a reviewer can verify:
// the report, the redacted evidence it cites and a manifest with the SHA-256
// of every file. Raw tool output and the ledger are never included.
package bundle

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/evidence"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
	"github.com/ratomirjovanovic/pandaward/internal/report"
	"github.com/ratomirjovanovic/pandaward/internal/store"
	"github.com/ratomirjovanovic/pandaward/internal/version"
)

// ManifestName is the manifest's path inside a bundle.
const ManifestName = "manifest.json"

const (
	maxFileBytes  = 64 << 20
	maxTotalBytes = 1 << 30
)

// FileEntry is one file listed in a manifest.
type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Manifest describes a bundle.
type Manifest struct {
	SchemaVersion int              `json:"schema_version"`
	Generator     string           `json:"generator"`
	CreatedAt     string           `json:"created_at"`
	Project       string           `json:"project"`
	Assessment    store.Assessment `json:"assessment"`
	Files         []FileEntry      `json:"files"`
	Note          string           `json:"note"`
}

// Export writes the bundle for report r to out, which must not exist. It
// returns the manifest's SHA-256, which the recipient can compare through a
// separate channel. Export fails closed: evidence that does not match its
// recorded hash, or any file that redaction would still change, aborts it.
func Export(r *report.Report, private, out string) (string, int, error) {
	files := map[string][]byte{}
	rep, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", 0, err
	}
	files["report.json"] = rep
	files["report.md"] = []byte(report.Markdown(r))
	for i := range r.EvidenceIndex {
		row := r.EvidenceIndex[i]
		b, err := evidence.Read(private, &row)
		if err != nil {
			return "", 0, fmt.Errorf("refusing to export: %w", err)
		}
		files["evidence/"+path.Base(filepath.ToSlash(row.Path))] = b
	}
	names := make([]string, 0, len(files))
	for n, b := range files {
		if redact.HasSecrets(string(b)) {
			return "", 0, fmt.Errorf("refusing to export: %s still contains text that redaction would change", n)
		}
		names = append(names, n)
	}
	sort.Strings(names)

	m := Manifest{SchemaVersion: model.SchemaVersion, Generator: "pandaward " + version.Version, CreatedAt: store.Now(), Project: r.Project, Assessment: r.Assessment,
		Note: "Every file is listed with its SHA-256. Compare the manifest's own SHA-256 with the value the sender gave you through a separate channel."}
	for _, n := range names {
		sum := sha256.Sum256(files[n])
		m.Files = append(m.Files, FileEntry{Path: n, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(files[n]))})
	}
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", 0, err
	}

	// Entries get a fixed timestamp so the archive depends only on content.
	stamp := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range append(names, ManifestName) {
		b := files[n]
		if n == ManifestName {
			b = mb
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Deflate, Modified: stamp})
		if err != nil {
			return "", 0, err
		}
		if _, err := w.Write(b); err != nil {
			return "", 0, err
		}
	}
	if err := zw.Close(); err != nil {
		return "", 0, err
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", 0, err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		os.Remove(out)
		return "", 0, err
	}
	if err := f.Close(); err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(mb)
	return hex.EncodeToString(sum[:]), len(names), nil
}

// Verify checks a bundle: every file listed in the manifest is present with
// the recorded size and SHA-256, nothing else is in the archive, and entry
// names are plain relative paths. It returns the manifest and its SHA-256.
func Verify(p string) (*Manifest, string, error) {
	zr, err := zip.OpenReader(p)
	if err != nil {
		return nil, "", err
	}
	defer zr.Close()
	contents := map[string][]byte{}
	var total int64
	for _, f := range zr.File {
		n := f.Name
		if n == "" || strings.HasPrefix(n, "/") || strings.Contains(n, `\`) || strings.Contains(n, "..") || path.Clean(n) != n {
			return nil, "", fmt.Errorf("unsafe entry name %q", n)
		}
		if _, dup := contents[n]; dup {
			return nil, "", fmt.Errorf("duplicate entry %q", n)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, "", err
		}
		b, err := io.ReadAll(io.LimitReader(rc, maxFileBytes+1))
		rc.Close()
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", n, err)
		}
		if len(b) > maxFileBytes {
			return nil, "", fmt.Errorf("%s is larger than %d bytes", n, maxFileBytes)
		}
		if total += int64(len(b)); total > maxTotalBytes {
			return nil, "", errors.New("bundle is larger than allowed")
		}
		contents[n] = b
	}
	mb, ok := contents[ManifestName]
	if !ok {
		return nil, "", errors.New("bundle has no " + ManifestName)
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(mb))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, "", fmt.Errorf("manifest: %w", err)
	}
	listed := map[string]bool{ManifestName: true}
	var problems []string
	for _, fe := range m.Files {
		listed[fe.Path] = true
		b, ok := contents[fe.Path]
		if !ok {
			problems = append(problems, fe.Path+": missing")
			continue
		}
		sum := sha256.Sum256(b)
		if int64(len(b)) != fe.Bytes || hex.EncodeToString(sum[:]) != fe.SHA256 {
			problems = append(problems, fe.Path+": content does not match the manifest")
		}
	}
	for n := range contents {
		if !listed[n] {
			problems = append(problems, n+": not listed in the manifest")
		}
	}
	sort.Strings(problems)
	sum := sha256.Sum256(mb)
	if len(problems) > 0 {
		return &m, hex.EncodeToString(sum[:]), errors.New(strings.Join(problems, "; "))
	}
	return &m, hex.EncodeToString(sum[:]), nil
}
