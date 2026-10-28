package engine

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/scope"
)

// approvalKeyPath is a per-user secret outside every repository. Approvals
// are bound to it, so a ledger copied from elsewhere (for example a
// .pandaward/private/state.db committed to a malicious repository) can never
// carry a valid approval.
// PANDAWARD_CONFIG_DIR overrides the user config directory (used by tests).
func approvalKeyPath() (string, error) {
	if d := config.Env("CONFIG_DIR"); d != "" {
		return filepath.Join(d, "approval.key"), nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("no user config directory for the approval key: %w", err)
	}
	return filepath.Join(dir, "pandaward", "approval.key"), nil
}

// adoptLegacyKey copies the key from the pre-rename location (pensec/ in
// the user config directory) to p, so approvals made with 0.1.x stay valid.
func adoptLegacyKey(p string) ([]byte, error) {
	if config.Env("CONFIG_DIR") != "" {
		return nil, os.ErrNotExist
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, os.ErrNotExist
	}
	b, err := os.ReadFile(filepath.Join(dir, config.LegacyUserDir, "approval.key"))
	if err != nil || len(b) != 32 {
		return nil, os.ErrNotExist
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

func approvalKey(create bool) ([]byte, error) {
	p, err := approvalKeyPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		b, err = adoptLegacyKey(p)
	}
	if err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("approval key %s is damaged; delete it and approve the scope again", p)
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) || !create {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

// ApprovalSubject is what an approval binds to: the exact manifest bytes,
// this project and this user's approval key. create makes the key on first
// use; checks pass false so that a missing key simply means "not approved".
func (e *Engine) ApprovalSubject(m *scope.Manifest, create bool) (string, error) {
	key, err := approvalKey(create)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(e.ProjectID + "|" + m.Hash()))
	return hex.EncodeToString(mac.Sum(nil)), nil
}
