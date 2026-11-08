package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/redact"
	"github.com/ratomirjovanovic/pandaward/internal/scope"
)

// maxProvisionOutput caps what a provisioning command may print.
const maxProvisionOutput = 256 << 10

// provisioned is the result of the provision command. Values stay in
// memory only: they are never written to the ledger, evidence or reports.
type provisioned struct {
	values map[string]string // value_env -> header value
	inputs map[string]string // body_env or header_env -> value
	raw    []byte            // stdout, handed to cleanup on stdin
}

// ProvisionCommand runs one provisioning command; tests replace it. It
// returns stdout and a redaction-safe description of any failure.
var ProvisionCommand = runProvisionCommand

func runProvisionCommand(ctx context.Context, root string, argv []string, stdin []byte, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = root
	cmd.WaitDelay = 2 * time.Second
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb limitedBuffer
	out.max, errb.max = maxProvisionOutput, 4<<10
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return out.Bytes(), fmt.Errorf("timed out after %s", timeout)
	}
	if out.over {
		return nil, fmt.Errorf("printed more than %d bytes", maxProvisionOutput)
	}
	if err != nil {
		// stderr is not repeated: a failing script may print a token in a
		// form redaction does not recognize.
		msg := err.Error()
		if errb.Len() > 0 {
			msg += " (its stderr is not shown, so no credential can leak; run the command yourself to see it)"
		}
		return out.Bytes(), errors.New(msg)
	}
	return out.Bytes(), nil
}

type limitedBuffer struct {
	bytes.Buffer
	max  int
	over bool
}

// Write keeps at most max bytes and reports every byte as written, so a
// chatty command is not killed by a short write.
func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len()+n > b.max {
		b.over = true
		p = p[:max(0, b.max-b.Len())]
	}
	b.Buffer.Write(p)
	return n, nil
}

// scrub removes every provisioned value from a message before redaction,
// so a command that echoes a token on failure does not leak it.
func scrub(msg string, values map[string]string) string {
	for _, v := range values {
		if len(v) >= 4 {
			msg = strings.ReplaceAll(msg, v, "[redacted]")
		}
	}
	return redact.Line(msg)
}

// provisionIdentities runs the provision command of an approved manifest
// and reads the credentials it prints. Only names the manifest declares as
// value_env are accepted.
func (e *Engine) provisionIdentities(ctx context.Context, m *scope.Manifest) (*provisioned, error) {
	ip := m.IdentityProvisioning
	out, err := ProvisionCommand(ctx, e.Root, ip.Provision, nil, ip.Timeout())
	var doc struct {
		Credentials map[string]string `json:"credentials"`
		Inputs      map[string]string `json:"inputs"`
	}
	known := map[string]bool{}
	for _, id := range m.Identities {
		known[id.ValueEnv] = true
	}
	parseErr := json.Unmarshal(bytes.TrimSpace(out), &doc)
	if err != nil {
		return nil, fmt.Errorf("identity provisioning (%s) failed: %s", argvText(ip.Provision), scrub(scrub(err.Error(), doc.Credentials), doc.Inputs))
	}
	if parseErr != nil {
		return nil, fmt.Errorf("identity provisioning (%s) did not print JSON {\"credentials\": {\"<value_env>\": \"<header value>\"}}", argvText(ip.Provision))
	}
	var unknown []string
	for k, v := range doc.Credentials {
		switch {
		case !known[k]:
			unknown = append(unknown, k)
		case strings.TrimSpace(v) == "":
			return nil, fmt.Errorf("identity provisioning returned an empty value for %s", k)
		case strings.ContainsAny(v, "\r\n"):
			return nil, fmt.Errorf("identity provisioning returned a value with a line break for %s", k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("identity provisioning returned %s, which no identity declares as value_env", strings.Join(unknown, ", "))
	}
	envs := m.InputEnvs()
	for k, v := range doc.Inputs {
		header, ok := envs[k]
		switch {
		case !ok:
			unknown = append(unknown, k)
		case header && strings.ContainsAny(v, "\r\n"):
			return nil, fmt.Errorf("identity provisioning returned a header value with a line break for %s", k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("identity provisioning returned inputs %s, which no check declares as body_env or header_env", strings.Join(unknown, ", "))
	}
	return &provisioned{values: doc.Credentials, inputs: doc.Inputs, raw: out}, nil
}

// cleanupIdentities runs the cleanup command with the provision output on
// stdin. It gets its own timeout, so it also runs after a cancelled test.
func (e *Engine) cleanupIdentities(m *scope.Manifest, p *provisioned) error {
	ip := m.IdentityProvisioning
	if ip == nil || len(ip.Cleanup) == 0 || p == nil {
		return nil
	}
	if _, err := ProvisionCommand(context.Background(), e.Root, ip.Cleanup, p.raw, ip.Timeout()); err != nil {
		return fmt.Errorf("identity cleanup (%s) failed: %s", argvText(ip.Cleanup), scrub(scrub(err.Error(), p.values), p.inputs))
	}
	return nil
}

func argvText(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		if strings.ContainsAny(a, " \t\"") {
			a = fmt.Sprintf("%q", a)
		}
		parts[i] = a
	}
	return redact.Line(strings.Join(parts, " "))
}

var _ io.Writer = (*limitedBuffer)(nil)
