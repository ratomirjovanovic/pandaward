package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/scope"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

const (
	bodyEvent  = `{"id":"evt_7f1c2a","type":"payment.succeeded","credits":10}`
	sigEvent   = "t=1,v1=sig-5e2b9c11"
	bodyCoupon = `{"code":"WELCOME-4d1a"}`
)

// walletApp credits a payment event on every delivery and redeems a coupon
// with a check-then-write race; fixed records event ids and serializes the
// redemption.
func walletApp(fixed *atomic.Bool) *httptest.Server {
	var mu, redeemMu sync.Mutex
	credits, balance := 0, 0
	events := map[string]bool{}
	redeemed := map[string]bool{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/webhooks/payment", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Webhook-Signature") != sigEvent {
			http.Error(w, "bad signature", http.StatusBadRequest)
			return
		}
		var in struct {
			ID      string
			Credits int
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		mu.Lock()
		defer mu.Unlock()
		if fixed.Load() && events[in.ID] {
			fmt.Fprint(w, `{"duplicate":true}`)
			return
		}
		events[in.ID] = true
		credits += in.Credits
		fmt.Fprint(w, `{"ok":true}`)
	})
	mux.HandleFunc("/api/coupons/redeem", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != tokAlice {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		var in struct{ Code string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		if fixed.Load() {
			redeemMu.Lock()
			defer redeemMu.Unlock()
		}
		mu.Lock()
		used := redeemed[in.Code]
		mu.Unlock()
		if used {
			http.Error(w, "already redeemed", http.StatusConflict)
			return
		}
		time.Sleep(50 * time.Millisecond) // the window between check and write
		mu.Lock()
		redeemed[in.Code] = true
		balance += 5
		mu.Unlock()
		fmt.Fprint(w, `{"ok":true}`)
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != tokAlice {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(w, `{"wallet":{"credits":%d,"balance":"%d"}}`, credits, balance)
	})
	return httptest.NewServer(mux)
}

const effectYAML = `identities:
  - {name: alice, header: Authorization, value_env: PANDAWARD_T_ALICE}
effect_checks:
  - name: payment webhook replay
    control: F-002
    action: {method: POST, path: /api/webhooks/payment, body_env: PANDAWARD_T_EVENT, header_env: {Webhook-Signature: PANDAWARD_T_SIG}}
    repeat: 3
    probe: {method: GET, path: /api/me, as: alice, json: wallet.credits}
    expect_delta: 10
  - name: coupon under concurrency
    control: Q-002
    action: {method: POST, path: /api/coupons/redeem, as: alice, body_env: PANDAWARD_T_COUPON}
    repeat: 5
    probe: {method: GET, path: /api/me, as: alice, json: wallet.balance}
    expect_delta: 5
`

func effectProject(t *testing.T, target string) *engine.Engine {
	t.Helper()
	root := testfixture.VulnerableRepo(t)
	e, _, err := engine.Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	if _, err := e.Scan(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	y := strings.NewReplacer(
		`owner: ""`, `owner: "Fixture Owner"`,
		`reference: ""`, `reference: "TEST-12"`,
		`purpose: ""`, `purpose: "effect test"`,
		`acknowledged: false`, `acknowledged: true`,
		"targets: []", "targets:\n  - url: "+target,
		"allowed_methods: [GET, HEAD]", "allowed_methods: [GET, HEAD, POST]",
		"allow_private_addresses: false", "allow_private_addresses: true",
		"requests_per_second: 1", "requests_per_second: 10",
		"identities: []\n", "",
		"effect_checks: []\n", "",
	).Replace(scope.Template) + effectYAML
	if err := os.WriteFile(scope.Path(root), []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEffectChecksFailDoubleProcessingAndPassWhenFixed(t *testing.T) {
	t.Setenv("PANDAWARD_CONFIG_DIR", t.TempDir())
	var fixed atomic.Bool
	app := walletApp(&fixed)
	defer app.Close()
	noZAP(t)
	t.Setenv("PANDAWARD_T_ALICE", tokAlice)
	t.Setenv("PANDAWARD_T_EVENT", bodyEvent)
	t.Setenv("PANDAWARD_T_SIG", sigEvent)
	t.Setenv("PANDAWARD_T_COUPON", bodyCoupon)
	e := effectProject(t, app.URL)
	approveScope(t, e)

	res, err := e.StagingActive(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	for _, cid := range []string{"F-002", "Q-002"} {
		if res.Controls[cid] != string(model.StatusFail) {
			t.Errorf("%s = %s, want FAIL (%v)", cid, res.Controls[cid], res.Notes)
		}
	}
	fs, _ := e.St.Findings(e.ProjectID)
	var rules []string
	for _, f := range fs {
		if f.Collector == "effect" {
			rules = append(rules, f.RuleID+" "+string(f.Confidence))
		}
	}
	sort.Strings(rules)
	if fmt.Sprint(rules) != "[effect.duplicate-processing CONFIRMED effect.race-condition CONFIRMED]" {
		t.Fatalf("effect findings %v", rules)
	}
	assertNoEffectInputs(t, e)

	// The fixed app needs a new event id and coupon, as a provisioning
	// command would hand out.
	fixed.Store(true)
	t.Setenv("PANDAWARD_T_EVENT", strings.Replace(bodyEvent, "evt_7f1c2a", "evt_0b9d33", 1))
	t.Setenv("PANDAWARD_T_COUPON", strings.Replace(bodyCoupon, "WELCOME-4d1a", "WELCOME-8c2e", 1))
	res, err = e.StagingActive(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	for _, cid := range []string{"F-002", "Q-002"} {
		if res.Controls[cid] != string(model.StatusPass) {
			t.Errorf("fixed: %s = %s, want PASS (%v)", cid, res.Controls[cid], res.Notes)
		}
	}
	fs, _ = e.St.Findings(e.ProjectID)
	for _, f := range fs {
		if f.Collector == "effect" && f.Status != model.FindingRemediated {
			t.Errorf("%s %s is %s after the fix, want REMEDIATED", f.ID, f.RuleID, f.Status)
		}
	}
	assertNoEffectInputs(t, e)

	// A used coupon has no effect at all, which says nothing about races.
	res, err = e.StagingActive(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if res.Controls["Q-002"] != string(model.StatusInconclusive) {
		t.Errorf("used coupon: Q-002 = %s, want INCONCLUSIVE (%v)", res.Controls["Q-002"], res.Notes)
	}
}

func assertNoEffectInputs(t *testing.T, e *engine.Engine) {
	t.Helper()
	assertNoTokens(t, e)
	assertAbsent(t, e, "evt_7f1c2a", "evt_0b9d33", "sig-5e2b9c11", "WELCOME-4d1a", "WELCOME-8c2e")
}
