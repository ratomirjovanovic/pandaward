package catalog_test

import (
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pensec/internal/adapters"
	"github.com/ratomirjovanovic/pensec/internal/catalog"
)

// Adapters decided outside the adapter registry: evidence integrity runs in
// the engine after every scan, and header observation is a runtime profile.
var engineAdapters = map[string]bool{"builtin-evidence": true, "observe-headers": true}

func TestControlsAreConsistent(t *testing.T) {
	domains := map[string]bool{}
	for _, d := range catalog.Domains {
		domains[d.ID] = true
	}
	registered := map[string]adapters.Adapter{}
	for _, a := range adapters.Registry() {
		registered[a.Name()] = a
	}
	seen := map[string]bool{}
	for _, c := range catalog.Controls {
		if seen[c.ID] {
			t.Errorf("duplicate control %s", c.ID)
		}
		seen[c.ID] = true
		if !domains[c.Domain] || !strings.HasPrefix(c.ID, c.Domain+"-") {
			t.Errorf("%s: domain %q is unknown or does not match the ID", c.ID, c.Domain)
		}
		switch c.Method {
		case catalog.MethodStatic, catalog.MethodExternal:
			if registered[c.Adapter] == nil && !engineAdapters[c.Adapter] {
				t.Errorf("%s: adapter %q is not registered", c.ID, c.Adapter)
			}
		case catalog.MethodRuntime:
			if c.Profile == "" {
				t.Errorf("%s: runtime control without a profile", c.ID)
			}
		case catalog.MethodManual:
			if c.Adapter != "" {
				t.Errorf("%s: manual control must not name an adapter", c.ID)
			}
		default:
			t.Errorf("%s: unknown method %q", c.ID, c.Method)
		}
		if c.Requires == "" || c.Title == "" {
			t.Errorf("%s: missing title or applicability requirement", c.ID)
		}
	}
}

// Every control an adapter claims must name that adapter in the catalog,
// otherwise its decision would be written under the wrong owner.
func TestAdaptersClaimTheirOwnControls(t *testing.T) {
	for _, a := range adapters.Registry() {
		if len(a.Controls()) == 0 {
			t.Errorf("%s claims no controls", a.Name())
		}
		for _, id := range a.Controls() {
			c := catalog.ControlByID(id)
			if c == nil {
				t.Errorf("%s claims unknown control %s", a.Name(), id)
				continue
			}
			if c.Adapter != a.Name() {
				t.Errorf("%s claims %s, which the catalog assigns to %q", a.Name(), id, c.Adapter)
			}
		}
	}
}

func TestEdgesReferenceKnownControls(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range catalog.Edges {
		if seen[e.ID] {
			t.Errorf("duplicate edge %s", e.ID)
		}
		seen[e.ID] = true
		if len(e.Needs) == 0 || len(e.Tests) == 0 {
			t.Errorf("%s: edge needs at least one asset feature and one linked control", e.ID)
		}
		for _, id := range e.Tests {
			if catalog.ControlByID(id) == nil {
				t.Errorf("%s links unknown control %s", e.ID, id)
			}
		}
	}
}
