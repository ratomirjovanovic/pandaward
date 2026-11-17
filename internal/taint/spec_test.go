package taint

import "testing"

func TestLoadJavaScript(t *testing.T) {
	s, err := Load("javascript")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Sinks) < 6 {
		t.Fatalf("%d sinks", len(s.Sinks))
	}
	for _, k := range s.Sinks {
		if k.ID == "" || k.Control == "" || k.CWE == "" || k.Title == "" || k.Fix == "" {
			t.Errorf("sink %+v lacks metadata", k)
		}
	}
	if s.Sanitizes("path.basename")&Path == 0 || s.Sanitizes("parseInt") != All {
		t.Fatal("sanitizers not loaded")
	}
}

func TestTrace(t *testing.T) {
	tr := NewSource(1, "req.query.x", false).Add(2, "cmd").Add(2, "cmd").Add(3, "exec")
	st := tr.Steps()
	if len(st) != 3 || st[0].What != "req.query.x" || st[2].Line != 3 {
		t.Fatalf("%+v", st)
	}
}
