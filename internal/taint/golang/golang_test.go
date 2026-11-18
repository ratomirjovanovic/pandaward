package golang

import (
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/flow"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

// analyze lowers a Go file and returns its flows as "kind:line".
func analyze(t *testing.T, src string) []string {
	t.Helper()
	spec, err := taint.Load("go")
	if err != nil {
		t.Fatal(err)
	}
	proj := flow.New(spec).NewProject(func(n string) (*ir.Module, []string) {
		if n != "a" {
			return nil, nil
		}
		m, errs := Parse("a.go", src, Env{Module: "a"})
		if errs != 0 {
			t.Fatalf("syntax error in test source")
		}
		return m, strings.Split(src, "\n")
	})
	var out []string
	for _, f := range proj.Module("a") {
		out = append(out, f.Sink.KindStr+":"+strconv.Itoa(f.Line))
	}
	sort.Strings(out)
	return out
}

const head = "package main\n\nimport (\n\t\"database/sql\"\n\t\"fmt\"\n\t\"net/http\"\n\t\"os\"\n\t\"os/exec\"\n\t\"path/filepath\"\n\t\"strconv\"; \"strings\"; \"html/template\"\n)\n\nvar db *sql.DB\n\n"

// body is the text after the imports, the first line of it is line 16.
func TestFlows(t *testing.T) {
	for _, c := range []struct{ name, src, want string }{
		{"sql concat", "func h(w http.ResponseWriter, r *http.Request) {\n\tid := r.FormValue(\"id\")\n\tdb.Query(\"SELECT * FROM u WHERE id = \" + id)\n}\n", "sql:17"},
		{"sql sprintf", "func h(w http.ResponseWriter, r *http.Request) {\n\tid := r.URL.Query().Get(\"id\")\n\tq := fmt.Sprintf(\"SELECT * FROM u WHERE id = '%s'\", id)\n\trows, err := db.Query(q)\n\t_ = rows\n\t_ = err\n}\n", "sql:18"},
		{"sql placeholder", "func h(w http.ResponseWriter, r *http.Request) {\n\tid := r.FormValue(\"id\")\n\tdb.Query(\"SELECT * FROM u WHERE id = ?\", id)\n}\n", ""},
		{"sql atoi", "func h(w http.ResponseWriter, r *http.Request) {\n\tid, _ := strconv.Atoi(r.FormValue(\"id\"))\n\tdb.Query(fmt.Sprintf(\"SELECT * FROM u WHERE id = %d\", id))\n}\n", ""},
		{"xss fprintf", "func h(w http.ResponseWriter, r *http.Request) {\n\tfmt.Fprintf(w, \"<p>%s</p>\", r.FormValue(\"n\"))\n}\n", "xss:16"},
		{"xss write", "func h(w http.ResponseWriter, r *http.Request) {\n\tn := r.PostFormValue(\"n\")\n\tw.Write([]byte(\"<p>\" + n + \"</p>\"))\n}\n", "xss:17"},
		{"xss constant", "func h(w http.ResponseWriter, r *http.Request) {\n\tfmt.Fprintf(w, \"<p>%s</p>\", \"hi\")\n}\n", ""},
		{"command", "func h(w http.ResponseWriter, r *http.Request) {\n\thost := r.FormValue(\"host\")\n\tout, _ := exec.Command(\"sh\", \"-c\", \"ping \"+host).Output()\n\t_ = out\n}\n", "cmd:17"},
		{"command constant", "func h(w http.ResponseWriter, r *http.Request) {\n\texec.Command(\"ls\", \"-l\").Run()\n}\n", ""},
		{"path", "func h(w http.ResponseWriter, r *http.Request) {\n\tf, _ := os.Open(r.URL.Query().Get(\"f\"))\n\t_ = f\n}\n", "path:16"},
		{"path base", "func h(w http.ResponseWriter, r *http.Request) {\n\tf, _ := os.Open(filepath.Base(r.URL.Query().Get(\"f\")))\n\t_ = f\n}\n", ""},
		{"url path", "func h(w http.ResponseWriter, r *http.Request) {\n\tos.ReadFile(\"/srv\" + r.URL.Path)\n}\n", "path:16"},
		{"redirect", "func h(w http.ResponseWriter, r *http.Request) {\n\thttp.Redirect(w, r, r.URL.Query().Get(\"next\"), 302)\n}\n", "redirect:16"},
		{"ssrf", "func h(w http.ResponseWriter, r *http.Request) {\n\tresp, _ := http.Get(r.FormValue(\"u\"))\n\t_ = resp\n}\n", "ssrf:16"},
		{"closure", "func h(w http.ResponseWriter, r *http.Request) {\n\tid := r.FormValue(\"id\")\n\trun := func() {\n\t\tdb.Query(\"SELECT \" + id)\n\t}\n\trun()\n}\n", "sql:18"},
		{"helper function", "func find(id string) {\n\tdb.Query(\"SELECT \" + id)\n}\n\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tfind(r.FormValue(\"id\"))\n}\n", "sql:16"},
		{"method", "type Repo struct{ db *sql.DB }\n\nfunc (s *Repo) find(id string) {\n\ts.db.Query(\"SELECT \" + id)\n}\n\nfunc h(w http.ResponseWriter, r *http.Request) {\n\ts := &Repo{}\n\ts.find(r.FormValue(\"id\"))\n}\n", "sql:18"},
		{"if guard", "func h(w http.ResponseWriter, r *http.Request) {\n\tid := r.FormValue(\"id\")\n\tif id == \"1\" || id == \"2\" {\n\t\tdb.Query(\"SELECT \" + id)\n\t}\n}\n", ""},
		{"if else", "func h(w http.ResponseWriter, r *http.Request) {\n\tvar q string\n\tif r.Method == \"GET\" {\n\t\tq = r.FormValue(\"q\")\n\t} else {\n\t\tq = \"x\"\n\t}\n\tdb.Query(\"SELECT \" + q)\n}\n", "sql:22"},
		{"loop", "func h(w http.ResponseWriter, r *http.Request) {\n\tfor _, v := range r.Form[\"id\"] {\n\t\tdb.Query(\"SELECT \" + v)\n\t}\n}\n", "sql:17"},
		{"log writer", "func h(w http.ResponseWriter, r *http.Request) {\n\tfmt.Fprintf(os.Stderr, \"%s\", r.FormValue(\"n\"))\n}\n", ""},
		{"redirect trimmed", "func h(w http.ResponseWriter, r *http.Request) {\n\thttp.Redirect(w, r, \"/\"+strings.Trim(r.URL.Path, \"/\"), 301)\n}\n", ""},
		{"template parse", "func h(w http.ResponseWriter, r *http.Request) {\n\tt, _ := template.New(\"x\").Parse(r.FormValue(\"t\"))\n\t_ = t\n}\n", "code:16"},
		{"switch", "func h(w http.ResponseWriter, r *http.Request) {\n\tswitch r.Method {\n\tcase \"GET\":\n\t\tdb.Query(\"SELECT \" + r.FormValue(\"a\"))\n\t}\n}\n", "sql:18"},
	} {
		got := strings.Join(analyze(t, head+c.src), " ")
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestSyntaxError(t *testing.T) {
	_, errs := Parse("a.go", "package main\nfunc h( {\n", Env{Module: "a"})
	if errs == 0 {
		t.Error("a broken file must be counted")
	}
}
