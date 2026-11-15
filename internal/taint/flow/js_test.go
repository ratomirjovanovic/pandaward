package flow

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
	"github.com/ratomirjovanovic/pandaward/internal/taint/js"
)

// jsFlows analyzes one JavaScript file in library mode and returns
// "sink:line" for each flow.
func jsFlows(t *testing.T, src string) []string {
	t.Helper()
	spec, err := taint.Load("jsir")
	if err != nil {
		t.Fatal(err)
	}
	f := js.Parse("app.js", src, js.OptionsFor("app.js"))
	p := New(spec).NewProject(func(string) (*ir.Module, []string) { return nil, nil })
	p.Library = true
	var out []string
	for _, x := range p.AnalyzeOne(js.Lower(f, "app.js", nil), strings.Split(src, "\n")) {
		out = append(out, fmt.Sprintf("%s:%d", x.Sink.ID, x.Line))
	}
	return out
}

// TestJSNestedExports checks that a function a module exports from inside
// the function it wraps itself in is analyzed as exported.
func TestJSNestedExports(t *testing.T) {
	src := `(function () {
  var exec = require('child_process').exec, findLoad;
  findLoad = exports.findLoad = function findLoad(arg, cb) {
    exec('wmic path ' + arg, cb);
  };
}());`
	if got := strings.Join(jsFlows(t, src), " "); got != "taint.js-command-injection:4" {
		t.Errorf("got %q", got)
	}
}

// TestJSRouteHandlers checks that the flows in a handler the module body
// registers are reported: loading the module analyzes its body, and the
// handler with it.
func TestJSRouteHandlers(t *testing.T) {
	cases := []struct{ src, want string }{
		{`var http = require('http');
var fs = require('fs');
http.createServer(function (req, res) {
  fs.readFile(req.url, function (e, d) { res.end(d); });
}).listen(80);`, "taint.js-path-traversal:4"},
		{`var express = require('express');
var app = express();
app.get('/', function (req, res) {
  eval(req.query.code);
});`, "taint.js-code-injection:4"},
	}
	for _, c := range cases {
		got := strings.Join(jsFlows(t, c.src), " ")
		if got != c.want {
			t.Errorf("got %q, want %q\n%s", got, c.want, c.src)
		}
	}
}
