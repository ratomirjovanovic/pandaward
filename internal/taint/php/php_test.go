package php

import (
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/flow"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

// analyze lowers a PHP file and returns its flows as "kind:line".
func analyze(t *testing.T, src string) []string {
	t.Helper()
	spec, err := taint.Load("php")
	if err != nil {
		t.Fatal(err)
	}
	proj := flow.New(spec).NewProject(func(n string) (*ir.Module, []string) {
		if n != "a" {
			return nil, nil
		}
		m, _ := Parse("a.php", src)
		m.Name = "a"
		return m, strings.Split(src, "\n")
	})
	var out []string
	for _, f := range proj.Module("a") {
		out = append(out, f.Sink.KindStr+":"+strconv.Itoa(f.Line))
	}
	sort.Strings(out)
	return out
}

func TestFlows(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      string
	}{
		{"sql concat", "<?php\n$id = $_GET['id'];\n$q = \"SELECT * FROM u WHERE id = '\" . $id . \"'\";\nmysqli_query($c, $q);\n", "sql:4"},
		{"sql interpolation", "<?php\n$id = $_REQUEST['id'];\n$q = \"SELECT * FROM u WHERE id = '$id'\";\n$r = mysqli_query($c, $q);\n", "sql:4"},
		{"sql method", "<?php\n$id = $_POST['id'];\n$res = $mysqli->query(\"SELECT * FROM u WHERE id = $id\");\n", "sql:3"},
		{"sql cast", "<?php\n$id = (int)$_GET['id'];\nmysqli_query($c, \"SELECT * FROM u WHERE id = $id\");\n", ""},
		{"sql intval", "<?php\n$id = intval($_GET['id']);\nmysqli_query($c, \"SELECT * FROM u WHERE id = $id\");\n", ""},
		{"sql escaped", "<?php\n$id = mysqli_real_escape_string($c, $_GET['id']);\nmysqli_query($c, \"SELECT * FROM u WHERE id = '$id'\");\n", ""},
		{"sql constant", "<?php\nmysqli_query($c, \"SELECT * FROM u WHERE id = 1\");\n", ""},
		{"xss echo", "<?php\necho 'Hello ' . $_GET['name'];\n", "xss:2"},
		{"xss escaped", "<?php\necho 'Hello ' . htmlspecialchars($_GET['name']);\n", ""},
		{"xss interpolated", "<?php\n$n = $_GET['name'];\necho \"<pre>Hello {$n}</pre>\";\n", "xss:3"},
		{"include", "<?php\n$file = $_GET['page'];\ninclude($file);\n", "path:3"},
		{"include const", "<?php\ninclude 'config.php';\n", ""},
		{"redirect", "<?php\nheader(\"Location: \" . $_GET['url']);\n", "redirect:2"},
		{"cmd", "<?php\n$ip = $_REQUEST['ip'];\n$out = shell_exec('ping ' . $ip);\n", "cmd:3"},
		{"cmd escaped", "<?php\n$ip = escapeshellarg($_REQUEST['ip']);\n$out = shell_exec('ping ' . $ip);\n", ""},
		{"eval", "<?php\neval($_POST['code']);\n", "code:2"},
		{"foreach", "<?php\nforeach ($_POST as $k => $v) {\n  echo $v;\n}\n", "xss:3"},
		{"function param", "<?php\nfunction show($s) {\n  echo $s;\n}\nshow($_GET['q']);\n", "xss:3"},
		{"if else", "<?php\n$x = $_GET['x'];\nif (isset($x)) {\n  $y = $x;\n} else {\n  $y = 'a';\n}\necho $y;\n", "xss:8"},
		{"class method", "<?php\nclass Box {\n  function f($v) {\n    echo $v;\n  }\n}\n$a = new Box();\n$a->f($_GET['v']);\n", "xss:4"},
		{"unserialize", "<?php\n$o = unserialize($_COOKIE['o']);\n", "deser:2"},
		{"array element", "<?php\n$p = array('a' => $_GET['a'], 'b' => 'x');\necho $p['a'];\n", "xss:3"},
		{"heredoc", "<?php\n$n = $_GET['n'];\necho <<<EOT\nHello $n\nEOT;\n", "xss:3"},
		{"template", "<html><?php $n = $_GET['n']; ?>\n<p><?php echo $n; ?></p>\n", "xss:2"},
		{"short echo", "<?php $n = $_GET['n']; ?>\n<p><?= $n ?></p>\n", "xss:2"},
		{"switch", "<?php\n$o = $_GET['o'];\nswitch ($o) {\n  case 'a':\n    echo $o;\n    break;\n  default:\n    break;\n}\n", "xss:5"},
		{"try catch", "<?php\ntry {\n  echo $_GET['t'];\n} catch (Exception $e) {\n  echo 'x';\n}\n", "xss:3"},
		{"closure", "<?php\n$f = function($s) { echo $s; };\n$f($_GET['c']);\n", "xss:2"},
		{"arrow", "<?php\n$n = $_GET['n'];\n$f = fn($s) => print($n);\n$f(1);\n", "xss:3"},
		{"ternary", "<?php\n$v = isset($_GET['v']) ? $_GET['v'] : 'd';\necho $v;\n", "xss:3"},
		{"coalesce", "<?php\n$v = $_GET['v'] ?? 'd';\necho $v;\n", "xss:3"},
		{"list", "<?php\n[$a, $b] = $_GET['p'];\necho $a;\n", "xss:3"},
		{"compound concat", "<?php\n$h = '<b>';\n$h .= $_GET['n'];\necho $h;\n", "xss:4"},
	} {
		got := strings.Join(analyze(t, c.src), " ")
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	_, errs := Parse("a.php", "<?php\n$a = ;\necho 1;\n")
	if errs == 0 {
		t.Error("a broken statement must be counted")
	}
	_, errs = Parse("a.php", "<?php\nfunction f(int $a = 1, ?string $b = null): string { return $b ?? 'x'; }\nclass A extends B implements C { private ?int $x = 1; public function __construct(private $y = 2) {} }\n")
	if errs != 0 {
		t.Errorf("valid code gave %d errors", errs)
	}
}

func TestGuards(t *testing.T) {
	for _, c := range []struct{ name, src, want string }{
		{"numeric value", "<?php\n$id = $_GET['id'];\nif (is_numeric($id)) {\n  mysqli_query($c, \"SELECT * FROM u WHERE id = $id\");\n}\n", ""},
		{"numeric else", "<?php\n$id = $_GET['id'];\nif (!is_numeric($id)) {\n  die('x');\n}\nmysqli_query($c, \"SELECT * FROM u WHERE id = $id\");\n", ""},
		{"not checked", "<?php\n$id = $_GET['id'];\nif (strlen($id) > 0) {\n  mysqli_query($c, \"SELECT * FROM u WHERE id = $id\");\n}\n", "sql:4"},
		{"server is not a source", "<?php\nheader($_SERVER['SERVER_PROTOCOL'] . ' 404 Not Found');\n", ""},
	} {
		if got := strings.Join(analyze(t, c.src), " "); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
