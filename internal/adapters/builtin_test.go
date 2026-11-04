package adapters

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// runOn writes files into a fresh directory, builds the inventory and runs
// one adapter on it.
func runOn(t *testing.T, a Adapter, files map[string]string) []model.Signal {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	inv, err := inventory.Walk(root, inventory.Options{MaxFileBytes: 1 << 20, MaxFiles: 1000})
	if err != nil {
		t.Fatal(err)
	}
	res, run := a.Run(context.Background(), &Context{Root: root, Inv: inv})
	if run.ExitClass != model.ExitOK {
		t.Fatalf("%s did not complete: %s %s", a.Name(), run.ExitClass, run.Detail)
	}
	return res.Signals
}

func fired(sigs []model.Signal, rule string) bool {
	for _, s := range sigs {
		if s.RuleID == rule {
			return true
		}
	}
	return false
}

// The per-rule vulnerable and safe cases live in the benchmark corpus
// (internal/benchmark), whose test fails on any miss or false positive.

func TestCodeRulesSkipCommentsAndTests(t *testing.T) {
	sigs := runOn(t, codeAdapter{}, map[string]string{
		"src/a.js":       "// eval(userInput);\n",
		"test/a.test.js": "eval(userInput);\n",
	})
	if fired(sigs, "code.js-eval") {
		t.Fatal("comments and test files must not fire code rules")
	}
}

// Each case is a whole file; the rule must fire on it or stay silent.
func TestCodeRuleFalsePositiveGuards(t *testing.T) {
	cases := []struct {
		rule, file, src string
		want            bool
	}{
		// code.js-shell: a file's own exec helper is not child_process.
		{"code.js-shell", "a.ts", "async function exec(box, cmd, args) { return box.run(cmd, args); }\nawait exec(box, \"git\", [\"status\"]);\n", false},
		{"code.js-shell", "a.ts", "const exec = async (box, cmd) => box.run(cmd);\nawait exec(box, cmd);\n", false},
		{"code.js-shell", "a.js", "import { exec } from \"child_process\";\nexec(`ls ${dir}`);\n", true},
		{"code.js-shell", "a.js", "import { exec } from \"./shell\";\nexec(`ls ${dir}`);\n", true},
		{"code.js-shell", "a.js", "const exec = require(\"./shell\").exec;\nexec(cmd);\n", true},
		{"code.js-shell", "a.js", "const { exec } = require(\"node:child_process\");\nfunction exec2() {}\nexec(cmd);\n", true},
		{"code.js-shell", "a.js", "function exec(cmd) { return run(cmd); }\nspawn(cmd, { shell: true });\n", true},
		// Only constants and process ids interpolated.
		{"code.js-shell", "a.js", "const { execSync } = require(\"child_process\");\nexecSync(`lsof -ti tcp:${PORT}`);\nexecSync(`kill ${child.pid}`);\n", false},
		{"code.js-shell", "a.js", "const { execSync } = require(\"child_process\");\nexecSync(`lsof -ti tcp:${PORT} ${host}`);\n", true},
		{"code.js-shell", "a.js", "const { execSync } = require(\"child_process\");\nexecSync(`kill ${req.query.pid}x`);\n", true},

		// code.html-sink: template tokens only in templates.
		{"code.html-sink", "a.ts", "const r = { body: 'not valid json{{{' };\n", false},
		{"code.html-sink", "a.js", "const ok = x || safe;\n", false},
		{"code.html-sink", "a.hbs", "<div>{{{body}}}</div>\n", true},
		{"code.html-sink", "a.ejs", "<div><%- body %></div>\n", true},
		{"code.html-sink", "a.jsx", "<script dangerouslySetInnerHTML={{ __html: JSON.stringify(d).replace(/</g, \"\\\\u003c\") }} />\n", false},
		{"code.html-sink", "a.jsx", "<script dangerouslySetInnerHTML={{ __html: JSON.stringify(d) }} />\n", true},
		{"code.html-sink", "a.jsx", "<script dangerouslySetInnerHTML={{ __html: JSON.stringify(d).replace(/</, \"\") }} />\n", true},
		{"code.html-sink", "a.js", "el.innerHTML = '<b>Loading</b>';\n", false},
		{"code.html-sink", "a.js", "el.innerHTML = `<b>Loading</b>`; // spinner\n", false},
		{"code.html-sink", "a.js", "const SPINNER = '<b>Loading</b>';\nel.innerHTML = SPINNER;\n", false},
		{"code.html-sink", "a.js", "const SPINNER = '<b>' + label;\nel.innerHTML = SPINNER;\n", true},
		{"code.html-sink", "a.js", "el.innerHTML = SPINNER;\n", true},
		{"code.html-sink", "a.js", "el.innerHTML = `<b>${msg}</b>`;\n", true},
		{"code.html-sink", "a.js", "el.innerHTML = \"<b>\" + msg;\n", true},
		{"code.html-sink", "a.js", "el.innerHTML = msg;\n", true},

		// code.secret-logged: prose in a message is not a logged value.
		{"code.secret-logged", "a.js", "console.log(`secret saved to ${file}`);\n", false},
		{"code.secret-logged", "a.js", "console.error(\"secret-shaped value; refusing\");\n", false},
		{"code.secret-logged", "a.js", "console.log(\"login\", password);\n", true},
		{"code.secret-logged", "a.js", "console.log(`k ${apiKey}`);\n", true},
		{"code.secret-logged", "a.js", "console.log(\"secret=\", s);\n", true},
		{"code.secret-logged", "a.js", "console.log(`password=${p}`);\n", true},
		{"code.secret-logged", "a.py", "print(f\"token {api_key}\")\n", true},
		{"code.secret-logged", "a.py", "print(\"password: %s\" % pw)\n", true},
		{"code.secret-logged", "a.rb", "puts(\"key #{secret}\")\n", true},

		// code.sql-concat: one quote class opens and closes a literal.
		{"code.sql-concat", "a.ts", "await sql(`select count(*) from t where e like '%x.test'`);\n", false},
		{"code.sql-concat", "a.js", "db.query(\"SELECT * FROM u WHERE id = \" + id);\n", true},
		{"code.sql-concat", "a.py", "cur.execute('SELECT * FROM u WHERE n = %s' % name)\n", true},
		{"code.sql-concat", "a.js", "db.query(`SELECT * FROM u WHERE id = ${id}` + order);\n", false}, // reported as code.sql-template
		{"code.sql-template", "a.js", "db.query(`SELECT * FROM u WHERE id = ${id}` + order);\n", true},

		// code.weak-hash-password: a hashing call, not just the word.
		{"code.weak-hash-password", "a.ts", "const ok = [\"sha1\", \"sha256\"].some(a => verify(sig, sign(id, password, a)));\n", false},
		{"code.weak-hash-password", "a.py", "h = hashlib.md5(password).hexdigest()\n", true},
		{"code.weak-hash-password", "a.js", "const h = crypto.createHash('sha1').update(password).digest('hex');\n", true},
		{"code.weak-hash-password", "a.php", "<?php $h = md5($password);\n", true},
		{"code.weak-hash-password", "a.php", "<?php $h = hash('sha1', $password);\n", true},
		{"code.weak-hash-password", "A.java", "byte[] h = MessageDigest.getInstance(\"SHA-1\").digest(password.getBytes());\n", true},
		{"code.weak-hash-password", "A.java", "String h = DigestUtils.md5Hex(password);\n", true},
		{"code.weak-hash-password", "a.rb", "h = Digest::SHA1.hexdigest(password)\n", true},
		{"code.weak-hash-password", "a.go", "h := md5.Sum([]byte(password))\n", true},
		{"code.weak-hash-password", "a.js", "const h = execSync(`echo ${password} | md5sum`);\n", true},
		{"code.weak-hash-password", "a.js", "const h = Hashing.sha1().hashString(password, UTF_8);\n", true},
		{"code.weak-hash-password", "a.js", "const h = await crypto.subtle.digest('SHA-1', enc.encode(password));\n", true},
		{"code.weak-hash-password", "a.php", "<?php $h = hash_hmac('sha256', $password, $k);\n", false},

		// code.llm-output-exec: the output must be an argument of the sink.
		{"code.llm-output-exec", "a.ts", "import OpenAI from \"openai\";\nconst o = (await exec(box, \"git\", [\"ls\", p])).output;\n", false},
		{"code.llm-output-exec", "a.ts", "import OpenAI from \"openai\";\nconst m = /x(\\d+)/.exec(completion.choices[0].message.content);\n", false},
		{"code.llm-output-exec", "a.ts", "import OpenAI from \"openai\";\nexec(completion.choices[0].message.content);\n", true},
		{"code.llm-output-exec", "a.ts", "import OpenAI from \"openai\";\nimport cp from \"child_process\";\ncp.exec(response.output_text);\n", true},
		{"code.llm-output-exec", "a.py", "from openai import OpenAI\nsubprocess.run(answer, shell=True)\n", true},
	}
	for _, c := range cases {
		sigs := runOn(t, codeAdapter{}, map[string]string{"src/" + c.file: c.src})
		if got := fired(sigs, c.rule); got != c.want {
			t.Errorf("%s on %q: fired=%v, want %v", c.rule, c.src, got, c.want)
		}
	}
}

// One finding per rule and line, even when a rule has several table entries.
func TestCodeRuleOneSignalPerLine(t *testing.T) {
	sigs := runOn(t, codeAdapter{}, map[string]string{"src/a.js": "const { exec } = require(\"child_process\");\nexec(cmd, { shell: true });\n"})
	n := 0
	for _, s := range sigs {
		if s.RuleID == "code.js-shell" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("code.js-shell reported %d times, want 1", n)
	}
}
