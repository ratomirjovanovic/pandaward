package adapters

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pensec/internal/inventory"
	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/redact"
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

type ruleCase struct {
	file     string // file name; the extension selects the language
	pos, neg string // content that must and must not fire the rule
}

// codeCases holds a firing and a non-firing case for every code rule. The
// test fails when a rule in codeRules has no entry, so new rules need cases.
var codeCases = map[string]ruleCase{
	"code.js-eval":              {"a.js", "eval(userInput);\n", "widget.eval(userInput);\n"},
	"code.py-eval":              {"a.py", "eval(data)\n", "model.eval()\n"},
	"code.php-eval":             {"a.php", "<?php eval($code);\n", "<?php $obj->eval($code);\n"},
	"code.ruby-eval":            {"a.rb", "eval(\"puts 1\")\n", "obj.eval(\"puts 1\")\n"},
	"code.js-shell":             {"a.js", "exec(`ls ${dir}`);\n", "execFile('ls', [dir]);\n"},
	"code.py-shell":             {"a.py", "subprocess.run(cmd, shell=True)\n", "subprocess.run([\"ls\", d])\n"},
	"code.go-shell":             {"a.go", "exec.Command(\"sh\", \"-c\", cmd)\n", "exec.Command(\"ls\", dir)\n"},
	"code.php-shell":            {"a.php", "<?php shell_exec(\"ls \" . $dir);\n", "<?php shell_exec(\"ls\");\n"},
	"code.java-shell":           {"A.java", "Runtime.getRuntime().exec(cmd);\n", "new ProcessBuilder(\"ls\").start();\n"},
	"code.ruby-shell":           {"a.rb", "out = `ls #{dir}`\n", "system(\"ls\", dir)\n"},
	"code.sql-concat":           {"a.js", "db.query(\"SELECT * FROM users WHERE id = \" + id);\n", "db.query(\"SELECT * FROM users WHERE id = $1\", [id]);\n"},
	"code.sql-template":         {"a.js", "db.query(`SELECT * FROM users WHERE id = ${id}`);\n", "db.query(sql`SELECT * FROM users WHERE id = ${id}`);\n"},
	"code.sql-unsafe-raw":       {"a.js", "prisma.$queryRawUnsafe(q);\n", "prisma.$queryRaw(q);\n"},
	"code.py-deserialize":       {"a.py", "obj = pickle.loads(data)\n", "cfg = yaml.load(text, Loader=yaml.SafeLoader)\n"},
	"code.java-deserialize":     {"A.java", "ObjectInputStream in = new ObjectInputStream(s);\n", "ObjectMapper m = new ObjectMapper();\n"},
	"code.php-unserialize":      {"a.php", "<?php $o = unserialize($data);\n", "<?php $o = json_decode($data);\n"},
	"code.dotnet-deserialize":   {"A.cs", "var f = new BinaryFormatter();\n", "var o = JsonSerializer.Deserialize<T>(x);\n"},
	"code.ruby-deserialize":     {"a.rb", "obj = Marshal.load(data)\n", "obj = YAML.safe_load(data)\n"},
	"code.tls-verify-off":       {"a.py", "requests.get(u, verify=False)\n", "requests.get(u, verify=True)\n"},
	"code.weak-hash-password":   {"a.py", "h = hashlib.md5(password).hexdigest()\n", "h = hashlib.md5(file_bytes).hexdigest()\n"},
	"code.insecure-random":      {"a.js", "const token = Math.random().toString(36);\n", "const jitter = Math.random() * 100;\n"},
	"code.jwt-none":             {"a.js", "jwt.verify(t, k, { algorithms: ['none'] });\n", "jwt.verify(t, k, { algorithms: ['RS256'] });\n"},
	"code.jwt-decode-no-verify": {"a.js", "const p = jwt.decode(token);\n", "const p = jwt.verify(token, key);\n"},
	"code.cookie-flags-off":     {"a.js", "res.cookie('sid', v, { httpOnly: false });\n", "res.cookie('sid', v, { httpOnly: true, secure: true });\n"},
	"code.html-sink":            {"a.js", "el.innerHTML = msg;\n", "el.innerHTML = DOMPurify.sanitize(msg);\n"},
	"code.secret-logged":        {"a.js", "console.log(\"login\", password);\n", "console.log(\"invalid password\");\n"},
}

func TestEveryCodeRuleFiresAndStaysQuiet(t *testing.T) {
	for _, r := range codeRules {
		c, ok := codeCases[r.ID]
		if !ok {
			t.Errorf("%s has no test case in codeCases", r.ID)
			continue
		}
		t.Run(r.ID, func(t *testing.T) {
			if !fired(runOn(t, codeAdapter{}, map[string]string{"src/" + c.file: c.pos}), r.ID) {
				t.Errorf("did not fire on %q", c.pos)
			}
			if fired(runOn(t, codeAdapter{}, map[string]string{"src/" + c.file: c.neg}), r.ID) {
				t.Errorf("fired on %q", c.neg)
			}
		})
	}
	for id := range codeCases {
		found := false
		for _, r := range codeRules {
			found = found || r.ID == id
		}
		if !found {
			t.Errorf("codeCases has %s, which is not a rule", id)
		}
	}
}

func TestCodeRulesSkipCommentsAndTests(t *testing.T) {
	sigs := runOn(t, codeAdapter{}, map[string]string{
		"src/a.js":       "// eval(userInput);\n",
		"test/a.test.js": "eval(userInput);\n",
	})
	if fired(sigs, "code.js-eval") {
		t.Fatal("comments and test files must not fire code rules")
	}
}

// adapterCase is one firing and one non-firing repository for a rule of an
// adapter that looks at whole files rather than single lines.
type adapterCase struct {
	rule     string
	adapter  Adapter
	pos, neg map[string]string
}

const pinnedSHA = "8e5e7e5ab8b370d6c329ec480221332ada57f0ab"

func workflow(on, body string, perms bool) string {
	s := "on: [" + on + "]\n"
	if perms {
		s += "permissions:\n  contents: read\n"
	}
	return s + "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n" + body
}

var fileCases = []adapterCase{
	{"code.llm-output-exec", codeAdapter{},
		map[string]string{"src/agent.py": "from openai import OpenAI\neval(completion.choices[0].message.content)\n"},
		map[string]string{"src/agent.py": "from openai import OpenAI\nprint(completion.choices[0].message.content)\n"}},
	{"code.cors-wildcard-credentials", codeAdapter{},
		map[string]string{"src/app.js": "app.use(cors({ origin: true, credentials: true }));\n"},
		map[string]string{"src/app.js": "app.use(cors({ origin: true }));\n"}},
	{"code.webhook-no-signature", codeAdapter{},
		map[string]string{"src/app.js": "app.post('/webhooks/stripe', (req, res) => { pay(req.body); });\n"},
		map[string]string{"src/app.js": "app.post('/webhooks/stripe', (req, res) => { stripe.webhooks.constructEvent(req.body, sig, key); });\n"}},

	{"cicd.unpinned-action", cicdAdapter{},
		map[string]string{".github/workflows/ci.yml": workflow("push", "      - uses: actions/checkout@v4\n", true)},
		map[string]string{".github/workflows/ci.yml": workflow("push", "      - uses: actions/checkout@"+pinnedSHA+"\n", true)}},
	{"cicd.script-injection", cicdAdapter{},
		map[string]string{".github/workflows/ci.yml": workflow("issues", "      - run: echo \"${{ github.event.issue.title }}\"\n", true)},
		map[string]string{".github/workflows/ci.yml": workflow("issues", "      - env:\n          TITLE: ${{ github.event.issue.title }}\n        run: echo \"$TITLE\"\n", true)}},
	{"cicd.prt-untrusted-checkout", cicdAdapter{},
		map[string]string{".github/workflows/ci.yml": workflow("pull_request_target", "      - uses: actions/checkout@"+pinnedSHA+"\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n", true)},
		map[string]string{".github/workflows/ci.yml": workflow("pull_request", "      - uses: actions/checkout@"+pinnedSHA+"\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n", true)}},
	{"cicd.no-permissions", cicdAdapter{},
		map[string]string{".github/workflows/ci.yml": workflow("push", "      - run: make\n", false)},
		map[string]string{".github/workflows/ci.yml": workflow("push", "      - run: make\n", true)}},

	{"infra.unpinned-base-image", infraAdapter{},
		map[string]string{"Dockerfile": "FROM node:latest\nUSER node\n"},
		map[string]string{"Dockerfile": "FROM node:20.11.1\nUSER node\n"}},
	{"infra.container-root", infraAdapter{},
		map[string]string{"Dockerfile": "FROM node:20.11.1\nCMD [\"node\"]\n"},
		map[string]string{"Dockerfile": "FROM node:20.11.1\nUSER node\nCMD [\"node\"]\n"}},
	{"infra.privileged-container", infraAdapter{},
		map[string]string{"docker-compose.yml": "services:\n  app:\n    image: app:1\n    privileged: true\n"},
		map[string]string{"docker-compose.yml": "services:\n  app:\n    image: app:1\n    privileged: false\n"}},
	{"infra.public-storage", infraAdapter{},
		map[string]string{"main.tf": "resource \"aws_s3_bucket_acl\" \"b\" {\n  acl = \"public-read\"\n}\n"},
		map[string]string{"main.tf": "resource \"aws_s3_bucket_acl\" \"b\" {\n  acl = \"private\"\n}\n"}},
	{"infra.world-open-admin-port", infraAdapter{},
		map[string]string{"main.tf": "ingress {\n  from_port = 22\n  to_port = 22\n  cidr_blocks = [\"0.0.0.0/0\"]\n}\n"},
		map[string]string{"main.tf": "ingress {\n  from_port = 443\n  to_port = 443\n  cidr_blocks = [\"0.0.0.0/0\"]\n}\n"}},

	{"supply.missing-lockfile", supplyAdapter{},
		map[string]string{"package.json": `{"name":"a"}`},
		map[string]string{"package.json": `{"name":"a"}`, "package-lock.json": `{"packages":{}}`}},
	{"supply.install-script", supplyAdapter{},
		map[string]string{"package.json": `{"name":"a"}`, "package-lock.json": `{"packages":{"node_modules/x":{"version":"1.0.0","hasInstallScript": true}}}`},
		map[string]string{"package.json": `{"name":"a"}`, "package-lock.json": `{"packages":{"node_modules/x":{"version":"1.0.0"}}}`}},
	{"supply.unpinned-requirements", supplyAdapter{},
		map[string]string{"requirements.txt": "flask>=2\n"},
		map[string]string{"requirements.txt": "flask==2.3.3\n"}},
	{"supply.mcp-unpinned", supplyAdapter{},
		map[string]string{".mcp.json": `{"mcpServers":{"fs":{"command":"npx","args":["-y","@scope/server"]}}}`},
		map[string]string{".mcp.json": `{"mcpServers":{"fs":{"command":"npx","args":["-y","@scope/server@1.2.3"]}}}`}},
	{"supply.mcp-inline-credential", supplyAdapter{},
		map[string]string{".mcp.json": `{"mcpServers":{"api":{"command":"node","args":["s.js"],"env":{"API_KEY":"abc123def456"}}}}`},
		map[string]string{".mcp.json": `{"mcpServers":{"api":{"command":"node","args":["s.js"],"env":{"API_KEY":"${API_KEY}"}}}}`}},

	{"mobile.android-debuggable", mobileAdapter{},
		map[string]string{"app/src/main/AndroidManifest.xml": `<manifest><application android:debuggable="true"/></manifest>`},
		map[string]string{"app/src/main/AndroidManifest.xml": `<manifest><application android:debuggable="false"/></manifest>`}},
	{"mobile.android-allow-backup", mobileAdapter{},
		map[string]string{"app/src/main/AndroidManifest.xml": `<manifest><application android:allowBackup="true"/></manifest>`},
		map[string]string{"app/src/main/AndroidManifest.xml": `<manifest><application android:allowBackup="false"/></manifest>`}},
	{"mobile.android-cleartext", mobileAdapter{},
		map[string]string{"app/src/main/AndroidManifest.xml": `<manifest><application android:usesCleartextTraffic="true"/></manifest>`},
		map[string]string{"app/src/main/AndroidManifest.xml": `<manifest><application android:usesCleartextTraffic="false"/></manifest>`}},
	{"mobile.android-exported-component", mobileAdapter{},
		map[string]string{"app/src/main/AndroidManifest.xml": `<manifest><application><receiver android:name=".Sync" android:exported="true"/></application></manifest>`},
		map[string]string{"app/src/main/AndroidManifest.xml": `<manifest><application><receiver android:name=".Sync" android:exported="true" android:permission="com.example.SYNC"/></application></manifest>`}},
	{"mobile.ios-ats-arbitrary-loads", mobileAdapter{},
		map[string]string{"ios/App/Info.plist": "<plist><dict>\n<key>NSAllowsArbitraryLoads</key>\n<true/>\n</dict></plist>\n"},
		map[string]string{"ios/App/Info.plist": "<plist><dict>\n<key>NSAllowsArbitraryLoads</key>\n<false/>\n</dict></plist>\n"}},
}

func TestEveryFileRuleFiresAndStaysQuiet(t *testing.T) {
	for _, c := range fileCases {
		t.Run(c.rule, func(t *testing.T) {
			if !fired(runOn(t, c.adapter, c.pos), c.rule) {
				t.Errorf("did not fire on %v", c.pos)
			}
			if fired(runOn(t, c.adapter, c.neg), c.rule) {
				t.Errorf("fired on %v", c.neg)
			}
		})
	}
}

// secretSamples builds a value in each secret format at runtime, so the
// repository itself never contains a string that looks like a credential.
var secretSamples = map[string]string{
	"aws-access-key-id":       "AKIA" + strings.Repeat("Q7", 8),
	"github-token":            "gh" + "p_" + strings.Repeat("a1B2", 9),
	"github-fine-grained-pat": "github" + "_pat_" + strings.Repeat("a1B2c3", 11),
	"gitlab-token":            "gl" + "pat-" + strings.Repeat("a1B2", 6),
	"slack-token":             "xo" + "xb-" + strings.Repeat("1a2b", 4),
	"slack-webhook":           "https://hooks.slack.com/" + "services/" + strings.Repeat("T1B2C3", 5),
	"stripe-live-key":         "sk_" + "live_" + strings.Repeat("Z9", 12),
	"google-api-key":          "AI" + "za" + strings.Repeat("Sy", 17) + "A",
	"anthropic-api-key":       "sk-" + "ant-" + strings.Repeat("a1B2", 6),
	"openai-api-key":          "sk-" + "proj-" + strings.Repeat("a1B2", 6) + "T3Blbk" + "FJ" + strings.Repeat("c3D4", 6),
	"npm-token":               "np" + "m_" + strings.Repeat("a1B2", 9),
	"sendgrid-key":            "SG" + "." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 43),
	"twilio-key":              "S" + "K" + strings.Repeat("0a", 16),
	"private-key":             "-----BEGIN " + "RSA PRIVATE KEY-----",
	"jwt":                     "ey" + "J" + strings.Repeat("h", 12) + ".ey" + "J" + strings.Repeat("p", 12) + "." + strings.Repeat("s", 12),
	"db-url-password":         "postgres" + "://app:" + "s3cr3tPw" + "@db.internal:5432/app",
}

func TestEverySecretRuleFiresAndSkipsExamples(t *testing.T) {
	for _, r := range redact.SecretRules {
		v, ok := secretSamples[r.ID]
		if !ok {
			t.Errorf("%s has no sample in secretSamples", r.ID)
			continue
		}
		t.Run(r.ID, func(t *testing.T) {
			if !fired(runOn(t, secretsAdapter{}, map[string]string{"src/config.js": "const v = \"" + v + "\";\n"}), "secret."+r.ID) {
				t.Errorf("did not fire on the sample")
			}
		})
	}
	sigs := runOn(t, secretsAdapter{}, map[string]string{"src/config.js": "const v = \"" + secretSamples["stripe-live-key"] + "\"; // EXAMPLE value\n"})
	if fired(sigs, "secret.stripe-live-key") {
		t.Error("values marked as examples must not fire")
	}
	sigs = runOn(t, secretsAdapter{}, map[string]string{"src/config.js": "const url = \"postgres" + "://app:${DB_PASSWORD}@db/app\";\n"})
	if fired(sigs, "secret.db-url-password") {
		t.Error("a templated database password must not fire")
	}
}
