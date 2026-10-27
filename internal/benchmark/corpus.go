// Package benchmark measures the built-in rules against a versioned corpus
// of vulnerable and safe cases and reports TP, FP, FN and TN per rule.
//
// The corpus is small and written by the PenSec authors, so the numbers say
// how the rules behave on these cases, not how they generalize. Each case is
// a tiny repository; it is written to a temporary directory and scanned with
// the same inventory and adapter code a real scan uses.
package benchmark

import (
	"strings"

	"github.com/ratomirjovanovic/pensec/internal/redact"
)

// CorpusVersion changes whenever cases are added, removed or edited.
const CorpusVersion = "2026.10.1"

// Case is one repository that a rule must fire on (Vulnerable) or must not
// fire on (Safe).
type Case struct {
	Rule       string
	Adapter    string
	Vulnerable bool
	Files      map[string]string
	// Git commits the files to a fresh repository first (tracked-file rules).
	Git  bool
	Note string
}

const pinnedSHA = "8e5e7e5ab8b370d6c329ec480221332ada57f0ab"

func workflow(on, body string, perms bool) string {
	s := "on: [" + on + "]\n"
	if perms {
		s += "permissions:\n  contents: read\n"
	}
	return s + "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n" + body
}

// pair adds one vulnerable and one safe case.
func pair(rule, adapter string, vuln, safe map[string]string) []Case {
	return []Case{{Rule: rule, Adapter: adapter, Vulnerable: true, Files: vuln}, {Rule: rule, Adapter: adapter, Files: safe}}
}

// code adds a vulnerable and a safe single-line source file.
func code(rule, file, vuln, safe string) []Case {
	return pair(rule, "builtin-code", map[string]string{"src/" + file: vuln}, map[string]string{"src/" + file: safe})
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

// secretSafe is the non-firing counterpart of each sample: a value marked as
// an example, or the format's harmless sibling where markers do not apply.
func secretSafe(id, v string) string {
	switch id {
	case "private-key":
		return "-----BEGIN " + "PUBLIC KEY-----"
	case "db-url-password":
		return "postgres" + "://app:${DB_PASSWORD}@db/app"
	}
	return v + "\"; // EXAMPLE value, not a credential\nconst w = \"x"
}

// Corpus returns every case, grouped by rule in a fixed order.
func Corpus() []Case {
	var cs []Case
	add := func(c []Case) { cs = append(cs, c...) }

	add(code("code.js-eval", "a.js", "eval(userInput);\n", "widget.eval(userInput);\n"))
	add(code("code.py-eval", "a.py", "eval(data)\n", "model.eval()\n"))
	add(code("code.php-eval", "a.php", "<?php eval($code);\n", "<?php $obj->eval($code);\n"))
	add(code("code.ruby-eval", "a.rb", "eval(\"puts 1\")\n", "obj.eval(\"puts 1\")\n"))
	add(code("code.js-shell", "a.js", "exec(`ls ${dir}`);\n", "execFile('ls', [dir]);\n"))
	add(code("code.py-shell", "a.py", "subprocess.run(cmd, shell=True)\n", "subprocess.run([\"ls\", d])\n"))
	add(code("code.go-shell", "a.go", "exec.Command(\"sh\", \"-c\", cmd)\n", "exec.Command(\"ls\", dir)\n"))
	add(code("code.php-shell", "a.php", "<?php shell_exec(\"ls \" . $dir);\n", "<?php shell_exec(\"ls\");\n"))
	add(code("code.java-shell", "A.java", "Runtime.getRuntime().exec(cmd);\n", "new ProcessBuilder(\"ls\").start();\n"))
	add(code("code.ruby-shell", "a.rb", "out = `ls #{dir}`\n", "system(\"ls\", dir)\n"))
	add(code("code.sql-concat", "a.js", "db.query(\"SELECT * FROM users WHERE id = \" + id);\n", "db.query(\"SELECT * FROM users WHERE id = $1\", [id]);\n"))
	add(code("code.sql-template", "a.js", "db.query(`SELECT * FROM users WHERE id = ${id}`);\n", "db.query(sql`SELECT * FROM users WHERE id = ${id}`);\n"))
	add(code("code.sql-unsafe-raw", "a.js", "prisma.$queryRawUnsafe(q);\n", "prisma.$queryRaw(q);\n"))
	add(code("code.py-deserialize", "a.py", "obj = pickle.loads(data)\n", "cfg = yaml.load(text, Loader=yaml.SafeLoader)\n"))
	add(code("code.java-deserialize", "A.java", "ObjectInputStream in = new ObjectInputStream(s);\n", "ObjectMapper m = new ObjectMapper();\n"))
	add(code("code.php-unserialize", "a.php", "<?php $o = unserialize($data);\n", "<?php $o = json_decode($data);\n"))
	add(code("code.dotnet-deserialize", "A.cs", "var f = new BinaryFormatter();\n", "var o = JsonSerializer.Deserialize<T>(x);\n"))
	add(code("code.ruby-deserialize", "a.rb", "obj = Marshal.load(data)\n", "obj = YAML.safe_load(data)\n"))
	add(code("code.tls-verify-off", "a.py", "requests.get(u, verify=False)\n", "requests.get(u, verify=True)\n"))
	add(code("code.weak-hash-password", "a.py", "h = hashlib.md5(password).hexdigest()\n", "h = hashlib.md5(file_bytes).hexdigest()\n"))
	add(code("code.insecure-random", "a.js", "const token = Math.random().toString(36);\n", "const jitter = Math.random() * 100;\n"))
	add(code("code.jwt-none", "a.js", "jwt.verify(t, k, { algorithms: ['none'] });\n", "jwt.verify(t, k, { algorithms: ['RS256'] });\n"))
	add(code("code.jwt-decode-no-verify", "a.js", "const p = jwt.decode(token);\n", "const p = jwt.verify(token, key);\n"))
	add(code("code.cookie-flags-off", "a.js", "res.cookie('sid', v, { httpOnly: false });\n", "res.cookie('sid', v, { httpOnly: true, secure: true });\n"))
	add(code("code.html-sink", "a.js", "el.innerHTML = msg;\n", "el.innerHTML = DOMPurify.sanitize(msg);\n"))
	add(code("code.secret-logged", "a.js", "console.log(\"login\", password);\n", "console.log(\"invalid password\");\n"))
	// Comments and test files are out of scope for code rules.
	cs = append(cs, Case{Rule: "code.js-eval", Adapter: "builtin-code", Files: map[string]string{"src/a.js": "// eval(userInput);\n", "test/a.test.js": "eval(userInput);\n"},
		Note: "commented out and in a test file"})

	add(pair("code.llm-output-exec", "builtin-code",
		map[string]string{"src/agent.py": "from openai import OpenAI\neval(completion.choices[0].message.content)\n"},
		map[string]string{"src/agent.py": "from openai import OpenAI\nprint(completion.choices[0].message.content)\n"}))
	add(pair("code.cors-wildcard-credentials", "builtin-code",
		map[string]string{"src/app.js": "app.use(cors({ origin: true, credentials: true }));\n"},
		map[string]string{"src/app.js": "app.use(cors({ origin: true }));\n"}))
	add(pair("code.webhook-no-signature", "builtin-code",
		map[string]string{"src/app.js": "app.post('/webhooks/stripe', (req, res) => { pay(req.body); });\n"},
		map[string]string{"src/app.js": "app.post('/webhooks/stripe', (req, res) => { stripe.webhooks.constructEvent(req.body, sig, key); });\n"}))
	add(pair("inventory.undeclared-route", "builtin-inventory",
		map[string]string{"package.json": `{"dependencies":{"express":"4"}}`, "openapi.yaml": "openapi: 3.0.0\npaths:\n  /a: {}\n", "src/app.js": "app.get('/a', h);\napp.get('/b', h);\n"},
		map[string]string{"package.json": `{"dependencies":{"express":"4"}}`, "openapi.yaml": "openapi: 3.0.0\npaths:\n  /a: {}\n  /b: {}\n", "src/app.js": "app.get('/a', h);\napp.get('/b', h);\n"}))

	add(pair("cicd.unpinned-action", "builtin-cicd",
		map[string]string{".github/workflows/ci.yml": workflow("push", "      - uses: actions/checkout@v4\n", true)},
		map[string]string{".github/workflows/ci.yml": workflow("push", "      - uses: actions/checkout@"+pinnedSHA+"\n", true)}))
	add(pair("cicd.script-injection", "builtin-cicd",
		map[string]string{".github/workflows/ci.yml": workflow("issues", "      - run: echo \"${{ github.event.issue.title }}\"\n", true)},
		map[string]string{".github/workflows/ci.yml": workflow("issues", "      - env:\n          TITLE: ${{ github.event.issue.title }}\n        run: echo \"$TITLE\"\n", true)}))
	add(pair("cicd.prt-untrusted-checkout", "builtin-cicd",
		map[string]string{".github/workflows/ci.yml": workflow("pull_request_target", "      - uses: actions/checkout@"+pinnedSHA+"\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n", true)},
		map[string]string{".github/workflows/ci.yml": workflow("pull_request", "      - uses: actions/checkout@"+pinnedSHA+"\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n", true)}))
	add(pair("cicd.no-permissions", "builtin-cicd",
		map[string]string{".github/workflows/ci.yml": workflow("push", "      - run: make\n", false)},
		map[string]string{".github/workflows/ci.yml": workflow("push", "      - run: make\n", true)}))

	add(pair("infra.unpinned-base-image", "builtin-infra",
		map[string]string{"Dockerfile": "FROM node:latest\nUSER node\n"},
		map[string]string{"Dockerfile": "FROM node:20.11.1\nUSER node\n"}))
	add(pair("infra.container-root", "builtin-infra",
		map[string]string{"Dockerfile": "FROM node:20.11.1\nCMD [\"node\"]\n"},
		map[string]string{"Dockerfile": "FROM node:20.11.1\nUSER node\nCMD [\"node\"]\n"}))
	add(pair("infra.privileged-container", "builtin-infra",
		map[string]string{"docker-compose.yml": "services:\n  app:\n    image: app:1\n    privileged: true\n"},
		map[string]string{"docker-compose.yml": "services:\n  app:\n    image: app:1\n    privileged: false\n"}))
	add(pair("infra.public-storage", "builtin-infra",
		map[string]string{"main.tf": "resource \"aws_s3_bucket_acl\" \"b\" {\n  acl = \"public-read\"\n}\n"},
		map[string]string{"main.tf": "resource \"aws_s3_bucket_acl\" \"b\" {\n  acl = \"private\"\n}\n"}))
	add(pair("infra.world-open-admin-port", "builtin-infra",
		map[string]string{"main.tf": "ingress {\n  from_port = 22\n  to_port = 22\n  cidr_blocks = [\"0.0.0.0/0\"]\n}\n"},
		map[string]string{"main.tf": "ingress {\n  from_port = 443\n  to_port = 443\n  cidr_blocks = [\"0.0.0.0/0\"]\n}\n"}))

	add(pair("supply.missing-lockfile", "builtin-supply",
		map[string]string{"package.json": `{"name":"a"}`},
		map[string]string{"package.json": `{"name":"a"}`, "package-lock.json": `{"packages":{}}`}))
	add(pair("supply.install-script", "builtin-supply",
		map[string]string{"package.json": `{"name":"a"}`, "package-lock.json": `{"packages":{"node_modules/x":{"version":"1.0.0","hasInstallScript": true}}}`},
		map[string]string{"package.json": `{"name":"a"}`, "package-lock.json": `{"packages":{"node_modules/x":{"version":"1.0.0"}}}`}))
	add(pair("supply.unpinned-requirements", "builtin-supply",
		map[string]string{"requirements.txt": "flask>=2\n"},
		map[string]string{"requirements.txt": "flask==2.3.3\n"}))
	add(pair("supply.mcp-unpinned", "builtin-supply",
		map[string]string{".mcp.json": `{"mcpServers":{"fs":{"command":"npx","args":["-y","@scope/server"]}}}`},
		map[string]string{".mcp.json": `{"mcpServers":{"fs":{"command":"npx","args":["-y","@scope/server@1.2.3"]}}}`}))
	add(pair("supply.mcp-inline-credential", "builtin-supply",
		map[string]string{".mcp.json": `{"mcpServers":{"api":{"command":"node","args":["s.js"],"env":{"API_KEY":"abc123def456"}}}}`},
		map[string]string{".mcp.json": `{"mcpServers":{"api":{"command":"node","args":["s.js"],"env":{"API_KEY":"${API_KEY}"}}}}`}))

	manifest := "app/src/main/AndroidManifest.xml"
	add(pair("mobile.android-debuggable", "builtin-mobile",
		map[string]string{manifest: `<manifest><application android:debuggable="true"/></manifest>`},
		map[string]string{manifest: `<manifest><application android:debuggable="false"/></manifest>`}))
	add(pair("mobile.android-allow-backup", "builtin-mobile",
		map[string]string{manifest: `<manifest><application android:allowBackup="true"/></manifest>`},
		map[string]string{manifest: `<manifest><application android:allowBackup="false"/></manifest>`}))
	add(pair("mobile.android-cleartext", "builtin-mobile",
		map[string]string{manifest: `<manifest><application android:usesCleartextTraffic="true"/></manifest>`},
		map[string]string{manifest: `<manifest><application android:usesCleartextTraffic="false"/></manifest>`}))
	add(pair("mobile.android-exported-component", "builtin-mobile",
		map[string]string{manifest: `<manifest><application><receiver android:name=".Sync" android:exported="true"/></application></manifest>`},
		map[string]string{manifest: `<manifest><application><receiver android:name=".Sync" android:exported="true" android:permission="com.example.SYNC"/></application></manifest>`}))
	add(pair("mobile.ios-ats-arbitrary-loads", "builtin-mobile",
		map[string]string{"ios/App/Info.plist": "<plist><dict>\n<key>NSAllowsArbitraryLoads</key>\n<true/>\n</dict></plist>\n"},
		map[string]string{"ios/App/Info.plist": "<plist><dict>\n<key>NSAllowsArbitraryLoads</key>\n<false/>\n</dict></plist>\n"}))

	for _, r := range redact.SecretRules {
		v := secretSamples[r.ID]
		if v == "" {
			continue // reported by the coverage check
		}
		add(pair("secret."+r.ID, "builtin-secrets",
			map[string]string{"src/config.js": "const v = \"" + v + "\";\n"},
			map[string]string{"src/config.js": "const v = \"" + secretSafe(r.ID, v) + "\";\n"}))
	}
	cs = append(cs,
		Case{Rule: "secret.tracked-sensitive-file", Adapter: "builtin-secrets", Vulnerable: true, Git: true, Files: map[string]string{".env": "API_TOKEN=x\n", "src/a.js": "x\n"}},
		Case{Rule: "secret.tracked-sensitive-file", Adapter: "builtin-secrets", Git: true, Files: map[string]string{".gitignore": ".env\n", ".env": "API_TOKEN=x\n", "src/a.js": "x\n"},
			Note: "the .env file exists only in the working tree"})
	return cs
}
