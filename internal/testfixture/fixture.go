// Package testfixture builds a deliberately vulnerable repository in a
// temporary directory for tests. Secret-shaped values are assembled at
// runtime so that no credential-like literal is committed.
package testfixture

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var (
	// FakeStripe matches the Stripe live-key format but is not a real key.
	FakeStripe = "sk_" + "live_" + strings.Repeat("Z9", 12)
	// FakeGitHub matches the GitHub token format but is not a real token.
	FakeGitHub = "gh" + "p_" + strings.Repeat("a1B2", 9)
)

// Write creates a file under root.
func Write(t testing.TB, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// VulnerableRepo returns a temp repository with seeded weaknesses.
func VulnerableRepo(t testing.TB) string {
	t.Helper()
	root := t.TempDir()
	Write(t, root, "package.json", `{"name":"fixture","dependencies":{"express":"^4.0.0","jsonwebtoken":"^9.0.0","stripe":"^14.0.0"}}`)
	Write(t, root, "src/server.js", strings.Join([]string{
		`const express = require('express'); const jwt = require('jsonwebtoken'); const { exec } = require('child_process');`,
		`const stripe = require('stripe')('` + FakeStripe + `');`,
		`const app = express();`,
		`app.use(cors({ origin: true, credentials: true }));`,
		`app.post('/api/login', (req, res) => { const u = jwt.decode(req.body.token); res.json(u); });`,
		`app.get('/api/invoices/:id', (req, res) => { db.query("SELECT * FROM invoices WHERE id = " + req.params.id); });`,
		`app.post('/webhooks/stripe', (req, res) => { applyPayment(req.body); res.sendStatus(200); });`,
		`app.get('/admin/run', (req, res) => { exec(` + "`ls ${req.query.dir}`" + `); eval(req.query.code); });`,
		`document.getElementById('x').innerHTML = req.query.msg;`,
	}, "\n"))
	Write(t, root, "app.py", strings.Join([]string{
		`import pickle, subprocess, requests`,
		`from openai import OpenAI`,
		`def run(data, completion):`,
		`    obj = pickle.loads(data)`,
		`    requests.get("https://example.org", verify=False)`,
		`    subprocess.run("ls " + data, shell=True)`,
		`    eval(completion.choices[0].message.content)`,
		`TOKEN = "` + FakeGitHub + `"`,
	}, "\n"))
	Write(t, root, ".github/workflows/ci.yml", strings.Join([]string{
		`on: [pull_request_target]`,
		`jobs:`,
		`  build:`,
		`    runs-on: ubuntu-latest`,
		`    steps:`,
		`      - uses: actions/checkout@v4`,
		`        with:`,
		`          ref: ${{ github.event.pull_request.head.sha }}`,
		`      - uses: someone/deploy-action@main`,
		`      - run: |`,
		`          echo "${{ github.event.issue.title }}"`,
	}, "\n"))
	Write(t, root, "Dockerfile", "FROM node:latest\nCOPY . .\nCMD [\"node\",\"src/server.js\"]\n")
	Write(t, root, "infra/main.tf", strings.Join([]string{
		`resource "aws_s3_bucket_acl" "b" { acl = "public-read" }`,
		`resource "aws_security_group" "ssh" {`,
		`  ingress {`,
		`    from_port = 22`,
		`    to_port = 22`,
		`    cidr_blocks = ["0.0.0.0/0"]`,
		`  }`,
		`}`,
	}, "\n"))
	Write(t, root, "android/app/src/main/AndroidManifest.xml", `<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:debuggable="true" android:allowBackup="true">
<activity android:name=".Main" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/></intent-filter></activity>
<receiver android:name=".Sync" android:exported="true"/></application></manifest>`)
	Write(t, root, "openapi.yaml", "openapi: 3.0.0\npaths:\n  /api/login:\n    post: {}\n")
	Write(t, root, ".env", "SECRET_VALUE_NOT_READ="+FakeStripe+"\n")
	if git, err := exec.LookPath("git"); err == nil {
		for _, args := range [][]string{{"init", "-q"}, {"add", "-A", "-f"}, {"-c", "user.email=t@example.org", "-c", "user.name=t", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"}} {
			cmd := exec.Command(git, args...)
			cmd.Dir = root
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Logf("git %v: %v %s", args, err, out)
			}
		}
	}
	return root
}

// HasGit reports whether git is available.
func HasGit() bool {
	_, err := exec.LookPath("git")
	return err == nil
}
