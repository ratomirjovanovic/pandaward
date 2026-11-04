package adapters

import (
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/model"
)

func workflowSignals(t *testing.T, wf string) []model.Signal {
	t.Helper()
	return runOn(t, cicdAdapter{}, map[string]string{".github/workflows/ci.yml": wf})
}

func ruleSignals(sigs []model.Signal, rule string) []model.Signal {
	var out []model.Signal
	for _, s := range sigs {
		if s.RuleID == rule {
			out = append(out, s)
		}
	}
	return out
}

// job builds a workflow with optional workflow-level and job-level
// permissions blocks and the given step lines.
func job(wfPerms, jobPerms, steps string) string {
	s := "on: [push]\n"
	if wfPerms != "" {
		s += "permissions:\n" + wfPerms
	}
	s += "jobs:\n  release:\n    runs-on: ubuntu-latest\n"
	if jobPerms != "" {
		s += "    permissions:\n" + jobPerms
	}
	return s + "    steps:\n" + steps
}

func TestUnpinnedToolInstall(t *testing.T) {
	idToken := "      id-token: write\n      contents: read\n"
	cases := []struct {
		name string
		wf   string
		want []string // package specs reported, in order
		sev  model.Severity
	}{
		{"major only with id-token", job("", idToken, "      - run: npm install -g npm@11\n"), []string{"npm@11"}, model.SevMedium},
		{"exact version", job("", idToken, "      - run: npm install -g npm@11.21.1\n"), nil, ""},
		{"read-only job", job("", "      contents: read\n", "      - run: npm install -g npm@latest\n"), nil, ""},
		{"no permissions declared", job("", "", "      - run: npm install -g npm@latest\n"), nil, ""},
		{"local install", job("", idToken, "      - run: npm install\n      - run: npm install typescript\n"), nil, ""},
		{"inherits workflow write", job("  contents: write\n", "", "      - run: npm i -g pnpm\n"), []string{"pnpm"}, model.SevLow},
		{"job overrides workflow", job("  id-token: write\n", "      contents: read\n", "      - run: npm i -g pnpm\n"), nil, ""},
		{"write-all", "on: [push]\npermissions: write-all\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm i -g tool@^2.1.0\n", []string{"tool@^2.1.0"}, model.SevMedium},
		{"flow permissions", "on: [push]\njobs:\n  a:\n    permissions: { packages: write, contents: read }\n    steps:\n      - run: sudo npm install --global @scope/cli@11.x\n", []string{"@scope/cli@11.x"}, model.SevLow},
		{"block script", job("", idToken, "      - name: tools\n        run: |\n          set -e\n          npm ci && npm i -g semantic-release@~24.0.0 @scope/cli@1.2.3\n"), []string{"semantic-release@~24.0.0"}, model.SevMedium},
		{"npx latest", job("", idToken, "      - run: npx -y create-thing@latest init\n"), []string{"create-thing@latest"}, model.SevMedium},
		{"npx local bin", job("", idToken, "      - run: npx tsc --noEmit\n"), nil, ""},
		{"pnpm and yarn", job("", "      packages: write\n", "      - run: pnpm add -g turbo\n      - run: yarn global add lerna@8\n"), []string{"turbo", "lerna@8"}, model.SevLow},
		{"variable and path", job("", idToken, "      - run: npm i -g \"$TOOL\" ./local-pkg ${{ inputs.pkg }}\n"), nil, ""},
		{"unknown flag", job("", idToken, "      - run: npm i -g --registry https://r.example.com tool\n"), nil, ""},
		{"commented out", job("", idToken, "      # - run: npm i -g tool\n      - run: echo ok # npm i -g tool\n"), nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ruleSignals(workflowSignals(t, c.wf), "cicd.unpinned-tool-install")
			if len(got) != len(c.want) {
				t.Fatalf("got %d signals %v, want %v", len(got), got, c.want)
			}
			for i, s := range got {
				if s.Key != c.want[i] || s.Severity != c.sev || s.ControlID != "N-001" {
					t.Errorf("signal %d: key %q severity %s control %s, want %q %s N-001", i, s.Key, s.Severity, s.ControlID, c.want[i], c.sev)
				}
			}
		})
	}
}

func TestImageNotPinned(t *testing.T) {
	digest := "@sha256:" + strings.Repeat("ab", 32)
	perms := "  contents: read\n"
	cases := []struct {
		name string
		wf   string
		want []string
	}{
		{"docker run tag", job(perms, "", "      - run: docker run --rm ghcr.io/org/tool:v1 scan\n"), []string{"ghcr.io/org/tool:v1"}},
		{"docker run digest", job(perms, "", "      - run: docker run --rm ghcr.io/org/tool:v1"+digest+" scan\n"), nil},
		{"docker run variable", job(perms, "", "      - run: docker run $IMAGE\n"), nil},
		{"docker run expression", job(perms, "", "      - run: docker run --rm ${{ env.IMG }}\n"), nil},
		{"flag values", job(perms, "", "      - run: docker run -it --rm -v \"$PWD:/w\" -w /w -e K=V -p 8080:80 --name n --network host --entrypoint sh node:20 -c ls\n"), []string{"node:20"}},
		{"attached and = values", job(perms, "", "      - run: docker run -eA=b --env=X=1 -v${{ github.workspace }}:/src alpine:3.20 true\n"), []string{"alpine:3.20"}},
		{"unknown flag", job(perms, "", "      - run: docker run --some-new-flag x:y alpine:3.20\n"), nil},
		{"continued lines", job(perms, "", "      - run: |\n          docker run --rm \\\n            -v /a:/b \\\n            alpine:3.20 true\n"), []string{"alpine:3.20"}},
		{"no tag may be local", job(perms, "", "      - run: docker run --rm mytool\n"), nil},
		{"built in workflow", job(perms, "", "      - run: docker build -t app:ci .\n      - run: docker run app:ci\n"), nil},
		{"uses docker", job(perms, "", "      - uses: docker://alpine:3.20\n      - uses: docker://alpine:3.20"+digest+"\n"), []string{"alpine:3.20"}},
		{"container scalar", "on: [push]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    container: node:20\n    steps:\n      - run: make\n", []string{"node:20"}},
		{"container block", "on: [push]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    container:\n      image: node:20" + digest + "\n      options: --user 1001\n    steps:\n      - run: make\n", nil},
		{"container flow", "on: [push]\njobs:\n  a:\n    container: { image: \"node:20\", options: --cpus 1 }\n    steps:\n      - run: make\n", []string{"node:20"}},
		{"container expression", "on: [push]\njobs:\n  a:\n    container: ${{ matrix.image }}\n    steps:\n      - run: make\n", nil},
		{"services", "on: [push]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    services:\n      db:\n        image: postgres:16\n        ports:\n          - 5432:5432\n      cache:\n        image: redis:7" + digest + "\n    steps:\n      - run: make\n", []string{"postgres:16"}},
		{"echo is not docker run", job(perms, "", "      - run: echo \"docker run alpine:3.20\"\n"), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ruleSignals(workflowSignals(t, c.wf), "cicd.image-not-pinned")
			if len(got) != len(c.want) {
				t.Fatalf("got %d signals %v, want %v", len(got), got, c.want)
			}
			for i, s := range got {
				if s.Key != c.want[i] || s.Severity != model.SevLow || s.ControlID != "N-001" {
					t.Errorf("signal %d: key %q severity %s control %s, want %q low N-001", i, s.Key, s.Severity, s.ControlID, c.want[i])
				}
			}
		})
	}
}
