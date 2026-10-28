// Package catalog is the versioned control and cross-domain edge catalog.
//
// Controls are written as narrow, checkable statements so that a PASS means
// exactly what the title says and nothing more. References use public,
// stable identifiers (CWE, OWASP API Top 10 2023 categories); requirement
// level IDs from ASVS/MASVS are intentionally not invented here.
package catalog

// Version of the built-in catalog. Bump on any semantic change.
const Version = "2026.10-m3"

// Domain is one of the A-R work partitions.
type Domain struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Domains A-R.
var Domains = []Domain{
	{"A", "Asset inventory, architecture and threat model"},
	{"B", "Authentication, sessions and identity"},
	{"C", "Authorization, roles and tenant isolation"},
	{"D", "Input, output, injection and data flow"},
	{"E", "Secrets, cryptography, privacy and storage"},
	{"F", "Business logic, integrity and financial workflows"},
	{"G", "API contracts, integrations and messaging"},
	{"H", "Web frontend, browser and client-side controls"},
	{"I", "Dependencies, SBOM and software supply chain"},
	{"J", "Cloud, infrastructure, network and IaC"},
	{"K", "Android application security"},
	{"L", "iOS application security"},
	{"M", "Dynamic application/API security testing"},
	{"N", "CI/CD, source control and release security"},
	{"O", "Observability, detection and recovery"},
	{"P", "AI/LLM, agents, prompts and MCP"},
	{"Q", "Availability, concurrency and abuse resistance"},
	{"R", "Reporting, governance and remediation assurance"},
}

// DomainName returns the name of a domain ID.
func DomainName(id string) string {
	for _, d := range Domains {
		if d.ID == id {
			return d.Name
		}
	}
	return id
}

// Method describes how a control can be decided.
const (
	MethodStatic   = "static"   // decided by a built-in or external static adapter
	MethodExternal = "external" // decided by an optional third-party tool
	MethodRuntime  = "runtime"  // needs an approved runtime profile
	MethodManual   = "manual"   // needs manual-assisted review and attestation
)

// Control is one catalog entry.
type Control struct {
	ID       string   `json:"id"`
	Domain   string   `json:"domain"`
	Title    string   `json:"title"`
	Method   string   `json:"method"`
	Adapter  string   `json:"adapter,omitempty"`
	Requires string   `json:"requires"`
	Refs     []string `json:"refs,omitempty"`
	// Profile is the runtime profile that can decide a runtime control.
	Profile string `json:"profile,omitempty"`
}

// Controls is the built-in control catalog.
var Controls = []Control{
	{ID: "A-001", Domain: "A", Title: "Repository inventory walk completed without unreadable or skipped files", Method: MethodStatic, Adapter: "builtin-inventory", Requires: "any"},
	{ID: "A-002", Domain: "A", Title: "Externally reachable routes enumerated with file references", Method: MethodStatic, Adapter: "builtin-inventory", Requires: "web"},
	{ID: "A-003", Domain: "A", Title: "Declared API contract (OpenAPI) matches discovered routes", Method: MethodStatic, Adapter: "builtin-inventory", Requires: "openapi"},
	{ID: "A-004", Domain: "A", Title: "Asset owners, trust boundaries and abuse cases reviewed", Method: MethodManual, Requires: "any"},

	{ID: "B-001", Domain: "B", Title: "JWT verification is not disabled and does not accept the 'none' algorithm", Method: MethodStatic, Adapter: "builtin-code", Requires: "code", Refs: []string{"CWE-347"}},
	{ID: "B-002", Domain: "B", Title: "Session cookies are not explicitly configured without Secure/HttpOnly", Method: MethodStatic, Adapter: "builtin-code", Requires: "web", Refs: []string{"CWE-614", "CWE-1004"}},
	{ID: "B-003", Domain: "B", Title: "Login, reset and MFA state machine tested with negative cases", Method: MethodRuntime, Requires: "auth", Profile: "staging-active", Refs: []string{"API2:2023"}},
	{ID: "B-004", Domain: "B", Title: "Session expiry and revocation enforced server-side", Method: MethodRuntime, Requires: "auth", Profile: "staging-active", Refs: []string{"CWE-613"}},

	{ID: "C-001", Domain: "C", Title: "Object-level authorization enforced on parameterized routes (BOLA)", Method: MethodRuntime, Requires: "param_routes", Profile: "staging-active", Refs: []string{"API1:2023", "CWE-639"}},
	{ID: "C-002", Domain: "C", Title: "Function-level authorization enforced on privileged routes", Method: MethodRuntime, Requires: "admin_routes", Profile: "staging-active", Refs: []string{"API5:2023", "CWE-285"}},
	{ID: "C-003", Domain: "C", Title: "Authorization checks reviewed for every route handler", Method: MethodManual, Requires: "web", Refs: []string{"CWE-862"}},

	{ID: "D-001", Domain: "D", Title: "No dynamic code evaluation (eval/new Function/exec of strings)", Method: MethodStatic, Adapter: "builtin-code", Requires: "code", Refs: []string{"CWE-95"}},
	{ID: "D-002", Domain: "D", Title: "No shell command construction through a shell interpreter", Method: MethodStatic, Adapter: "builtin-code", Requires: "code", Refs: []string{"CWE-78"}},
	{ID: "D-003", Domain: "D", Title: "No SQL statements built by string concatenation or interpolation", Method: MethodStatic, Adapter: "builtin-code", Requires: "code", Refs: []string{"CWE-89"}},
	{ID: "D-004", Domain: "D", Title: "No unsafe deserialization APIs on untrusted data", Method: MethodStatic, Adapter: "builtin-code", Requires: "code", Refs: []string{"CWE-502"}},
	{ID: "D-005", Domain: "D", Title: "Injection probes executed against approved target", Method: MethodRuntime, Adapter: "zap", Requires: "web", Profile: "staging-active"},
	{ID: "D-006", Domain: "D", Title: "Semgrep data-flow rules (SSRF, path traversal, template injection) and project rules report no findings", Method: MethodExternal, Adapter: "semgrep", Requires: "code"},

	{ID: "E-001", Domain: "E", Title: "No high-confidence secret patterns in repository files", Method: MethodStatic, Adapter: "builtin-secrets", Requires: "any", Refs: []string{"CWE-798"}},
	{ID: "E-002", Domain: "E", Title: "Environment and credential files are not tracked in git", Method: MethodStatic, Adapter: "builtin-secrets", Requires: "git", Refs: []string{"CWE-538"}},
	{ID: "E-003", Domain: "E", Title: "TLS certificate verification is not disabled in code", Method: MethodStatic, Adapter: "builtin-code", Requires: "code", Refs: []string{"CWE-295"}},
	{ID: "E-004", Domain: "E", Title: "No weak hash or non-cryptographic random used for security values", Method: MethodStatic, Adapter: "builtin-code", Requires: "code", Refs: []string{"CWE-327", "CWE-338"}},
	{ID: "E-005", Domain: "E", Title: "Gitleaks reports no secrets", Method: MethodExternal, Adapter: "gitleaks", Requires: "any", Refs: []string{"CWE-798"}},

	{ID: "F-001", Domain: "F", Title: "Business invariants for money and entitlement flows documented and reviewed", Method: MethodManual, Requires: "payments"},
	{ID: "F-002", Domain: "F", Title: "Idempotency and double-processing tested with synthetic fixtures", Method: MethodRuntime, Requires: "payments", Profile: "staging-active", Refs: []string{"CWE-362"}},

	{ID: "G-001", Domain: "G", Title: "Webhook handlers verify a signature before acting on the payload", Method: MethodStatic, Adapter: "builtin-code", Requires: "webhooks", Refs: []string{"CWE-345"}},
	{ID: "G-002", Domain: "G", Title: "Runtime API authorization matches the declared contract", Method: MethodRuntime, Requires: "web", Profile: "staging-active", Refs: []string{"API1:2023", "API3:2023"}},

	{ID: "H-001", Domain: "H", Title: "No raw HTML injection sinks (innerHTML, dangerouslySetInnerHTML, v-html, |safe)", Method: MethodStatic, Adapter: "builtin-code", Requires: "code", Refs: []string{"CWE-79"}},
	{ID: "H-002", Domain: "H", Title: "CORS is not configured as wildcard together with credentials", Method: MethodStatic, Adapter: "builtin-code", Requires: "web", Refs: []string{"CWE-942"}},
	{ID: "H-003", Domain: "H", Title: "Security response headers present on approved deployed target", Method: MethodRuntime, Adapter: "observe-headers", Requires: "any", Profile: "production-observe", Refs: []string{"CWE-693"}},

	{ID: "I-001", Domain: "I", Title: "Every package manifest has a committed lockfile", Method: MethodStatic, Adapter: "builtin-supply", Requires: "packages", Refs: []string{"CWE-829"}},
	{ID: "I-002", Domain: "I", Title: "Dependencies with install-time scripts are listed for review", Method: MethodStatic, Adapter: "builtin-supply", Requires: "npm_lock", Refs: []string{"CWE-506"}},
	{ID: "I-003", Domain: "I", Title: "No known-vulnerable dependencies in an advisory database", Method: MethodExternal, Adapter: "osv-scanner", Requires: "packages", Refs: []string{"CWE-1395"}},
	{ID: "I-004", Domain: "I", Title: "Python requirements pinned to exact versions", Method: MethodStatic, Adapter: "builtin-supply", Requires: "python_reqs", Refs: []string{"CWE-829"}},

	{ID: "J-001", Domain: "J", Title: "Container images do not run as root", Method: MethodStatic, Adapter: "builtin-infra", Requires: "dockerfile", Refs: []string{"CWE-250"}},
	{ID: "J-002", Domain: "J", Title: "Container base images pinned (no latest or missing tag)", Method: MethodStatic, Adapter: "builtin-infra", Requires: "dockerfile", Refs: []string{"CWE-829"}},
	{ID: "J-003", Domain: "J", Title: "No privileged containers or host networking in compose/Kubernetes", Method: MethodStatic, Adapter: "builtin-infra", Requires: "orchestration", Refs: []string{"CWE-250"}},
	{ID: "J-004", Domain: "J", Title: "IaC does not expose public storage or world-open admin ports", Method: MethodStatic, Adapter: "builtin-infra", Requires: "terraform", Refs: []string{"CWE-284"}},
	{ID: "J-005", Domain: "J", Title: "Trivy reports no IaC misconfigurations", Method: MethodExternal, Adapter: "trivy", Requires: "iac"},

	{ID: "K-001", Domain: "K", Title: "Android manifest: not debuggable, no backup, no cleartext traffic", Method: MethodStatic, Adapter: "builtin-mobile", Requires: "android", Refs: []string{"CWE-489", "CWE-530", "CWE-319"}},
	{ID: "K-002", Domain: "K", Title: "Android exported components protected by permission", Method: MethodStatic, Adapter: "builtin-mobile", Requires: "android", Refs: []string{"CWE-926"}},
	{ID: "K-003", Domain: "K", Title: "Android runtime storage and transport verified on emulator", Method: MethodRuntime, Requires: "android", Profile: "local-runtime"},

	{ID: "L-001", Domain: "L", Title: "iOS App Transport Security does not allow arbitrary loads", Method: MethodStatic, Adapter: "builtin-mobile", Requires: "ios", Refs: []string{"CWE-319"}},
	{ID: "L-002", Domain: "L", Title: "iOS keychain and storage verified on simulator", Method: MethodRuntime, Requires: "ios", Profile: "local-runtime"},

	{ID: "M-001", Domain: "M", Title: "Passive DAST (ZAP baseline) against approved target", Method: MethodRuntime, Adapter: "zap", Requires: "web", Profile: "staging-active"},

	{ID: "N-001", Domain: "N", Title: "Third-party GitHub Actions pinned to a full commit SHA", Method: MethodStatic, Adapter: "builtin-cicd", Requires: "github_workflows", Refs: []string{"CWE-829"}},
	{ID: "N-002", Domain: "N", Title: "No untrusted event data interpolated into run: scripts", Method: MethodStatic, Adapter: "builtin-cicd", Requires: "github_workflows", Refs: []string{"CWE-78"}},
	{ID: "N-003", Domain: "N", Title: "pull_request_target workflows do not check out untrusted PR code", Method: MethodStatic, Adapter: "builtin-cicd", Requires: "github_workflows", Refs: []string{"CWE-829"}},
	{ID: "N-004", Domain: "N", Title: "Workflow GITHUB_TOKEN permissions declared explicitly", Method: MethodStatic, Adapter: "builtin-cicd", Requires: "github_workflows", Refs: []string{"CWE-250"}},

	{ID: "O-001", Domain: "O", Title: "Security events logged and alerted (privilege changes, auth failures)", Method: MethodManual, Requires: "web"},
	{ID: "O-002", Domain: "O", Title: "Secrets and credentials not written to logs", Method: MethodStatic, Adapter: "builtin-code", Requires: "code", Refs: []string{"CWE-532"}},

	{ID: "P-001", Domain: "P", Title: "Model output is not executed as code or shell", Method: MethodStatic, Adapter: "builtin-code", Requires: "llm", Refs: []string{"CWE-94"}},
	{ID: "P-002", Domain: "P", Title: "MCP server configs pinned and free of inline credentials", Method: MethodStatic, Adapter: "builtin-supply", Requires: "mcp_config", Refs: []string{"CWE-829", "CWE-798"}},
	{ID: "P-003", Domain: "P", Title: "Prompt-injection and tool-authorization cases tested", Method: MethodRuntime, Requires: "llm", Profile: "staging-active"},

	{ID: "Q-001", Domain: "Q", Title: "Rate limiting applied to authentication and expensive routes", Method: MethodManual, Requires: "web", Refs: []string{"API4:2023", "CWE-770"}},
	{ID: "Q-002", Domain: "Q", Title: "Concurrency and duplicate-action tests on stateful flows", Method: MethodRuntime, Requires: "payments", Profile: "staging-active", Refs: []string{"CWE-362"}},

	{ID: "R-001", Domain: "R", Title: "All evidence artifacts of this assessment verify against recorded SHA-256", Method: MethodStatic, Adapter: "builtin-evidence", Requires: "any"},
	{ID: "R-002", Domain: "R", Title: "Imported third-party analyzer results (SARIF) report no findings", Method: MethodExternal, Adapter: "sarif-import", Requires: "sarif"},
}

// ControlByID returns a control or nil.
func ControlByID(id string) *Control {
	for i := range Controls {
		if Controls[i].ID == id {
			return &Controls[i]
		}
	}
	return nil
}

// EdgeRule describes how a seed cross-domain edge is instantiated.
// An edge is created only when the inventory feature named in Needs has
// concrete assets; those assets become the edge provenance.
type EdgeRule struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Scenario string   `json:"scenario"`
	Needs    []string `json:"needs"`
	Tests    []string `json:"tests"`
}

// Edges is the seed edge catalog. Each Needs entry must be satisfied.
var Edges = []EdgeRule{
	{ID: "AB1", Title: "Discovered login endpoints -> session tests", Scenario: "New auth route missing token/session coverage", Needs: []string{"auth_routes"}, Tests: []string{"A-002", "B-003", "B-004"}},
	{ID: "AC1", Title: "Asset owners -> access policies", Scenario: "Orphan routes lack authorization checks", Needs: []string{"routes"}, Tests: []string{"C-002", "C-003"}},
	{ID: "AD1", Title: "Input entrypoints -> sinks", Scenario: "Ingress path crosses a parsing or command boundary", Needs: []string{"route_files_with_sinks"}, Tests: []string{"D-001", "D-002", "D-003", "D-004", "D-005"}},
	{ID: "AE1", Title: "Asset classification -> secret scan", Scenario: "Secret material flows into config, workflow or IaC", Needs: []string{"secrets_in_config"}, Tests: []string{"E-001", "E-002"}},
	{ID: "AG1", Title: "Service inventory -> API coverage", Scenario: "Undocumented endpoints bypass contract tests", Needs: []string{"openapi", "routes"}, Tests: []string{"A-003", "G-002"}},
	{ID: "AJ1", Title: "Cloud-deployed asset -> exposure", Scenario: "Private API exposed by ingress or policy drift", Needs: []string{"routes", "deploy_config"}, Tests: []string{"J-001", "J-003", "J-004"}},
	{ID: "BC1", Title: "Authenticated identity -> authorization", Scenario: "Valid user can access another tenant's object", Needs: []string{"auth_routes", "param_routes"}, Tests: []string{"C-001"}},
	{ID: "CG1", Title: "Object access -> API response", Scenario: "Mass assignment or property-level data access", Needs: []string{"param_routes"}, Tests: []string{"C-001", "G-002"}},
	{ID: "DG1", Title: "Webhook input -> API trust", Scenario: "Unsigned callback payload drives privileged state", Needs: []string{"webhooks"}, Tests: []string{"G-001"}},
	{ID: "DH1", Title: "HTML output -> browser", Scenario: "Unescaped backend content reaches the DOM", Needs: []string{"html_sinks"}, Tests: []string{"H-001"}},
	{ID: "DP1", Title: "Prompt content -> tools", Scenario: "Untrusted retrieved text triggers a tool action", Needs: []string{"llm"}, Tests: []string{"P-001", "P-003"}},
	{ID: "EI1", Title: "Secrets -> dependencies", Scenario: "Package lifecycle script obtains environment secret", Needs: []string{"install_scripts", "github_workflows"}, Tests: []string{"I-002", "N-002"}},
	{ID: "FG1", Title: "Payment state -> webhooks", Scenario: "Replay moves payment into an invalid terminal state", Needs: []string{"payments", "webhooks"}, Tests: []string{"F-001", "G-001"}},
	{ID: "FQ1", Title: "State machine -> race", Scenario: "Concurrent requests bypass idempotency", Needs: []string{"payments"}, Tests: []string{"F-002", "Q-002"}},
	{ID: "HJ1", Title: "Web headers -> CDN/edge config", Scenario: "Edge overrides CSP or cache policy", Needs: []string{"headers_observed", "deploy_config"}, Tests: []string{"H-003", "J-004"}},
	{ID: "IN1", Title: "Action dependency -> CI integrity", Scenario: "Unpinned third-party action may change code", Needs: []string{"third_party_actions"}, Tests: []string{"N-001"}},
	{ID: "BK1", Title: "Mobile identity -> Android storage", Scenario: "Token copied to Android insecure storage", Needs: []string{"android", "auth"}, Tests: []string{"K-001", "K-003"}},
	{ID: "BL1", Title: "Mobile identity -> iOS keychain", Scenario: "Session material stored outside platform controls", Needs: []string{"ios", "auth"}, Tests: []string{"L-001", "L-002"}},
	{ID: "JP1", Title: "IAM -> MCP credentials", Scenario: "Agent receives wider credentials than the tool requires", Needs: []string{"mcp_config"}, Tests: []string{"P-002"}},
}

// Profiles known to the policy engine.
var Profiles = []string{"local-passive", "local-runtime", "staging-active", "production-observe", "manual-assisted"}
