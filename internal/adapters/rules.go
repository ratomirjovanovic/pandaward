package adapters

import (
	"sort"

	"github.com/ratomirjovanovic/pandaward/internal/redact"
)

// fileRuleIDs are the rules built-in adapters emit outside the codeRules
// and secret tables. A test keeps this list in sync with the source.
var fileRuleIDs = []string{
	"inventory.undeclared-route",
	"code.llm-output-exec", "code.cors-wildcard-credentials", "code.webhook-no-signature",
	"secret.tracked-sensitive-file",
	"cicd.unpinned-action", "cicd.script-injection", "cicd.prt-untrusted-checkout", "cicd.no-permissions",
	"infra.unpinned-base-image", "infra.container-root", "infra.privileged-container", "infra.public-storage", "infra.world-open-admin-port",
	"supply.missing-lockfile", "supply.install-script", "supply.unpinned-requirements", "supply.mcp-unpinned", "supply.mcp-inline-credential",
	"mobile.android-debuggable", "mobile.android-allow-backup", "mobile.android-cleartext", "mobile.android-exported-component", "mobile.ios-ats-arbitrary-loads", "mobile.ios-get-task-allow",
}

// RuleIDs returns every rule ID the built-in adapters can emit, sorted.
// Rule IDs of optional tools and of imported SARIF results
// (sarif.<tool>.<rule>) come from outside PandaWard and are not listed.
func RuleIDs() []string {
	out := append([]string{}, fileRuleIDs...)
	for _, r := range codeRules {
		out = append(out, r.ID)
	}
	for _, r := range mobileStorageRules {
		out = append(out, r.ID)
	}
	for _, r := range redact.SecretRules {
		out = append(out, "secret."+r.ID)
	}
	sort.Strings(out)
	return out
}
