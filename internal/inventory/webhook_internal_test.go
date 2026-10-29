package inventory

import "testing"

// OAuth, OIDC and SSO callbacks are browser redirects, not webhooks (#158);
// payment and provider callbacks still are.
func TestIsWebhookPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/webhooks/stripe":             true,
		"/api/stripe/webhook":          true,
		"/hooks/github":                true,
		"/payment/callback":            true,
		"/api/paypal/callback":         true,
		"/ipn":                         true,
		"/api/notify/order":            true,
		"/api/github/oauth/callback":   false,
		"/api/auth/callback/github":    false,
		"/auth/google/callback":        false,
		"/login/callback":              false,
		"/sso/saml/callback":           false,
		"/oauth2/callback":             false,
		"/api/oauth/webhook":           true,
		"/api/auth/hooks/user-created": true,
		"/api/orders":                  false,
		"/api/authors/callback":        true,
	} {
		if got := isWebhookPath(p); got != want {
			t.Errorf("isWebhookPath(%q) = %v, want %v", p, got, want)
		}
	}
}
