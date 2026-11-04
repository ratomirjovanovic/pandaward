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

// An OAuth redirect handler reads both "code" and "state" from the query.
func TestReadsOAuthCodeAndState(t *testing.T) {
	for src, want := range map[string]bool{
		`const code = url.searchParams.get("code"); const state = url.searchParams.get("state");`: true,
		`exchange(req.query.code, req.query.state)`:                                               true,
		`const { code, state } = req.query;`:                                                      true,
		`const { state, code } = await request.query`:                                             true,
		`code := r.URL.Query().Get("code"); st := r.URL.Query().Get("state")`:                     true,
		`code = request.args["code"]; state = request.args.get("state")`:                          true,
		`c.Query("code"); c.Query("state")`:                                                       true,
		`const code = url.searchParams.get("code");`:                                              false,
		`const order = req.query.order; const state = req.query.state;`:                           false,
		`const body = await req.json(); const { code, state } = body;`:                            false,
	} {
		if got := readsOAuthCodeAndState(&File{Lines: []string{src}}); got != want {
			t.Errorf("readsOAuthCodeAndState(%q) = %v, want %v", src, got, want)
		}
	}
}

// Only a GET-only callback with the OAuth query proof leaves the webhooks.
func TestOAuthRedirectRoute(t *testing.T) {
	oauth := &File{Lines: []string{`exchange(req.query.code, req.query.state)`}}
	plain := &File{Lines: []string{`markPaid(req.query.order)`}}
	get, post := map[string]bool{"GET": true}, map[string]bool{"GET": true, "POST": true}
	for _, c := range []struct {
		path    string
		methods map[string]bool
		f       *File
		want    bool
	}{
		{"/api/provider-app/callback", get, oauth, true},
		{"/api/provider-app/callback", post, oauth, false},
		{"/api/provider-app/callback", get, plain, false},
		{"/api/provider-app/callback", map[string]bool{"ANY": true}, oauth, false},
		{"/api/webhook/callback", get, oauth, false},
		{"/api/ipn", get, oauth, false},
	} {
		if got := oauthRedirectRoute(c.path, c.methods, c.f); got != c.want {
			t.Errorf("oauthRedirectRoute(%q, %v) = %v, want %v", c.path, c.methods, got, c.want)
		}
	}
}
