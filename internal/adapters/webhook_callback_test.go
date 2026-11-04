package adapters

import (
	"slices"
	"testing"
)

// A GET-only callback route that reads the OAuth "code" and "state" query
// parameters is a browser redirect, not a webhook. Without that proof a
// callback stays a webhook, whatever its method.
func TestWebhookCallbackOAuthRedirect(t *testing.T) {
	sigs := runOn(t, codeAdapter{}, map[string]string{
		"package.json": `{"name":"app","dependencies":{"next":"15.0.0"}}`,
		// POST callback without verification: a webhook.
		"app/api/payments/callback/route.ts": "export async function POST(req: Request) {\n  const body = await req.json();\n  await markPaid(body.orderId);\n  return Response.json({ ok: true });\n}\n",
		// GET-only OAuth redirect: reads code and state.
		"app/api/provider-app/callback/route.ts": "export async function GET(req: Request) {\n  const url = new URL(req.url);\n  const code = url.searchParams.get(\"code\");\n  const state = url.searchParams.get(\"state\");\n  await exchange(code, state);\n  return Response.redirect(\"/\");\n}\n",
		// GET-only callback without code and state: some payment providers
		// call back with GET, so this stays a webhook.
		"app/api/gateway/callback/route.ts": "export async function GET(req: Request) {\n  const url = new URL(req.url);\n  const order = url.searchParams.get(\"order\");\n  await markPaid(order);\n  return Response.json({ ok: true });\n}\n",
		// Reads code and state but also accepts POST: stays a webhook.
		"app/api/mixed/callback/route.ts": "export async function GET(req: Request) {\n  const url = new URL(req.url);\n  await exchange(url.searchParams.get('code'), url.searchParams.get('state'));\n  return Response.redirect(\"/\");\n}\nexport async function POST(req: Request) {\n  await markPaid((await req.json()).id);\n  return Response.json({ ok: true });\n}\n",
		// Explicit webhook word, GET-only with code and state: stays a webhook.
		"app/api/webhook/route.ts": "export async function GET(req: Request) {\n  const url = new URL(req.url);\n  await exchange(url.searchParams.get('code'), url.searchParams.get('state'));\n  return Response.json({ ok: true });\n}\n",
		// Express GET-only OAuth redirect reading req.query.
		"src/server.js": "const app = require('express')();\napp.get('/api/partner/callback', async (req, res) => {\n  await exchange(req.query.code, req.query.state);\n  res.redirect('/');\n});\n",
	})
	var files []string
	for _, s := range sigs {
		if s.RuleID == "code.webhook-no-signature" {
			files = append(files, s.File)
		}
	}
	for file, want := range map[string]bool{
		"app/api/payments/callback/route.ts":     true,
		"app/api/gateway/callback/route.ts":      true,
		"app/api/mixed/callback/route.ts":        true,
		"app/api/webhook/route.ts":               true,
		"app/api/provider-app/callback/route.ts": false,
		"src/server.js":                          false,
	} {
		if got := slices.Contains(files, file); got != want {
			t.Errorf("webhook-no-signature on %s: fired=%v, want %v (fired on %v)", file, got, want, files)
		}
	}
}
