package adapters

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// decide writes files into a fresh directory, runs the inventory adapter
// and returns its decision for one control.
func decide(t *testing.T, files map[string]string, control string) Decision {
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
	res, run := inventoryAdapter{}.Run(context.Background(), &Context{Root: root, Inv: inv})
	if run.ExitClass != model.ExitOK {
		t.Fatalf("inventory adapter did not complete: %s", run.Detail)
	}
	d, ok := res.Decisions[control]
	if !ok {
		t.Fatalf("no decision for %s", control)
	}
	return d
}

// appRouter is a pure App Router app in a pnpm monorepo, with every kind
// of special folder: a route group, dynamic, catch-all and optional
// catch-all segments, a parallel slot, an intercepting route and a private
// folder that must not count.
func appRouter() map[string]string {
	return map[string]string{
		"package.json":        `{"name":"mono","private":true}`,
		"pnpm-workspace.yaml": "packages:\n  - apps/*\n",
		"apps/web/package.json": `{"name":"web","scripts":{"dev":"next dev","build":"next build","start":"next start"},` +
			`"dependencies":{"next":"15.0.0","react":"19.0.0"}}`,
		"apps/web/next.config.ts": "import type { NextConfig } from 'next'\n\nconst config: NextConfig = {\n" +
			"  async redirects() {\n    return [{ source: '/old', destination: '/new', permanent: true }]\n  },\n}\n\nexport default config\n",
		"apps/web/middleware.ts": "import { NextResponse, type NextRequest } from 'next/server'\n\n" +
			"export function middleware(request: NextRequest) {\n" +
			"  if (!request.cookies.get('session')) {\n    const url = request.nextUrl.clone()\n    url.pathname = '/login'\n    return NextResponse.redirect(url)\n  }\n" +
			"  if (request.method === 'POST' && !request.headers.get('origin')) {\n    return NextResponse.json({ error: 'forbidden' }, { status: 403 })\n  }\n" +
			"  return NextResponse.next()\n}\n",
		"apps/web/app/layout.tsx":                         "export default function RootLayout({ children }) { return children }\n",
		"apps/web/app/page.tsx":                           "export default function Home() { return null }\n",
		"apps/web/app/(marketing)/about/page.tsx":         "export default function About() { return null }\n",
		"apps/web/app/(shop)/layout.tsx":                  "export default function ShopLayout({ children }) { return children }\n",
		"apps/web/app/(shop)/items/[id]/page.tsx":         "export default function Item() { return null }\n",
		"apps/web/app/docs/[...slug]/page.tsx":            "export default function Docs() { return null }\n",
		"apps/web/app/files/[[...path]]/page.tsx":         "export default function Files() { return null }\n",
		"apps/web/app/feed/@modal/(.)photo/[id]/page.tsx": "export default function PhotoModal() { return null }\n",
		"apps/web/app/feed/@modal/default.tsx":            "export default function Default() { return null }\n",
		"apps/web/app/feed/photo/[id]/page.tsx":           "export default function Photo() { return null }\n",
		"apps/web/app/_components/button.tsx":             "export function Button() { return null }\n",
		"apps/web/app/_internal/route.ts":                 "export async function GET() { return Response.json({}) }\n",
		"apps/web/app/api/items/route.ts":                 "export async function GET() { return Response.json([]) }\nexport async function POST() { return Response.json({}) }\n",
		"apps/web/app/api/auth/[...nextauth]/route.ts":    "import { handlers } from '@/auth'\nconst { GET: get, POST: post } = handlers\nexport { get as GET, post as POST }\n",
		"apps/web/app/sitemap.ts":                         "export default function sitemap() { return [] }\n",
		"apps/web/app/items/actions.ts":                   "'use server'\n\nexport async function saveItem(data: FormData) {}\n",
	}
}

func TestA002PureAppRouterPasses(t *testing.T) {
	d := decide(t, appRouter(), "A-002")
	if d.Status != model.StatusPass {
		t.Fatalf("A-002 = %s: %s", d.Status, d.Reason)
	}
	t.Log(d.Reason)
	for _, want := range []string{
		"1 app(s): apps/web (apps/web/app): 7 pages, 2 route handlers (4 methods), 2 layouts, 1 server actions, 1 metadata routes",
		"3 with dynamic segments, 2 catch-all, 1 optional catch-all; 2 route groups, 1 parallel slots, 1 intercepting folders",
		"middleware apps/web/middleware.ts redirects or rewrites to internal paths (1) and rejects requests with error statuses (1)",
		"apps/web/next.config.ts: 1 rewrites or redirects to internal paths",
		"no custom server", "`pandaward routes`",
	} {
		if !strings.Contains(d.Reason, want) {
			t.Errorf("reason lacks %q:\n%s", want, d.Reason)
		}
	}
}

// Each case adds one thing that can serve routes outside the file table;
// A-002 must stay INCONCLUSIVE and the reason must name it.
func TestA002BlockersKeepInconclusive(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"custom server", map[string]string{
			"apps/web/server.js": "const { createServer } = require('http')\nconst next = require('next')\nconst app = next({ dev: false })\n" +
				"const handle = app.getRequestHandler()\napp.prepare().then(() => createServer((req, res) => handle(req, res)).listen(3000))\n",
		}, "apps/web/server.js:4 starts a custom Next.js server"},
		{"custom server script", map[string]string{
			"apps/web/package.json": `{"scripts":{"start":"node server.js"},"dependencies":{"next":"15.0.0"}}`,
		}, "the \"start\" script in apps/web/package.json runs `node server.js`, not next"},
		{"external rewrite", map[string]string{
			"apps/web/next.config.ts": "const config = {\n  async rewrites() {\n    return [{ source: '/api/:path*', destination: 'https://backend.example.com/:path*' }]\n  },\n}\nexport default config\n",
		}, "apps/web/next.config.ts:3 rewrites to the external origin https://backend.example.com/:path*"},
		{"computed rewrite", map[string]string{
			"apps/web/next.config.ts": "const config = {\n  async rewrites() {\n    return [{ source: '/x/:p*', destination: process.env.UPSTREAM + '/:p*' }]\n  },\n}\nexport default config\n",
		}, "a rewrites destination is not a literal"},
		{"unknown config wrapper", map[string]string{
			"apps/web/next.config.ts": "import { withMicrofrontends } from '@vercel/microfrontends/next/config'\nexport default withMicrofrontends({})\n",
		}, "wraps the config in withMicrofrontends"},
		{"express", map[string]string{
			"services/api/package.json": `{"dependencies":{"express":"4.21.0"}}`,
			"services/api/index.js":     "const express = require('express')\nconst app = express()\napp.get('/health', (req, res) => res.send('ok'))\napp.listen(8080)\n",
		}, "1 express route registrations (e.g. services/api/index.js:3)"},
		{"express dependency without routes", map[string]string{
			"apps/web/package.json": `{"dependencies":{"next":"15.0.0","express":"4.21.0"}}`,
		}, "apps/web/package.json depends on the server framework express"},
		{"hono in a catch-all route", map[string]string{
			"apps/web/app/api/[[...route]]/route.ts": "import { Hono } from 'hono'\nimport { handle } from 'hono/vercel'\nconst app = new Hono().basePath('/api')\nexport const GET = handle(app)\n",
		}, "imports the server framework hono"},
		{"middleware rewrite to another origin", map[string]string{
			"apps/web/middleware.ts": "import { NextResponse } from 'next/server'\nexport function middleware(req) {\n  return NextResponse.rewrite(new URL('https://legacy.example.com/app'))\n}\n",
		}, "middleware apps/web/middleware.ts:3 rewrites to an external origin"},
		{"middleware from a library", map[string]string{
			"apps/web/middleware.ts": "import { clerkMiddleware } from '@clerk/nextjs/server'\nexport default clerkMiddleware()\n",
		}, "is created by code from another module"},
		{"middleware returns a response of its own", map[string]string{
			"apps/web/middleware.ts": "import { NextResponse } from 'next/server'\nexport function middleware(req) {\n  if (req.nextUrl.pathname === '/status') return NextResponse.json({ up: true })\n  return NextResponse.next()\n}\n",
		}, "answers requests itself without a literal error status"},
		{"serverless function", map[string]string{
			"supabase/functions/send-mail/index.ts": "Deno.serve(async (req) => new Response('ok'))\n",
		}, "supabase/functions/send-mail/index.ts is a serverless function"},
		{"php", map[string]string{
			"plugins/wp/plugin.php": "<?php\nadd_action('admin_post_x', 'handler');\n",
		}, "1 PHP files (e.g. plugins/wp/plugin.php)"},
		{"vercel external rewrite", map[string]string{
			"apps/web/vercel.json": `{"rewrites":[{"source":"/blog/:p*","destination":"https://blog.example.com/:p*"}]}`,
		}, "apps/web/vercel.json rewrites to the external origin https://blog.example.com/:p*"},
		{"openapi path without a route file", map[string]string{
			"openapi.yaml": "openapi: 3.0.0\npaths:\n  /api/items:\n    get: {}\n  /api/legacy:\n    get: {}\n",
		}, "the OpenAPI contract declares 1 paths no route file defines (e.g. /api/legacy)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := appRouter()
			for k, v := range c.files {
				files[k] = v
			}
			d := decide(t, files, "A-002")
			if d.Status != model.StatusInconclusive {
				t.Fatalf("A-002 = %s, want INCONCLUSIVE: %s", d.Status, d.Reason)
			}
			if !strings.Contains(d.Reason, c.want) {
				t.Errorf("reason lacks %q:\n%s", c.want, d.Reason)
			}
			if !strings.Contains(d.Reason, "PASS is blocked") {
				t.Errorf("reason does not say what blocks PASS:\n%s", d.Reason)
			}
		})
	}
}

// Test code that starts a server (a Playwright fixture, a mocked upstream)
// is not part of the deployed app.
func TestA002IgnoresTestServers(t *testing.T) {
	files := appRouter()
	files["apps/web/e2e/fixture.spec.ts"] = "import http from 'node:http'\nconst s = http.createServer((q, r) => r.end('ok'))\n"
	files["apps/web/__tests__/proxy.test.ts"] = "import express from 'express'\nconst app = express()\n"
	if d := decide(t, files, "A-002"); d.Status != model.StatusPass {
		t.Fatalf("A-002 = %s: %s", d.Status, d.Reason)
	}
}

// Projects without a Next.js app keep the heuristic decision.
func TestA002OtherFrameworksUnchanged(t *testing.T) {
	d := decide(t, map[string]string{
		"package.json": `{"dependencies":{"express":"4.21.0"}}`,
		"index.js":     "const express = require('express')\nconst app = express()\napp.get('/health', h)\n",
	}, "A-002")
	if d.Status != model.StatusInconclusive || !strings.HasPrefix(d.Reason, "1 HTTP routes, 0 GraphQL operations") {
		t.Fatalf("A-002 = %s: %s", d.Status, d.Reason)
	}
}
