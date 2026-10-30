package inventory_test

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// entrypoints returns "kind id" for every entrypoint asset, sorted.
func entrypoints(inv *inventory.Inventory) []string {
	var out []string
	for _, a := range inv.Assets {
		switch a.Kind {
		case "route", "graphql_operation", "grpc_method", "queue_consumer", "cron_job", "server_action":
			out = append(out, a.ID)
		}
	}
	sort.Strings(out)
	return out
}

func asset(inv *inventory.Inventory, id string) *model.Asset {
	for i := range inv.Assets {
		if inv.Assets[i].ID == id {
			return &inv.Assets[i]
		}
	}
	return nil
}

// The fixture from the acceptance criteria: a monorepo with two HTTP
// services (Express with routers mounted from other files, FastAPI with
// router prefixes), a queue worker and a GraphQL API.
func TestMonorepoEntrypoints(t *testing.T) {
	inv := writeAndWalk(t, map[string]string{
		"services/api/package.json": `{"dependencies":{"express":"4"}}`,
		"services/api/src/app.js": "const express = require('express');\n" +
			"const users = require('./routes/users');\n" +
			"const app = express();\n" +
			"const admin = express.Router();\n" +
			"admin.get('/stats', stats);\n" +
			"app.use('/api/users', users);\n" +
			"app.use('/admin', requireAdmin, admin);\n" +
			"app.get('/health', health);\n",
		"services/api/src/routes/users.js": "const router = require('express').Router();\n" +
			"router.get('/:id', show);\n" +
			"router.post('/', create);\n" +
			"module.exports = router;\n",

		"services/billing/requirements.txt": "fastapi==0.110.0\n",
		"services/billing/app/main.py": "from fastapi import FastAPI\n" +
			"from .routers import invoices\n" +
			"app = FastAPI()\n" +
			"app.include_router(invoices.router, prefix=\"/v1\")\n" +
			"@app.get(\"/health\")\n" +
			"def health(): pass\n",
		"services/billing/app/routers/invoices.py": "from fastapi import APIRouter\n" +
			"router = APIRouter(prefix=\"/invoices\")\n" +
			"@router.get(\"/{invoice_id}\")\n" +
			"def show(invoice_id: str): pass\n" +
			"@router.post(\"\")\n" +
			"def create(): pass\n",
		"services/billing/proto/billing.proto": "syntax = \"proto3\";\npackage billing.v1;\nservice Billing {\n  rpc GetInvoice(GetInvoiceRequest) returns (Invoice);\n}\n",

		"services/worker/package.json": `{"dependencies":{"bullmq":"5","node-cron":"3"}}`,
		"services/worker/index.js": "const { Worker } = require('bullmq');\n" +
			"const cron = require('node-cron');\n" +
			"new Worker('emails', async job => send(job));\n" +
			"cron.schedule('0 * * * *', cleanup);\n",

		"services/graphql/package.json":   `{"dependencies":{"@apollo/server":"4"}}`,
		"services/graphql/schema.graphql": "type Query {\n  invoice(id: ID!): Invoice\n  me: User\n}\n\ntype Mutation {\n  login(email: String!, password: String!): Token\n}\n\ntype Invoice {\n  id: ID!\n}\n",
	})
	want := []string{
		"consumer:bullmq:emails@services/worker/index.js:3",
		"cron:0 * * * *@services/worker/index.js:4",
		"graphql:Mutation.login@services/graphql/schema.graphql",
		"graphql:Query.invoice@services/graphql/schema.graphql",
		"graphql:Query.me@services/graphql/schema.graphql",
		"grpc:/billing.v1.Billing/GetInvoice@services/billing/proto/billing.proto",
		"route:GET:/admin/stats@services/api/src/app.js",
		"route:GET:/api/users/:id@services/api/src/routes/users.js",
		"route:GET:/health@services/api/src/app.js",
		"route:GET:/health@services/billing/app/main.py",
		"route:GET:/v1/invoices/{invoice_id}@services/billing/app/routers/invoices.py",
		"route:POST:/api/users@services/api/src/routes/users.js",
		"route:POST:/v1/invoices@services/billing/app/routers/invoices.py",
	}
	if got := entrypoints(inv); !slices.Equal(got, want) {
		t.Fatalf("entrypoints:\n got  %q\n want %q", got, want)
	}

	// Provenance keeps the file and line of the definition, and the service.
	a := asset(inv, "route:GET:/api/users/:id@services/api/src/routes/users.js")
	if a.Locator != "services/api/src/routes/users.js" || a.Line != 2 || a.Meta["service"] != "services/api" || a.Meta["framework"] != "express" {
		t.Errorf("route provenance: %+v", a)
	}
	if a := asset(inv, "graphql:Query.invoice@services/graphql/schema.graphql"); a.Line != 2 || a.Meta["service"] != "services/graphql" {
		t.Errorf("graphql provenance: %+v", a)
	}

	if got := inv.Features["services"]; !slices.Equal(got, []string{"services/api", "services/billing", "services/graphql", "services/worker"}) {
		t.Errorf("services = %v", got)
	}
	for feature, id := range map[string]string{
		"param_routes":       "graphql:Query.invoice@services/graphql/schema.graphql",
		"auth_routes":        "graphql:Mutation.login@services/graphql/schema.graphql",
		"admin_routes":       "route:GET:/admin/stats@services/api/src/app.js",
		"queue_consumers":    "consumer:bullmq:emails@services/worker/index.js:3",
		"cron_jobs":          "cron:0 * * * *@services/worker/index.js:4",
		"grpc_methods":       "grpc:/billing.v1.Billing/GetInvoice@services/billing/proto/billing.proto",
		"graphql_operations": "graphql:Query.me@services/graphql/schema.graphql",
	} {
		if !slices.Contains(inv.Features[feature], id) {
			t.Errorf("%s does not contain %s: %v", feature, id, inv.Features[feature])
		}
	}
}

func TestFrameworkPrefixes(t *testing.T) {
	inv := writeAndWalk(t, map[string]string{
		"src/main.ts": "const app = await NestFactory.create(AppModule);\napp.setGlobalPrefix('api');\n",
		"src/users.controller.ts": "import { Controller, Get, Post } from '@nestjs/common';\n" +
			"@Controller('users')\nexport class UsersController {\n  @Get()\n  list() {}\n  @Get(':id')\n  show() {}\n  @Post()\n  create() {}\n}\n",
		"src/main/java/OrderController.java": "@RestController\n@RequestMapping(\"/orders\")\npublic class OrderController {\n" +
			"  @GetMapping\n  public List<Order> all() {}\n  @GetMapping(\"/{id}\")\n  public Order one() {}\n" +
			"  @RequestMapping(value = \"/{id}/cancel\", method = RequestMethod.POST)\n  public void cancel() {}\n}\n",
		"web/views.py":       "from flask import Blueprint\nbp = Blueprint('admin', __name__, url_prefix='/admin')\n@bp.route('/users')\ndef users(): pass\n",
		"cmd/server/main.go": "r := gin.Default()\nv1 := r.Group(\"/v1\")\nv1.GET(\"/items/:id\", h)\nmux.HandleFunc(\"DELETE /items/{id}\", h)\n",
	})
	got := entrypoints(inv)
	for _, want := range []string{
		"route:GET:/api/users@src/users.controller.ts",
		"route:GET:/api/users/:id@src/users.controller.ts",
		"route:POST:/api/users@src/users.controller.ts",
		"route:GET:/orders@src/main/java/OrderController.java",
		"route:GET:/orders/{id}@src/main/java/OrderController.java",
		"route:POST:/orders/{id}/cancel@src/main/java/OrderController.java",
		"route:ANY:/admin/users@web/views.py",
		"route:GET:/v1/items/:id@cmd/server/main.go",
		"route:DELETE:/items/{id}@cmd/server/main.go",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %q", want, got)
		}
	}
	if len(got) != 9 {
		t.Errorf("unexpected entrypoints: %q", got)
	}
	if inv.Features["services"] != nil {
		t.Error("a repository without several manifests is not a monorepo")
	}
}

func TestEntrypointLookalikesAreIgnored(t *testing.T) {
	inv := writeAndWalk(t, map[string]string{
		"src/types.ts":   "type Query = { users: User[] };\n",
		"src/browser.js": "const w = new Worker('worker.js');\n",
		"src/client.js":  "axios.get('/api/users');\nfetch('/api/users');\n",
	})
	if got := entrypoints(inv); len(got) != 0 {
		t.Fatalf("no entrypoints expected, got %q", got)
	}
}

func writeAndWalk(t *testing.T, files map[string]string) *inventory.Inventory {
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
	inv, err := inventory.Walk(root, inventory.Options{MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func TestNextServerActions(t *testing.T) {
	inv := writeAndWalk(t, map[string]string{
		"package.json": `{"dependencies":{"next":"15"}}`,
		"app/actions.ts": "// account actions\n'use server';\n\nexport async function renameUser(id: string) {}\n" +
			"export const removeUser = async (id: string) => {};\nfunction helper() {}\n",
		"app/page.tsx":  "export default function Page() {\n  async function save(data: FormData) {\n    \"use server\";\n    await db.save(data);\n  }\n  return null;\n}\n",
		"app/client.ts": "const note = 'use server';\nexport function plain() {}\n",
	})
	got := entrypoints(inv)
	want := []string{
		"server_action:removeUser@app/actions.ts:5",
		"server_action:renameUser@app/actions.ts:4",
		"server_action:save@app/page.tsx:3",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("entrypoints = %q, want %q", got, want)
	}
	if n := len(inv.Features["server_actions"]); n != 3 {
		t.Errorf("server_actions feature has %d entries", n)
	}
	if n := len(inv.Features["routes"]); n != 0 {
		t.Errorf("server actions must not count as HTTP routes, got %d", n)
	}
}
