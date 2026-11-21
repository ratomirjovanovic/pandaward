package adapters

import (
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
)

func jsFile(src string) (*inventory.File, string) {
	return &inventory.File{Path: "src/a.ts", Lang: "typescript", Lines: strings.Split(src, "\n")}, src
}

func TestDNSRebindCheck(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"lookup, check, fetch", "import { lookup } from \"node:dns/promises\";\nasync function f(url) {\n  const u = new URL(url);\n  const addrs = await lookup(u.hostname, { all: true });\n  if (!addrs.every((a) => isPublicAddress(a.address))) return null;\n  return fetch(u);\n}", 1},
		{"host passed to the request", "import dns from \"dns\";\nasync function f(host) {\n  const a = await dns.promises.lookup(host);\n  if (isPrivate(a.address)) return;\n  return axios.get(host);\n}", 1},
		{"connection-time lookup", "import { lookup } from \"node:dns/promises\";\nconst agent = new Agent({ connect: { lookup: checked } });\nasync function f(url) {\n  const u = new URL(url);\n  const a = await lookup(u.hostname);\n  if (isPrivate(a.address)) return;\n  return fetch(u, { dispatcher: agent });\n}", 0},
		{"no address check", "import { lookup } from \"node:dns/promises\";\nasync function f(url) {\n  const u = new URL(url);\n  const a = await lookup(u.hostname);\n  log(a);\n  return fetch(u);\n}", 0},
		{"request to another url", "import { lookup } from \"node:dns/promises\";\nasync function f(url) {\n  const a = await lookup(url);\n  if (isPrivate(a.address)) return;\n  return fetch(\"https://api.example.com/x\");\n}", 0},
		{"no dns import", "async function f(u) {\n  const a = await lookup(u.hostname);\n  if (isPrivate(a)) return;\n  return fetch(u);\n}", 0},
	}
	for _, tc := range cases {
		f, text := jsFile(tc.src)
		if got := len(dnsRebindSignals(f, text, "builtin-code")); got != tc.want {
			t.Errorf("%s: %d signals, want %d", tc.name, got, tc.want)
		}
	}
}

func TestExcessiveExposure(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"findMany without select", "const events = await db.usageEvent.findMany({ where: { userId: user.id } });\nreturn NextResponse.json({ events });", 1},
		{"multi-line call", "const user = await prisma.user.findUnique({\n  where: { id },\n});\nres.json(user);", 1},
		{"with select", "const events = await db.usageEvent.findMany({ where: { userId: user.id }, select: { id: true } });\nreturn NextResponse.json({ events });", 0},
		{"with omit", "const u = await prisma.user.findFirst({\n  where: { id },\n  omit: { passwordHash: true },\n});\nres.json(u);", 0},
		{"mapped before the response", "const events = await db.usageEvent.findMany({ where: {} });\nreturn NextResponse.json({ events: events.map(toDto) });", 0},
		{"not returned", "const events = await db.usageEvent.findMany({ where: {} });\nreturn NextResponse.json({ count: total });", 0},
		{"destructured", "const { a } = await db.x.findFirst({ where: {} });\nres.json(a);", 0},
	}
	for _, tc := range cases {
		f, _ := jsFile(tc.src)
		if got := len(excessiveExposureSignals(f, "builtin-code")); got != tc.want {
			t.Errorf("%s: %d signals, want %d", tc.name, got, tc.want)
		}
	}
}
