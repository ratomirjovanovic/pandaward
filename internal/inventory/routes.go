package inventory

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/ratomirjovanovic/pensec/internal/model"
)

// Entrypoint extraction. Everything here is heuristic and line based: it
// recognizes common framework conventions, resolves router prefixes that are
// declared in the same file or mounted from another file through a relative
// import, and never executes or type-checks code.

// entry is one discovered entrypoint before it becomes an asset.
type entry struct {
	kind       string // route, graphql_operation, grpc_method, queue_consumer, cron_job
	method     string
	path       string
	file       string
	line       int
	framework  string
	confidence string
	recv       string // router variable the route is registered on
	hasArgs    bool   // GraphQL field takes arguments
}

// mount attaches routes to a prefix. A self mount is a router's own prefix
// (APIRouter(prefix=...), Blueprint(url_prefix=...)). A local mount attaches
// router variable recv to router variable on in the same file. A file mount
// attaches every route of target to router variable on in file.
type mount struct {
	file   string
	on     string // router variable that does the mounting ("" = top level)
	prefix string
	recv   string // mounted router variable in the same file
	target string // mounted file
	self   bool
}

var (
	jsRouteRe    = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\.(get|post|put|patch|delete|all|options)\(\s*['"\x60]([^'"\x60]+)['"\x60]`)
	jsRouterVar  = regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:new\s+)?(?:require\(\s*['"]express['"]\s*\)\.Router|express\.Router|Router|express|Fastify|fastify|Hono|Koa|KoaRouter)\s*\(`)
	jsUseRe      = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\.use\(\s*['"\x60](/[^'"\x60]*)['"\x60]\s*,(.+)\)\s*;?\s*$`)
	jsRegisterRe = regexp.MustCompile(`\.register\(\s*(require\(\s*['"][^'"]+['"]\s*\)|[A-Za-z_$][\w$]*)\s*,\s*\{[^}]*prefix\s*:\s*['"\x60](/[^'"\x60]*)['"\x60]`)
	jsRequireRe  = regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)`)
	jsImportRe   = regexp.MustCompile(`^\s*import\s+([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^}]*\})?\s+from\s+['"]([^'"]+)['"]`)
	jsNamedRe    = regexp.MustCompile(`^\s*import\s*\{([^}]*)\}\s*from\s+['"]([^'"]+)['"]`)
	requireArgRe = regexp.MustCompile(`^require\(\s*['"]([^'"]+)['"]\s*\)$`)

	nestControllerRe = regexp.MustCompile(`@Controller\(\s*(?:['"\x60]([^'"\x60]*)['"\x60]|\{[^}]*path\s*:\s*['"\x60]([^'"\x60]*)['"\x60][^}]*\})?\s*\)`)
	nestMethodRe     = regexp.MustCompile(`@(Get|Post|Put|Patch|Delete|All|Options|Head)\(\s*(?:['"\x60]([^'"\x60]*)['"\x60])?\s*\)`)
	nestGlobalRe     = regexp.MustCompile(`\.setGlobalPrefix\(\s*['"\x60]([^'"\x60]*)['"\x60]`)

	pyRouteRe     = regexp.MustCompile(`^\s*@([A-Za-z_]\w*)\.(get|post|put|patch|delete|route|api_route)\(\s*['"]([^'"]*)['"]`)
	pyRouterVar   = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*=\s*(?:fastapi\.|flask\.)?(APIRouter|FastAPI|Flask|Blueprint)\(`)
	pyPrefixArg   = regexp.MustCompile(`\b(?:url_)?prefix\s*=\s*['"](/[^'"]*)['"]`)
	pyIncludeRe   = regexp.MustCompile(`\b(?:include_router|register_blueprint)\(\s*([A-Za-z_][\w.]*)`)
	pyFromImport  = regexp.MustCompile(`^\s*from\s+(\.*[\w.]*)\s+import\s+\(?([^)#]+)`)
	pyPlainImport = regexp.MustCompile(`^\s*import\s+([\w.]+)(?:\s+as\s+(\w+))?\s*$`)

	springClassMapRe  = regexp.MustCompile(`^\s*@RequestMapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*"([^"]*)"`)
	springMethodMapRe = regexp.MustCompile(`@(Get|Post|Put|Patch|Delete|Request)Mapping\b(?:\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*"([^"]*)")?`)
	springReqMethodRe = regexp.MustCompile(`RequestMethod\.(GET|POST|PUT|PATCH|DELETE)`)
	classDeclRe       = regexp.MustCompile(`\b(class|interface|object)\s+\w+`)

	goHandleRe     = regexp.MustCompile(`\b(?:http|mux|\w+)\.(?:HandleFunc|Handle)\(\s*"(?:(GET|POST|PUT|PATCH|DELETE)\s+)?(/[^"]*)"`)
	goRouterRe     = regexp.MustCompile(`\b([A-Za-z_]\w*)\.(GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete)\(\s*"(/[^"]*)"`)
	goGroupRe      = regexp.MustCompile(`\b([A-Za-z_]\w*)\s*:?=\s*([A-Za-z_]\w*)\.Group\(\s*"([^"]*)"`)
	laravelRe      = regexp.MustCompile(`Route::(get|post|put|patch|delete|any|match)\(\s*['"]([^'"]+)['"]`)
	djangoRe       = regexp.MustCompile(`\b(?:re_)?path\(\s*r?['"]([^'"]*)['"]\s*,`)
	rubyRouteRe    = regexp.MustCompile(`^\s*(get|post|put|patch|delete)\s+['"](/[^'"]*)['"]`)
	aspnetRe       = regexp.MustCompile(`\[(?:Http)?(Get|Post|Put|Patch|Delete)\(\s*"([^"]*)"\s*\)\]`)
	graphqlTypeRe  = regexp.MustCompile(`^\s*(?:extend\s+)?type\s+(Query|Mutation|Subscription)\b[^{=]*\{`)
	graphqlFieldRe = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*([(:])`)
	graphqlIDArgRe = regexp.MustCompile(`\(\s*[^)]*\b(id|\w+Id|\w+_id)\s*:`)
	nestGqlRe      = regexp.MustCompile(`@(Query|Mutation|Subscription)\(`)
	methodNameRe   = regexp.MustCompile(`^\s*(?:public\s+|private\s+|protected\s+)?(?:async\s+)?([A-Za-z_]\w*)\s*\(`)
	protoPackageRe = regexp.MustCompile(`^\s*package\s+([\w.]+)\s*;`)
	protoServiceRe = regexp.MustCompile(`^\s*service\s+(\w+)\s*\{`)
	protoRPCRe     = regexp.MustCompile(`^\s*rpc\s+(\w+)\s*\(`)
	workerRes      = []struct {
		re        *regexp.Regexp
		framework string
		needs     string // the file must contain this text, to avoid unrelated matches
	}{
		{regexp.MustCompile(`new\s+Worker\(\s*['"\x60]([^'"\x60]+)['"\x60]`), "bullmq", "bullmq"},
		{regexp.MustCompile(`@Processor\(\s*['"\x60]?([^'"\x60)]*)`), "nestjs-bull", "@Processor("},
		{regexp.MustCompile(`@(?:EventPattern|MessagePattern)\(\s*['"\x60]?([^'"\x60)]*)`), "nestjs-microservices", "Pattern("},
		{regexp.MustCompile(`^\s*@(?:[\w.]+\.)?(?:task|shared_task)\b`), "celery", "celery"},
		{regexp.MustCompile(`include\s+Sidekiq::(?:Worker|Job)`), "sidekiq", "Sidekiq"},
		{regexp.MustCompile(`@(?:KafkaListener|RabbitListener|SqsListener|JmsListener)\(\s*(?:\w+\s*=\s*)?\{?\s*"?([^"),}]*)`), "spring-messaging", "Listener("},
		{regexp.MustCompile(`channel\.consume\(\s*['"\x60]([^'"\x60]+)['"\x60]`), "amqplib", "amqplib"},
		{regexp.MustCompile(`\.subscribe\(\s*\{\s*topics?\s*:\s*\[?\s*['"\x60]([^'"\x60]+)['"\x60]`), "kafkajs", "kafkajs"},
	}
	cronRes = []struct {
		re        *regexp.Regexp
		framework string
		needs     string
	}{
		{regexp.MustCompile(`cron\.schedule\(\s*['"\x60]([^'"\x60]+)['"\x60]`), "node-cron", "cron"},
		{regexp.MustCompile(`new\s+CronJob\(\s*['"\x60]([^'"\x60]+)['"\x60]`), "cron", "CronJob"},
		{regexp.MustCompile(`@Cron\(\s*['"\x60]?([^'"\x60)]*)`), "nestjs-schedule", "@Cron("},
		{regexp.MustCompile(`@Scheduled\(\s*(?:cron\s*=\s*"([^"]+)"|(fixed\w+\s*=\s*[^,)]+))`), "spring", "@Scheduled("},
		{regexp.MustCompile(`\bschedule\.every\(([^)]*)\)`), "schedule", "schedule"},
		{regexp.MustCompile(`\bcrontab\(([^)]*)\)`), "celery-beat", "crontab("},
		{regexp.MustCompile(`\.AddFunc\(\s*"([^"]+)"`), "robfig-cron", "cron"},
	}
)

var jsLangs = map[string]bool{"javascript": true, "typescript": true}

// extractEntries finds entrypoints and router mounts declared in one file.
// resolve maps an import specifier of the file to a scanned file path.
func extractEntries(f *File, resolve func(from, spec string) string) ([]entry, []mount) {
	switch f.Lang {
	case "graphql":
		return graphqlEntries(f), nil
	case "proto":
		return protoEntries(f), nil
	}
	if !CodeLangs[f.Lang] {
		return nil, nil
	}
	var out []entry
	var mounts []mount
	add := func(e entry) {
		e.file = f.Path
		if e.kind == "" {
			e.kind = "route"
		}
		if e.confidence == "" {
			e.confidence = "heuristic"
		}
		out = append(out, e)
	}
	joined := strings.Join(f.Lines, "\n")
	switch {
	case jsLangs[f.Lang]:
		jsRoutes(f, joined, add, &mounts, resolve)
	case f.Lang == "python":
		pyRoutes(f, add, &mounts, resolve)
	case f.Lang == "java" || f.Lang == "kotlin":
		springRoutes(f, add)
	case f.Lang == "go":
		goRoutes(f, add)
	}
	for i, l := range f.Lines {
		if m := laravelRe.FindStringSubmatch(l); m != nil && f.Lang == "php" && strings.HasPrefix(m[2], "/") {
			add(entry{method: httpMethod(m[1]), path: m[2], line: i + 1, framework: "laravel"})
		}
		if m := djangoRe.FindStringSubmatch(l); m != nil && f.Lang == "python" && strings.Contains(f.Path, "urls") {
			add(entry{method: "ANY", path: m[1], line: i + 1, framework: "django"})
		}
		if m := rubyRouteRe.FindStringSubmatch(l); m != nil && f.Lang == "ruby" {
			add(entry{method: httpMethod(m[1]), path: m[2], line: i + 1, framework: "rails/sinatra"})
		}
		if m := aspnetRe.FindStringSubmatch(l); m != nil && f.Lang == "csharp" && strings.HasPrefix(m[2], "/") {
			add(entry{method: httpMethod(m[1]), path: m[2], line: i + 1, framework: "aspnet"})
		}
	}
	if m := nextRouteRe.FindStringSubmatch(f.Path); m != nil || nextPagesAPI.MatchString(f.Path) {
		var p string
		if m != nil {
			p = "/" + m[1]
		} else {
			p = "/api/" + nextPagesAPI.FindStringSubmatch(f.Path)[1]
		}
		p = nextGroupRe.ReplaceAllString(p, "")
		var methods []string
		for _, l := range f.Lines {
			if mm := nextMethodRe.FindStringSubmatch(l); mm != nil {
				methods = append(methods, mm[1])
			}
		}
		if len(methods) == 0 {
			methods = []string{"ANY"}
		}
		for _, method := range methods {
			add(entry{method: method, path: p, line: 1, framework: "nextjs", confidence: "file-convention"})
		}
	}
	if strings.Contains(joined, "type Query") || strings.Contains(joined, "type Mutation") || strings.Contains(joined, "type Subscription") {
		for _, e := range graphqlEntries(f) {
			add(e)
		}
	}
	if strings.Contains(joined, "@nestjs/graphql") {
		for i, l := range f.Lines {
			m := nestGqlRe.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			for j := i + 1; j < len(f.Lines) && j < i+6; j++ {
				t := strings.TrimSpace(f.Lines[j])
				if strings.HasPrefix(t, "@") || t == "" {
					continue
				}
				if mm := methodNameRe.FindStringSubmatch(f.Lines[j]); mm != nil {
					add(entry{kind: "graphql_operation", method: strings.ToUpper(m[1]), path: m[1] + "." + mm[1], line: i + 1, framework: "nestjs-graphql",
						hasArgs: strings.Contains(f.Lines[j], "@Args")})
				}
				break
			}
		}
	}
	for _, w := range workerRes {
		if !strings.Contains(joined, w.needs) {
			continue
		}
		for i, l := range f.Lines {
			if m := w.re.FindStringSubmatch(l); m != nil {
				add(entry{kind: "queue_consumer", method: "CONSUME", path: firstNonEmpty(m[1:]...), line: i + 1, framework: w.framework})
			}
		}
	}
	for _, c := range cronRes {
		if !strings.Contains(joined, c.needs) {
			continue
		}
		for i, l := range f.Lines {
			if m := c.re.FindStringSubmatch(l); m != nil {
				add(entry{kind: "cron_job", method: "SCHEDULE", path: firstNonEmpty(m[1:]...), line: i + 1, framework: c.framework})
			}
		}
	}
	return out, mounts
}

var nextGroupRe = regexp.MustCompile(`/\([^)]*\)`)

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return "(unnamed)"
}

func httpMethod(m string) string {
	m = strings.ToUpper(m)
	switch m {
	case "ROUTE", "ALL", "ANY", "MATCH", "REQUEST", "API_ROUTE":
		return "ANY"
	}
	return m
}

func jsRoutes(f *File, joined string, add func(entry), mounts *[]mount, resolve func(from, spec string) string) {
	routers := map[string]bool{"app": true, "router": true, "server": true, "api": true, "routes": true}
	imports := map[string]string{} // identifier -> module specifier
	for _, l := range f.Lines {
		if m := jsRouterVar.FindStringSubmatch(l); m != nil {
			routers[m[1]] = true
		}
		if m := jsRequireRe.FindStringSubmatch(l); m != nil {
			imports[m[1]] = m[2]
		}
		if m := jsImportRe.FindStringSubmatch(l); m != nil {
			imports[m[1]] = m[2]
		}
		if m := jsNamedRe.FindStringSubmatch(l); m != nil {
			for _, n := range strings.Split(m[1], ",") {
				parts := strings.Fields(n)
				if len(parts) > 0 {
					imports[parts[len(parts)-1]] = m[2]
				}
			}
		}
	}
	target := func(arg string) (recv, file string) {
		arg = strings.TrimSpace(arg)
		if m := requireArgRe.FindStringSubmatch(arg); m != nil {
			return "", resolve(f.Path, m[1])
		}
		if routers[arg] {
			return arg, ""
		}
		if spec, ok := imports[arg]; ok {
			return "", resolve(f.Path, spec)
		}
		return "", ""
	}
	isNest := strings.Contains(joined, "@Controller(")
	nestPrefix := ""
	for i, l := range f.Lines {
		if m := jsUseRe.FindStringSubmatch(l); m != nil && routers[m[1]] {
			args := strings.Split(m[3], ",")
			recv, file := target(args[len(args)-1])
			if recv != "" || file != "" {
				*mounts = append(*mounts, mount{file: f.Path, on: m[1], prefix: m[2], recv: recv, target: file})
			}
			continue
		}
		if m := jsRegisterRe.FindStringSubmatch(l); m != nil {
			if recv, file := target(m[1]); recv != "" || file != "" {
				*mounts = append(*mounts, mount{file: f.Path, prefix: m[2], recv: recv, target: file})
			}
			continue
		}
		if m := jsRouteRe.FindStringSubmatch(l); m != nil && routers[m[1]] && strings.HasPrefix(m[3], "/") {
			add(entry{method: httpMethod(m[2]), path: m[3], line: i + 1, framework: "express", recv: m[1]})
			continue
		}
		if !isNest {
			continue
		}
		if m := nestControllerRe.FindStringSubmatch(l); m != nil {
			nestPrefix = firstNonEmpty(m[1], m[2])
			if nestPrefix == "(unnamed)" {
				nestPrefix = ""
			}
			continue
		}
		if m := nestMethodRe.FindStringSubmatch(l); m != nil {
			add(entry{method: httpMethod(m[1]), path: joinRoute(nestPrefix, m[2]), line: i + 1, framework: "nestjs", recv: "nest"})
		}
	}
}

func pyRoutes(f *File, add func(entry), mounts *[]mount, resolve func(from, spec string) string) {
	routers := map[string]bool{"app": true, "router": true, "api": true, "bp": true, "blueprint": true}
	imports := map[string]string{} // name -> module (absolute or relative dotted path)
	for _, l := range f.Lines {
		if m := pyRouterVar.FindStringSubmatch(l); m != nil {
			routers[m[1]] = true
			if p := pyPrefixArg.FindStringSubmatch(l); p != nil {
				*mounts = append(*mounts, mount{file: f.Path, prefix: p[1], recv: m[1], self: true})
			}
		}
		if m := pyFromImport.FindStringSubmatch(l); m != nil {
			for _, n := range strings.Split(m[2], ",") {
				parts := strings.Fields(n)
				if len(parts) == 0 {
					continue
				}
				name, local := parts[0], parts[len(parts)-1]
				// `from pkg import mod` may import a module or an attribute;
				// keep both so the resolver can try the module file first.
				imports[local] = m[1] + "." + name + "|" + m[1]
			}
		}
		if m := pyPlainImport.FindStringSubmatch(l); m != nil {
			local := m[2]
			if local == "" {
				local = m[1]
			}
			imports[local] = m[1]
		}
	}
	for i, l := range f.Lines {
		if m := pyIncludeRe.FindStringSubmatch(l); m != nil {
			prefix := ""
			if p := pyPrefixArg.FindStringSubmatch(l); p != nil {
				prefix = p[1]
			}
			ident := m[1]
			head := strings.SplitN(ident, ".", 2)[0]
			if routers[ident] && !strings.Contains(ident, ".") {
				*mounts = append(*mounts, mount{file: f.Path, prefix: prefix, recv: ident})
				continue
			}
			if spec, ok := imports[head]; ok {
				for _, s := range strings.Split(spec, "|") {
					if t := resolve(f.Path, s); t != "" {
						*mounts = append(*mounts, mount{file: f.Path, prefix: prefix, target: t})
						break
					}
				}
			}
			continue
		}
		m := pyRouteRe.FindStringSubmatch(l)
		if m == nil || !routers[m[1]] {
			continue
		}
		p := m[3]
		if p != "" && !strings.HasPrefix(p, "/") {
			continue
		}
		add(entry{method: httpMethod(m[2]), path: p, line: i + 1, framework: "flask/fastapi", recv: m[1]})
	}
}

func springRoutes(f *File, add func(entry)) {
	prefix := ""
	for i, l := range f.Lines {
		if m := springClassMapRe.FindStringSubmatch(l); m != nil && declaresClassNext(f.Lines, i) {
			prefix = m[1]
			continue
		}
		m := springMethodMapRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		method := httpMethod(m[1])
		if mm := springReqMethodRe.FindStringSubmatch(l); mm != nil {
			method = mm[1]
		}
		p := joinRoute(prefix, m[2])
		add(entry{method: method, path: p, line: i + 1, framework: "spring"})
	}
}

// declaresClassNext reports whether the annotation at line i is attached to
// a class: the next line that is not an annotation declares one.
func declaresClassNext(lines []string, i int) bool {
	for j := i + 1; j < len(lines) && j < i+8; j++ {
		t := strings.TrimSpace(lines[j])
		if t == "" || strings.HasPrefix(t, "@") {
			continue
		}
		return classDeclRe.MatchString(t)
	}
	return false
}

func goRoutes(f *File, add func(entry)) {
	groups := map[string]string{} // group variable -> prefix
	for _, l := range f.Lines {
		if m := goGroupRe.FindStringSubmatch(l); m != nil {
			groups[m[1]] = joinRoute(groups[m[2]], m[3])
		}
	}
	for i, l := range f.Lines {
		if m := goHandleRe.FindStringSubmatch(l); m != nil {
			method := "ANY"
			if m[1] != "" {
				method = m[1]
			}
			add(entry{method: method, path: m[2], line: i + 1, framework: "go-net/http"})
			continue
		}
		if m := goRouterRe.FindStringSubmatch(l); m != nil && m[1] != "http" {
			add(entry{method: httpMethod(m[2]), path: joinRoute(groups[m[1]], m[3]), line: i + 1, framework: "go-router"})
		}
	}
}

func graphqlEntries(f *File) []entry {
	var out []entry
	op := ""
	for i, l := range f.Lines {
		if op == "" {
			if m := graphqlTypeRe.FindStringSubmatch(l); m != nil {
				op = m[1]
			}
			continue
		}
		if strings.Contains(l, "}") && !strings.Contains(l, "{") && strings.TrimSpace(strings.SplitN(l, "}", 2)[0]) == "" {
			op = ""
			continue
		}
		if m := graphqlFieldRe.FindStringSubmatch(l); m != nil {
			out = append(out, entry{kind: "graphql_operation", method: strings.ToUpper(op), path: op + "." + m[1], file: f.Path, line: i + 1,
				framework: "graphql-schema", confidence: "schema", hasArgs: m[2] == "(" && graphqlIDArgRe.MatchString(l)})
		}
	}
	return out
}

func protoEntries(f *File) []entry {
	var out []entry
	pkg, svc := "", ""
	for i, l := range f.Lines {
		if m := protoPackageRe.FindStringSubmatch(l); m != nil {
			pkg = m[1] + "."
		}
		if m := protoServiceRe.FindStringSubmatch(l); m != nil {
			svc = m[1]
			continue
		}
		if svc == "" {
			continue
		}
		if m := protoRPCRe.FindStringSubmatch(l); m != nil {
			out = append(out, entry{kind: "grpc_method", method: "RPC", path: "/" + pkg + svc + "/" + m[1], file: f.Path, line: i + 1, framework: "grpc", confidence: "schema"})
		}
		if strings.TrimSpace(l) == "}" {
			svc = ""
		}
	}
	return out
}

// joinRoute joins a prefix and a sub path into one path with a single
// leading slash and no trailing slash (except the root).
func joinRoute(prefix, sub string) string {
	p := "/" + strings.Trim(prefix, "/")
	if s := strings.Trim(sub, "/"); s != "" {
		p = strings.TrimSuffix(p, "/") + "/" + s
	}
	return p
}

// resolveModule maps an import specifier in file from to a scanned file:
// relative JavaScript/TypeScript specifiers and Python modules (relative or
// absolute from any ancestor directory of the importing file).
func (inv *Inventory) resolveModule(from, spec string) string {
	dir := path.Dir(from)
	exists := func(p string) string {
		p = path.Clean(p)
		if inv.FileByPath(p) != nil {
			return p
		}
		return ""
	}
	if strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") {
		base := path.Join(dir, spec)
		cands := []string{base}
		if strings.HasSuffix(base, ".js") {
			cands = append(cands, strings.TrimSuffix(base, ".js")+".ts")
		}
		for _, ext := range []string{".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", "/index.js", "/index.ts"} {
			cands = append(cands, base+ext)
		}
		for _, c := range cands {
			if p := exists(c); p != "" {
				return p
			}
		}
		return ""
	}
	if !strings.HasSuffix(from, ".py") || strings.ContainsAny(spec, "/@") {
		return ""
	}
	dots := len(spec) - len(strings.TrimLeft(spec, "."))
	rest := strings.ReplaceAll(strings.Trim(spec[dots:], "."), ".", "/")
	var bases []string
	if dots > 0 {
		b := dir
		for k := 1; k < dots; k++ {
			b = path.Dir(b)
		}
		bases = []string{b}
	} else {
		for b := dir; ; b = path.Dir(b) {
			bases = append(bases, b)
			if b == "." || b == "/" {
				break
			}
		}
	}
	for _, b := range bases {
		for _, c := range []string{path.Join(b, rest) + ".py", path.Join(b, rest, "__init__.py")} {
			if rest == "" && !strings.HasSuffix(c, "__init__.py") {
				continue
			}
			if p := exists(c); p != "" {
				return p
			}
		}
	}
	return ""
}

// applyMounts prefixes routes with the mounts that lead to them. A route can
// be reachable under several prefixes; chains across files are followed and
// cycles are cut.
func applyMounts(entries []entry, mounts []mount) []entry {
	self := map[string]string{}      // file|recv -> the router's own prefix
	local := map[string][]mount{}    // file|recv -> mounts of that router in its file
	byTarget := map[string][]mount{} // file -> mounts of the whole file elsewhere
	for _, m := range mounts {
		switch {
		case m.self:
			self[m.file+"|"+m.recv] = m.prefix
		case m.target != "":
			byTarget[m.target] = append(byTarget[m.target], m)
		case m.recv != "":
			local[m.file+"|"+m.recv] = append(local[m.file+"|"+m.recv], m)
		}
	}
	var prefixesOf func(file, recv string, seen map[string]bool) []string
	// outer lists the prefixes under which a whole file is mounted.
	outer := func(file string, seen map[string]bool) []string {
		var out []string
		for _, m := range byTarget[file] {
			for _, p := range prefixesOf(m.file, m.on, seen) {
				out = append(out, joinRoute(p, m.prefix))
			}
		}
		if len(out) == 0 {
			return []string{""}
		}
		return out
	}
	// prefixesOf lists the full prefixes of router recv in file.
	prefixesOf = func(file, recv string, seen map[string]bool) []string {
		key := file + "|" + recv
		if seen[key] {
			return nil
		}
		seen[key] = true
		defer delete(seen, key)
		var out []string
		for _, m := range local[key] {
			for _, p := range prefixesOf(file, m.on, seen) {
				out = append(out, joinRoute(p, m.prefix))
			}
		}
		if len(out) == 0 {
			out = outer(file, seen)
		}
		if own := self[key]; own != "" {
			for i := range out {
				out[i] = joinRoute(out[i], own)
			}
		}
		return out
	}
	var out []entry
	for _, e := range entries {
		if e.kind != "route" {
			out = append(out, e)
			continue
		}
		seen := map[string]bool{}
		for _, p := range prefixesOf(e.file, e.recv, map[string]bool{}) {
			x := e
			switch {
			case p != "":
				x.path = joinRoute(p, e.path)
			case x.path == "":
				x.path = "/"
			}
			if !seen[x.path] {
				seen[x.path] = true
				out = append(out, x)
			}
		}
	}
	return out
}

// addEntrypoints turns entries into assets and features. Every asset keeps
// its file and line; Meta records the service it belongs to. In a monorepo
// (more than one service root) each service is also an asset.
func (inv *Inventory) addEntrypoints(entries []entry, roots []string, nestGlobal map[string]string) {
	seen := map[string]bool{}
	for _, e := range entries {
		svc := serviceOf(roots, e.file)
		if e.framework == "nestjs" && nestGlobal[svc] != "" {
			e.path = joinRoute(nestGlobal[svc], e.path)
		}
		var id string
		domains := []string{"A", "B", "C", "D", "G"}
		switch e.kind {
		case "route":
			id = "route:" + e.method + ":" + e.path + "@" + e.file
		case "graphql_operation":
			id = "graphql:" + e.path + "@" + e.file
		case "grpc_method":
			id = "grpc:" + e.path + "@" + e.file
		case "queue_consumer":
			id = fmt.Sprintf("consumer:%s:%s@%s:%d", e.framework, e.path, e.file, e.line)
			domains = []string{"A", "D"}
		case "cron_job":
			id = fmt.Sprintf("cron:%s@%s:%d", e.path, e.file, e.line)
			domains = []string{"A", "D"}
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		hash := ""
		if f := inv.FileByPath(e.file); f != nil {
			hash = f.SHA256
		}
		inv.addAsset(model.Asset{ID: id, Kind: e.kind, Locator: e.file, Line: e.line, ContentHash: hash, Domains: domains,
			Meta: map[string]string{"method": e.method, "path": e.path, "framework": e.framework, "confidence": e.confidence, "service": svc}})
		switch e.kind {
		case "route", "graphql_operation", "grpc_method":
			inv.feature("web", e.file)
			switch e.kind {
			case "route":
				inv.feature("routes", id)
			case "graphql_operation":
				inv.feature("graphql_operations", id)
			case "grpc_method":
				inv.feature("grpc_methods", id)
			}
			if paramRe.MatchString(e.path) || e.hasArgs {
				inv.feature("param_routes", id)
			}
			if authPathRe.MatchString(e.path) {
				inv.feature("auth_routes", id)
				inv.feature("auth", id)
			}
			if adminPathRe.MatchString(e.path) {
				inv.feature("admin_routes", id)
			}
			if e.kind == "route" && webhookPathRe.MatchString(e.path) {
				inv.feature("webhooks", id)
			}
		case "queue_consumer":
			inv.feature("queue_consumers", id)
		case "cron_job":
			inv.feature("cron_jobs", id)
		}
	}
	if len(roots) > 1 {
		for _, r := range roots {
			inv.addAsset(model.Asset{ID: "service:" + r, Kind: "service", Locator: r, Domains: []string{"A"}})
			inv.feature("services", r)
		}
	}
}

// serviceRoots returns the directories that hold a package manifest.
func serviceRoots(files []*File) []string {
	set := map[string]bool{}
	for _, f := range files {
		switch strings.ToLower(path.Base(f.Path)) {
		case "package.json", "go.mod", "pyproject.toml", "requirements.txt", "pom.xml", "build.gradle", "build.gradle.kts", "cargo.toml", "composer.json", "gemfile", "pipfile":
			set[path.Dir(f.Path)] = true
		}
	}
	var out []string
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// serviceOf returns the deepest service root that contains p, or ".".
func serviceOf(roots []string, p string) string {
	best := "."
	for _, r := range roots {
		if r == "." {
			continue
		}
		if r != "." && strings.HasPrefix(p, r+"/") && (best == "." || len(r) > len(best)) {
			best = r
		}
	}
	return best
}
