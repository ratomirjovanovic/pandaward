package adapters

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// ---- Postgres/Supabase row-level security: C-004 ----
//
// An UPDATE (or ALL) policy whose USING clause matches the caller's own row
// by auth.uid() lets a user update every column of that row. When the table
// has a column such as is_admin or credits, the user can raise their own
// privileges unless something else limits the update. The check reads the
// SQL migrations in file-name order and stays silent whenever the statements
// are ambiguous or anything in the repository's SQL could limit the update.

// privilegedColumns are column names (exact, case-insensitive) whose value a
// user must not set on their own row.
var privilegedColumns = map[string]bool{
	"is_admin": true, "admin": true, "is_superadmin": true, "superadmin": true, "is_super_admin": true,
	"role": true, "is_staff": true, "plan": true, "tier": true, "credits": true, "balance": true,
}

const (
	sqlIdent = `(?:"[^"]+"|[a-z_][a-z0-9_$]*)`
	sqlQName = sqlIdent + `(?:\s*\.\s*` + sqlIdent + `)?`
)

var (
	createTableRe  = regexp.MustCompile(`^create\s+(?:(?:global|local)\s+)?(?:(?:temp|temporary|unlogged)\s+)?table\s+(?:if\s+not\s+exists\s+)?(` + sqlQName + `)\s*\(`)
	alterTableRe   = regexp.MustCompile(`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(` + sqlQName + `)\s+(.+)$`)
	dropTableRe    = regexp.MustCompile(`^drop\s+table\s+(?:if\s+exists\s+)?(.+?)(?:\s+(?:cascade|restrict))?$`)
	createPolicyRe = regexp.MustCompile(`^create\s+policy\s+(` + sqlIdent + `)\s+on\s+(?:table\s+)?(` + sqlQName + `)(.*)$`)
	alterPolicyRe  = regexp.MustCompile(`^alter\s+policy\s+(?:if\s+exists\s+)?(` + sqlIdent + `)\s+on\s+(?:table\s+)?(` + sqlQName + `)\s*(.*)$`)
	dropPolicyRe   = regexp.MustCompile(`^drop\s+policy\s+(?:if\s+exists\s+)?(` + sqlIdent + `)\s+on\s+(?:table\s+)?(` + sqlQName + `)`)

	addColumnRe    = regexp.MustCompile(`^add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?(` + sqlIdent + `)(.*)$`)
	dropColumnRe   = regexp.MustCompile(`^drop\s+(?:column\s+)?(?:if\s+exists\s+)?(` + sqlIdent + `)`)
	renameTableRe  = regexp.MustCompile(`^rename\s+to\s+(` + sqlIdent + `)$`)
	renameColumnRe = regexp.MustCompile(`^rename\s+(?:column\s+)?(` + sqlIdent + `)\s+to\s+(` + sqlIdent + `)$`)
	setSchemaRe    = regexp.MustCompile(`^set\s+schema\s+(` + sqlIdent + `)$`)

	policyCmdRe   = regexp.MustCompile(`^(?:\s*as\s+(permissive|restrictive))?\s*for\s+(all|select|insert|update|delete)\b`)
	policyToRe    = regexp.MustCompile(`\bto\s+(.+?)(?:\s+using\b|\s+with\s+check\b|$)`)
	policyUsingRe = regexp.MustCompile(`\busing\s*\(`)
	policyCheckRe = regexp.MustCompile(`\bwith\s+check\s*\(`)
	authUIDRe     = regexp.MustCompile(`\bauth\s*\.\s*uid\s*\(\s*\)`)
	generatedRe   = regexp.MustCompile(`\bgenerated\s+always\s+as\s*\(`)

	// Anything that may limit updates, found anywhere in any SQL file,
	// including function bodies and DO blocks.
	revokeRe        = regexp.MustCompile(`\brevoke\s+([^;]*?)\s+on\s+([^;]*?)\s+from\s`)
	grantRe         = regexp.MustCompile(`\bgrant\s+([^;]*?)\s+on\s+([^;]*?)\s+to\s`)
	beforeTriggerRe = regexp.MustCompile(`\bcreate\s+(?:or\s+replace\s+)?(?:constraint\s+)?trigger\s+` + sqlIdent + `\s+before\s+([^;]*?)\s+on\s+(?:table\s+)?(?:only\s+)?(` + sqlQName + `)`)
	allTablesRe     = regexp.MustCompile(`^all\s+tables\s+in\s+schema\s+(.+)$`)
	updatePrivRe    = regexp.MustCompile(`\b(update|all)\b`)
	updateColsRe    = regexp.MustCompile(`\bupdate\s*\(`)
	wordUpdateRe    = regexp.MustCompile(`\bupdate\b`)
	columnTokenRe   = regexp.MustCompile(`"[^"]+"|[a-z_][a-z0-9_$]*`)
)

// sqlStmt is one statement, lowercased, without comments, whitespace
// collapsed, with the line it starts on.
type sqlStmt struct {
	text string
	line int
}

// splitSQL splits a script into statements. Comments are dropped; quoted
// strings, quoted identifiers and dollar-quoted bodies are kept whole, so a
// semicolon inside them does not end a statement.
func splitSQL(src string) []sqlStmt {
	var out []sqlStmt
	var b strings.Builder
	line, start := 1, 0
	flush := func() {
		if t := strings.Join(strings.Fields(b.String()), " "); t != "" {
			out = append(out, sqlStmt{text: strings.ToLower(t), line: start})
		}
		b.Reset()
		start = 0
	}
	// copyTo writes src[i:j] and counts its newlines.
	copyTo := func(i, j int) {
		s := src[i:j]
		if start == 0 && strings.TrimSpace(s) != "" {
			start = line
		}
		line += strings.Count(s, "\n")
		b.WriteString(s)
	}
	n := len(src)
	for i := 0; i < n; {
		c := src[i]
		switch {
		case c == '-' && i+1 < n && src[i+1] == '-':
			j := strings.IndexByte(src[i:], '\n')
			if j < 0 {
				i = n
				continue
			}
			i += j
		case c == '/' && i+1 < n && src[i+1] == '*':
			depth, j := 1, i+2
			for j < n && depth > 0 {
				switch {
				case src[j] == '/' && j+1 < n && src[j+1] == '*':
					depth++
					j += 2
				case src[j] == '*' && j+1 < n && src[j+1] == '/':
					depth--
					j += 2
				default:
					if src[j] == '\n' {
						line++
					}
					j++
				}
			}
			b.WriteByte(' ')
			i = j
		case c == '\'' || c == '"':
			escapes := c == '\'' && i > 0 && (src[i-1] == 'e' || src[i-1] == 'E')
			j := i + 1
			for j < n {
				if escapes && src[j] == '\\' {
					j += 2
					continue
				}
				if src[j] == c {
					break
				}
				j++
			}
			copyTo(i, min(j+1, n))
			i = j + 1
		case c == '$' && (i == 0 || !isIdentByte(src[i-1])):
			tag := dollarTag(src[i:])
			if tag == "" {
				copyTo(i, i+1)
				i++
				continue
			}
			end := strings.Index(src[i+len(tag):], tag)
			if end < 0 {
				copyTo(i, n)
				i = n
				continue
			}
			j := i + len(tag) + end + len(tag)
			copyTo(i, j)
			i = j
		case c == ';':
			flush()
			i++
		default:
			copyTo(i, i+1)
			i++
		}
	}
	flush()
	return out
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// dollarTag returns the opening $tag$ at the start of s, or "".
func dollarTag(s string) string {
	for j := 1; j < len(s); j++ {
		c := s[j]
		if c == '$' {
			return s[:j+1]
		}
		if !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (j > 1 && c >= '0' && c <= '9')) {
			return ""
		}
	}
	return ""
}

// unquoteIdent strips the double quotes of a quoted identifier.
func unquoteIdent(id string) string {
	return strings.Trim(strings.TrimSpace(id), `"`)
}

// tableKey returns schema.name for a possibly qualified table name; an
// unqualified name is taken to be in public.
func tableKey(q string) string {
	parts := splitTopLevel(q, '.')
	if len(parts) == 2 {
		return unquoteIdent(parts[0]) + "." + unquoteIdent(parts[1])
	}
	return "public." + unquoteIdent(q)
}

// bareName returns the unqualified table name.
func bareName(key string) string {
	return key[strings.LastIndex(key, ".")+1:]
}

// splitTopLevel splits s on sep outside parentheses and double quotes.
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth, quoted, last := 0, false, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			quoted = !quoted
		case quoted:
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == sep && depth == 0:
			out = append(out, strings.TrimSpace(s[last:i]))
			last = i + 1
		}
	}
	return append(out, strings.TrimSpace(s[last:]))
}

// parenBody returns the text inside the parenthesis that opens at s[open],
// and false when it is not closed.
func parenBody(s string, open int) (string, bool) {
	depth, quoted := 0, false
	for i := open; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			quoted = !quoted
		case quoted:
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return s[open+1 : i], true
			}
		}
	}
	return "", false
}

var tableConstraintWords = map[string]bool{"constraint": true, "primary": true, "unique": true, "foreign": true, "check": true, "exclude": true, "like": true}

// rlsPolicy is an UPDATE or ALL policy that matches the caller's row.
type rlsPolicy struct {
	name, table string
	check       string // WITH CHECK expression, or USING when absent
	file        *inventory.File
	line        int
	ambiguous   bool
}

// rlsState is the schema built from one migrations directory.
type rlsState struct {
	columns  map[string][]string // table key -> columns in order
	policies map[string]*rlsPolicy
	order    []string // policy keys in creation order
}

func policyKey(table, name string) string { return table + "|" + name }

func (st *rlsState) apply(s sqlStmt, f *inventory.File) {
	t := s.text
	if m := createTableRe.FindStringSubmatchIndex(t); m != nil {
		key := tableKey(t[m[2]:m[3]])
		body, ok := parenBody(t, m[1]-1)
		if !ok {
			return
		}
		var cols []string
		for _, el := range splitTopLevel(body, ',') {
			fields := strings.Fields(el)
			if len(fields) < 2 || tableConstraintWords[fields[0]] || generatedRe.MatchString(el) {
				continue
			}
			cols = append(cols, unquoteIdent(fields[0]))
		}
		st.columns[key] = cols
		return
	}
	if m := alterTableRe.FindStringSubmatch(t); m != nil {
		key := tableKey(m[1])
		for _, act := range splitTopLevel(m[2], ',') {
			st.alter(key, act)
		}
		return
	}
	if m := dropTableRe.FindStringSubmatch(t); m != nil {
		for _, q := range splitTopLevel(m[1], ',') {
			key := tableKey(q)
			delete(st.columns, key)
			for k, p := range st.policies {
				if p.table == key {
					delete(st.policies, k)
				}
			}
		}
		return
	}
	if m := createPolicyRe.FindStringSubmatch(t); m != nil {
		name, key := unquoteIdent(m[1]), tableKey(m[2])
		if p := parsePolicy(m[3]); p != nil {
			p.name, p.table, p.file, p.line = name, key, f, s.line
			pk := policyKey(key, name)
			st.policies[pk] = p
			st.order = append(st.order, pk)
		} else {
			delete(st.policies, policyKey(key, name))
		}
		return
	}
	if m := alterPolicyRe.FindStringSubmatch(t); m != nil {
		pk := policyKey(tableKey(m[2]), unquoteIdent(m[1]))
		if p := st.policies[pk]; p != nil {
			// A renamed or rewritten policy is not followed further.
			p.ambiguous = true
		}
		return
	}
	if m := dropPolicyRe.FindStringSubmatch(t); m != nil {
		delete(st.policies, policyKey(tableKey(m[2]), unquoteIdent(m[1])))
	}
}

// alter applies one ALTER TABLE action.
func (st *rlsState) alter(key, act string) {
	cols, known := st.columns[key]
	if m := renameTableRe.FindStringSubmatch(act); m != nil {
		nk := key[:strings.LastIndex(key, ".")+1] + unquoteIdent(m[1])
		st.moveTable(key, nk)
		return
	}
	if m := setSchemaRe.FindStringSubmatch(act); m != nil {
		st.moveTable(key, unquoteIdent(m[1])+"."+bareName(key))
		return
	}
	if !known {
		return
	}
	if m := addColumnRe.FindStringSubmatch(act); m != nil {
		col := unquoteIdent(m[1])
		if tableConstraintWords[col] || generatedRe.MatchString(act) {
			return
		}
		st.columns[key] = append(cols, col)
		return
	}
	if m := renameColumnRe.FindStringSubmatch(act); m != nil {
		from, to := unquoteIdent(m[1]), unquoteIdent(m[2])
		for i, c := range cols {
			if c == from {
				cols[i] = to
			}
		}
		return
	}
	if m := dropColumnRe.FindStringSubmatch(act); m != nil {
		col := unquoteIdent(m[1])
		if col == "constraint" {
			return
		}
		out := cols[:0]
		for _, c := range cols {
			if c != col {
				out = append(out, c)
			}
		}
		st.columns[key] = out
	}
}

func (st *rlsState) moveTable(from, to string) {
	if cols, ok := st.columns[from]; ok {
		st.columns[to] = cols
		delete(st.columns, from)
	}
	for _, p := range st.policies {
		if p.table == from {
			p.ambiguous = true
		}
	}
}

// parsePolicy reads the part of CREATE POLICY after the table name and
// returns the policy when it is a permissive UPDATE or ALL policy for
// ordinary users whose USING clause compares with auth.uid(). Anything else
// returns nil.
func parsePolicy(rest string) *rlsPolicy {
	m := policyCmdRe.FindStringSubmatch(rest)
	if m == nil || m[1] == "restrictive" || (m[2] != "update" && m[2] != "all") {
		return nil
	}
	after := rest[len(m[0]):]
	if to := policyToRe.FindStringSubmatch(after); to != nil {
		user := false
		for _, r := range splitTopLevel(to[1], ',') {
			switch unquoteIdent(r) {
			case "authenticated", "public", "anon":
				user = true
			}
		}
		if !user {
			return nil
		}
	}
	u := policyUsingRe.FindStringIndex(after)
	if u == nil {
		return nil
	}
	using, ok := parenBody(after, u[1]-1)
	if !ok || !authUIDRe.MatchString(using) {
		return nil
	}
	// Without WITH CHECK, Postgres checks new rows against USING.
	p := &rlsPolicy{check: using}
	if c := policyCheckRe.FindStringIndex(after); c != nil {
		check, ok := parenBody(after, c[1]-1)
		if !ok {
			return nil
		}
		p.check = check
	}
	return p
}

// rlsGuards lists what may limit updates anywhere in the repository's SQL:
// tables (bare names) and schemas with a REVOKE of UPDATE, a column-limited
// GRANT UPDATE or a BEFORE UPDATE trigger.
type rlsGuards struct {
	tables  map[string]bool
	schemas map[string]bool
}

func (g rlsGuards) covers(key string) bool {
	return g.tables[bareName(key)] || g.schemas[key[:strings.LastIndex(key, ".")]]
}

func (g rlsGuards) addObjects(objs string) {
	objs = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(objs), "table "))
	if m := allTablesRe.FindStringSubmatch(objs); m != nil {
		for _, s := range splitTopLevel(m[1], ',') {
			g.schemas[unquoteIdent(s)] = true
		}
		return
	}
	for _, q := range splitTopLevel(objs, ',') {
		g.tables[bareName(tableKey(q))] = true
	}
}

func findGuards(text string, g rlsGuards) {
	for _, m := range revokeRe.FindAllStringSubmatch(text, -1) {
		if updatePrivRe.MatchString(m[1]) {
			g.addObjects(m[2])
		}
	}
	for _, m := range grantRe.FindAllStringSubmatch(text, -1) {
		if updateColsRe.MatchString(m[1]) {
			g.addObjects(m[2])
		}
	}
	for _, m := range beforeTriggerRe.FindAllStringSubmatch(text, -1) {
		if wordUpdateRe.MatchString(m[1]) {
			g.tables[bareName(tableKey(m[2]))] = true
		}
	}
}

// rlsSignals runs the check over the inventory's SQL files.
func rlsSignals(inv *inventory.Inventory, collector string) []model.Signal {
	guards := rlsGuards{tables: map[string]bool{}, schemas: map[string]bool{}}
	dirs := map[string][]*inventory.File{}
	for _, f := range inv.Files {
		if f.Lang != "sql" {
			continue
		}
		var all []string
		for _, s := range splitSQL(strings.Join(f.Lines, "\n")) {
			all = append(all, s.text)
		}
		findGuards(strings.Join(all, ";\n"), guards)
		if inventory.IsSQLMigration(f.Path) && !IsTestPath(f.Path) {
			d := path.Dir(f.Path)
			dirs[d] = append(dirs[d], f)
		}
	}
	var out []model.Signal
	names := make([]string, 0, len(dirs))
	for d := range dirs {
		names = append(names, d)
	}
	sort.Strings(names)
	for _, d := range names {
		files := dirs[d]
		sort.Slice(files, func(i, j int) bool { return path.Base(files[i].Path) < path.Base(files[j].Path) })
		st := &rlsState{columns: map[string][]string{}, policies: map[string]*rlsPolicy{}}
		for _, f := range files {
			for _, s := range splitSQL(strings.Join(f.Lines, "\n")) {
				st.apply(s, f)
			}
		}
		seen := map[string]bool{}
		for _, pk := range st.order {
			p := st.policies[pk]
			if p == nil || seen[pk] || p.ambiguous || guards.covers(p.table) {
				continue
			}
			seen[pk] = true
			var priv []string
			for _, c := range st.columns[p.table] {
				if privilegedColumns[c] && !mentionsColumn(p.check, c) {
					priv = append(priv, c)
				}
			}
			if len(priv) == 0 || p.line < 1 || p.line > len(p.file.Lines) {
				continue
			}
			s := sig(lineRule{ID: "sql.rls-update-privileged-column", Control: "C-004", Title: "Row-level security lets users update a privileged column of their own row",
				Severity: model.SevHigh, Confidence: model.Hypothesis, CWE: "CWE-269",
				Message: fmt.Sprintf("Policy %q lets a user update their own row of %s (matched by auth.uid()), and the table has the privileged column(s) %s. No column-limited GRANT UPDATE, REVOKE UPDATE or BEFORE UPDATE trigger on %s was found, so a user may be able to change %s on their own row and raise their privileges.",
					p.name, p.table, strings.Join(priv, ", "), bareName(p.table), priv[0]),
				Fix: "Limit which columns users can update: REVOKE UPDATE on the table from authenticated and GRANT UPDATE (only the editable columns), or add a BEFORE UPDATE trigger that rejects changes to privileged columns, or move privileged columns to a table users cannot write."}, p.file, p.line, collector)
			s.Key = p.table + "." + priv[0]
			out = append(out, s)
		}
	}
	return out
}

// mentionsColumn reports whether a WITH CHECK expression refers to col.
func mentionsColumn(expr, col string) bool {
	for _, tok := range columnTokenRe.FindAllString(expr, -1) {
		if unquoteIdent(tok) == col {
			return true
		}
	}
	return false
}
