package adapters

import (
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// #589: SQL text built from constants, placeholders or checked names is
// listed as information; a value that reaches the text keeps its severity.
func TestSQLSafePartsDemotion(t *testing.T) {
	cases := []struct {
		name, file, src string
		safe            bool
	}{
		// Constant table name, bound values.
		{"const table js", "a.js", "const TABLE = 'sessions';\ndb.query(`SELECT * FROM ${TABLE} WHERE id = ?`, [id]);\n", true},
		{"const table py", "a.py", "TABLE = \"sessions\"\ncur.execute(f\"SELECT * FROM {TABLE} WHERE id = ?\", (sid,))\n", true},
		// Placeholders sized from a list.
		{"placeholders js", "a.js", "const ph = ids.map(() => '?').join(',');\ndb.all(`SELECT * FROM t WHERE id IN (${ph})`, ids);\n", true},
		{"placeholders inline js", "a.js", "db.all(`SELECT * FROM t WHERE id IN (${ids.map(() => '?').join(',')})`, ids);\n", true},
		{"placeholders py", "a.py", "cur.execute(f\"SELECT * FROM t WHERE id IN ({','.join('?' for _ in ids)})\", ids)\n", true},
		{"placeholders repeat py", "a.py", "cur.execute(f\"SELECT * FROM t WHERE id IN ({','.join(['?'] * len(ids))})\", ids)\n", true},
		// Fragment lists pushed as fixed strings.
		{"fragments js", "a.js", "const sets = [];\nif (a) sets.push('a = ?');\nif (b) sets.push('b = ?');\ndb.run(`UPDATE t SET ${sets.join(', ')} WHERE id = ?`, vals);\n", true},
		{"fragments py", "a.py", "sets = []\nif a:\n    sets.append(\"a = ?\")\ncur.execute(f\"UPDATE t SET {', '.join(sets)} WHERE id = ?\", vals)\n", true},
		// Lookup in a constant map.
		{"lookup map js", "a.js", "const COLS = { name: 'name', age: 'age' };\ndb.query(`SELECT * FROM t ORDER BY ${COLS[sort]}`);\n", true},
		// Number conversion.
		{"limit number", "a.js", "db.query(`SELECT * FROM t LIMIT ${Number(n)}`);\n", true},
		{"limit int py", "a.py", "cur.execute(f\"SELECT * FROM t LIMIT {int(n)}\")\n", true},
		// Name checked against a pattern, rejecting.
		{"regex checked js", "a.js", "if (!/^[a-zA-Z0-9_]+$/.test(table)) throw new Error('bad');\ndb.query(`SELECT * FROM ${table} WHERE id = ?`, [id]);\n", true},
		{"regex checked py", "a.py", "if not re.match(r'^[a-zA-Z0-9_]+$', table):\n    raise ValueError('bad')\ncur.execute(f\"SELECT * FROM {table} WHERE id = ?\", (k,))\n", true},
		{"constructor checked ts", "a.ts", "class S {\n  constructor(tableName: string) {\n    if (!/^[a-zA-Z0-9_]+$/.test(tableName)) throw new Error('bad');\n    this.tableName = tableName;\n  }\n  async get(id) {\n    return this.db.query(`SELECT * FROM ${this.tableName} WHERE id = $1`, [id]);\n  }\n}\n", true},
		// Allowlist, rejecting.
		{"allowlist js", "a.js", "const ALLOWED = ['a', 'b'];\nif (!ALLOWED.includes(col)) throw new Error('bad');\ndb.query(`SELECT * FROM t ORDER BY ${col}`);\n", true},
		// Identifier quoting call.
		{"escapeId", "a.js", "db.query(`SELECT * FROM ${mysql.escapeId(name)} WHERE id = ?`, [id]);\n", true},
		// Constant concatenation.
		{"const concat", "a.js", "const q = \"DELETE FROM a;\" + \"DELETE FROM b;\";\n", true},
		{"concat const name", "a.js", "const T = 'users';\ndb.query(\"SELECT * FROM \" + T + \" WHERE id = ?\", [id]);\n", true},

		// A request value stays reported.
		{"request value js", "a.js", "db.query(`SELECT * FROM t WHERE id = ${req.query.id}`);\n", false},
		{"plain variable js", "a.js", "db.query(`SELECT * FROM t WHERE id = ${id}`);\n", false},
		{"value concat js", "a.js", "db.query(\"SELECT * FROM u WHERE id = \" + id);\n", false},
		{"fstring value py", "a.py", "cur.execute(f\"SELECT * FROM u WHERE name = {name}\")\n", false},
		{"percent py", "a.py", "cur.execute('SELECT * FROM u WHERE n = %s' % name)\n", false},
		// A check whose result is ignored does not count.
		{"check ignored js", "a.js", "/^[a-z]+$/.test(table);\ndb.query(`SELECT * FROM ${table}`);\n", false},
		{"check not rejecting js", "a.js", "if (!/^[a-z]+$/.test(table)) { log('odd'); }\ndb.query(`SELECT * FROM ${table}`);\n", false},
		{"allowlist ignored js", "a.js", "ALLOWED.includes(col);\ndb.query(`SELECT * FROM t ORDER BY ${col}`);\n", false},
		// A fragment list that takes a request key stays reported.
		{"fragments from keys js", "a.js", "const sets = [];\nfor (const k of Object.keys(body)) sets.push(`${k} = ?`);\ndb.run(`UPDATE t SET ${sets.join(', ')}`, vals);\n", false},
		// One safe and one unsafe part.
		{"mixed js", "a.js", "const T = 'users';\ndb.query(`SELECT * FROM ${T} WHERE name = '${name}'`);\n", false},
		// A lookup in something that is not a constant collection.
		{"lookup not const js", "a.js", "const COLS = loadCols();\ndb.query(`SELECT * FROM t ORDER BY ${COLS[sort]}`);\n", false},
		// A constant that is reassigned is not a constant.
		{"reassigned const js", "a.js", "let T = 'users';\nT = req.query.t;\ndb.query(`SELECT * FROM ${T}`);\n", false},
		// Continuation after a plus is read.
		{"continuation value js", "a.js", "db.query(\"SELECT * FROM u WHERE id = \" +\n  id);\n", false},
	}
	for _, c := range cases {
		sigs := runOn(t, codeAdapter{}, map[string]string{"src/" + c.file: c.src})
		var got model.Severity
		seen := false
		for _, s := range sigs {
			switch s.RuleID {
			case "code.sql-template", "code.sql-concat", "code.sql-unsafe-raw":
				if !seen || s.Severity != model.SevInfo {
					got = s.Severity
				}
				seen = true
			}
		}
		if !seen {
			t.Errorf("%s: no SQL signal at all", c.name)
			continue
		}
		if c.safe && got != model.SevInfo {
			t.Errorf("%s: want information, got %q", c.name, got)
		}
		if !c.safe && got != model.SevHigh {
			t.Errorf("%s: want high, got %q", c.name, got)
		}
	}
}
