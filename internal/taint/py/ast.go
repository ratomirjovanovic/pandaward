// Package py parses Python 3 source for the taint engine. It covers the
// grammar of Python 3.12 and 3.13 (f-strings with nested quotes, match
// statements, type parameters and aliases, walrus, async, decorators,
// positional-only and keyword-only parameters) and keeps parsing after a
// syntax error, losing only the broken statement.
//
// The AST keeps what data-flow analysis needs: names, literals, calls,
// attributes, subscripts, operators, comprehensions, assignments and control
// flow. Type annotations are parsed and kept where they name a type a model
// may need (parameters, assignments), comments are dropped. Every node
// records the 1-based line and column (in bytes) where it starts.
package py

// Node is any AST node.
type Node interface{ At() Pos }

// Expr is an expression; assignment targets are expressions too.
type Expr interface {
	Node
	expr()
}

// Stmt is a statement.
type Stmt interface {
	Node
	stmt()
}

// Pos is a source position, embedded in every node.
type Pos struct{ Line, Col int }

func (p Pos) At() Pos { return p }

// ConstKind is the kind of a constant.
type ConstKind uint8

const (
	ConstStr ConstKind = iota
	ConstBytes
	ConstNum
	ConstTrue
	ConstFalse
	ConstNone
	ConstEllipsis
)

type (
	// Name is an identifier.
	Name struct {
		Pos
		Id string
	}
	// Const is a literal. Val is the decoded text of a string or bytes
	// literal (adjacent literals joined), or the source text of a number.
	Const struct {
		Pos
		Kind ConstKind
		Val  string
	}
	// FString is an f-string, or adjacent literals of which at least one is
	// an f-string. Parts alternate in source order between *Const (text) and
	// *FormattedValue.
	FString struct {
		Pos
		Parts []Expr
	}
	// FormattedValue is one {expr!conv:spec} field of an f-string. Spec is
	// nil or an *FString.
	FormattedValue struct {
		Pos
		Value Expr
		Conv  byte // 0, 's', 'r' or 'a'
		Spec  Expr
	}
	// Attribute is obj.name.
	Attribute struct {
		Pos
		Obj  Expr
		Name string
	}
	// Subscript is obj[index]; a slice index is a *Slice, several indexes
	// a *Tuple.
	Subscript struct {
		Pos
		Obj   Expr
		Index Expr
	}
	// Slice is lo:hi:step inside a subscript; each part may be nil.
	Slice struct {
		Pos
		Lo, Hi, Step Expr
	}
	// Call is func(args).
	Call struct {
		Pos
		Func Expr
		Args []*Arg
	}
	// BinOp is l op r with op one of + - * / // % ** @ << >> & | ^.
	BinOp struct {
		Pos
		Op   string
		L, R Expr
	}
	// BoolOp is a chain of and or or.
	BoolOp struct {
		Pos
		Op     string // "and" or "or"
		Values []Expr
	}
	// UnaryOp is not x, -x, +x or ~x.
	UnaryOp struct {
		Pos
		Op string
		X  Expr
	}
	// Compare is l op1 r1 op2 r2 ...; ops are < > == >= <= != in "not in"
	// is "is not".
	Compare struct {
		Pos
		L      Expr
		Ops    []string
		Rights []Expr
	}
	// IfExp is body if test else orelse.
	IfExp struct {
		Pos
		Test, Body, Else Expr
	}
	// Lambda is lambda params: body.
	Lambda struct {
		Pos
		Params []*Param
		Body   Expr
	}
	// Tuple, List and Set are displays; a parenthesized tuple and a bare
	// one (a, b = ...) are both Tuple.
	Tuple struct {
		Pos
		Elts []Expr
	}
	List struct {
		Pos
		Elts []Expr
	}
	Set struct {
		Pos
		Elts []Expr
	}
	// Dict is a dict display; a nil key marks **value.
	Dict struct {
		Pos
		Keys   []Expr
		Values []Expr
	}
	// Comp is a list, set or generator comprehension (Kind "list", "set",
	// "gen") or a dict comprehension (Kind "dict", with Key).
	Comp struct {
		Pos
		Kind string
		Key  Expr // dict comprehensions only
		Elt  Expr
		Gens []*Comprehension
	}
	// Starred is *x in a call, display or target.
	Starred struct {
		Pos
		X Expr
	}
	// NamedExpr is target := value.
	NamedExpr struct {
		Pos
		Target *Name
		Value  Expr
	}
	// Await is await x.
	Await struct {
		Pos
		X Expr
	}
	// Yield is yield x or, with From, yield from x; X may be nil.
	Yield struct {
		Pos
		X    Expr
		From bool
	}
	// MatchAs is pattern as name in a case pattern; Pattern may be nil
	// (a capture pattern is a plain Name).
	MatchAs struct {
		Pos
		Pattern Expr
		Name    string
	}
	// Bad stands for source that did not parse.
	Bad struct{ Pos }
)

// Arg is one argument of a call: positional, keyword (Name set), *x (Star
// "*") or **x (Star "**").
type Arg struct {
	Pos
	Name  string
	Star  string
	Value Expr
}

// Param is one parameter. Kind is "" (ordinary), "*" (*args), "**"
// (**kwargs), "/" (the positional-only marker) or "*marker" (a bare *).
type Param struct {
	Pos
	Name    string
	Kind    string
	Default Expr
	Ann     Expr
}

// Comprehension is one for ... in ... if ... clause.
type Comprehension struct {
	Target Expr
	Iter   Expr
	Ifs    []Expr
	Async  bool
}

type (
	ExprStmt struct {
		Pos
		X Expr
	}
	// Assign is t1 = t2 = value.
	Assign struct {
		Pos
		Targets []Expr
		Value   Expr
	}
	// AugAssign is target op= value; Op is the operator without "=".
	AugAssign struct {
		Pos
		Target Expr
		Op     string
		Value  Expr
	}
	// AnnAssign is target: ann [= value].
	AnnAssign struct {
		Pos
		Target Expr
		Ann    Expr
		Value  Expr
	}
	FuncDef struct {
		Pos
		Name       string
		TypeParams []*Param // def f[T: bound](...): Ann is the bound
		Params     []*Param
		Returns    Expr
		Body       []Stmt
		Decorators []Expr
		Async      bool
	}
	ClassDef struct {
		Pos
		Name       string
		TypeParams []*Param
		Bases      []*Arg
		Body       []Stmt
		Decorators []Expr
	}
	Return struct {
		Pos
		X Expr
	}
	Delete struct {
		Pos
		Targets []Expr
	}
	Pass     struct{ Pos }
	Break    struct{ Pos }
	Continue struct{ Pos }
	If       struct {
		Pos
		Test Expr
		Body []Stmt
		Else []Stmt // an elif is an If alone in Else
	}
	For struct {
		Pos
		Target Expr
		Iter   Expr
		Body   []Stmt
		Else   []Stmt
		Async  bool
	}
	While struct {
		Pos
		Test Expr
		Body []Stmt
		Else []Stmt
	}
	With struct {
		Pos
		Items []*WithItem
		Body  []Stmt
		Async bool
	}
	Raise struct {
		Pos
		Exc, Cause Expr
	}
	Try struct {
		Pos
		Body     []Stmt
		Handlers []*Handler
		Else     []Stmt
		Finally  []Stmt
	}
	Assert struct {
		Pos
		Test, Msg Expr
	}
	// Import is import a.b as c, d.
	Import struct {
		Pos
		Names []*Alias
	}
	// ImportFrom is from ..module import names; Level counts the dots and a
	// single name "*" is a star import.
	ImportFrom struct {
		Pos
		Module string
		Level  int
		Names  []*Alias
	}
	Global struct {
		Pos
		Names []string
	}
	Nonlocal struct {
		Pos
		Names []string
	}
	Match struct {
		Pos
		Subject Expr
		Cases   []*Case
	}
	// TypeAlias is type Name[params] = value.
	TypeAlias struct {
		Pos
		Name       *Name
		TypeParams []*Param
		Value      Expr
	}
	// BadStmt stands for a statement that did not parse.
	BadStmt struct{ Pos }
)

type WithItem struct {
	Ctx    Expr
	Target Expr
}

// Handler is an except (or except*) clause.
type Handler struct {
	Pos
	Type Expr
	Name string
	Body []Stmt
	Star bool
}

// Alias is name [as asname] in an import.
type Alias struct {
	Name   string
	AsName string
}

// Case is case pattern [if guard]: body.
type Case struct {
	Pos
	Pattern Expr
	Guard   Expr
	Body    []Stmt
}

func (*Name) expr()           {}
func (*Const) expr()          {}
func (*FString) expr()        {}
func (*FormattedValue) expr() {}
func (*Attribute) expr()      {}
func (*Subscript) expr()      {}
func (*Slice) expr()          {}
func (*Call) expr()           {}
func (*BinOp) expr()          {}
func (*BoolOp) expr()         {}
func (*UnaryOp) expr()        {}
func (*Compare) expr()        {}
func (*IfExp) expr()          {}
func (*Lambda) expr()         {}
func (*Tuple) expr()          {}
func (*List) expr()           {}
func (*Set) expr()            {}
func (*Dict) expr()           {}
func (*Comp) expr()           {}
func (*Starred) expr()        {}
func (*NamedExpr) expr()      {}
func (*Await) expr()          {}
func (*Yield) expr()          {}
func (*MatchAs) expr()        {}
func (*Bad) expr()            {}

func (*ExprStmt) stmt()   {}
func (*Assign) stmt()     {}
func (*AugAssign) stmt()  {}
func (*AnnAssign) stmt()  {}
func (*FuncDef) stmt()    {}
func (*ClassDef) stmt()   {}
func (*Return) stmt()     {}
func (*Delete) stmt()     {}
func (*Pass) stmt()       {}
func (*Break) stmt()      {}
func (*Continue) stmt()   {}
func (*If) stmt()         {}
func (*For) stmt()        {}
func (*While) stmt()      {}
func (*With) stmt()       {}
func (*Raise) stmt()      {}
func (*Try) stmt()        {}
func (*Assert) stmt()     {}
func (*Import) stmt()     {}
func (*ImportFrom) stmt() {}
func (*Global) stmt()     {}
func (*Nonlocal) stmt()   {}
func (*Match) stmt()      {}
func (*TypeAlias) stmt()  {}
func (*BadStmt) stmt()    {}

// File is a parsed module.
type File struct {
	Path   string
	Body   []Stmt
	Errors []Error
}

// Error is a syntax error the parser recovered from.
type Error struct {
	Line, Col int
	Msg       string
}

func (e Error) Error() string { return itoa(e.Line) + ":" + itoa(e.Col) + ": " + e.Msg }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
