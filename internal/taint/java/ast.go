// Package java parses Java source for the taint engine: classes,
// interfaces, enums, records and annotation types with their members,
// every statement and expression of Java 21 (lambdas, method references,
// switch expressions, pattern instanceof, text blocks, generics) and
// annotations with their arguments. Types are kept as their dotted name
// without type arguments, plus [] for arrays, which is what data-flow
// analysis needs. The parser keeps going after a syntax error, losing only
// the broken statement or member. Every node records its 1-based line and
// column.
package java

// Pos is a source position, embedded in every node.
type Pos struct{ Line, Col int }

func (p Pos) At() Pos { return p }

// Node is any AST node.
type Node interface{ At() Pos }

// Expr is an expression.
type Expr interface {
	Node
	expr()
}

// Stmt is a statement.
type Stmt interface {
	Node
	stmt()
}

// LitKind is the kind of a literal.
type LitKind uint8

const (
	LitString LitKind = iota
	LitChar
	LitInt
	LitFloat
	LitTrue
	LitFalse
	LitNull
)

type (
	// Name is an identifier, or this or super.
	Name struct {
		Pos
		Id string
	}
	Literal struct {
		Pos
		Kind LitKind
		Val  string
	}
	// Field is x.name, or a qualified name a.b.c.
	Field struct {
		Pos
		X    Expr
		Name string
	}
	// Call is [x.]name(args); X is nil for an unqualified call.
	Call struct {
		Pos
		X    Expr
		Name string
		Args []Expr
	}
	// New is new Type(args) [{body}] or new Type[dims] [{init}].
	New struct {
		Pos
		Type  string
		Outer Expr // outer.new Inner()
		Args  []Expr
		Body  *ClassDecl // anonymous class
		Dims  []Expr     // array dimensions
		Init  *ArrayInit
	}
	ArrayInit struct {
		Pos
		Elts []Expr
	}
	Index struct {
		Pos
		X, Index Expr
	}
	Binary struct {
		Pos
		Op   string
		L, R Expr
	}
	// Unary is a prefix (Op ++ -- + - ! ~) or, with Postfix, x++ or x--.
	Unary struct {
		Pos
		Op      string
		X       Expr
		Postfix bool
	}
	// Assign is l op r with op = += -= ...
	Assign struct {
		Pos
		Op   string
		L, R Expr
	}
	Cond struct {
		Pos
		C, T, F Expr
	}
	Cast struct {
		Pos
		Type string
		X    Expr
	}
	// InstanceOf is x instanceof Type [name]; Bind is the pattern variable.
	InstanceOf struct {
		Pos
		X    Expr
		Type string
		Bind string
	}
	// Lambda has an expression body or a *Block.
	Lambda struct {
		Pos
		Params []*Param
		Body   Node
	}
	// MethodRef is x::name (name is "new" for a constructor reference).
	MethodRef struct {
		Pos
		X    Expr
		Name string
	}
	// ClassLit is Type.class.
	ClassLit struct {
		Pos
		Type string
	}
	// SwitchExpr is a switch used as an expression.
	SwitchExpr struct {
		Pos
		X     Expr
		Cases []*Case
	}
	// TypeExpr stands for a type in expression position (a qualifier such
	// as int[] in int[]::new).
	TypeExpr struct {
		Pos
		Type string
	}
	Bad struct{ Pos }
)

type (
	Block struct {
		Pos
		Stmts []Stmt
	}
	// LocalVar declares variables of one type.
	LocalVar struct {
		Pos
		Type string
		Vars []*Var
		Mods []string
	}
	ExprStmt struct {
		Pos
		X Expr
	}
	If struct {
		Pos
		C    Expr
		Then Stmt
		Else Stmt
	}
	While struct {
		Pos
		C    Expr
		Body Stmt
	}
	DoWhile struct {
		Pos
		Body Stmt
		C    Expr
	}
	For struct {
		Pos
		Init   []Stmt
		C      Expr
		Update []Expr
		Body   Stmt
	}
	ForEach struct {
		Pos
		Type string
		Name string
		Iter Expr
		Body Stmt
	}
	Return struct {
		Pos
		X Expr
	}
	Throw struct {
		Pos
		X Expr
	}
	Break struct {
		Pos
		Label string
	}
	Continue struct {
		Pos
		Label string
	}
	Yield struct {
		Pos
		X Expr
	}
	Try struct {
		Pos
		Resources []Stmt // *LocalVar or *ExprStmt
		Body      *Block
		Catches   []*Catch
		Finally   *Block
	}
	Switch struct {
		Pos
		X     Expr
		Cases []*Case
	}
	Sync struct {
		Pos
		X    Expr
		Body *Block
	}
	Labeled struct {
		Pos
		Label string
		Body  Stmt
	}
	Assert struct {
		Pos
		C, Msg Expr
	}
	// LocalClass is a class, record, enum or interface declared in a body.
	LocalClass struct {
		Pos
		Decl *ClassDecl
	}
	Empty   struct{ Pos }
	BadStmt struct{ Pos }
)

// Var is one declared variable with its initializer.
type Var struct {
	Pos
	Name string
	Dims int
	Init Expr
}

// Catch is catch (T1 | T2 name) {body}.
type Catch struct {
	Pos
	Types []string
	Name  string
	Body  *Block
}

// Case is one case of a switch: its labels (nil with Default), an
// optional guard (when), and its statements; an arrow case with an
// expression body has a single *ExprStmt or a *Yield.
type Case struct {
	Pos
	Labels  []Expr
	Default bool
	Guard   Expr
	Arrow   bool
	Body    []Stmt
}

// Param is a formal parameter.
type Param struct {
	Pos
	Type        string
	Name        string
	Varargs     bool
	Annotations []*Annotation
}

// Annotation is @Name or @Name(args).
type Annotation struct {
	Pos
	Name string
	Args []*AnnArg
}

// AnnArg is name = value, or a single value (Name "value").
type AnnArg struct {
	Name  string
	Value Expr
}

// ClassDecl is a class, interface, enum, record or annotation type.
type ClassDecl struct {
	Pos
	Kind        string // class, interface, enum, record, @interface
	Name        string
	Mods        []string
	Annotations []*Annotation
	Extends     []string
	Implements  []string
	Components  []*Param // record components
	Consts      []*EnumConst
	Members     []Member
}

// EnumConst is an enum constant with its arguments and body.
type EnumConst struct {
	Pos
	Name string
	Args []Expr
	Body *ClassDecl
}

// Member is a member of a class body.
type Member interface {
	Node
	member()
}

type (
	FieldDecl struct {
		Pos
		Type        string
		Vars        []*Var
		Mods        []string
		Annotations []*Annotation
	}
	// Method is a method or, with Ctor, a constructor; Body is nil when
	// abstract or native.
	Method struct {
		Pos
		Name        string
		Ret         string
		Params      []*Param
		Throws      []string
		Body        *Block
		Mods        []string
		Annotations []*Annotation
		Ctor        bool
	}
	Initializer struct {
		Pos
		Static bool
		Body   *Block
	}
)

func (*FieldDecl) member()   {}
func (*Method) member()      {}
func (*Initializer) member() {}
func (*ClassDecl) member()   {}

// Import is import [static] a.b.C[.*].
type Import struct {
	Path   string
	Static bool
	Star   bool
}

// File is a compilation unit.
type File struct {
	Path    string
	Package string
	Imports []Import
	Types   []*ClassDecl
	Errors  []Error
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
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
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

func (*Name) expr()       {}
func (*Literal) expr()    {}
func (*Field) expr()      {}
func (*Call) expr()       {}
func (*New) expr()        {}
func (*ArrayInit) expr()  {}
func (*Index) expr()      {}
func (*Binary) expr()     {}
func (*Unary) expr()      {}
func (*Assign) expr()     {}
func (*Cond) expr()       {}
func (*Cast) expr()       {}
func (*InstanceOf) expr() {}
func (*Lambda) expr()     {}
func (*MethodRef) expr()  {}
func (*ClassLit) expr()   {}
func (*SwitchExpr) expr() {}
func (*TypeExpr) expr()   {}
func (*Bad) expr()        {}

func (*Block) stmt()      {}
func (*LocalVar) stmt()   {}
func (*ExprStmt) stmt()   {}
func (*If) stmt()         {}
func (*While) stmt()      {}
func (*DoWhile) stmt()    {}
func (*For) stmt()        {}
func (*ForEach) stmt()    {}
func (*Return) stmt()     {}
func (*Throw) stmt()      {}
func (*Break) stmt()      {}
func (*Continue) stmt()   {}
func (*Yield) stmt()      {}
func (*Try) stmt()        {}
func (*Switch) stmt()     {}
func (*Sync) stmt()       {}
func (*Labeled) stmt()    {}
func (*Assert) stmt()     {}
func (*LocalClass) stmt() {}
func (*Empty) stmt()      {}
func (*BadStmt) stmt()    {}
