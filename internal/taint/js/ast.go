package js

// The AST keeps what data-flow analysis needs and drops the rest: types,
// decorators, comments and most syntactic detail. Every node records the
// 1-based line it starts on.

// Node is any AST node.
type Node interface{ Ln() int }

// Expr is an expression. Patterns (destructuring targets) are expressions
// too: Ident, Member, ObjectLit, ArrayLit, Assign (a default value), Spread
// (a rest element) and Bad.
type Expr interface {
	Node
	expr()
}

// Stmt is a statement or declaration.
type Stmt interface {
	Node
	stmt()
}

// Pos is embedded in every node.
type Pos struct{ Line int }

func (p Pos) Ln() int { return p.Line }

type (
	// Ident is a name, including this, super and the contextual keywords.
	Ident struct {
		Pos
		Name string
	}
	// Lit is a literal. Kind is String, Number, Regex or Ident (true, false,
	// null, undefined is an Ident); Val is the cooked string value or the
	// source text.
	Lit struct {
		Pos
		Kind Kind
		Val  string
	}
	// TemplateLit is a template literal; Quasis has one more element than
	// Exprs. Tag is set for a tagged template.
	TemplateLit struct {
		Pos
		Tag    Expr
		Quasis []string
		Exprs  []Expr
	}
	// Member is obj.prop, obj[expr] (Computed) or obj.#priv.
	Member struct {
		Pos
		Obj      Expr
		Prop     string // the property name when not computed
		Computed Expr
		Optional bool
	}
	// Call is a call or, with New, a constructor call.
	Call struct {
		Pos
		Callee   Expr
		Args     []Expr
		New      bool
		Optional bool
	}
	Binary struct {
		Pos
		Op   string
		L, R Expr
	}
	Unary struct {
		Pos
		Op string // ! ~ + - typeof void delete await, ++ -- (prefix or Postfix)
		X  Expr
		// Postfix is set for x++ and x--.
		Postfix bool
	}
	// Assign is an assignment, or a default value in a pattern (Op "=").
	Assign struct {
		Pos
		Op     string
		Target Expr
		Value  Expr
	}
	Cond struct {
		Pos
		Test, Then, Else Expr
	}
	Seq struct {
		Pos
		List []Expr
	}
	// ArrayLit is an array literal or pattern; holes are nil.
	ArrayLit struct {
		Pos
		Elems []Expr
	}
	ObjectLit struct {
		Pos
		Props []*Prop
	}
	// Spread is ...x in arrays, calls, objects and rest patterns.
	Spread struct {
		Pos
		X Expr
	}
	Yield struct {
		Pos
		X        Expr
		Delegate bool
	}
	Func struct {
		Pos
		Name      string
		Params    []Expr // patterns
		Body      []Stmt // nil for a declaration without body (TypeScript overload)
		ExprBody  Expr   // arrow function with an expression body
		Arrow     bool
		Async     bool
		Generator bool
	}
	Class struct {
		Pos
		Name    string
		Super   Expr
		Members []*ClassMember
	}
	// JSXElement is <Tag attrs>children</Tag>; a fragment has an empty Tag.
	JSXElement struct {
		Pos
		Tag      string
		Attrs    []*JSXAttr
		Children []Expr // TJSXText, JSXElement or expressions in {...}
	}
	JSXText struct {
		Pos
		Text string
	}
	// Bad stands for source that did not parse.
	Bad struct{ Pos }
)

// Prop is one property of an object literal or pattern.
type Prop struct {
	Pos
	Key      string // the key when it is an identifier, string or number
	Computed Expr
	Value    Expr // for a spread (Kind "spread") the spread operand
	// Kind is "init", "get", "set", "method", "shorthand" or "spread".
	Kind string
}

// ClassMember is a method, accessor, field or static block.
type ClassMember struct {
	Pos
	Key      string
	Computed Expr
	Static   bool
	// Kind is "method", "get", "set", "constructor", "field" or "block".
	Kind  string
	Value Expr   // *Func for methods, the initializer for fields
	Block []Stmt // static block
	// ParamProps names the constructor parameters declared as properties
	// (TypeScript `constructor(private x)`).
	ParamProps []string
}

// JSXAttr is name={value}, name="value", a bare name, or {...spread}
// (Spread set, Name empty).
type JSXAttr struct {
	Pos
	Name   string
	Value  Expr
	Spread bool
}

type (
	ExprStmt struct {
		Pos
		X Expr
	}
	// VarDecl is var, let, const, using or await using.
	VarDecl struct {
		Pos
		Kind  string
		Decls []*Declarator
	}
	Return struct {
		Pos
		X Expr
	}
	If struct {
		Pos
		Test Expr
		Then Stmt
		Else Stmt
	}
	// For is the classic three-clause loop; Init is a *VarDecl or *ExprStmt.
	For struct {
		Pos
		Init   Stmt
		Test   Expr
		Update Expr
		Body   Stmt
	}
	// ForIn is for-in and, with Of, for-of; Left is a *VarDecl with one
	// declarator without initializer, or a pattern in an *ExprStmt.
	ForIn struct {
		Pos
		Left  Stmt
		Right Expr
		Body  Stmt
		Of    bool
		Await bool
	}
	While struct {
		Pos
		Test Expr
		Body Stmt
		Do   bool
	}
	Block struct {
		Pos
		List []Stmt
	}
	Try struct {
		Pos
		Block   *Block
		Param   Expr // the catch binding, nil when absent
		Handler *Block
		Finally *Block
	}
	Switch struct {
		Pos
		Disc  Expr
		Cases []*Case
	}
	Throw struct {
		Pos
		X Expr
	}
	// Branch is break or continue.
	Branch struct {
		Pos
		Tok   string
		Label string
	}
	Labeled struct {
		Pos
		Label string
		Body  Stmt
	}
	FuncDecl struct {
		Pos
		Func *Func
	}
	ClassDecl struct {
		Pos
		Class *Class
	}
	// Import is an import declaration. A side-effect import has no specifiers.
	Import struct {
		Pos
		Source string
		Specs  []ImportSpec
	}
	// Export is an export declaration: Decl for `export <declaration>`,
	// Default for `export default <expr>` (a function or class expression
	// for the declaration forms), Specs for `export { a as b }` and
	// re-exports with From.
	Export struct {
		Pos
		Decl    Stmt
		Default Expr
		Specs   []ExportSpec
		From    string
		// All is set for `export * from` (Specs then holds the namespace
		// alias, if any).
		All bool
	}
	// Empty is an empty statement or a declaration without runtime effect
	// (TypeScript types and interfaces).
	Empty struct{ Pos }
	// BadStmt stands for a statement that did not parse.
	BadStmt struct{ Pos }
)

// Declarator is one binding of a VarDecl.
type Declarator struct {
	Pos
	Target Expr // a pattern
	Init   Expr
}

// Case is a switch case; Test is nil for default.
type Case struct {
	Pos
	Test Expr
	Body []Stmt
}

// ImportSpec binds Local to the export Imported of the module ("default"
// for a default import, "*" for a namespace import).
type ImportSpec struct {
	Imported, Local string
}

// ExportSpec exports Local under Exported.
type ExportSpec struct {
	Local, Exported string
}

func (*Ident) expr()       {}
func (*Lit) expr()         {}
func (*TemplateLit) expr() {}
func (*Member) expr()      {}
func (*Call) expr()        {}
func (*Binary) expr()      {}
func (*Unary) expr()       {}
func (*Assign) expr()      {}
func (*Cond) expr()        {}
func (*Seq) expr()         {}
func (*ArrayLit) expr()    {}
func (*ObjectLit) expr()   {}
func (*Spread) expr()      {}
func (*Yield) expr()       {}
func (*Func) expr()        {}
func (*Class) expr()       {}
func (*JSXElement) expr()  {}
func (*JSXText) expr()     {}
func (*Bad) expr()         {}

func (*ExprStmt) stmt()  {}
func (*VarDecl) stmt()   {}
func (*Return) stmt()    {}
func (*If) stmt()        {}
func (*For) stmt()       {}
func (*ForIn) stmt()     {}
func (*While) stmt()     {}
func (*Block) stmt()     {}
func (*Try) stmt()       {}
func (*Switch) stmt()    {}
func (*Throw) stmt()     {}
func (*Branch) stmt()    {}
func (*Labeled) stmt()   {}
func (*FuncDecl) stmt()  {}
func (*ClassDecl) stmt() {}
func (*Import) stmt()    {}
func (*Export) stmt()    {}
func (*Empty) stmt()     {}
func (*BadStmt) stmt()   {}

// File is a parsed source file.
type File struct {
	Path   string
	Stmts  []Stmt
	Errors []Error
}

// Error is a syntax error the parser recovered from.
type Error struct {
	Line int
	Msg  string
}
