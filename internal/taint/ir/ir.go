// Package ir is the language-independent form the taint engine analyzes:
// each function is a control flow graph of basic blocks holding simple
// instructions (copy, operator, attribute and index load and store, call,
// container build) over named variables and temporaries. Branch conditions
// stay operands, so a check that leaves the function on bad input is seen
// on each outgoing edge. Front ends (internal/taint/py, later Java and
// JavaScript) lower their AST to it.
package ir

import (
	"fmt"
	"strconv"
	"strings"
)

// Pos is a 1-based line and column.
type Pos struct{ Line, Col int }

// ConstKind is the kind of a constant.
type ConstKind uint8

const (
	Str ConstKind = iota
	Bytes
	Int
	Float
	Bool
	None
	Other
)

// Const is a literal value. Val is the decoded text of a string, the
// decimal text of an integer, "true" or "false" for a boolean.
type Const struct {
	Kind ConstKind
	Val  string
}

// Truth reports the truth value of a constant and whether it is known.
func (c *Const) Truth() (bool, bool) {
	switch c.Kind {
	case Str, Bytes:
		return c.Val != "", true
	case Int:
		n, err := strconv.ParseInt(c.Val, 10, 64)
		return n != 0, err == nil
	case Float:
		f, err := strconv.ParseFloat(c.Val, 64)
		return f != 0, err == nil
	case Bool:
		return c.Val == "true", true
	case None:
		return false, true
	}
	return false, false
}

func (c *Const) String() string {
	switch c.Kind {
	case Str:
		return strconv.Quote(c.Val)
	case Bytes:
		return "b" + strconv.Quote(c.Val)
	case None:
		return "None"
	}
	return c.Val
}

// Operand is a variable or a constant; the zero Operand is "nothing".
type Operand struct {
	Var   string
	Const *Const
}

// V returns a variable operand.
func V(name string) Operand { return Operand{Var: name} }

// C returns a constant operand.
func C(k ConstKind, val string) Operand { return Operand{Const: &Const{k, val}} }

// IsZero reports the empty operand.
func (o Operand) IsZero() bool { return o.Var == "" && o.Const == nil }

func (o Operand) String() string {
	switch {
	case o.Const != nil:
		return o.Const.String()
	case o.Var != "":
		return o.Var
	}
	return "_"
}

// IsTemp reports a temporary of the lowering, as opposed to a variable of
// the source.
func IsTemp(name string) bool { return strings.HasPrefix(name, "$") }

// Op is an instruction's operation.
type Op uint8

const (
	// Copy: Dst = A.
	Copy Op = iota
	// Bin: Dst = A Name B, Name an operator (+, %, ==, in, not in, is, ...).
	Bin
	// Unary: Dst = Name A (not, -, +, ~).
	Unary
	// Load: Dst = A.Name.
	Load
	// Store: A.Name = B.
	Store
	// Index: Dst = A[B]; with Name "slice", A[B:C].
	Index
	// SetIndex: A[B] = C.
	SetIndex
	// Call: Dst = A(Args) or, with Name set, Dst = A.Name(Args) where A is
	// the receiver. Keys holds each argument's keyword ("" positional, "*"
	// for *x and "**" for **x).
	Call
	// Build: Dst = a container or string (Name list, tuple, set, dict,
	// str) of Args; a dict has its keys in Keys2 (zero operand for **x).
	Build
	// Free: Dst = the variable Name of an enclosing scope or the module.
	Free
	// Import: Dst = the module or member Name (dotted, absolute).
	Import
	// Func: Dst = the function Fn defined here.
	Func
	// Iter: Dst = an element of the iterable A.
	Iter
	// Del: delete A.Name (Name set) or A[B].
	Del
	// Cast: Dst = A, of the class Name (a declared type or a cast).
	Cast
)

var opNames = [...]string{"copy", "bin", "unary", "load", "store", "index", "setindex", "call", "build", "free", "import", "func", "iter", "del", "cast"}

func (o Op) String() string { return opNames[o] }

// Instr is one instruction.
type Instr struct {
	Op    Op
	Pos   Pos
	Dst   string
	Name  string
	A     Operand
	B     Operand
	C     Operand
	Args  []Operand
	Keys  []string
	Keys2 []Operand
	Fn    *Function
}

// TermKind is how a block ends.
type TermKind uint8

const (
	// Jump goes to Succs[0].
	Jump TermKind = iota
	// Branch goes to Succs[0] when Cond is true, Succs[1] otherwise.
	Branch
	// Return leaves the function with Value (zero operand: None).
	Return
	// Raise leaves the function with an exception.
	Raise
)

// Term ends a block.
type Term struct {
	Kind  TermKind
	Pos   Pos
	Cond  Operand
	Value Operand
	Succs []*Block
}

// Block is a basic block. Handlers are the exception handlers that may run
// after any of its instructions.
type Block struct {
	Index    int
	Instrs   []*Instr
	Term     Term
	Preds    []*Block
	Handlers []*Block
}

// Param is a function parameter. Kind is "" (ordinary), "*" or "**".
type Param struct {
	Name string
	Kind string
	Pos  Pos
	// Ann is the dotted name of the annotation, if it is a name.
	Ann string
	// Default is the default value when it is a constant.
	Default *Const
	// Decorators are the parameter's annotations (Java).
	Decorators []Decorator
}

// Decorator is a decorator applied to a function: the dotted name it calls
// or names, and the constant positional arguments of the call.
type Decorator struct {
	Name string
	Args []string
	Call bool
	// Keys are the argument names of an annotation (value, name, ...).
	Keys []string
}

// Function is one function or the body of a module or class.
type Function struct {
	Name       string
	Pos        Pos
	Params     []Param
	Decorators []Decorator
	Blocks     []*Block // Blocks[0] is the entry
	Parent     *Function
	// Class is the name of the class whose body defines the function.
	Class string
	// Bases are the dotted names of a class body's base classes.
	Bases []string
	// Defs maps each temporary to the instruction that sets it.
	Defs map[string]*Instr
}

// Entry returns the entry block.
func (f *Function) Entry() *Block { return f.Blocks[0] }

// Module is a lowered source file.
type Module struct {
	Path string
	// Name is the dotted module name, when known.
	Name  string
	Init  *Function
	Funcs []*Function // every function, the module body first
}

// NewBlock adds a block to f.
func (f *Function) NewBlock() *Block {
	b := &Block{Index: len(f.Blocks)}
	f.Blocks = append(f.Blocks, b)
	return b
}

// Link records the predecessors of every block and the temporaries'
// definitions, once the blocks are complete.
func (f *Function) Link() {
	f.Defs = map[string]*Instr{}
	for _, b := range f.Blocks {
		b.Preds = nil
	}
	for _, b := range f.Blocks {
		for _, s := range b.Term.Succs {
			s.Preds = append(s.Preds, b)
		}
		for _, h := range b.Handlers {
			h.Preds = append(h.Preds, b)
		}
		for _, in := range b.Instrs {
			if IsTemp(in.Dst) {
				f.Defs[in.Dst] = in
			}
		}
	}
}

// String prints a function for tests and debugging.
func (f *Function) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "func %s(", f.Name)
	for i, p := range f.Params {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(p.Kind + p.Name)
	}
	sb.WriteString(")\n")
	for _, b := range f.Blocks {
		fmt.Fprintf(&sb, "b%d:", b.Index)
		if len(b.Handlers) > 0 {
			sb.WriteString(" handlers")
			for _, h := range b.Handlers {
				fmt.Fprintf(&sb, " b%d", h.Index)
			}
		}
		sb.WriteString("\n")
		for _, in := range b.Instrs {
			sb.WriteString("  " + in.String() + "\n")
		}
		sb.WriteString("  " + b.Term.String() + "\n")
	}
	return sb.String()
}

func (in *Instr) String() string {
	dst := ""
	if in.Dst != "" {
		dst = in.Dst + " = "
	}
	switch in.Op {
	case Copy:
		return dst + in.A.String()
	case Bin:
		return dst + in.A.String() + " " + in.Name + " " + in.B.String()
	case Unary:
		return dst + in.Name + " " + in.A.String()
	case Load:
		return dst + in.A.String() + "." + in.Name
	case Store:
		return in.A.String() + "." + in.Name + " = " + in.B.String()
	case Index:
		if in.Name == "slice" {
			return dst + in.A.String() + "[" + in.B.String() + ":" + in.C.String() + "]"
		}
		return dst + in.A.String() + "[" + in.B.String() + "]"
	case SetIndex:
		return in.A.String() + "[" + in.B.String() + "] = " + in.C.String()
	case Call:
		callee := in.A.String()
		if in.Name != "" {
			callee += "." + in.Name
		}
		return dst + callee + "(" + args(in.Args, in.Keys) + ")"
	case Build:
		if in.Name == "dict" {
			var parts []string
			for i, a := range in.Args {
				if in.Keys2[i].IsZero() {
					parts = append(parts, "**"+a.String())
					continue
				}
				parts = append(parts, in.Keys2[i].String()+": "+a.String())
			}
			return dst + "dict{" + strings.Join(parts, ", ") + "}"
		}
		return dst + in.Name + "{" + args(in.Args, nil) + "}"
	case Free:
		return dst + "free " + in.Name
	case Import:
		return dst + "import " + in.Name
	case Func:
		return dst + "func " + in.Fn.Name
	case Iter:
		return dst + "iter " + in.A.String()
	case Cast:
		return dst + "(" + in.Name + ") " + in.A.String()
	case Del:
		if in.Name != "" {
			return "del " + in.A.String() + "." + in.Name
		}
		return "del " + in.A.String() + "[" + in.B.String() + "]"
	}
	return "?"
}

func args(as []Operand, keys []string) string {
	var parts []string
	for i, a := range as {
		k := ""
		if i < len(keys) {
			k = keys[i]
		}
		switch k {
		case "":
			parts = append(parts, a.String())
		case "*", "**":
			parts = append(parts, k+a.String())
		default:
			parts = append(parts, k+"="+a.String())
		}
	}
	return strings.Join(parts, ", ")
}

func (t Term) String() string {
	succ := func(i int) string { return fmt.Sprintf("b%d", t.Succs[i].Index) }
	switch t.Kind {
	case Jump:
		return "jump " + succ(0)
	case Branch:
		return "if " + t.Cond.String() + " then " + succ(0) + " else " + succ(1)
	case Return:
		return "return " + t.Value.String()
	case Raise:
		return "raise"
	}
	return "?"
}
