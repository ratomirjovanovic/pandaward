"""Print the position of selected AST nodes of every .py file under the
given directories, as CPython's ast module sees them, for pyparse -diff.

    python tools/pyparse/astnodes.py <dir>... > nodes.tsv

Each line: path, node type, line, column (0-based, in UTF-8 bytes).
"""
import ast
import os
import sys

TYPES = {
    "Call": "Call", "Attribute": "Attribute", "Subscript": "Subscript", "Name": "Name",
    "JoinedStr": "FString", "FunctionDef": "FuncDef", "AsyncFunctionDef": "FuncDef",
    "ClassDef": "ClassDef", "Return": "Return", "If": "If", "For": "For", "AsyncFor": "For",
    "While": "While", "With": "With", "AsyncWith": "With", "Try": "Try", "TryStar": "Try",
    "Assign": "Assign", "AugAssign": "AugAssign", "AnnAssign": "AnnAssign", "Lambda": "Lambda",
    "ListComp": "Comp", "SetComp": "Comp", "DictComp": "Comp", "GeneratorExp": "Comp",
    "Match": "Match", "Import": "Import", "ImportFrom": "ImportFrom", "Raise": "Raise",
    "NamedExpr": "NamedExpr", "Await": "Await", "Yield": "Yield", "YieldFrom": "Yield",
}


def main():
    out = sys.stdout
    for root in sys.argv[1:]:
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__", ".tox", ".mypy_cache")]
            for name in files:
                if not name.endswith(".py"):
                    continue
                path = os.path.join(dirpath, name)
                try:
                    if os.path.getsize(path) > 1 << 20:
                        continue
                    with open(path, "rb") as f:
                        src = f.read()
                    tree = ast.parse(src, path)
                except Exception:
                    continue
                for node in ast.walk(tree):
                    t = TYPES.get(type(node).__name__)
                    if t is None:
                        continue
                    line, col = node.lineno, node.col_offset
                    if t in ("FuncDef", "ClassDef") and getattr(node, "decorator_list", None):
                        pass  # lineno is the def line since 3.8
                    out.write(f"{path}\t{t}\t{line}\t{col}\n")


if __name__ == "__main__":
    main()
