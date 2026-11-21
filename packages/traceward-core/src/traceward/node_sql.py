"""Bounded straight-line analysis of Node.js SQLite query construction."""

import hashlib
import re
from dataclasses import dataclass
from typing import Literal

import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language, Node, Parser

from traceward.models import Detector, Diagnostic, Evidence, Finding, FlowNode, Location
from traceward.registry import NODE_SQL

JAVASCRIPT = Language(tree_sitter_javascript.language())
TYPESCRIPT = Language(tree_sitter_typescript.language_typescript())
TSX = Language(tree_sitter_typescript.language_tsx())

MAX_AST_NODES = 100_000
MAX_TRACE_STEPS = 64
MAX_EXPRESSION_DEPTH = 48
MAX_FINDINGS = 128
DECIMAL_INDEX = re.compile(rb"(?:0|[1-9][0-9]{0,8})")
IDENTIFIERS = {"identifier", "shorthand_property_identifier_pattern", "type_identifier"}


def _nodes(node: Node) -> list[Node]:
    return [child for child in node.named_children if not child.is_extra]


def _text(node: Node | None) -> bytes:
    return (node.text or b"") if node is not None else b""


def _sqlite_import(node: Node) -> bool:
    """Only the exact named value import can establish the constructor."""
    if node.type != "import_statement":
        return False
    source = node.child_by_field_name("source")
    if _text(source) not in {b"'node:sqlite'", b'"node:sqlite"'}:
        return False
    parts = _nodes(node)
    if (
        len(parts) != 2
        or parts[0].type != "import_clause"
        or any(child.type == "type" for child in node.children)
    ):
        return False
    clause = _nodes(parts[0])
    if len(clause) != 1 or clause[0].type != "named_imports":
        return False
    imports = _nodes(clause[0])
    if len(imports) != 1 or imports[0].type != "import_specifier":
        return False
    specifier = imports[0]
    return _text(specifier.child_by_field_name("name")) == b"DatabaseSync" and not any(
        child.type in {"as", "type"} for child in specifier.children
    )


def _optional(node: Node) -> bool:
    # Tree-sitter JavaScript names this token. The TypeScript grammar uses punctuation.
    return any(child.type in {"?.", "optional_chain"} for child in node.children)


def _ambiguous_binding(root: Node) -> Node | None:
    """Reject shadowing even when its declaration is later in the top-level file."""
    imports = False
    declarations: set[bytes] = set()
    pending = [root]
    while pending:
        node = pending.pop()
        parent = node.parent
        if parent == root:
            if _sqlite_import(node):
                if imports:
                    return node
                imports = True
                continue
            if node.type == "lexical_declaration":
                for declarator in _nodes(node):
                    name = declarator.child_by_field_name("name")
                    if name is not None and name.type == "identifier":
                        symbol = _text(name)
                        if symbol in declarations:
                            return name
                        declarations.add(symbol)
        if node.type in IDENTIFIERS:
            spelling = _text(node)
            if b"\\" in spelling:
                return node  # Escaped identifiers can spell reserved bindings.
            if spelling == b"process":
                if not (
                    parent is not None
                    and parent.type == "member_expression"
                    and parent.child_by_field_name("object") == node
                    and _text(parent.child_by_field_name("property")) == b"argv"
                ):
                    return node
            if spelling == b"DatabaseSync":
                if not (
                    parent is not None
                    and (
                        parent.type == "type_annotation"
                        or (
                            parent.type == "new_expression"
                            and parent.child_by_field_name("constructor") == node
                        )
                    )
                ):
                    return node
        pending.extend(reversed(node.named_children))
    return None


@dataclass(frozen=True)
class Value:
    kind: Literal["string", "database", "statement", "unknown"] = "unknown"
    flow: tuple[FlowNode, ...] = ()
    concatenated: bool = False


class Unsupported(Exception):
    def __init__(self, node: Node, message: str, code: str = "UNSUPPORTED_FLOW"):
        self.node = node
        self.message = message
        self.code = code


class NodeSqlAnalysis:
    def __init__(self, data: bytes, path: str, language: str):
        self.data = data
        self.path = path
        self.language = language
        self.rule = NODE_SQL[language]
        self.findings: list[Finding] = []
        self.diagnostics: list[Diagnostic] = []
        self.values: dict[bytes, Value] = {}
        self.sqlite_imported = False
        self.occurrences: dict[bytes, int] = {}

    def location(self, node: Node) -> Location:
        return Location(
            path=self.path,
            start_line=node.start_point.row + 1,
            start_column=node.start_point.column + 1,
            end_line=node.end_point.row + 1,
            end_column=node.end_point.column + 1,
        )

    def analyze(self) -> None:
        grammar = JAVASCRIPT
        if self.language == "typescript":
            grammar = TSX if self.path.lower().endswith(".tsx") else TYPESCRIPT
        try:
            root = Parser(grammar, timeout_micros=500_000).parse(self.data).root_node
        except ValueError:
            self.diagnostics.append(
                Diagnostic(code="PARSE_TIMEOUT", message="Node.js parser timed out.", level="error")
            )
            return
        if root.descendant_count > MAX_AST_NODES:
            self.diagnostics.append(
                Diagnostic(
                    code="AST_LIMIT",
                    message="Node.js AST exceeds the node budget.",
                    level="error",
                )
            )
            return
        if root.has_error:
            node = root
            while not node.is_missing and not node.is_error:
                child = next((child for child in node.children if child.has_error), None)
                if child is None:
                    break
                node = child
            self.diagnostics.append(
                Diagnostic(
                    code="PARSE_ERROR",
                    message="Invalid JavaScript or TypeScript syntax; file skipped.",
                    level="error",
                    location=self.location(node),
                )
            )
            return
        ambiguous = _ambiguous_binding(root)
        if ambiguous is not None:
            self.diagnostics.append(
                Diagnostic(
                    code="UNRESOLVED_BINDING",
                    message="Cannot resolve Node.js bindings in this scope.",
                    location=self.location(ambiguous),
                )
            )
            return
        try:
            for statement in _nodes(root):
                self.statement(statement)
        except Unsupported as error:
            self.diagnostics.append(
                Diagnostic(
                    code=error.code, message=error.message, location=self.location(error.node)
                )
            )

    def statement(self, node: Node) -> None:
        if _sqlite_import(node):
            self.sqlite_imported = True
        elif (
            node.type == "lexical_declaration"
            and _text(node.child_by_field_name("kind")) == b"const"
        ):
            for declaration in _nodes(node):
                self.declare(declaration)
        elif node.type == "expression_statement":
            (expression,) = _nodes(node)
            self.evaluate(expression)
        elif node.type not in {"empty_statement", "hash_bang_line"}:
            raise Unsupported(node, "Unsupported top-level statement; remaining path skipped.")

    def declare(self, node: Node) -> None:
        name = node.child_by_field_name("name")
        init = node.child_by_field_name("value")
        if name is None or name.type != "identifier" or init is None:
            raise Unsupported(node, "Expected a simple initialized const declaration.")
        symbol = _text(name)
        if len(symbol) > 128:
            raise Unsupported(name, "Local identifier exceeds the limit.", "ANALYSIS_LIMIT")
        value = self.evaluate(init)
        if value.flow:
            value = self.extend(value, name, "assignment", symbol.decode())
        self.values[symbol] = value

    def extend(
        self, value: Value, node: Node, kind: Literal["assignment", "concatenation"], symbol: str
    ) -> Value:
        if len(value.flow) >= MAX_TRACE_STEPS - 1:
            raise Unsupported(node, "Node.js flow exceeds the evidence budget.", "ANALYSIS_LIMIT")
        step = FlowNode(kind=kind, symbol=symbol, location=self.location(node))
        return Value("string", (*value.flow, step), value.concatenated or kind == "concatenation")

    def evaluate(self, node: Node, depth: int = 0) -> Value:
        if depth > MAX_EXPRESSION_DEPTH:
            raise Unsupported(
                node, "Node.js expression nesting exceeds the limit.", "ANALYSIS_LIMIT"
            )
        if node.type == "identifier":
            value = self.values.get(_text(node))
            if value is not None:
                # Connections and statements must be assigned directly from their creation call.
                return value if value.kind == "string" else Value()
        if node.type == "string":
            return Value("string")
        if node.type == "template_string" and not any(
            child.type == "template_substitution" for child in _nodes(node)
        ):
            return Value("string")
        if node.type in {"number", "true", "false", "null"}:
            return Value()
        if node.type == "subscript_expression":
            return self.argv(node)
        if node.type == "parenthesized_expression":
            return self.evaluate(_nodes(node)[0], depth + 1)
        if node.type == "binary_expression" and _text(node.child_by_field_name("operator")) == b"+":
            left, right = _nodes(node)
            lhs = self.evaluate(left, depth + 1)
            rhs = self.evaluate(right, depth + 1)
            if lhs.kind != "string" or rhs.kind != "string":
                raise Unsupported(node, "Expected two known strings for concatenation.")
            tainted = lhs if lhs.flow else rhs
            return self.extend(tainted, node, "concatenation", "+") if tainted.flow else tainted
        if node.type == "new_expression":
            return self.new_database(node)
        if node.type == "call_expression":
            return self.call(node, depth)
        raise Unsupported(node, "Unsupported Node.js expression; remaining path skipped.")

    def argv(self, node: Node) -> Value:
        receiver = node.child_by_field_name("object")
        index = node.child_by_field_name("index")
        decimal = _text(index)
        if (
            not _optional(node)
            and receiver is not None
            and receiver.type == "member_expression"
            and not _optional(receiver)
            and _text(receiver.child_by_field_name("object")) == b"process"
            and _text(receiver.child_by_field_name("property")) == b"argv"
            and DECIMAL_INDEX.fullmatch(decimal)
        ):
            if int(decimal) < 2:  # The first two entries describe Node and the entry point.
                return Value("string")
            step = FlowNode(kind="source", symbol="process.argv", location=self.location(node))
            return Value("string", (step,))
        raise Unsupported(node, "Expected process.argv with a literal decimal index.")

    def new_database(self, node: Node) -> Value:
        args = node.child_by_field_name("arguments")
        arguments = _nodes(args) if args is not None else []
        if (
            self.sqlite_imported
            and _text(node.child_by_field_name("constructor")) == b"DatabaseSync"
            and len(arguments) == 1
            and arguments[0].type == "string"
            and node.child_by_field_name("type_arguments") is None
        ):
            return Value("database")
        raise Unsupported(node, "Expected new DatabaseSync with one literal database path.")

    def call(self, node: Node, depth: int) -> Value:
        target = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if (
            target is None
            or target.type != "member_expression"
            or args is None
            or args.type != "arguments"
            or _optional(node)
            or _optional(target)
            or node.child_by_field_name("type_arguments") is not None
        ):
            raise Unsupported(node, "Expected a direct SQLite method call.")
        name = target.child_by_field_name("object")
        method = _text(target.child_by_field_name("property"))
        receiver = self.values.get(_text(name)) if name and name.type == "identifier" else None
        arguments = _nodes(args)
        if receiver is not None and receiver.kind == "database" and method in {b"prepare", b"exec"}:
            if len(arguments) != 1:
                raise Unsupported(node, "Expected one SQL argument to the SQLite method.")
            query = self.evaluate(arguments[0], depth + 1)
            if query.kind != "string":
                raise Unsupported(arguments[0], "Cannot establish a string SQL argument.")
            if query.concatenated:
                self.emit(node, query, f"node:sqlite.DatabaseSync.{method.decode()}")
            return Value("statement") if method == b"prepare" else Value()
        if (
            receiver is not None
            and receiver.kind == "statement"
            and method in {b"run", b"get", b"all", b"iterate"}
        ):
            # Positional binding passes values separately; no query-text sink.
            for parameter in arguments:
                self.evaluate(parameter, depth + 1)
            return Value()
        raise Unsupported(node, "Cannot resolve a supported SQLite receiver and method.")

    def emit(self, sink: Node, query: Value, symbol: str) -> None:
        if len(self.findings) >= MAX_FINDINGS:
            raise Unsupported(sink, "Node.js result budget reached.", "ANALYSIS_LIMIT")
        rule = self.rule
        identity = hashlib.sha256(
            b"\0".join(
                (rule.id.encode(), self.path.encode("utf-8", "surrogateescape"), _text(sink))
            )
        ).digest()
        ordinal = self.occurrences.get(identity, 0)
        self.occurrences[identity] = ordinal + 1
        digest = hashlib.sha256(identity + ordinal.to_bytes(4, "big")).hexdigest()
        location = self.location(sink)
        self.findings.append(
            Finding(
                id=f"tw_{digest[:16]}",
                fingerprint=f"sha256:{digest}",
                rule_id=rule.id,
                cwe=[rule.cwe],
                title=rule.title,
                detectors=[Detector(id=rule.id, version=rule.version)],
                guidance=rule.guidance,
                references=[rule.reference],
                location=location,
                evidence=Evidence(
                    source=query.flow[0].location,
                    sink=location,
                    flow=[*query.flow, FlowNode(kind="sink", symbol=symbol, location=location)],
                    uncertainties=[
                        "The syntactic model assumes the standard Node.js process and SQLite APIs.",
                        "Review reachability and who controls these command-line arguments.",
                    ],
                ),
            )
        )
