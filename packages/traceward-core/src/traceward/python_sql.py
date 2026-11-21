"""Bounded syntactic model for interactive input reaching a SQLite query in Python."""

import hashlib
import unicodedata
from dataclasses import dataclass, field
from typing import Literal

import tree_sitter_python
from tree_sitter import Language, Node, Parser

from traceward.models import Detector, Diagnostic, Evidence, Finding, FlowNode, Location
from traceward.registry import PYTHON_SQL

PYTHON = Language(tree_sitter_python.language())


def children(node: Node) -> list[Node]:
    return [child for child in node.named_children if not child.is_extra]


def text(node: Node | None) -> bytes:
    return (node.text or b"") if node is not None else b""


def sqlite_import(node: Node) -> bool:
    names = children(node) if node.type == "import_statement" else []
    return len(names) == 1 and names[0].type == "dotted_name" and text(names[0]) == b"sqlite3"


def ambiguous_binding(root: Node, *, module: bool) -> Node | None:
    """Check lexical shadowing, including bindings that occur after a use in a function."""
    pending = [root]
    while pending:
        node = pending.pop()
        # Python normalizes identifiers before binding. Refuse ambiguous spellings
        # so e.g. a compatibility character cannot hide a receiver reassignment.
        if node.type == "identifier":
            spelling = text(node)
            if not spelling.isascii() and not unicodedata.is_normalized("NFKC", spelling.decode()):
                return node
        if node.type == "wildcard_import":
            return node
        if module and node.type == "function_definition":
            name = node.child_by_field_name("name")
            if unicodedata.normalize("NFKC", text(name).decode()) in {"input", "sqlite3"}:
                return node
            continue
        if module and sqlite_import(node):
            continue
        if node.type == "identifier" and text(node) in {b"input", b"sqlite3"}:
            reference = node
            parent = node.parent
            assert parent is not None
            if text(node) == b"sqlite3" and parent.type == "attribute":
                if parent.child_by_field_name("object") == node:
                    reference, parent = parent, parent.parent
            if (
                parent is None
                or parent.type != "call"
                or parent.child_by_field_name("function") != reference
            ):
                return node
        pending.extend(node.named_children)
    return None


def plain_string(node: Node) -> bool:
    if node.type != "string":
        return False
    prefix = text(node.named_child(0)).lower().rstrip(b"\"'")
    return prefix in {b"", b"u", b"r"}


@dataclass(frozen=True)
class Value:
    is_string: bool = False
    flow: tuple[FlowNode, ...] = ()
    concatenated: bool = False
    receiver: Literal["Connection", "Cursor"] | None = None


@dataclass
class Scope:
    name: str
    sqlite_imported: bool = False
    values: dict[bytes, Value] = field(default_factory=dict)


class Unsupported(Exception):
    def __init__(self, node: Node, message: str):
        self.node = node
        self.message = message


class PythonAnalysis:
    def __init__(self, data: bytes, path: str):
        self.data = data
        self.path = path
        self.findings: list[Finding] = []
        self.diagnostics: list[Diagnostic] = []
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
        try:
            root = Parser(PYTHON, timeout_micros=500_000).parse(self.data).root_node
        except ValueError:
            self.diagnostics.append(
                Diagnostic(
                    code="PARSE_TIMEOUT",
                    message="Python parser exceeded its time budget.",
                    level="error",
                )
            )
            return
        if root.descendant_count > 100_000:
            self.diagnostics.append(
                Diagnostic(
                    code="AST_LIMIT", message="Python AST exceeds 100,000 nodes.", level="error"
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
                    message="Invalid Python syntax; file skipped.",
                    level="error",
                    location=self.location(node),
                )
            )
            return
        if self.unresolved_scope(root, module=True):
            return
        self.block(root, Scope("<module>"), module=True)

    def unresolved_scope(self, node: Node, *, module: bool) -> bool:
        ambiguous = ambiguous_binding(node, module=module)
        if ambiguous is None:
            return False
        self.diagnostics.append(
            Diagnostic(
                code="UNRESOLVED_BINDING",
                message="Python name resolution is ambiguous in this scope.",
                location=self.location(ambiguous),
            )
        )
        return True

    def block(self, body: Node, scope: Scope, *, module: bool = False) -> None:
        for node in children(body):
            if len(self.findings) >= 128 or len(self.diagnostics) >= 64:
                if not self.diagnostics or self.diagnostics[-1].code != "ANALYSIS_LIMIT":
                    self.diagnostics.append(
                        Diagnostic(
                            code="ANALYSIS_LIMIT",
                            message="Python result budget reached.",
                            location=self.location(node),
                        )
                    )
                return
            try:
                if module and sqlite_import(node):
                    scope.sqlite_imported = True
                elif module and node.type == "import_statement":
                    names = children(node)
                    if (
                        len(names) != 1
                        or names[0].type != "dotted_name"
                        or names[0].named_child_count != 1
                    ):
                        raise Unsupported(node, "Expected a single unaliased module import.")
                    scope.values.pop(text(names[0]), None)
                elif module and node.type == "function_definition":
                    symbol = text(node.child_by_field_name("name"))
                    scope.values.pop(symbol, None)
                    if not self.unresolved_scope(node, module=False):
                        inner = node.child_by_field_name("body")
                        assert inner is not None
                        self.block(inner, Scope(symbol.decode(), scope.sqlite_imported))
                elif node.type == "expression_statement":
                    expressions = children(node)
                    if len(expressions) != 1:
                        raise Unsupported(node, "Expected a single expression statement.")
                    expression = expressions[0]
                    if expression.type == "assignment":
                        self.assign(expression, scope)
                    else:
                        self.evaluate(expression, scope)
                elif node.type == "return_statement" and not module:
                    for value in children(node):
                        self.evaluate(value, scope)
                    return
                elif node.type != "pass_statement":
                    raise Unsupported(node, "Unsupported statement; remaining Python path skipped.")
            except Unsupported as error:
                self.diagnostics.append(
                    Diagnostic(
                        code="UNSUPPORTED_FLOW",
                        message=error.message,
                        location=self.location(error.node),
                    )
                )
                return

    def assign(self, node: Node, scope: Scope) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if (
            left is None
            or left.type != "identifier"
            or right is None
            or left.end_byte - left.start_byte > 128
        ):
            raise Unsupported(node, "Expected a local name and a simple assignment.")
        name = text(left)
        value = self.evaluate(right, scope)
        if value.flow:
            value = self.extend(
                value,
                FlowNode(kind="assignment", symbol=name.decode(), location=self.location(left)),
                left,
            )
        scope.values[name] = value

    def extend(self, value: Value, step: FlowNode, node: Node) -> Value:
        if len(value.flow) >= 64:
            raise Unsupported(node, "Python flow exceeds the 64-step evidence budget.")
        return Value(True, (*value.flow, step), value.concatenated or step.kind == "concatenation")

    def evaluate(self, node: Node, scope: Scope, depth: int = 0) -> Value:
        if depth > 48:
            raise Unsupported(node, "Python expression nesting exceeds 48 levels.")
        if node.type == "identifier":
            value = scope.values.get(text(node), Value())
            # Only a constructor call establishes a receiver. Drop receiver aliases.
            return Value() if value.receiver else value
        if plain_string(node):
            return Value(is_string=True)
        if node.type in {"integer", "none", "true", "false"}:
            return Value()
        if node.type == "parenthesized_expression":
            return self.evaluate(children(node)[0], scope, depth + 1)
        if node.type == "binary_operator" and text(node.child_by_field_name("operator")) == b"+":
            left, right = children(node)
            lhs = self.evaluate(left, scope, depth + 1)
            rhs = self.evaluate(right, scope, depth + 1)
            if not lhs.is_string or not rhs.is_string:
                raise Unsupported(node, "Cannot establish two string operands for concatenation.")
            value = lhs if lhs.flow else rhs
            if value.flow:
                value = self.extend(
                    value,
                    FlowNode(kind="concatenation", symbol="+", location=self.location(node)),
                    node,
                )
            return value
        if node.type == "call":
            return self.call(node, scope, depth)
        raise Unsupported(node, "Unsupported Python expression; remaining path skipped.")

    def call(self, node: Node, scope: Scope, depth: int) -> Value:
        target = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        assert target is not None and args is not None
        arguments = children(args)
        if target.type == "identifier" and text(target) == b"input":
            if not arguments or (len(arguments) == 1 and plain_string(arguments[0])):
                return Value(
                    True, (FlowNode(kind="source", symbol="input", location=self.location(node)),)
                )
        if target.type != "attribute":
            raise Unsupported(node, "Unresolved Python call; remaining path skipped.")
        owner = target.child_by_field_name("object")
        method = text(target.child_by_field_name("attribute"))
        if owner is None or owner.type != "identifier":
            raise Unsupported(node, "Expected a local SQLite receiver.")
        name = text(owner)
        if name == b"sqlite3" and method == b"connect":
            if not scope.sqlite_imported or len(arguments) != 1 or not plain_string(arguments[0]):
                raise Unsupported(
                    node, "Expected an imported sqlite3.connect with one literal database name."
                )
            return Value(receiver="Connection")
        receiver = scope.values.get(name, Value()).receiver
        if receiver == "Connection" and method == b"cursor":
            if arguments:
                raise Unsupported(node, "Cursor factories are unsupported.")
            return Value(receiver="Cursor")
        if receiver and method == b"execute":
            if len(arguments) == 2:
                bindings = arguments[1]
                if bindings.type not in {"tuple", "list"} or any(
                    arg.type != "identifier" and not plain_string(arg) and arg.type != "integer"
                    for arg in children(bindings)
                ):
                    raise Unsupported(bindings, "Expected simple positional parameter bindings.")
            elif len(arguments) != 1:
                raise Unsupported(node, "Unsupported SQLite execute arguments.")
            query = self.evaluate(arguments[0], scope, depth + 1)
            if query.concatenated:
                self.emit(scope, node, query, f"sqlite3.{receiver}.execute")
            return Value()
        raise Unsupported(node, "Unresolved Python call; remaining path skipped.")

    def emit(self, scope: Scope, sink: Node, query: Value, symbol: str) -> None:
        rule = PYTHON_SQL
        identity = hashlib.sha256(
            b"\0".join(
                (
                    rule.id.encode(),
                    self.path.encode("utf-8", "surrogateescape"),
                    scope.name.encode(),
                    text(sink),
                )
            )
        ).digest()
        ordinal = self.occurrences.get(identity, 0)
        self.occurrences[identity] = ordinal + 1
        digest = hashlib.sha256(identity + ordinal.to_bytes(4, "big")).hexdigest()
        location = self.location(sink)
        flow = [
            *query.flow,
            FlowNode(kind="sink", symbol=symbol, location=location),
        ]
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
                    source=flow[0].location,
                    sink=location,
                    flow=flow,
                    uncertainties=[
                        "Syntactic API model assumes standard builtins and sqlite3 at runtime.",
                        "Review reachability and the trust boundary of interactive input.",
                    ],
                ),
            )
        )
