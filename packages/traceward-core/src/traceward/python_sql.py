"""Bounded syntactic model for untrusted input reaching a SQLite query in Python."""

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


def flask_import(node: Node) -> frozenset[bytes]:
    if (
        node.type != "import_from_statement"
        or text(node.child_by_field_name("module_name")) != b"flask"
    ):
        return frozenset()
    names = [text(name) for name in node.children_by_field_name("name")]
    if not names or len(names) != len(set(names)) or set(names) - {b"Flask", b"request"}:
        return frozenset()
    return frozenset(names)


def function_definition(node: Node) -> Node | None:
    definition = (
        node.child_by_field_name("definition") if node.type == "decorated_definition" else node
    )
    return (
        definition if definition is not None and definition.type == "function_definition" else None
    )


def ambiguous_binding(root: Node, *, module: bool, flask_names: frozenset[bytes]) -> Node | None:
    """Check lexical shadowing, including bindings that occur after a use in a function."""
    protected = {b"input", b"sqlite3"} | flask_names
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
        if module:
            if (function := function_definition(node)) is not None:
                name = function.child_by_field_name("name")
                spelling = unicodedata.normalize("NFKC", text(name).decode()).encode()
                if spelling in protected:
                    return node
                pending.extend(child for child in children(node) if child.type == "decorator")
                continue
            if sqlite_import(node) or flask_import(node):
                continue
        if node.type == "identifier" and text(node) in protected:
            reference = node
            parent = node.parent
            assert parent is not None
            if text(node) == b"request" and parent.type == "attribute":
                continue
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


def request_args(node: Node) -> bool:
    return (
        node.type == "attribute"
        and text(node.child_by_field_name("object")) == b"request"
        and text(node.child_by_field_name("attribute")) == b"args"
    )


@dataclass(frozen=True)
class Value:
    is_string: bool = False
    flow: tuple[FlowNode, ...] = ()
    concatenated: bool = False
    receiver: Literal["Connection", "Cursor"] | None = None
    flask_app: bool = False


@dataclass
class Scope:
    name: str
    sqlite_imported: bool = False
    flask_names: frozenset[bytes] = frozenset()
    values: dict[bytes, Value] = field(default_factory=dict)

    @property
    def flask_request_available(self) -> bool:
        return self.name != "<module>" and b"request" in self.flask_names


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
        flask_names = frozenset(
            name for statement in children(root) for name in flask_import(statement)
        )
        if self.unresolved_scope(root, module=True, flask_names=flask_names):
            return
        self.block(root, Scope("<module>"), module=True)

    def unresolved_scope(self, node: Node, *, module: bool, flask_names: frozenset[bytes]) -> bool:
        ambiguous = ambiguous_binding(node, module=module, flask_names=flask_names)
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
                elif module and (flask_names := flask_import(node)):
                    scope.flask_names |= flask_names
                elif module and node.type == "import_statement":
                    names = children(node)
                    if (
                        len(names) != 1
                        or names[0].type != "dotted_name"
                        or names[0].named_child_count != 1
                    ):
                        raise Unsupported(node, "Expected a single unaliased module import.")
                    scope.values.pop(text(names[0]), None)
                elif module and (function := function_definition(node)) is not None:
                    self.function(node, function, scope)
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

    def function(self, statement: Node, definition: Node, scope: Scope) -> None:
        if statement != definition:
            decorators = [child for child in children(statement) if child.type == "decorator"]
            if len(decorators) != 1 or not self.flask_route(decorators[0], scope):
                raise Unsupported(
                    statement, "Expected one literal route on a local Flask application."
                )
        symbol = text(definition.child_by_field_name("name"))
        scope.values.pop(symbol, None)
        if not self.unresolved_scope(definition, module=False, flask_names=scope.flask_names):
            inner = definition.child_by_field_name("body")
            assert inner is not None
            self.block(inner, Scope(symbol.decode(), scope.sqlite_imported, scope.flask_names))

    def flask_route(self, decorator: Node, scope: Scope) -> bool:
        (expression,) = children(decorator)
        if expression.type != "call":
            return False
        target = expression.child_by_field_name("function")
        arguments = expression.child_by_field_name("arguments")
        if target is None or target.type != "attribute" or arguments is None:
            return False
        owner = text(target.child_by_field_name("object"))
        method = text(target.child_by_field_name("attribute"))
        args = children(arguments)
        return (
            scope.values.get(owner, Value()).flask_app
            and method in {b"get", b"route"}
            and len(args) == 1
            and plain_string(args[0])
        )

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
            # Only a constructor call establishes its receiver.
            return Value() if value.receiver or value.flask_app else value
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
        if node.type == "subscript" and scope.flask_request_available:
            receiver = node.child_by_field_name("value")
            keys = node.children_by_field_name("subscript")
            if (
                receiver is not None
                and request_args(receiver)
                and len(keys) == 1
                and not any(child.type == "," for child in node.children)
                and plain_string(keys[0])
            ):
                return self.source(node, "flask.request.args")
        raise Unsupported(node, "Unsupported Python expression; remaining path skipped.")

    def source(self, node: Node, symbol: str) -> Value:
        step = FlowNode(kind="source", symbol=symbol, location=self.location(node))
        return Value(True, (step,))

    def call(self, node: Node, scope: Scope, depth: int) -> Value:
        target = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        assert target is not None and args is not None
        arguments = children(args)
        if target.type == "identifier" and text(target) == b"input":
            if not arguments or (len(arguments) == 1 and plain_string(arguments[0])):
                return self.source(node, "input")
        if (
            target.type == "identifier"
            and text(target) == b"Flask"
            and b"Flask" in scope.flask_names
            and len(arguments) == 1
            and (plain_string(arguments[0]) or text(arguments[0]) == b"__name__")
        ):
            return Value(flask_app=True)
        if target.type != "attribute":
            raise Unsupported(node, "Unresolved Python call; remaining path skipped.")
        owner = target.child_by_field_name("object")
        method = text(target.child_by_field_name("attribute"))
        if owner is not None and request_args(owner) and method == b"get":
            if (
                scope.flask_request_available
                and 1 <= len(arguments) <= 2
                and all(plain_string(argument) for argument in arguments)
            ):
                return self.source(node, "flask.request.args.get")
            raise Unsupported(node, "Expected imported Flask query arguments with literal strings.")
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
        flask_source = query.flow[0].symbol.startswith("flask.")
        api_scope = (
            "Syntactic API model assumes standard Flask and sqlite3 at runtime."
            if flask_source
            else "Syntactic API model assumes standard builtins and sqlite3 at runtime."
        )
        boundary = (
            "Review the active Flask request context and whether the query argument is present."
            if flask_source
            else "Review reachability and the trust boundary of interactive input."
        )
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
                    uncertainties=[api_scope, boundary],
                ),
            )
        )
