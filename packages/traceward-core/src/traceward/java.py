"""Bounded Tree-sitter Java parsing and conservative straight-line local flow.

This is an experimental syntactic API model, not Java type resolution. The scanner
never executes input, resolves dependencies, or treats SQL-looking text as evidence.
"""

import hashlib
from dataclasses import dataclass

import tree_sitter_java
from tree_sitter import Language, Node, Parser

from traceward.models import Diagnostic, Evidence, Finding, FlowNode, Location

JAVA = Language(tree_sitter_java.language())
RULE = "java.sql.concatenated-untrusted-input"
REQUEST_TYPES = {"HttpServletRequest", "ServletRequest"}
JDBC_TYPES = {"Statement", "Connection", "PreparedStatement"}


def walk(node: Node, limit: int = 100_000) -> list[Node]:
    result = []
    pending = [node]
    while pending:
        current = pending.pop()
        result.append(current)
        if len(result) > limit:
            break
        pending.extend(reversed(current.named_children))
    return result


@dataclass(frozen=True)
class AnalysisUnit:
    name: str
    location: Location


@dataclass(frozen=True)
class CallSite:
    name: str
    location: Location


@dataclass(frozen=True)
class Value:
    flow: tuple[FlowNode, ...] = ()
    concatenated: bool = False


class JavaAnalysis:
    def __init__(self, code: bytes, path: str):
        self.code = code
        self.path = path
        self.findings: list[Finding] = []
        self.diagnostics: list[Diagnostic] = []
        self.units: list[AnalysisUnit] = []
        self.calls: list[CallSite] = []
        self.values: dict[str, Value] = {}
        self.types: dict[str, str] = {}
        self.method = ""
        self.occurrences: dict[str, int] = {}

    def text(self, node: Node | None) -> str:
        return self.code[node.start_byte : node.end_byte].decode("utf-8") if node else ""

    def location(self, node: Node) -> Location:
        return Location(
            path=self.path,
            start_line=node.start_point.row + 1,
            start_column=node.start_point.column + 1,
            end_line=node.end_point.row + 1,
            end_column=node.end_point.column + 1,
        )

    def analyze(self) -> None:
        # Native parser budget, in addition to source-byte and AST-node limits.
        parser = Parser(JAVA, timeout_micros=500_000)
        try:
            tree = parser.parse(self.code)
        except ValueError:
            self.diagnostics.append(
                Diagnostic(
                    code="PARSE_TIMEOUT",
                    message="Java parser exceeded its resource budget.",
                    level="error",
                )
            )
            return
        nodes = walk(tree.root_node)
        if len(nodes) > 100_000:
            self.diagnostics.append(
                Diagnostic(
                    code="AST_LIMIT",
                    message="Java AST exceeds 100,000 nodes.",
                    level="error",
                )
            )
            return
        if tree.root_node.has_error:
            errors = [n for n in nodes if n.type == "ERROR" or n.is_missing]
            self.diagnostics.extend(
                Diagnostic(
                    code="PARSE_ERROR",
                    message="Invalid Java syntax; this file was not analyzed.",
                    level="error",
                    location=self.location(n),
                )
                for n in errors[:10]
            )
            return
        for node in nodes:
            if node.type == "method_invocation":
                self.calls.append(
                    CallSite(
                        self.text(node.child_by_field_name("name")),
                        self.location(node),
                    )
                )
            if node.type not in {"method_declaration", "constructor_declaration"}:
                continue
            self.values = {}
            self.types = {}
            name = self.text(node.child_by_field_name("name"))
            params = node.child_by_field_name("parameters")
            self.method = name + self.text(params)
            self.units.append(AnalysisUnit(name, self.location(node)))
            if params:
                for param in params.named_children:
                    symbol = self.text(param.child_by_field_name("name"))
                    self.types[symbol] = self.text(param.child_by_field_name("type")).split(".")[-1]
            body = node.child_by_field_name("body")
            if body:
                self.block(body)

    def block(self, block: Node) -> None:
        for statement in block.named_children:
            if statement.type == "local_variable_declaration":
                typename = self.text(statement.child_by_field_name("type")).split(".")[-1]
                for decl in statement.named_children:
                    if decl.type == "variable_declarator":
                        name = self.text(decl.child_by_field_name("name"))
                        value = decl.child_by_field_name("value")
                        self.assign(name, self.evaluate(value), decl)
                        self.types[name] = typename
            elif statement.type in {"expression_statement", "return_statement", "throw_statement"}:
                for expression in statement.named_children:
                    self.evaluate(expression)
                if statement.type in {"return_statement", "throw_statement"}:
                    break
            elif statement.type in {"line_comment", "block_comment", "empty_statement"}:
                continue
            else:
                self.diagnostics.append(
                    Diagnostic(
                        code="UNSUPPORTED_FLOW",
                        message="Unsupported control flow or scope; remaining method skipped.",
                        location=self.location(statement),
                    )
                )
                break

    def assign(self, name: str, value: Value, node: Node) -> Value:
        if value.flow:
            value = Value(
                value.flow
                + (
                    FlowNode(
                        kind="assignment",
                        location=self.location(node),
                        symbol=name,
                    ),
                ),
                value.concatenated,
            )
        self.values[name] = value
        return value

    def evaluate(self, node: Node | None, depth: int = 0) -> Value:
        if node is None:
            return Value()
        if depth > 128:
            self.diagnostics.append(
                Diagnostic(
                    code="EXPRESSION_LIMIT",
                    message="Expression nesting limit reached.",
                    location=self.location(node),
                )
            )
            return Value()
        if node.type == "identifier":
            return self.values.get(self.text(node), Value())
        if node.type == "parenthesized_expression":
            return self.evaluate(node.named_children[0], depth + 1)
        if node.type == "binary_expression":
            left = self.evaluate(node.child_by_field_name("left"), depth + 1)
            right = self.evaluate(node.child_by_field_name("right"), depth + 1)
            flow = left.flow or right.flow
            if self.text(node.child_by_field_name("operator")) == "+" and flow:
                return Value(
                    flow
                    + (
                        FlowNode(
                            kind="concatenation",
                            location=self.location(node),
                            symbol="+",
                        ),
                    ),
                    True,
                )
            return Value()
        if node.type == "assignment_expression":
            target = node.child_by_field_name("left")
            value = self.evaluate(node.child_by_field_name("right"), depth + 1)
            op = self.text(node.child_by_field_name("operator"))
            name = self.text(target)
            if target and target.type == "identifier":
                if op == "+=":
                    previous = self.values.get(name, Value())
                    flow = previous.flow or value.flow
                    if flow:
                        flow += (
                            FlowNode(
                                kind="concatenation",
                                location=self.location(node),
                                symbol="+=",
                            ),
                        )
                    value = Value(flow, bool(flow))
                elif op != "=":
                    value = Value()
                return self.assign(name, value, node)
            return Value()
        if node.type == "method_invocation":
            receiver = self.text(node.child_by_field_name("object"))
            name = self.text(node.child_by_field_name("name"))
            args = node.child_by_field_name("arguments")
            values = [self.evaluate(arg, depth + 1) for arg in args.named_children] if args else []
            receiver_type = self.types.get(receiver)
            if receiver_type in REQUEST_TYPES and name in {"getParameter", "getHeader"}:
                return Value(
                    (
                        FlowNode(
                            kind="source",
                            location=self.location(node),
                            symbol=f"{receiver_type}.{name}",
                        ),
                    )
                )
            is_sink = (
                receiver_type == "Statement"
                and name in {"executeQuery", "executeUpdate", "execute", "addBatch"}
            ) or (receiver_type == "Connection" and name in {"prepareStatement", "prepareCall"})
            if is_sink and values and values[0].flow and values[0].concatenated:
                self.emit(node, values[0], f"{receiver_type}.{name}")
            if any(value.flow for value in values):
                if not is_sink and not (
                    receiver_type == "PreparedStatement" and name.startswith("set")
                ):
                    self.diagnostics.append(
                        Diagnostic(
                            code="UNRESOLVED_CALL",
                            message="Tainted argument crosses an unmodeled call.",
                            location=self.location(node),
                        )
                    )
            return Value()
        if node.type in {
            "string_literal",
            "character_literal",
            "decimal_integer_literal",
            "null_literal",
            "true",
            "false",
        }:
            return Value()
        # Visit calls in unfamiliar expressions, without inventing propagation semantics.
        values = [self.evaluate(child, depth + 1) for child in node.named_children]
        if any(v.flow for v in values):
            self.diagnostics.append(
                Diagnostic(
                    code="UNSUPPORTED_EXPRESSION",
                    message="Flow through this expression is unsupported.",
                    location=self.location(node),
                )
            )
        return Value()

    def emit(self, sink: Node, value: Value, symbol: str) -> None:
        # Content-derived, root-relative and stable across scan IDs and absolute roots.
        key = "\0".join((self.path, self.method, self.text(sink)))
        occurrence = self.occurrences.get(key, 0)
        self.occurrences[key] = occurrence + 1
        digest = hashlib.sha256(f"{RULE}\0{key}\0{occurrence}".encode()).hexdigest()
        location = self.location(sink)
        flow = list(value.flow) + [FlowNode(kind="sink", location=location, symbol=symbol)]
        self.findings.append(
            Finding(
                id=f"tw_{digest[:16]}",
                fingerprint=f"sha256:{digest}",
                location=location,
                evidence=Evidence(
                    source=flow[0].location,
                    sink=location,
                    flow=flow,
                    uncertainties=[
                        "Receiver types are syntactic; Java imports and dispatch are not resolved.",
                        "Only straight-line method-local evidence; exploitability requires review.",
                    ],
                ),
            )
        )
