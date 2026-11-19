"""Deterministic Java token normalization independent of learned corpus statistics."""

import tree_sitter_java
from tree_sitter import Language, Parser

JAVA_LANGUAGE = Language(tree_sitter_java.language())
NORMALIZATION = "juliet-java-v1"


def normalize_java(code: str) -> str:
    """Strip comments and method modifiers, mask method names and rename locals.

    API names, operators, type names and literal contents retain their semantics.
    Normalization parses a method inside a wrapper but never compiles or executes it.
    """
    raw = code.encode("utf-8")
    if len(raw) > 65536:
        raise ValueError("Java example exceeds 64 KiB")
    parser = Parser(JAVA_LANGUAGE, timeout_micros=500_000)
    source = raw
    tree = parser.parse(source)
    if tree.root_node.has_error:
        source = b"class TraceWardCorpus {\n" + raw + b"\n}"
        tree = parser.parse(source)
    if tree.root_node.has_error:
        raise ValueError("Cannot normalize invalid Java")
    stack = [tree.root_node]
    nodes = []
    while stack:
        node = stack.pop()
        if len(nodes) >= 100_000:
            raise ValueError("Java token budget exceeded")
        if (
            node.type == "modifiers"
            and node.parent is not None
            and node.parent.type in {"method_declaration", "constructor_declaration"}
        ):
            continue
        nodes.append(node)
        stack.extend(reversed(node.children))
    variable_names = {}
    method_spans = set()
    for node in nodes:
        if node.type in {"method_declaration", "constructor_declaration"}:
            name = node.child_by_field_name("name")
            if name:
                method_spans.add((name.start_byte, name.end_byte))
        if node.type in {"variable_declarator", "formal_parameter", "catch_formal_parameter"}:
            name = node.child_by_field_name("name")
            if name:
                text = source[name.start_byte : name.end_byte].decode()
                variable_names.setdefault(text, f"local{len(variable_names)}")
    tokens = []
    for node in nodes:
        if node.children or node.type in {"line_comment", "block_comment"}:
            continue
        text = source[node.start_byte : node.end_byte].decode("utf-8")
        if (node.start_byte, node.end_byte) in method_spans:
            text = "tracewardMethod"
        elif node.type == "identifier":
            parent = node.parent
            api_name = parent.child_by_field_name("name") if parent else None
            is_api = parent and parent.type == "method_invocation" and api_name == node
            if not is_api:
                text = variable_names.get(text, text)
            if text.startswith("CWE89_SQL_Injection__"):
                text = "TraceWardCase"
        tokens.append(text)
    return " ".join(tokens)
