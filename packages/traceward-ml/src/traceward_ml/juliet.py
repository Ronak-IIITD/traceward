"""Extract upstream-labeled, self-contained Juliet Java CWE-89 entry methods.

Labels describe synthetic test intent. They are accepted only for generated
single-file cases with a recognized source/sink filename and matching header.
Helpers requiring caller context and methods delegating their sink are omitted.
No Java is compiled, loaded or executed.
"""

import os
import re
import stat
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from traceward.java import JAVA, walk
from tree_sitter import Node, Parser

from traceward_ml.dataset import sha256

SOURCE_FAMILIES = frozenset(
    {
        "Environment",
        "File",
        "PropertiesFile",
        "Property",
        "URLConnection",
        "connect_tcp",
        "console_readLine",
        "database",
        "getCookies_Servlet",
        "getParameter_Servlet",
        "getQueryString_Servlet",
        "listen_tcp",
    }
)
SINKS = frozenset({"execute", "executeBatch", "executeQuery", "executeUpdate", "prepareStatement"})
CASE_NAME = re.compile(
    r"^CWE89_SQL_Injection__(?P<family>.+)_(?P<sink>executeBatch|executeQuery|executeUpdate|execute|prepareStatement)_(?P<variant>\d{2})$"
)
SAFE_ENTRY = re.compile(r"^good(?:B2G|G2B)\d*$")
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_FILES = 10000


def _text(source: bytes, node: Node | None) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8") if node else ""


def _diagnostic(path: str, code: str, message: str, line: int | None = None) -> dict[str, Any]:
    return {"source_path": path, "code": code, "message": message, "line": line}


def _direct_nodes(node: Node) -> list[Node]:
    """Exclude nested classes/methods so their sinks cannot label an outer method."""
    output = []
    pending = list(reversed(node.named_children))
    while pending:
        current = pending.pop()
        if current.type in {"method_declaration", "class_declaration", "class_body"}:
            continue
        output.append(current)
        if len(output) > 100000:
            raise ValueError("Method AST exceeds 100,000 nodes")
        pending.extend(reversed(current.named_children))
    return output


def load_flaw_manifest(root: Path) -> tuple[dict[str, frozenset[int]], str]:
    """Read the bounded authoritative per-file CWE-89 flaw-line metadata."""
    candidates = [root / "Java/manifest.xml", root / "manifest.xml"]
    manifests = [path for path in candidates if path.is_file() and not path.is_symlink()]
    if len(manifests) != 1:
        raise ValueError("Expected exactly one verified Juliet Java manifest.xml")
    with manifests[0].open("rb") as stream:
        content = stream.read(10 * 1024 * 1024 + 1)
    if len(content) > 10 * 1024 * 1024 or b"<!DOCTYPE" in content or b"<!ENTITY" in content:
        raise ValueError("Juliet manifest exceeds limits or declares entities")
    try:
        files = list(ET.fromstring(content).iter("file"))
    except ET.ParseError as exc:
        # The pinned release has unmatched testcase closing tags outside CWE-89.
        # Read its intact CWE-89 file elements independently, without repairing labels.
        if sha256(content) != "e0227dee176a75d56aee13482bea309dc78fdfc707762bb7ce42336e7ef6045b":
            raise ValueError("Unrecognized malformed Juliet manifest") from exc
        fragments = re.findall(
            rb'(?m)^    <file path="CWE89_SQL_Injection__[A-Za-z0-9_]+\.java"'
            rb"(?:/>|>[^<]*(?:<flaw [^<>]+/>[^<]*)*</file>)",
            content,
        )
        if len(fragments) != content.count(b'<file path="CWE89_SQL_Injection__'):
            raise ValueError("CWE-89 XML records are incomplete") from exc
        files = [ET.fromstring(fragment) for fragment in fragments]
    output: dict[str, frozenset[int]] = {}
    for file in files:
        name = file.get("path", "")
        if not name.startswith("CWE89_SQL_Injection__") or not name.endswith(".java"):
            continue
        if Path(name).name != name or name in output:
            raise ValueError("Juliet manifest has ambiguous source filenames")
        lines = []
        for flaw in file.findall("flaw"):
            if not flaw.get("name", "").startswith(("CWE-089:", "CWE-89:")):
                continue
            line = int(flaw.attrib["line"])
            if line < 1:
                raise ValueError("Juliet manifest has an invalid flaw line")
            lines.append(line)
        output[name] = frozenset(lines)
    if not output:
        raise ValueError("Juliet manifest has no CWE-89 metadata")
    return output, sha256(content)


def extract_file(
    source: bytes, source_path: str, flaw_lines: frozenset[int], manifest_sha256: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Extract exact method bytes and provenance, without inventing missing labels."""
    path = Path(source_path)
    if not flaw_lines:
        return [], [
            _diagnostic(
                source_path,
                "MISSING_FLAW_METADATA",
                "No authoritative CWE-89 flaw lines for this file.",
            )
        ]
    match = CASE_NAME.fullmatch(path.stem)
    if match is None or match["family"] not in SOURCE_FAMILIES:
        return [], [
            _diagnostic(
                source_path, "UNSUPPORTED_CASE", "Not a recognized single-file CWE-89 case."
            )
        ]
    if len(source) > MAX_SOURCE_BYTES or b"\0" in source:
        return [], [
            _diagnostic(
                source_path, "INVALID_SOURCE", "Source exceeds limits or contains NUL bytes."
            )
        ]
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError:
        return [], [_diagnostic(source_path, "INVALID_ENCODING", "Expected UTF-8 source.")]
    header = text[:4096]
    if (
        "TEMPLATE GENERATED TESTCASE FILE" not in header
        or f"Filename: {path.name}" not in header
        or not re.search(r"CWE:\s*89\s+SQL Injection", header)
        or not re.search(r"BadSource:\s*" + re.escape(match["family"]) + r"\b", header)
    ):
        return [], [
            _diagnostic(
                source_path,
                "UNVERIFIED_LABEL_HEADER",
                "Generated-case provenance does not match the filename.",
            )
        ]
    parser = Parser(JAVA, timeout_micros=500000)
    try:
        tree = parser.parse(source)
    except ValueError:
        return [], [
            _diagnostic(source_path, "PARSE_TIMEOUT", "Java parser exhausted its time budget.")
        ]
    nodes = walk(tree.root_node)
    if len(nodes) > 100000:
        return [], [_diagnostic(source_path, "AST_LIMIT", "Source AST exceeds 100,000 nodes.")]
    if tree.root_node.has_error:
        error = next(
            (node for node in nodes if node.type == "ERROR" or node.is_missing), tree.root_node
        )
        return [], [
            _diagnostic(
                source_path,
                "PARSE_ERROR",
                "Invalid Java source; no labels extracted.",
                error.start_point.row + 1,
            )
        ]
    classes = [node for node in tree.root_node.named_children if node.type == "class_declaration"]
    if len(classes) != 1 or _text(source, classes[0].child_by_field_name("name")) != path.stem:
        return [], [
            _diagnostic(
                source_path,
                "CLASS_MISMATCH",
                "Expected exactly the generated class named by the file.",
            )
        ]
    body = classes[0].child_by_field_name("body")
    if body is None:
        return [], [_diagnostic(source_path, "NO_METHODS", "Generated class has no method body.")]
    examples, diagnostics = [], []
    for method in body.named_children:
        if method.type != "method_declaration":
            continue
        name = _text(source, method.child_by_field_name("name"))
        label = 1 if name == "bad" else 0 if SAFE_ENTRY.fullmatch(name) else None
        if label is None:
            diagnostics.append(
                _diagnostic(
                    source_path,
                    "UNLABELED_METHOD",
                    "Dispatcher or unknown method omitted.",
                    method.start_point.row + 1,
                )
            )
            continue
        method_body = method.child_by_field_name("body")
        if method_body is None:
            diagnostics.append(
                _diagnostic(
                    source_path,
                    "NO_METHOD_BODY",
                    "Abstract method requires caller context.",
                    method.start_point.row + 1,
                )
            )
            continue
        descendants = _direct_nodes(method_body)
        calls = [node for node in descendants if node.type == "method_invocation"]
        call_names = {_text(source, call.child_by_field_name("name")) for call in calls}
        # An entry method invoking another labeled helper is not a standalone example.
        delegates = any(
            re.match(r"^(?:bad|good)(?:Sink|Source|B2G|G2B)", call) for call in call_names
        )
        if delegates or not call_names.intersection(SINKS):
            diagnostics.append(
                _diagnostic(
                    source_path,
                    "CONTEXT_DEPENDENT_METHOD",
                    "No self-contained SQL sink, or delegation requires another method.",
                    method.start_point.row + 1,
                )
            )
            continue
        method_flaws = sorted(
            line
            for line in flaw_lines
            if method.start_point.row + 1 <= line <= method.end_point.row + 1
        )
        label = int(name == "bad")
        if (label == 1 and not method_flaws) or (label == 0 and method_flaws):
            diagnostics.append(
                _diagnostic(
                    source_path,
                    "LABEL_CONFLICT",
                    "Method convention disagrees with upstream flaw lines.",
                    method.start_point.row + 1,
                )
            )
            continue
        code = _text(source, method)
        if len(code.encode("utf-8")) > 65536:
            diagnostics.append(
                _diagnostic(
                    source_path,
                    "METHOD_SIZE_LIMIT",
                    "Method exceeds 64 KiB.",
                    method.start_point.row + 1,
                )
            )
            continue
        content_hash = sha256(code.encode("utf-8"))
        identity = (
            f"nist-juliet-java-1.3\0{source_path}\0{name}\0{method.start_byte}\0{content_hash}"
        )
        examples.append(
            {
                "id": "juliet-" + sha256(identity.encode()),
                "code": code,
                "label": label,
                "repository_id": "nist-juliet-java-1.3",
                "content_sha256": content_hash,
                "source_path": source_path,
                "source_file_sha256": sha256(source),
                "label_manifest_sha256": manifest_sha256,
                "flaw_lines": method_flaws,
                "method_name": name,
                "start_byte": method.start_byte,
                "end_byte": method.end_byte,
                "start_line": method.start_point.row + 1,
                "start_column": method.start_point.column + 1,
                "end_line": method.end_point.row + 1,
                "end_column": method.end_point.column + 1,
                "cwe": "CWE-89",
                "input_source_family": match["family"],
                "sink_family": match["sink"],
                "flow_variant": match["variant"],
                "case_id": path.stem,
                "label_confidence": "high",
                "label_basis": (
                    "Juliet filename/header, generated entry-method convention "
                    "and authoritative manifest flaw-line agreement"
                ),
                "label_scope": "synthetic testcase intent; not independently proven exploitability",
            }
        )
    return examples, diagnostics


def extract_examples(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Read a verified extraction tree; the acquisition layer validates its archive."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Expected an existing non-symlink extraction directory")
    flaw_index, manifest_hash = load_flaw_manifest(root)
    examples, diagnostics = [], []
    files = 0
    for directory, subdirectories, names in os.walk(root, followlinks=False):
        subdirectories[:] = sorted(
            name for name in subdirectories if not (Path(directory) / name).is_symlink()
        )
        for name in sorted(names):
            if not name.startswith("CWE89_SQL_Injection__") or not name.endswith(".java"):
                continue
            files += 1
            if files > MAX_FILES:
                raise ValueError("Input exceeds 10,000 Java files")
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                diagnostics.append(
                    _diagnostic(relative, "SYMLINK_SKIPPED", "Source symlink rejected.")
                )
                continue
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError("Source entry is not a regular file")
                source = stream.read(MAX_SOURCE_BYTES + 1)
            records, problems = extract_file(
                source, relative, flaw_index.get(name, frozenset()), manifest_hash
            )
            examples.extend(records)
            diagnostics.extend(problems)
    examples.sort(key=lambda row: row["id"])
    diagnostics.sort(key=lambda row: (row["source_path"], row["line"] or 0, row["code"]))
    return examples, diagnostics
