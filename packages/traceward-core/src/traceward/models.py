"""Versioned result contract. Columns are one-based UTF-8 bytes; ends are exclusive."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from traceward import __version__


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Location(Contract):
    path: str
    start_line: int = Field(ge=1)
    start_column: int = Field(ge=1)
    end_line: int = Field(ge=1)
    end_column: int = Field(ge=1)


class FlowNode(Contract):
    kind: Literal["source", "assignment", "concatenation", "sink"]
    location: Location
    symbol: str


class Evidence(Contract):
    source: Location
    sink: Location
    flow: list[FlowNode]
    uncertainties: list[str]


class Detector(Contract):
    type: Literal["taint_rule"] = "taint_rule"
    id: str = "java.sql.concatenated-untrusted-input"
    version: str = "0.1.0"
    maturity: Literal["experimental"] = "experimental"


class Finding(Contract):
    id: str
    fingerprint: str
    rule_id: str = "java.sql.concatenated-untrusted-input"
    cwe: list[str] = Field(default_factory=lambda: ["CWE-89"])
    title: str = "Potential SQL injection via query concatenation"
    severity: Literal["high"] = "high"
    confidence: Literal["medium"] = "medium"
    evidence_level: Literal["heuristic_candidate"] = "heuristic_candidate"
    analysis_completeness: Literal["partial"] = "partial"
    location: Location
    evidence: Evidence
    detectors: list[Detector] = Field(default_factory=lambda: [Detector()])
    guidance: str = "Use a constant SQL template with PreparedStatement and bind untrusted values."
    references: list[str] = Field(
        default_factory=lambda: ["https://cwe.mitre.org/data/definitions/89.html"]
    )


class Diagnostic(Contract):
    code: str
    message: str
    level: Literal["info", "warning", "error"] = "warning"
    location: Location | None = None


class Coverage(Contract):
    languages_detected: list[str] = Field(default_factory=list)
    supported_checks: list[str] = Field(default_factory=lambda: ["CWE-89"])
    unsupported_checks: list[str] = Field(
        default_factory=lambda: [
            "CWE-79",
            "CWE-78",
            "CWE-22",
            "CWE-918",
            "CWE-787",
            "CWE-416",
            "CWE-798",
            "CWE-502",
            "CWE-863",
            "CWE-190",
            "CWE-295",
        ]
    )
    partial: bool = True
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Experimental Java CWE-89 subset; no external precision/recall evaluation yet.",
            "Only straight-line method-local flow and explicitly typed servlet/JDBC receivers.",
            "Branches, loops, fields, aliases, interprocedural flow and dispatch are unsupported.",
            "No supported findings does not certify that code is secure. ML is disabled.",
        ]
    )


class Summary(Contract):
    files_discovered: int = 0
    files_analyzed: int = 0
    findings: int = 0
    errors: int = 0


class Source(Contract):
    kind: Literal["file", "directory", "snippet"]
    revision: str | None = None


class Scanner(Contract):
    name: Literal["TraceWard"] = "TraceWard"
    version: str = __version__


class ScanResult(Contract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    scan_id: str
    source: Source
    scanner: Scanner = Field(default_factory=Scanner)
    coverage: Coverage = Field(default_factory=Coverage)
    summary: Summary = Field(default_factory=Summary)
    findings: list[Finding] = Field(default_factory=list)
    diagnostics: list[Diagnostic] = Field(default_factory=list)
    duration_ms: int = 0
