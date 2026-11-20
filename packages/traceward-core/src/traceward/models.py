"""Versioned result contract. Columns are one-based UTF-8 bytes; ends are exclusive."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from traceward import __version__
from traceward.registry import JAVA_SQL


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


class FlowTrace(Contract):
    source: Location
    sink: Location
    flow: list[FlowNode]

    @model_validator(mode="after")
    def check_endpoints(self) -> "FlowTrace":
        if len(self.flow) < 2 or self.flow[0].kind != "source" or self.flow[-1].kind != "sink":
            raise ValueError("A flow trace must start at a source and end at a sink")
        if self.flow[0].location != self.source or self.flow[-1].location != self.sink:
            raise ValueError("Trace endpoints must match their recorded locations")
        return self


class Evidence(FlowTrace):
    uncertainties: list[str]


class Detector(Contract):
    type: Literal["taint_rule"] = "taint_rule"
    id: str = JAVA_SQL.id
    version: str = JAVA_SQL.version
    maturity: Literal["experimental"] = "experimental"


class Finding(Contract):
    id: str
    fingerprint: str
    rule_id: str = JAVA_SQL.id
    cwe: list[str] = Field(default_factory=lambda: [JAVA_SQL.cwe])
    title: str = JAVA_SQL.title
    severity: Literal["high"] = "high"
    confidence: Literal["medium"] = "medium"
    evidence_level: Literal["heuristic_candidate"] = "heuristic_candidate"
    analysis_completeness: Literal["partial"] = "partial"
    location: Location
    evidence: Evidence
    detectors: list[Detector] = Field(default_factory=lambda: [Detector()])
    guidance: str = JAVA_SQL.guidance
    references: list[str] = Field(default_factory=lambda: [JAVA_SQL.reference])


class Diagnostic(Contract):
    code: str
    message: str
    level: Literal["info", "warning", "error"] = "warning"
    location: Location | None = None


class Coverage(Contract):
    languages_detected: list[str] = Field(default_factory=list)
    supported_checks: list[str] = Field(default_factory=lambda: [JAVA_SQL.cwe])
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
            "Try-with-resources follows the normal path only; exception handlers are skipped.",
            "Branches, loops, fields, receiver aliases and interprocedural flow are unsupported.",
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
