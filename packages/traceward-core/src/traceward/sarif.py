"""Render the scan result as a portable SARIF 2.1.0 log."""

from urllib.parse import quote

from traceward.models import Diagnostic, Finding, Location, ScanResult
from traceward.registry import RULES

SCHEMA_URL = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
SOURCE_ROOT = "%SRCROOT%"


def physical_location(location: Location) -> dict[str, object]:
    # TraceWard tracks UTF-8 byte columns. SARIF uses Unicode columns, so export
    # whole lines without reopening source or emitting inaccurate columns.
    end_line = location.end_line
    if location.end_column == 1 and end_line > location.start_line:
        end_line -= 1
    return {
        "artifactLocation": {
            "uri": quote(location.path, safe="/", errors="surrogateescape"),
            "uriBaseId": SOURCE_ROOT,
        },
        "region": {"startLine": location.start_line, "endLine": end_line},
    }


def notification(diagnostic: Diagnostic) -> dict[str, object]:
    entry: dict[str, object] = {
        "level": "note" if diagnostic.level == "info" else diagnostic.level,
        "message": {"text": f"{diagnostic.code}: {diagnostic.message}"},
    }
    if diagnostic.location is not None:
        entry["locations"] = [{"physicalLocation": physical_location(diagnostic.location)}]
    return entry


def finding_result(finding: Finding, rule_index: int) -> dict[str, object]:
    steps = [
        {
            "kinds": [step.kind],
            "location": {
                "physicalLocation": physical_location(step.location),
                "message": {"text": step.symbol},
            },
        }
        for step in finding.evidence.flow
    ]
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": "warning",
        "message": {"text": f"{finding.title}. {finding.guidance}"},
        "locations": [{"physicalLocation": physical_location(finding.location)}],
        "partialFingerprints": {"tracewardFingerprint/v1": finding.fingerprint},
        "codeFlows": [{"threadFlows": [{"locations": steps}]}],
        "properties": {
            "severity": finding.severity,
            "confidence": finding.confidence,
            "evidenceLevel": finding.evidence_level,
            "analysisCompleteness": finding.analysis_completeness,
            "uncertainties": finding.evidence.uncertainties,
        },
    }


def sarif_log(result: ScanResult, status: int) -> dict[str, object]:
    applicable = [
        rule for rule in RULES.values() if rule.language in result.coverage.languages_detected
    ]
    # Preserve the category used by existing Java-only SARIF uploads.
    category = "local-cwe89/"
    if len(applicable) == 1:
        category = f"{applicable[0].language}-cwe89/"
    rule_indexes = {rule.id: index for index, rule in enumerate(applicable)}
    rules = [
        {
            "id": rule.id,
            "shortDescription": {"text": rule.title},
            "help": {"text": rule.guidance},
            "helpUri": rule.reference,
            "defaultConfiguration": {"level": "warning"},
            "properties": {
                "tags": ["security", rule.cwe],
                "maturity": rule.maturity,
                "ruleVersion": rule.version,
            },
        }
        for rule in applicable
    ]
    return {
        "$schema": SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "automationDetails": {"id": category},
                "tool": {
                    "driver": {
                        "name": result.scanner.name,
                        "semanticVersion": result.scanner.version,
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {
                    SOURCE_ROOT: {"description": {"text": "The TraceWard scan root."}}
                },
                "columnKind": "utf16CodeUnits",
                "invocations": [
                    {
                        "executionSuccessful": result.summary.errors == 0,
                        "exitCode": status,
                        "toolExecutionNotifications": [
                            notification(item) for item in result.diagnostics
                        ],
                    }
                ],
                "results": [
                    finding_result(item, rule_indexes[item.rule_id]) for item in result.findings
                ],
                "properties": {
                    "coverage": result.coverage.model_dump(),
                    "summary": result.summary.model_dump(),
                },
            }
        ],
    }
