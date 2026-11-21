import json

import pytest
from pydantic import ValidationError
from traceward.models import Evidence
from traceward.registry import JAVA_SQL, load_rules
from traceward.scanner import scan_snippet


def test_invalid_manifests() -> None:
    rule = JAVA_SQL.model_dump()
    for entries in (
        [],
        [rule, rule],
        [dict(rule, version="latest")],
        [dict(rule, maturity="validated")],
        [dict(rule, language="python")],
    ):
        with pytest.raises(ValueError):
            load_rules(json.dumps(entries).encode())


def test_flow_requires_matching_endpoints() -> None:
    result = scan_snippet(
        "class X { void f(HttpServletRequest r, Statement s){"
        's.executeQuery("Q"+r.getParameter("id"));}}'
    )
    evidence = result.findings[0].evidence.model_dump()
    evidence["sink"] = evidence["source"]
    with pytest.raises(ValidationError):
        Evidence.model_validate(evidence)
