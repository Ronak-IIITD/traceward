"""Validated metadata for the scanner's bundled deterministic rules."""

from importlib.resources import files
from types import MappingProxyType
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    id: str = Field(pattern=r"^[a-z]+\.[a-z0-9-]+\.[a-z0-9-]+$")
    version: str = Field(pattern=r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
    type: Literal["taint_rule"]
    language: Literal["java", "python"]
    cwe: str = Field(pattern=r"^CWE-[1-9]\d*$")
    maturity: Literal["experimental"]
    title: str = Field(min_length=1)
    guidance: str = Field(min_length=1)
    reference: str = Field(pattern=r"^https://\S+$")


def load_rules(manifest: bytes) -> MappingProxyType[str, Rule]:
    rules = TypeAdapter(list[Rule]).validate_json(manifest)
    indexed = {rule.id: rule for rule in rules}
    if not rules or len(indexed) != len(rules):
        raise ValueError("Expected a nonempty rule registry with unique IDs")
    if any(rule.id.split(".", 1)[0] != rule.language for rule in rules):
        raise ValueError("Rule ID must start with its language")
    return MappingProxyType(indexed)


RULES = load_rules(files("traceward").joinpath("rules.json").read_bytes())
JAVA_SQL = RULES["java.sql.concatenated-untrusted-input"]
PYTHON_SQL = RULES["python.sqlite.concatenated-input"]
SUPPORTED_LANGUAGES = frozenset(rule.language for rule in RULES.values())
