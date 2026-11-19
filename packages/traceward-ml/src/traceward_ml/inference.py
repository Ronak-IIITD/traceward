"""Load a bounded JSON linear model only after checking an expected content digest."""

import math
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from traceward_ml.dataset import read_bounded, sha256
from traceward_ml.experiment import FEATURE_CONTRACT


class SVMArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["1.0.0"]
    usage: Literal["offline_research_only"]
    feature_contract: dict[str, str | bool | int]
    vocabulary: dict[str, int]
    idf: list[float]
    coefficients: list[float]
    intercept: float
    classes: list[int]
    decision_value: str

    @model_validator(mode="after")
    def check_contract(self) -> "SVMArtifact":
        count = len(self.vocabulary)
        if self.feature_contract != FEATURE_CONTRACT or self.classes != [0, 1]:
            raise ValueError("Model feature or class contract is incompatible")
        if not 0 < count <= 20000 or set(self.vocabulary.values()) != set(range(count)):
            raise ValueError("Model vocabulary indices are invalid")
        if len(self.idf) != count or len(self.coefficients) != count:
            raise ValueError("Model feature dimensions are inconsistent")
        if not all(math.isfinite(v) for v in [*self.idf, *self.coefficients, self.intercept]):
            raise ValueError("Model weights must be finite")
        if not all(v > 0 for v in self.idf):
            raise ValueError("Model IDF values must be positive")
        return self


def load_artifact(path: Path, expected_sha256: str) -> SVMArtifact:
    data = read_bounded(path, 10 * 1024 * 1024)
    if sha256(data) != expected_sha256:
        raise ValueError("Model artifact digest mismatch")
    return SVMArtifact.model_validate_json(data)


def score_code(artifact: SVMArtifact, code: str) -> dict[str, float | int | str]:
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer

    if len(code.encode("utf-8")) > 65536:
        raise ValueError("Inference source exceeds 64 KiB")
    vectorizer = TfidfVectorizer(
        lowercase=False,
        token_pattern=FEATURE_CONTRACT["token_pattern"],
        vocabulary=artifact.vocabulary,
        norm="l2",
    )
    vectorizer.idf_ = np.asarray(artifact.idf)
    value = float(vectorizer.transform([code]).dot(np.asarray(artifact.coefficients))[0])
    value += artifact.intercept
    return {
        "label": int(value > 0),
        "decision_value": value,
        "usage": artifact.usage,
        "evidence_level": "ml_suspected" if value > 0 else "no_ml_signal",
        "interpretation": "Uncalibrated research score; manual review required",
    }
