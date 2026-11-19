"""Load a bounded JSON linear model only after checking an expected content digest."""

import json
import math
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from traceward_ml.artifacts import PortableArtifact
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
    preprocessing: Literal["identity", "juliet-java-v1"] = "identity"

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


def load_artifact(path: Path, expected_sha256: str) -> SVMArtifact | PortableArtifact:
    data = read_bounded(path, 10 * 1024 * 1024)
    if sha256(data) != expected_sha256:
        raise ValueError("Model artifact digest mismatch")
    raw = json.loads(data)
    if not isinstance(raw, dict):
        raise ValueError("Model artifact must be a JSON object")
    if raw.get("schema_version") == "1.1.0":
        return PortableArtifact.model_validate(raw)
    return SVMArtifact.model_validate(raw)


def preprocess_code(code: str, preprocessing: str) -> str:
    if preprocessing == "identity":
        return code
    if preprocessing == "juliet-java-v1":
        from traceward_ml.features import normalize_java

        return normalize_java(code)
    raise ValueError("Unknown source preprocessing contract")


def predict_codes(
    artifact: SVMArtifact | PortableArtifact, codes: list[str]
) -> tuple[list[int], list[float]]:
    """Reconstruct bounded fitted features and evaluate JSON state without Python pickle."""
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer

    if not codes or len(codes) > 50000:
        raise ValueError("Prediction batch must have between 1 and 50000 examples")
    if any(len(code.encode("utf-8")) > 65536 for code in codes):
        raise ValueError("Inference source exceeds 64 KiB")
    vectorizer = TfidfVectorizer(
        lowercase=False,
        token_pattern=FEATURE_CONTRACT["token_pattern"],
        vocabulary=artifact.vocabulary,
        norm="l2",
    )
    vectorizer.idf_ = np.asarray(artifact.idf)
    features = vectorizer.transform(
        [preprocess_code(code, artifact.preprocessing) for code in codes]
    )
    if isinstance(artifact, SVMArtifact) or artifact.model_type == "logreg":
        values = np.asarray(features.dot(np.asarray(artifact.coefficients))).ravel()
        values += artifact.intercept
        labels = (values > 0).astype(int).tolist()
        if isinstance(artifact, SVMArtifact):
            return labels, values.tolist()
        probabilities = [
            1 / (1 + math.exp(-float(value)))
            if value >= 0
            else math.exp(float(value)) / (1 + math.exp(float(value)))
            for value in values
        ]
        return labels, probabilities
    if artifact.model_type == "rf":
        probabilities = []
        for row_index in range(features.shape[0]):
            row = features.getrow(row_index)
            sparse_values = dict(
                zip(row.indices.tolist(), row.data.astype(np.float32).tolist(), strict=True)
            )
            total = 0.0
            for tree in artifact.trees:
                node = 0
                while tree.children_left[node] != -1:
                    feature_value = sparse_values.get(tree.feature[node], 0.0)
                    node = (
                        tree.children_left[node]
                        if feature_value <= tree.threshold[node]
                        else tree.children_right[node]
                    )
                total += tree.probabilities[node][1]
            probabilities.append(total / len(artifact.trees))
        return [int(value > 0.5) for value in probabilities], probabilities
    from xgboost import Booster, DMatrix

    booster = Booster()
    booster.load_model(bytearray(json.dumps(artifact.booster).encode()))
    values = booster.predict(DMatrix(features)).tolist()
    return [int(value > 0.5) for value in values], [float(value) for value in values]


def score_code(artifact: SVMArtifact | PortableArtifact, code: str) -> dict[str, float | int | str]:
    labels, values = predict_codes(artifact, [code])
    return {
        "label": labels[0],
        "decision_value": values[0],
        "score_kind": "uncalibrated_margin"
        if isinstance(artifact, SVMArtifact)
        else "uncalibrated_classifier_probability",
        "usage": artifact.usage,
        "evidence_level": "ml_suspected" if labels[0] else "no_ml_signal",
        "interpretation": "Uncalibrated research score; manual review required",
    }
