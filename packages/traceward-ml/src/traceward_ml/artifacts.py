"""Portable non-pickle TF-IDF and classifier state for offline research inference."""

import math
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, model_validator


class TreeArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    children_left: list[int]
    children_right: list[int]
    feature: list[int]
    threshold: list[float]
    probabilities: list[list[float]]

    @model_validator(mode="after")
    def check_tree(self) -> "TreeArtifact":
        size = len(self.children_left)
        if not 0 < size <= 100_000 or any(
            len(values) != size
            for values in (self.children_right, self.feature, self.threshold, self.probabilities)
        ):
            raise ValueError("Random forest tree dimensions are inconsistent")
        if not all(math.isfinite(value) for value in self.threshold):
            raise ValueError("Tree thresholds must be finite")
        for index, (left, right, feature, probabilities) in enumerate(
            zip(
                self.children_left,
                self.children_right,
                self.feature,
                self.probabilities,
                strict=True,
            )
        ):
            if left == right == -1:
                if feature != -2:
                    raise ValueError("Leaf features must use the leaf sentinel")
            elif not (index < left < size and index < right < size and feature >= 0):
                raise ValueError("Tree child indices must form an acyclic forward tree")
            if (
                len(probabilities) != 2
                or not all(math.isfinite(value) and 0 <= value <= 1 for value in probabilities)
                or not math.isclose(sum(probabilities), 1, rel_tol=1e-8, abs_tol=1e-8)
            ):
                raise ValueError("Each node must contain two class probabilities")
        return self


class PortableArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["1.1.0"]
    usage: Literal["offline_research_only"]
    model_type: Literal["logreg", "rf", "xgboost"]
    feature_contract: dict[str, str | bool | int]
    vocabulary: dict[str, int]
    idf: list[float]
    classes: list[int]
    preprocessing: Literal["identity", "juliet-java-v1"] = "identity"
    coefficients: list[float] | None = None
    intercept: float | None = None
    trees: list[TreeArtifact] | None = None
    booster: dict[str, Any] | None = None

    @model_validator(mode="after")
    def check_model(self) -> "PortableArtifact":
        from traceward_ml.experiment import FEATURE_CONTRACT

        size = len(self.vocabulary)
        if self.feature_contract != FEATURE_CONTRACT or self.classes != [0, 1]:
            raise ValueError("Model feature or class contract is incompatible")
        if not 0 < size <= 20000 or set(self.vocabulary.values()) != set(range(size)):
            raise ValueError("Model vocabulary indices are invalid")
        if len(self.idf) != size or not all(math.isfinite(v) and v > 0 for v in self.idf):
            raise ValueError("Model IDF values are invalid")
        if self.model_type == "logreg":
            if self.trees is not None or self.booster is not None:
                raise ValueError("Linear classifier contains incompatible state")
            if self.coefficients is None or len(self.coefficients) != size:
                raise ValueError("Model coefficient dimensions are inconsistent")
            if self.intercept is None or not all(
                math.isfinite(value) for value in [*self.coefficients, self.intercept]
            ):
                raise ValueError("Model weights must be finite")
        elif self.model_type == "rf":
            if (
                self.coefficients is not None
                or self.intercept is not None
                or self.booster is not None
            ):
                raise ValueError("Random forest contains incompatible state")
            if not self.trees or len(self.trees) > 1000:
                raise ValueError("Expected between one and 1,000 trees")
            if any(feature >= size for tree in self.trees for feature in tree.feature):
                raise ValueError("Tree feature is outside the vocabulary")
        elif self.coefficients is not None or self.intercept is not None or self.trees is not None:
            raise ValueError("XGBoost contains incompatible state")
        elif self.booster is None or set(self.booster) != {"learner", "version"}:
            raise ValueError("Expected an XGBoost native JSON booster")
        return self


def export_portable(
    pipeline: Any, model_type: str, preprocessing: str = "identity"
) -> dict[str, Any]:
    """Export fitted state without executing or serializing Python callables."""
    import json

    from traceward_ml.experiment import FEATURE_CONTRACT

    vectorizer = pipeline.named_steps["tfidf"]
    classifier = pipeline.named_steps["classifier"]
    result = {
        "schema_version": "1.1.0",
        "usage": "offline_research_only",
        "model_type": model_type,
        "preprocessing": preprocessing,
        "feature_contract": FEATURE_CONTRACT,
        "vocabulary": {token: int(index) for token, index in vectorizer.vocabulary_.items()},
        "idf": vectorizer.idf_.tolist(),
        "classes": [int(label) for label in classifier.classes_],
    }
    if model_type == "logreg":
        result.update(
            coefficients=classifier.coef_[0].tolist(), intercept=float(classifier.intercept_[0])
        )
    elif model_type == "rf":
        trees = []
        for estimator in classifier.estimators_:
            tree = estimator.tree_
            probabilities = tree.value[:, 0, :]
            probabilities = probabilities / probabilities.sum(axis=1, keepdims=True)
            trees.append(
                {
                    "children_left": tree.children_left.tolist(),
                    "children_right": tree.children_right.tolist(),
                    "feature": tree.feature.tolist(),
                    "threshold": tree.threshold.tolist(),
                    "probabilities": probabilities.tolist(),
                }
            )
        result["trees"] = trees
    elif model_type == "xgboost":
        result["booster"] = json.loads(classifier.get_booster().save_raw(raw_format="json"))
    else:
        raise ValueError("Unsupported portable model")
    return PortableArtifact.model_validate(result).model_dump(exclude_none=True)
