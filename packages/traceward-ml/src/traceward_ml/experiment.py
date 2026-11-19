"""Train on the declared training split, then measure fixed held-out splits."""

import json
import platform
import resource
import statistics
import sys
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from traceward_ml.dataset import Example, Manifest, sha256

FEATURE_CONTRACT = {
    "version": "1.0.0",
    "kind": "lexical-tfidf",
    "lowercase": False,
    "token_pattern": r"(?u)\b\w+\b|[+?.=;(){}]",
    "max_features": 20000,
    "norm": "l2",
}


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def build_classifier(name: str, seed: int) -> Any:
    if name == "svm":
        from sklearn.svm import LinearSVC

        return LinearSVC(C=0.1, random_state=seed, dual="auto")
    if name == "rf":
        from sklearn.ensemble import RandomForestClassifier

        return RandomForestClassifier(n_estimators=50, max_depth=4, random_state=seed, n_jobs=1)
    if name == "xgboost":
        from xgboost import XGBClassifier

        return XGBClassifier(n_estimators=50, max_depth=2, random_state=seed, n_jobs=1)
    raise ValueError(f"Unknown model {name}")


def classifier_metrics(labels: list[int], predictions: Any, scores: Any) -> dict[str, Any]:
    from sklearn.metrics import (
        average_precision_score,
        confusion_matrix,
        f1_score,
        precision_recall_fscore_support,
    )

    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel().tolist()
    precision, recall, f1, support = precision_recall_fscore_support(
        labels,
        predictions,
        labels=[0, 1],
        zero_division=0,
    )
    return {
        "count": len(labels),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "false_positive_rate": fp / (tn + fp) if tn + fp else None,
        "macro_f1": float(f1_score(labels, predictions, labels=[0, 1], average="macro")),
        "average_precision": float(average_precision_score(labels, scores))
        if 1 in labels
        else None,
        "per_class": {
            str(label): {
                "precision": float(precision[label]),
                "recall": float(recall[label]),
                "f1": float(f1[label]),
                "support": int(support[label]),
            }
            for label in (0, 1)
        },
    }


def measure_latency(pipeline: Any, codes: list[str]) -> dict[str, Any]:
    elapsed = []
    for code in codes[:100]:
        start = time.perf_counter_ns()
        pipeline.predict([code])
        elapsed.append((time.perf_counter_ns() - start) / 1_000_000)
    ordered = sorted(elapsed)
    return {
        "samples": len(elapsed),
        "includes": "TF-IDF transform plus classifier predict",
        "p50_ms": statistics.median(elapsed),
        "p95_ms": ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))],
    }


def export_svm(pipeline: Any) -> dict[str, Any]:
    vectorizer = pipeline.named_steps["tfidf"]
    classifier = pipeline.named_steps["classifier"]
    return {
        "schema_version": "1.0.0",
        "usage": "offline_research_only",
        "feature_contract": FEATURE_CONTRACT,
        "vocabulary": {token: int(index) for token, index in vectorizer.vocabulary_.items()},
        "idf": vectorizer.idf_.tolist(),
        "coefficients": classifier.coef_[0].tolist(),
        "intercept": float(classifier.intercept_[0]),
        "classes": [int(label) for label in classifier.classes_],
        "decision_value": "uncalibrated SVM margin; values are not exploit probabilities",
    }


def measure_rule_baseline(examples: list[Example]) -> dict[str, Any]:
    from traceward.scanner import scan_snippet

    labels, predictions = [], []
    errors = partial = 0
    for row in examples:
        code = row.code if "class " in row.code else "class CorpusMethod {\n" + row.code + "\n}"
        result = scan_snippet(code)
        labels.append(row.label)
        predictions.append(int(bool(result.findings)))
        errors += int(bool(result.summary.errors))
        partial += int(result.coverage.partial)
    metrics = classifier_metrics(labels, predictions, predictions)
    metrics.update({"analysis_errors": errors, "partial_scans": partial})
    return metrics


def run_experiment(
    manifest: Manifest,
    examples: list[Example],
    output: Path,
    models: list[str],
    seed: int,
    code_revision: str,
    lock_digest: str,
) -> dict[str, Any]:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.pipeline import Pipeline

    if not models or len(models) != len(set(models)):
        raise ValueError("Select one or more unique model names")
    for name in models:
        if name not in {"svm", "rf", "xgboost"}:
            raise ValueError(f"Unknown model {name}")
    output.mkdir(parents=True, exist_ok=False)
    split_rows = {
        split: [row for row in examples if row.split == split]
        for split in ("train", "validation", "test")
    }
    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "dataset": manifest.model_dump(mode="json"),
        "corpus_kind": manifest.corpus_kind,
        "production_enabled": False,
        "code_revision": code_revision,
        "code_revision_role": "Base revision; source file digests identify the run code",
        "training_source_files_sha256": {
            path.name: sha256(path.read_bytes())
            for path in sorted(Path(__file__).parent.glob("*.py"))
        },
        "lock_sha256": lock_digest,
        "seed": seed,
        "feature_contract_sha256": sha256(canonical_json(FEATURE_CONTRACT)),
        "training_source_sha256": sha256(
            b"".join(
                path.name.encode() + path.read_bytes()
                for path in sorted(Path(__file__).parent.glob("*.py"))
            )
        ),
        "split_ids": {split: [row.id for row in rows] for split, rows in split_rows.items()},
        "dependencies": {name: version(name) for name in ("scikit-learn", "numpy", "scipy")},
        "hardware": {
            "platform": platform.platform(),
            "processor": platform.processor(),
            "python": sys.version,
        },
        "limitations": [
            "Lexical research baseline; corpus labels require independent review.",
            "No hyperparameter selection or calibration is performed.",
            "Repeated model selection on the test split invalidates held-out measurements.",
            "Rule baseline uses candidate presence; review its coverage limits.",
        ],
        "rule_baseline": {
            "interpretation": "Method-level candidate presence under the current rule scope",
            "metrics": {split: measure_rule_baseline(rows) for split, rows in split_rows.items()},
        },
        "models": {},
    }
    train = split_rows["train"]
    try:
        for name in models:
            vectorizer = TfidfVectorizer(
                lowercase=False,
                token_pattern=FEATURE_CONTRACT["token_pattern"],
                max_features=20000,
                norm="l2",
            )
            pipeline = Pipeline(
                [("tfidf", vectorizer), ("classifier", build_classifier(name, seed))]
            )
            start = time.perf_counter()
            pipeline.fit([row.code for row in train], [row.label for row in train])
            fit_seconds = time.perf_counter() - start
            measurements = {}
            for split in ("train", "validation", "test"):
                rows = split_rows[split]
                codes = [row.code for row in rows]
                predictions = pipeline.predict(codes)
                classifier = pipeline.named_steps["classifier"]
                features = vectorizer.transform(codes)
                if hasattr(classifier, "decision_function"):
                    scores = classifier.decision_function(features)
                else:
                    scores = classifier.predict_proba(features)[:, 1]
                measurements[split] = classifier_metrics(
                    [row.label for row in rows], predictions, scores
                )
            record: dict[str, Any] = {
                "fit_seconds": fit_seconds,
                "peak_process_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                "parameters": {
                    key: value
                    for key, value in pipeline.named_steps["classifier"].get_params().items()
                    if key in {"C", "dual", "random_state", "n_estimators", "max_depth", "n_jobs"}
                },
                "feature_count": len(vectorizer.vocabulary_),
                "metrics": measurements,
                "latency": measure_latency(pipeline, [row.code for row in split_rows["test"]]),
                "artifact": None,
            }
            if name == "svm":
                data = canonical_json(export_svm(pipeline))
                (output / "svm.json").write_bytes(data)
                record["artifact"] = {
                    "file": "svm.json",
                    "sha256": sha256(data),
                    "bytes": len(data),
                }
            if name == "xgboost":
                try:
                    report["dependencies"]["xgboost"] = version("xgboost")
                except PackageNotFoundError:
                    report["dependencies"]["xgboost-cpu"] = version("xgboost-cpu")
            report["models"][name] = record
        (output / "manifest.json").write_bytes(canonical_json(manifest.model_dump(mode="json")))
        (output / "report.json").write_bytes(canonical_json(report))
    except BaseException:
        # Leave only a failed-run marker, never a success-looking partial report.
        for child in output.iterdir():
            if child.is_file():
                child.unlink()
        (output / "FAILED").write_text("Experiment did not complete. No results are valid.\n")
        raise
    return report
