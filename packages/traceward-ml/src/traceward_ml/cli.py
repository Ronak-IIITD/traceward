"""Offline baseline training and integrity-checked research inference."""

import argparse
import json
import re
import sys
from pathlib import Path

from pydantic import ValidationError

from traceward_ml.dataset import load_dataset, read_bounded, sha256


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    fetch = commands.add_parser("fetch-juliet", help="Download and verify official Juliet Java 1.3")
    fetch.add_argument("--output", type=Path, required=True)
    prepare = commands.add_parser("prepare-juliet", help="Prepare the pinned Java CWE-89 dataset")
    prepare.add_argument("--archive", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--seed", type=int, default=38)
    train = commands.add_parser("train", help="Run fixed model baselines on declared corpus splits")
    train.add_argument("--manifest", type=Path, required=True)
    train.add_argument("--dataset", type=Path, required=True)
    train.add_argument("--output", type=Path, required=True, help="New output directory")
    train.add_argument(
        "--models",
        nargs="+",
        choices=["logreg", "svm", "rf", "xgboost"],
        default=["logreg", "svm", "rf", "xgboost"],
    )
    train.add_argument("--seed", type=int, default=38)
    train.add_argument(
        "--code-revision", required=True, help="Git revision of the training checkout"
    )
    train.add_argument("--lock", type=Path, required=True, help="Training dependency lockfile")
    predict = commands.add_parser(
        "predict", help="Score Java code with an offline JSON model artifact"
    )
    predict.add_argument("--model", type=Path, required=True)
    predict.add_argument(
        "--sha256", required=True, help="Expected model hash from a trusted report"
    )
    predict.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "fetch-juliet":
            from traceward_ml.acquisition import fetch_archive

            print(fetch_archive(args.output))
        elif args.command == "prepare-juliet":
            from traceward_ml.preparation import prepare_juliet

            summary = prepare_juliet(args.archive, args.output, args.seed)
            print(json.dumps({"output": str(args.output), "counts": summary["counts"]}, indent=2))
        elif args.command == "train":
            from traceward_ml.experiment import run_experiment

            if not re.fullmatch(r"[a-f0-9]{40}", args.code_revision):
                parser.error("--code-revision must be a full Git commit SHA")
            if not 0 <= args.seed <= 2147483647:
                parser.error("--seed must be between 0 and 2147483647")
            manifest, examples = load_dataset(args.manifest, args.dataset)
            report = run_experiment(
                manifest,
                examples,
                args.output,
                args.models,
                args.seed,
                args.code_revision,
                sha256(read_bounded(args.lock, 10 << 20)),
            )
            print(
                json.dumps(
                    {
                        "report": str(args.output / "report.json"),
                        "dataset": manifest.dataset_id,
                        "models": list(report["models"]),
                        "production_enabled": False,
                    },
                    indent=2,
                )
            )
        else:
            from traceward_ml.inference import load_artifact, score_code

            artifact = load_artifact(args.model, args.sha256)
            print(
                json.dumps(
                    score_code(artifact, read_bounded(args.path, 65536).decode("utf-8")), indent=2
                )
            )
    except ImportError:
        print("ML dependencies are unavailable. Install the project's ml extra.", file=sys.stderr)
        return 2
    except (OSError, ValueError, ValidationError):
        print(
            "Experiment input or model is invalid; verify hashes, splits and output paths.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
