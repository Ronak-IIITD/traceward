"""Regression checks for filtering and family-disjoint corpus acquisition."""

import runpy
from pathlib import Path

MODULE = runpy.run_path(str(Path(__file__).resolve().parents[1] / "acquire_megavul.py"))


def candidates():
    sources = {"repositories": {}, "commits": {}}
    rows = []
    repositories = ["xm-online/a", "xm-online/b", *[f"owner{n}/project" for n in range(6)]]
    for index, repository in enumerate(repositories):
        sources["repositories"][repository] = {"repository": repository, "spdx_id": "MIT"}
        sources["commits"][f"{repository}@abc"] = {"sha": "a" * 40, "parents": ["b" * 40]}
        for label in (0, 1):
            rows.append(
                {
                    "cwe_ids": ["CWE-89"],
                    "repo_name": repository,
                    "input": f"int function{index}_{label}() {{ return {index + label}; }}",
                    "file_path": "src/main/java/Example.java",
                    "commit_hash": "abc",
                    "is_vulnerable": label,
                    "cve_id": "CVE-2020-12345",
                    "func_name": "function",
                }
            )
    return rows, sources


def test_families_and_repositories_cannot_cross_splits():
    rows, sources = candidates()
    records, provenance, excluded = MODULE["records_from_rows"](rows, sources)
    assert not excluded
    assert len(records) == 16 and len(provenance) == 16
    family_splits = {
        row["split"] for row in records if row["repository_id"].startswith("xm-online/")
    }
    assert len(family_splits) == 1
    assert all(len(item["commit"]) == 40 for item in provenance)
    for split in ("train", "validation", "test"):
        assert {record["label"] for record in records if record["split"] == split} == {0, 1}


def test_duplicate_and_test_code_are_excluded():
    rows, sources = candidates()
    rows.append(dict(rows[0], input=rows[0]["input"].replace(" ", "\n")))
    rows.append(dict(rows[0], file_path="src/test/java/Example.java"))
    rows.append(dict(rows[0], repo_name="unknown/repository"))
    records, _, excluded = MODULE["records_from_rows"](rows, sources)
    assert len(records) == 16
    assert excluded["whitespace_equivalent_duplicate"] == 1
    assert excluded["test_code"] == 1
    assert excluded["repository_license_or_identity_unresolved"] == 1


def test_conflicting_labels_are_removed_from_both_classes():
    rows, sources = candidates()
    rows.append(dict(rows[0], is_vulnerable=1))
    records, _, excluded = MODULE["records_from_rows"](rows, sources)
    assert len(records) == 15
    assert excluded["conflicting_duplicate_labels"] == 2
