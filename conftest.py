"""Shared pytest options for reproducible CI test ordering."""

import random

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--order-seed", type=int, help="Shuffle collected tests with this seed.")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    seed = config.getoption("--order-seed")
    if seed is not None:
        random.Random(seed).shuffle(items)
