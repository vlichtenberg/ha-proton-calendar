"""Shared fixtures for Proton Calendar tests."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Allow loading custom_components in every test."""
    return


def load_fixture_text(name: str) -> str:
    """Read a fixture file as text."""
    return (FIXTURES / name).read_text(encoding="utf-8")


def load_fixture_bytes(name: str) -> bytes:
    """Read a fixture file as bytes."""
    return (FIXTURES / name).read_bytes()
