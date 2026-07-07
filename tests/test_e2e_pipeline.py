"""Opt-in full-stack pipeline test (requires Docker + bind:latest, + ollama for
full/heavy). Excluded from the default lane; run with `pytest -m e2e`.

Uses the session orchestrator booted by conftest and drives the real plugin
containers via scripts/e2e_driver.py in --attach mode. Tier is `smoke` by
default (fid + ghidriff, no ollama/QEMU); override with XBIN_E2E_TIER.
"""
import os

import pytest

import e2e_driver  # importable: conftest adds scripts/ to sys.path

pytestmark = [pytest.mark.e2e, pytest.mark.slow]


def test_pipeline(rest_base):
    tier = os.environ.get("XBIN_E2E_TIER", "smoke")
    rc = e2e_driver.run_tier(tier, attach=True)
    assert rc == 0, f"e2e tier '{tier}' failed (rc={rc})"

    client = e2e_driver.XbinClient(rest_base)
    assert client.results("signature_matching"), "signature_matching produced no hypotheses"
    if tier in ("full", "heavy"):
        assert client.results("equation_recovery"), "equation_recovery produced no hypotheses"
