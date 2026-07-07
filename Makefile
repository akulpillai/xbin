# xbin (BINDonly) developer / test targets.
# Run from the repo root. See docs/e2e_testing.md for the full walkthrough.

RYEPY ?= /home/akul/.rye/py/cpython@3.12.9/bin/python3
VENV  := .venv
PY    := $(VENV)/bin/python

.PHONY: help setup preflight test stage rebuild-base e2e-smoke e2e-full e2e-heavy clean

help:
	@echo "targets:"
	@echo "  setup        create .venv (rye cpython) + pip install -e . pytest"
	@echo "  preflight    check docker/redis/ollama/bind:latest/deps (smoke tier)"
	@echo "  test         fast Docker-free pytest lane"
	@echo "  stage        copy gs3.bin into uploads/ (scripts/fetch_test_binaries.sh)"
	@echo "  rebuild-base rebuild bind:latest with QEMU (kills the outdated instance)"
	@echo "  e2e-smoke    full-stack: fid + ghidriff"
	@echo "  e2e-full     + bind_se + bind_arbiter (needs ollama)"
	@echo "  e2e-heavy    + symbolic_regression (needs QEMU in bind:latest)"
	@echo "  clean        remove xbin-worker-* containers"

setup:
	$(RYEPY) -m venv $(VENV)
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e . pytest

preflight:
	scripts/preflight.sh --tier smoke

test:
	$(PY) -m pytest

stage:
	scripts/fetch_test_binaries.sh

rebuild-base:
	scripts/rebuild_bind_base.sh

e2e-smoke:
	scripts/e2e.sh smoke

e2e-full:
	scripts/e2e.sh full

e2e-heavy:
	scripts/e2e.sh heavy

clean:
	-docker rm -f $$(docker ps -aq --filter name=xbin-worker-) 2>/dev/null || true
