.DEFAULT_GOAL := help

.PHONY: help test inspect-local doctor-local smoke-local check-local

help:
	@printf '%s\n' \
	  'Available targets:' \
	  '  test          Run the Python test suite' \
	  '  inspect-local Inspect the bundled local Kimi-backed smoke pipeline' \
	  '  doctor-local  Check local Codex/Claude/Kimi smoke prerequisites' \
	  '  smoke-local   Run the bundled local Codex + Claude-on-Kimi smoke test' \
	  '  check-local   Run doctor-local, then smoke-local'

test:
	python3 -m pytest -q

inspect-local:
	python3 -m agentflow inspect examples/local-real-agents-kimi-smoke.yaml --output summary

doctor-local:
	python3 -m agentflow doctor examples/local-real-agents-kimi-smoke.yaml --output summary

smoke-local:
	python3 -m agentflow smoke --show-preflight

check-local: doctor-local smoke-local
