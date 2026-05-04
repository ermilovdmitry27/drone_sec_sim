.PHONY: test lint typecheck coverage benchmark validate-readme verify-smoke-logs validate-encryption protection-doc precommit-install secrets-check validate-config

PYTHON ?= .venv/bin/python

test:
	$(PYTHON) -m unittest discover -s tests

test-verbose:
	$(PYTHON) -m unittest discover -s tests -v

lint:
	ruff check security_agent/ tools/ tests/ scenarios/ monitor.py launch_stack.py

lint-fix:
	ruff check --fix security_agent/ tools/ tests/ scenarios/ monitor.py launch_stack.py

typecheck:
	mypy security_agent/ --ignore-missing-imports

coverage:
	$(PYTHON) -m coverage run -m unittest discover -s tests
	$(PYTHON) -m coverage report --fail-under=70
	$(PYTHON) -m coverage html

benchmark:
	$(PYTHON) -m unittest tests.test_benchmark -v

smoke-report:
	$(PYTHON) scenarios/run_threat_coverage.py --all --limit 5 --emit-profile-events --log-dir logs/threat_coverage_smoke_ci

verify-smoke-logs:
	$(PYTHON) tools/verify_audit_log.py \
		logs/threat_coverage_smoke_ci/threat_coverage.jsonl \
		logs/threat_coverage_smoke_ci/security_events.jsonl \
		logs/threat_coverage_smoke_ci/protocol_events.jsonl

validate-encryption:
	printf '\376\000\001\001\001\013\000\000' > /tmp/drone_sec_sim_mavlink.bin
	$(PYTHON) tools/encrypted_mavlink_datagram.py encrypt \
		--key-hex 1111111111111111111111111111111111111111111111111111111111111111 \
		--input /tmp/drone_sec_sim_mavlink.bin \
		--output /tmp/drone_sec_sim_mavlink.enc
	$(PYTHON) tools/encrypted_mavlink_datagram.py decrypt \
		--key-hex 1111111111111111111111111111111111111111111111111111111111111111 \
		--input /tmp/drone_sec_sim_mavlink.enc \
		--output /tmp/drone_sec_sim_mavlink.dec
	cmp /tmp/drone_sec_sim_mavlink.bin /tmp/drone_sec_sim_mavlink.dec
	$(PYTHON) tools/encrypted_mavlink_datagram.py encrypt \
		--key-hex 1111111111111111111111111111111111111111111111111111111111111111 \
		--operator-id operator-1 \
		--operator-token test-token \
		--input /tmp/drone_sec_sim_mavlink.bin \
		--output /tmp/drone_sec_sim_mavlink.auth.enc
	$(PYTHON) tools/encrypted_mavlink_datagram.py decrypt \
		--key-hex 1111111111111111111111111111111111111111111111111111111111111111 \
		--input /tmp/drone_sec_sim_mavlink.auth.enc \
		--output /tmp/drone_sec_sim_mavlink.auth.dec
	cmp /tmp/drone_sec_sim_mavlink.bin /tmp/drone_sec_sim_mavlink.auth.dec

protection-doc:
	$(PYTHON) tools/build_protection_methods_doc.py

validate-readme:
	$(PYTHON) launch_stack.py --help
	$(PYTHON) monitor.py --help
	$(PYTHON) scenarios/run_threat_coverage.py --help
	$(PYTHON) tools/architecture_report.py --help

validate-config:
	$(PYTHON) tools/validate_sim_stack.py sim_stack.json

precommit-install:
	$(PYTHON) -m pip install pre-commit 2>/dev/null || true
	pre-commit install

secrets-check:
	@echo "Checking for secrets (gitleaks required: brew install gitleaks or go install github.com/gitleaks/gitleaks@latest)"
	@command -v gitleaks >/dev/null 2>&1 || { echo "gitleaks not found, skipping"; exit 0; }
	gitleaks detect --verbose --no-color . || true

threat-coverage:
	$(PYTHON) scenarios/run_threat_coverage.py --all --log-dir logs/threat_coverage_all

threat-metrics:
	$(PYTHON) tools/threat_coverage_metrics.py

.DEFAULT_GOAL := test