.PHONY: test smoke-report protection-doc validate-readme verify-smoke-logs validate-encryption

PYTHON ?= .venv/bin/python

test:
	$(PYTHON) -m unittest discover -s tests

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
