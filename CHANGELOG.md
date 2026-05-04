# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `.env.example` template for environment configuration
- Unit tests for `security_agent/app.py` (print methods, initialization)
- Unit tests for `security_agent/collector.py` (normalizers, stream watching)
- Unit tests for `security_agent/state_guard.py` (param diff, mission snapshot, change detection)

### Changed
- None

### Deprecated
- None

### Removed
- None

### Fixed
- None

### Security
- None

## [0.1.0] - 2026-05-04

### Added
- Initial project structure with PX4 SITL integration
- Security Monitor with telemetry collection and threat detection
- MAVLink Gateway with filtering and encryption support
- Threat coverage runner and catalog (`scenarios/`)
- Security agent modules: `app.py`, `collector.py`, `detector.py`, `gateway.py`, `responder.py`, `risk_engine.py`, `state_guard.py`, `audit.py`
- Unit tests for `gateway`, `detector`, `responder`, `audit`, `risk_engine`
- Tools: `encrypted_mavlink_datagram.py`, `architecture_report.py`, `determinism_report.py`, `build_protection_methods_doc.py`, `build_threat_coverage_report.py`, `build_threat_coverage_catalog.py`, `extract_gz_x500_model_spec.py`, `build_simple_docx.py`, `verify_audit_log.py`
- `launch_stack.py` for running full stack (PX4 SITL + Gazebo + QGroundControl + Security Monitor)
- `monitor.py` for standalone Security Monitor
- `sim_stack.json` configuration file
- CI workflow (`.github/workflows/ci.yml`) with unit tests and README validation
- Documentation: `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `SECURITY.md`
- `Makefile` with targets: `test`, `smoke-report`, `protection-doc`, `validate-readme`, `verify-smoke-logs`, `validate-encryption`
- `.gitignore` excluding `.venv/`, `logs/`, `__pycache__/`, IDE configs
- `requirements.txt` and `pyproject.toml` with dependencies (`mavsdk==3.15.3`, `cryptography==42.0.8`)
- MIT License (`LICENSE`)
- Validation artifacts in `validation/` (model spec, hardware validation example, determinism report)
- Threat coverage catalog (`scenarios/threat_coverage_catalog.json`)
- Attack scenarios: `attack_navigation_excursion.py`, `attack_mission_overwrite.py`, `attack_param_tamper.py`, `attack_arm_disarm_flap.py`
- Simulation scenarios: `simulate_serial_control_log_flow.py`, `simulate_serial_control_detection.py`

[Unreleased]: https://github.com/yourusername/drone_sec_sim/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yourusername/drone_sec_sim/releases/tag/v0.1.0
