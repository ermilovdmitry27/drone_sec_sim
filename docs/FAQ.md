# Frequently Asked Questions (FAQ)

## General Questions

### Q: What is Drone Security Simulation?
**A:** Drone Security Simulation is a security testing framework for PX4-based drones. It provides a Security Monitor that detects threats (like unauthorized parameter changes, mission tampering, or navigation excursion) and can respond automatically.

### Q: Does this work with real drones?
**A:** The project supports both simulation (SITL with Gazebo) and hardware deployment. See `sim_stack.json` → `deployment_mode` to switch between `"sitl"` and `"hardware"`.

### Q: What PX4 version is supported?
**A:** The project is tested with PX4 v1.14+. Some features may work with older versions, but are not guaranteed.

### Q: Can I use this without QGroundControl?
**A:** Yes. You can run just the Security Monitor:
```bash
.venv/bin/python monitor.py --log-dir logs
```

## Installation & Setup

### Q: I get "ModuleNotFoundError: No module named 'mavsdk'"
**A:** You need to install dependencies:
```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### Q: PX4 fails to start - what should I check?
**A:** 
1. Verify PX4 directory in `sim_stack.json` → `px4_dir`
2. Ensure Gazebo is installed (comes with PX4)
3. Try building PX4 manually: `cd /path/to/PX4-Autopilot && make px4_sitl_default gazebo`

### Q: QGroundControl can't connect to the drone
**A:** 
1. In QGC, go to **Application Settings** → **Comm Links**
2. Add a UDP link on port **14552** (default `gateway_gcs_client_port`)
3. Ensure Security Monitor is running with `--enable-gateway`

### Q: The virtual environment doesn't work
**A:** Recreate it:
```bash
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## MAVLink Gateway

### Q: What does the MAVLink Gateway do?
**A:** The gateway sits between PX4 and ground control stations (like QGroundControl). It:
- Filters malicious MAVLink commands
- Optionally encrypts MAVLink traffic
- Authenticates operators
- Logs all protocol events

### Q: How do I enable gateway filtering?
**A:** Edit `sim_stack.json`:
```json
{
  "enable_gateway": true,
  "gateway_enforce": true
}
```
Or use CLI: `python launch_stack.py --enable-gateway --gateway-enforce`

### Q: What does `gateway_enforce` do?
**A:** When enabled, the gateway blocks:
- Parameter write commands
- Mission write commands  
- SERIAL_CONTROL messages
- Configured blocked command IDs

### Q: How does MAVLink encryption work?
**A:** 
1. Set `mavlink_encryption_key_hex` in `sim_stack.json` (64 hex chars = 32 bytes AES key)
2. Clients must encrypt their MAVLink datagrams with AES-GCM
3. Use `tools/encrypted_mavlink_datagram.py` for testing

### Q: What is operator authentication?
**A:** A security layer where clients must provide:
- `operator_id` (e.g., "operator-1")
- `token` (verified against SHA-256 hash in config)

Enable with: `"require_operator_auth": true`

## Threat Detection

### Q: What threats are currently covered?
**A:** Check the threat coverage catalog:
```bash
cat scenarios/threat_coverage_catalog.json
```
Or run coverage report:
```bash
python scenarios/run_threat_coverage.py --all
```

### Q: How do I add a new threat detection rule?
**A:** 
1. Edit `security_agent/detector.py`
2. Add logic in `analyze()` method
3. Create a test in `tests/test_detector.py`
4. Add entry to `scenarios/threat_coverage_catalog.json`

### Q: Can I customize detection thresholds?
**A:** Currently, thresholds are hardcoded in the detector. Future versions will support configuration via `sim_stack.json`.

### Q: Why was my parameter change blocked?
**A:** The gateway may be in `gateway_enforce` mode. Check:
```bash
cat sim_stack.json | grep gateway_enforce
```
If `true`, parameter writes are blocked by default.

## Security Monitor

### Q: What is "active response"?
**A:** When enabled (`--active-response`), the Security Monitor can automatically:
- Return drone to launch (RTL)
- Land immediately
- Terminate flight
- Lock down gateway

Without it, threats are logged but not acted upon.

### Q: How do I view security events?
**A:** Security events are logged to:
- `logs/threat_coverage_*/security_events.jsonl` (JSONL format)
- Console output (when running interactively)

### Q: What do the risk levels mean?
**A:**
- **LOW** - Informational, no action needed
- **MEDIUM** - Suspicious, increased monitoring
- **HIGH** - Threat detected, consider action
- **CRITICAL** - Immediate action required

### Q: Can I send alerts to my SIEM?
**A:** Yes! Set `siem_url` in `sim_stack.json`:
```json
{
  "siem_url": "http://your-siem:8080/events"
}
```

## Testing & CI

### Q: How do I run all tests?
**A:**
```bash
make test
# Or directly:
python -m unittest discover -s tests
```

### Q: What do the benchmark tests measure?
**A:** Benchmark tests (`test_benchmark.py`) measure:
- Threat detection latency
- Risk assessment speed
- Event queue throughput
- End-to-end pipeline latency

Run them with: `python -m unittest tests/test_benchmark.py -v`

### Q: How do I check code quality?
**A:**
```bash
ruff check security_agent/ tools/ tests/
mypy security_agent/ --ignore-missing-imports
```

Or use pre-commit hooks: `pre-commit run --all-files`

### Q: CI fails on "coverage under 70%" - what now?
**A:** Write more tests! Check coverage report:
```bash
coverage run -m unittest discover -s tests
coverage html  # Opens in browser
```

## Logs & Debugging

### Q: Where are the logs stored?
**A:** All logs go to the `logs/` directory (configurable via `log_dir`):
- `logs/threat_coverage.jsonl` - Threat coverage results
- `logs/security_events.jsonl` - Security events
- `logs/protocol_events.jsonl` - MAVLink protocol events
- `logs/telemetry.jsonl` - Telemetry data

### Q: How do I verify log integrity?
**A:** Use the audit log verifier:
```bash
python tools/verify_audit_log.py \
  logs/threat_coverage.jsonl \
  logs/security_events.jsonl \
  logs/protocol_events.jsonl
```

### Q: The logs are too verbose - how do I filter?
**A:** Use standard tools:
```bash
# Only security events
grep "security_event" logs/security_events.jsonl

# Only HIGH severity events
grep '"severity": "HIGH"' logs/security_events.jsonl
```

## Docker & Deployment

### Q: Can I run this in Docker?
**A:** Yes! Use the provided Dockerfile:
```bash
docker build -t drone_sec_sim .
docker run -p 14540:14540/udp drone_sec_sim
```

### Q: How do I use docker-compose?
**A:**
```bash
docker-compose up security-monitor
```

## Configuration

### Q: What is `sim_stack.json`?
**A:** The main configuration file for the simulation stack. It defines:
- PX4 directory and model
- Gateway settings
- Security monitor options
- Logging preferences

### Q: How do I validate my configuration?
**A:**
```bash
python tools/validate_sim_stack.py sim_stack.json
```

### Q: Can I have multiple configurations?
**A:** Yes! Use the `--config` flag:
```bash
python launch_stack.py --config /path/to/custom_config.json
```

## Performance

### Q: The Security Monitor is using too much CPU
**A:** Try:
1. Increasing throttling in collector (`throttle_seconds` in `collector.py`)
2. Running in headless mode: `"headless": true` in `sim_stack.json`
3. Disabling unused features (gateway, active response, etc.)

### Q: How many threats per second can it handle?
**A:** Benchmark results (on modern hardware):
- ~3M telemetry events/sec (detector)
- ~285K risk assessments/sec
- ~87K events/sec (queue throughput)

Run benchmarks: `python -m unittest tests/test_benchmark.py`

## Contributing

### Q: How do I contribute?
**A:** See `CONTRIBUTING.md` for guidelines. Quick steps:
1. Fork the repo
2. Create a feature branch
3. Make changes + add tests
4. Run `make test`
5. Submit a Pull Request

### Q: What coding standards do you use?
**A:**
- Python 3.12+ syntax
- Type hints where possible
- Ruff for linting
- mypy for type checking
- Google-style docstrings (optional)

### Q: How do I add a new tool?
**A:** 
1. Create `tools/your_tool.py`
2. Add entry to `tools/__init__.py` (if needed)
3. Document in `README.md`
4. Add tests in `tests/`

## Still Need Help?

- **Open an Issue:** [GitHub Issues](https://github.com/yourusername/drone_sec_sim/issues)
- **Check Documentation:** `docs/` folder
- **Review Examples:** `examples/` folder
- **Read API Docs:** `docs/API.md`
