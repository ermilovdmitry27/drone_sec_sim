# Quickstart Tutorial

This guide will walk you through setting up and running the Drone Security Simulation project from scratch.

## Prerequisites

- **Python 3.12+** - [Download here](https://www.python.org/downloads/)
- **PX4 Autopilot** - [Installation guide](https://docs.px4.io/main/en/dev_setup/building_px4.html)
- **Gazebo Simulator** - Installed with PX4
- **QGroundControl** - [Download AppImage](https://docs.qgroundcontrol.com/master/en/getting_started/download_and_install.html)

## Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/drone_sec_sim.git
cd drone_sec_sim
```

## Step 2: Create Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Linux/Mac
# Or on Windows: .venv\Scripts\activate
```

## Step 3: Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

This will install:
- `mavsdk==3.15.3` - MAVLink SDK for Python
- `cryptography==42.0.8` - Encryption support
- `jsonschema>=4.22.0` - Config validation

## Step 4: Configure Environment (Optional)

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` if you need to customize paths:
```bash
# Example: Change PX4 directory
PX4_DIR=/path/to/your/PX4-Autopilot
```

## Step 5: Verify Configuration

Check that `sim_stack.json` matches your setup:

```bash
# View current config
cat sim_stack.json

# Validate config against schema
python tools/validate_sim_stack.py
```

Default paths:
- PX4: `/home/user/PX4-Autopilot`
- QGC: `/home/user/QGroundControl.AppImage`

## Step 6: Run Full Stack (PX4 + Gazebo + QGC + Security Monitor)

```bash
.venv/bin/python launch_stack.py
```

**What happens:**
1. PX4 SITL starts with Gazebo simulator
2. Security Monitor starts (watching for threats)
3. QGroundControl launches (if path configured)
4. You'll see connection instructions for QGC

**Expected output:**
```
Профиль развёртывания: deployment_mode=sitl model=gz_x500 gateway=True active_response=False
Старт PX4 SITL: gz_x500
Старт Security Monitor
...
Стенд запущен. Нажмите Ctrl+C для остановки.
```

## Step 7: Connect QGroundControl

In QGroundControl:
1. Go to **Application Settings** → **Comm Links**
2. Click **Add**
3. Set Type: **UDP**
4. Port: **14552** (default gateway GCS client port)
5. Click **OK**, then **Connect**

## Step 8: Watch Security Monitoring

The Security Monitor will print telemetry and security events:

```
[POS] lat=55.755826 lon=37.617300 rel_alt=10.5m
[BAT] remaining=85% voltage=12.50V
[MODE] POSCTL
[SECURITY] time=2026-05-04T12:00:00Z rule=param_write_blocked severity=HIGH ...
```

## Step 9: Run Threat Coverage Tests

Test that threats are properly detected:

```bash
# Quick smoke test (5 threats)
.venv/bin/python scenarios/run_threat_coverage.py \
  --all --limit 5 \
  --log-dir logs/threat_coverage_smoke

# Full coverage run
.venv/bin/python scenarios/run_threat_coverage.py \
  --all \
  --log-dir logs/threat_coverage_all
```

## Step 10: View Reports

Generate documentation and reports:

```bash
# Architecture report
.venv/bin/python tools/architecture_report.py --format md

# Threat coverage metrics
.venv/bin/python tools/threat_coverage_metrics.py

# View logs
ls -la logs/
cat logs/threat_coverage_smoke/threat_coverage.jsonl
```

## Common Next Steps

### Enable Active Response
```bash
.venv/bin/python launch_stack.py --active-response
```

### Enable Gateway Enforcement
Edit `sim_stack.json`:
```json
{
  "gateway_enforce": true,
  "gateway_block_serial_control": true
}
```

### Run Unit Tests
```bash
make test
# Or directly:
.venv/bin/python -m unittest discover -s tests
```

### Check Code Quality
```bash
make validate-readme
ruff check security_agent/ tools/ tests/
mypy security_agent/
```

## Troubleshooting

### PX4 fails to start
- Check PX4 directory in `sim_stack.json`
- Ensure Gazebo is installed
- Try: `cd /path/to/PX4-Autopilot && make px4_sitl_default gazebo`

### Security Monitor can't connect
- Verify PX4 is running first
- Check UDP ports aren't blocked
- Try: `netstat -an | grep 14540`

### QGroundControl can't connect
- Ensure you created UDP Comm Link on port 14552
- Check `gateway_gcs_client_port` in config

### ImportError: No module named 'mavsdk'
- Activate virtual environment: `source .venv/bin/activate`
- Reinstall: `pip install mavsdk==3.15.3`

## Getting Help

- Check `docs/API.md` for API reference
- Check `docs/architecture.md` for system overview
- Review `examples/` for usage examples
- Open an issue: [GitHub Issues](https://github.com/yourusername/drone_sec_sim/issues)
