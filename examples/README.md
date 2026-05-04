# Examples

This directory contains usage examples for the Drone Security Simulation project.

## Available Examples

- `gateway_client.py` - Example of connecting to the MAVLink gateway as a client
- `monitor_simple.py` - Minimal example of running the Security Monitor
- `custom_detector.py` - Example of creating a custom threat detector
- `scenario_runner.py` - Example of running threat coverage scenarios programmatically

## Running Examples

Make sure you have installed the dependencies:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Then run any example:

```bash
.venv/bin/python examples/gateway_client.py
```
