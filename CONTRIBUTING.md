# Contributing

## Local Setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

## Checks Before Commit

Run:

```bash
make test
make validate-readme
make smoke-report
make verify-smoke-logs
make protection-doc
```

## Source Rules

- Keep claims in reports tied to concrete source files or generated artifacts.
- Do not mark hardware validation as passed without real test evidence.
- Do not commit generated `logs/` output unless it is intentionally promoted as
  evidence.
- Keep `docs/protection_methods_analysis.md`, `.html` and `.docx` synchronized
  by running `make protection-doc` after changing the markdown report.
