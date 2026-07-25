# Contributing

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Required checks

```bash
ruff check src tests
mypy src tests
python -m pytest
```

## Detection changes

A detection pull request must document:

- the threat behaviour and ATT&CK mapping;
- required log sources and fields;
- threshold rationale;
- expected false positives and blind spots;
- synthetic positive, negative, and boundary test cases;
- alert-schema changes;
- analyst validation steps.

Do not add production or personal data. Use documentation-reserved IP ranges, synthetic identities, and fabricated hostnames.
