# Contributing to air-adk-trust

Thanks for your interest in contributing! This package adds EU AI Act compliance to Google ADK agents via plugin callbacks.

## Quick Setup

```bash
git clone https://github.com/airblackbox/air-adk-trust.git
cd air-adk-trust
pip install -e ".[dev]"
pytest tests/ -v
```

All 43 tests should pass.

## How to Contribute

**Bug reports** — Open an issue with a minimal reproduction. Include the plugin configuration and callback behavior you observed.

**Audit chain issues** — If the HMAC chain verification fails unexpectedly or misses a tamper, that's critical — please report it.

**PII/injection patterns** — If you find PII patterns the detectors miss or false positives they shouldn't flag, open an issue with examples.

**Documentation** — README improvements, docstring fixes, and usage examples are always welcome.

## Pull Request Process

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Run `ruff check air_adk_trust/ --select E,F --ignore E501,F541` — must pass clean
4. Run `pytest tests/ -v` — all tests must pass
5. Open a PR with a clear description of what changed and why

## Code Style

- We use [ruff](https://github.com/astral-sh/ruff) for linting (rules: E, F)
- Tests use pytest with pytest-asyncio
- Write tests for any new detection patterns or callbacks

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
