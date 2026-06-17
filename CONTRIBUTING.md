# Contributing

proxima·red is primarily maintained by a single developer. Contributions are welcome, but please read this first.

## Reporting Bugs

Open an issue. Include:

- What you expected to happen
- What actually happened
- Steps to reproduce

For security issues, do **not** open a public issue. See [SECURITY.md](./SECURITY.md) instead.

## Suggesting Features

Open an issue with the `suggestion` label. Be aware that proxima·red is intentionally minimal — suggestions that introduce telemetry, reduce privacy defaults, or add unnecessary complexity are unlikely to be accepted regardless of implementation quality.

## Development Setup

See [docs/development.md](./docs/development.md) for instructions on setting up a local environment, running the development server, and running the test suite.

## Code Style

Python is formatted and linted with [Ruff](https://docs.astral.sh/ruff/) (100-character lines, double quotes):

```bash
ruff format .  # format
ruff check .   # lint (E, F, I rules)
```

JavaScript is formatted with [Prettier](https://prettier.io/) (100-character lines, double quotes, semicolons):

```bash
npx prettier --write static/js/
```

Please run both before submitting a pull request.

## Submitting Code

1. Open an issue before starting significant work, so we can discuss whether it fits the project before you invest time
2. Fork the repository and work on a feature branch
3. Keep changes focused
4. Run the test suite (`python manage.py test --settings=config.settings.testing`) and make sure nothing is broken
5. Submit a pull request with a clear description of what and why

All contributions must be compatible with AGPL-3.0. By submitting a pull request you confirm that you have the right to contribute the code and agree to license it under AGPL-3.0.

## Improving Documentation

Corrections, clarifications, and improvements to the README, self-hosting guide, or other docs are always welcome. Same process as code — fork, branch, PR.

## What Will Not Be Merged

- Anything that introduces telemetry or usage tracking
- Anything that weakens encryption defaults without explicit user choice
- Third-party analytics, ad network, or tracker integrations
- Dependencies that significantly increase the attack surface without a compelling reason
