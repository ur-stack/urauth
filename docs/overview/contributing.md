# Contributing

Contributions to urauth are welcome. This page covers how to get started, what areas need help, and what to expect when submitting a pull request.

## Getting Started

Clone the repository and install dependencies:

```bash
git clone https://github.com/grandmagus/urauth.git
cd urauth
```

**Python package:**

```bash
cd packages/py
uv sync --all-extras
```

**TypeScript packages:**

```bash
bun install
```

## What Needs Help

- **New OAuth2 providers** — Adding a provider requires a config entry and a token exchange handler. Existing providers in `urauth/oauth/` are good templates.
- **.NET / C# port** — The core design maps cleanly to ASP.NET Core middleware. See the [integrations page](./integrations) for scope.
- **Documentation** — Examples, how-to guides, and corrections to existing content are always welcome.
- **Bug reports** — If you find unexpected behavior, open an issue with a minimal reproduction.

## Pull Request Guidelines

Every pull request must pass CI before merge:

- `ruff` linting and `basedpyright` type checking (strict)
- `pytest` across Python 3.10–3.13
- `pip-audit` dependency scan
- `bandit` static analysis
- `detect-secrets` secret scanning

There is no mechanism to bypass these checks.

For non-trivial changes, open an issue first to discuss the approach. This avoids wasted effort on PRs that won't be merged due to design disagreement.

## Security Vulnerabilities

**Do not report security vulnerabilities through public GitHub issues.** Use [GitHub Security Advisories](https://github.com/ur-stack/urauth/security/advisories/new) to report privately. See the [Security page](./security#reporting) for the full disclosure process.

## Code Style

- Python: follow `ruff` defaults. No type: ignore comments without justification.
- TypeScript: follow the existing ESLint configuration.
- Commit messages: imperative mood, present tense (`add`, `fix`, `update` — not `added`, `fixed`, `updated`).

## License

urauth is released under the MIT License. By contributing, you agree that your contributions will be licensed under the same terms.
