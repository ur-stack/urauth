# Version Support Policy

This document describes how urauth versions are supported, when breaking changes can occur, and how deprecations are handled.

## Release Channels

| Channel | What It Receives | Duration |
|---|---|---|
| Latest minor release | Features, bug fixes, security fixes | Until the next minor release |
| Previous minor release | Security fixes only | 6 months after the next minor release |
| Older releases | Nothing | Unsupported |


> **`details`** — See source code for full API.

If `0.5.0` is the latest release and `0.6.0` ships today:

- `0.6.x` receives features, bug fixes, and security fixes.
- `0.5.x` receives security fixes only, for 6 months.
- `0.4.x` and older are unsupported.

:::

## Pre-1.0 Expectations

urauth is currently **pre-1.0**. This means:

- **No backward compatibility guarantees** between minor versions. A `0.x` to `0.y` upgrade may contain breaking changes.
- **Security fixes are backported** to the previous minor release for 6 months, even during pre-1.0 development.
- **Patch releases** (`0.x.1`, `0.x.2`) within a minor version will not contain breaking changes.


> **`warning`** — See source code for full API.

Pin your dependency to a specific minor version during pre-1.0:

```toml
# pyproject.toml
dependencies = [
    "urauth>=0.5,<0.6",
]
```

:::

## Post-1.0 Expectations

Once urauth reaches `1.0.0`, the following rules apply:

- **Breaking changes only in major versions** (`1.x` to `2.0`).
- **Minor versions** (`1.1`, `1.2`) add features and fix bugs without breaking existing APIs.
- **Patch versions** (`1.0.1`, `1.0.2`) contain only bug fixes and security patches.
- [Semantic Versioning 2.0.0](https://semver.org/) is followed strictly.

## Python Version Support

urauth matches the **CPython active support window**:

| Python Version | Status | urauth Support |
|---|---|---|
| 3.13 | Active | Supported |
| 3.12 | Active | Supported |
| 3.11 | Active | Supported |
| 3.10 | Security fixes only | Supported (will be dropped in a future minor release) |
| 3.9 and older | End of life | Not supported |

When CPython drops active support for a version, urauth will drop it in the **next minor release**.


> **`info`** — See source code for full API.

CI runs the full test suite on Python 3.10, 3.11, 3.12, and 3.13. All must pass before a release is published.

:::

## Deprecation Process

1. **Warn**: The feature is marked with a `DeprecationWarning` and documented as deprecated. This lasts for **one minor version**.
2. **Remove**: The feature is removed in the **next minor version** after the warning was introduced.

```python
# Example: deprecated in 0.5.0
import warnings

def old_function():
    warnings.warn(
        "old_function() is deprecated, use new_function() instead. "
        "It will be removed in 0.6.0.",
        DeprecationWarning,
        stacklevel=2,
    )
    return new_function()
```


> **`tip`** — See source code for full API.

Run your test suite with `-W error::DeprecationWarning` to catch deprecated urauth usage before upgrading:

```bash
python -W error::DeprecationWarning -m pytest
```

:::

## Breaking Change Communication

All breaking changes are documented in:

1. **CHANGELOG.md** -- every release includes a "Breaking Changes" section (if applicable).
2. **Migration guide** -- for significant changes, a dedicated migration guide is published in the docs.
3. **GitHub Release notes** -- linked from PyPI.

## Security Fixes

Security fixes receive special treatment:

- **Backported** to the previous minor release within the 6-month support window.
- **Released as patch versions** (e.g., `0.5.1`) as soon as possible after the fix is verified.
- **Disclosed** following a responsible disclosure timeline (fix first, then announce).


> **`danger`** — See source code for full API.

If you discover a security vulnerability in urauth, please report it privately. Do not open a public GitHub issue. See the SECURITY.md file in the repository root for disclosure instructions.

:::