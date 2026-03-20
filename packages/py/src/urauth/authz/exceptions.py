"""Access control exceptions."""

from __future__ import annotations

from urauth.exceptions import ForbiddenError

# AccessDeniedError is an alias for ForbiddenError (both represent 403)
AccessDeniedError = ForbiddenError


class PolicyEvaluationError(Exception):
    """Raised when a policy fails to evaluate (misconfiguration, runtime error)."""


class ConfigurationError(Exception):
    """Raised for invalid access control configuration."""
