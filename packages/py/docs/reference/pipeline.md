# Pipeline

Declarative auth configuration. The `Pipeline` class lets you compose authentication strategies, login methods, OAuth providers, and security features into a single configuration object that wires everything together.

## Pipeline

::: urauth.pipeline.Pipeline

## Strategies

Token and session strategies that control how authentication state is managed.

### JWTStrategy

::: urauth.pipeline.JWTStrategy

### SessionStrategy

::: urauth.pipeline.SessionStrategy

### BasicAuthStrategy

::: urauth.pipeline.BasicAuthStrategy

### APIKeyStrategy

::: urauth.pipeline.APIKeyStrategy

### FallbackStrategy

::: urauth.pipeline.FallbackStrategy

## Login Methods

Pluggable login method configurations.

### PasswordLogin

::: urauth.pipeline.PasswordLogin

### OAuthLogin

::: urauth.pipeline.OAuthLogin

### MagicLinkLogin

::: urauth.pipeline.MagicLinkLogin

### OTPLogin

::: urauth.pipeline.OTPLogin

### PasskeyLogin

::: urauth.pipeline.PasskeyLogin

## OAuth Providers

Pre-configured OAuth provider definitions.

### OAuthProvider

::: urauth.pipeline.OAuthProvider

### Google

::: urauth.pipeline.Google

### GitHub

::: urauth.pipeline.GitHub

### Microsoft

::: urauth.pipeline.Microsoft

### Apple

::: urauth.pipeline.Apple

### Discord

::: urauth.pipeline.Discord

### GitLab

::: urauth.pipeline.GitLab

## Features

Additional security features that can be composed into the pipeline.

### MFA

::: urauth.pipeline.MFA

### PasswordReset

::: urauth.pipeline.PasswordReset

### AccountLinking

::: urauth.pipeline.AccountLinking

### Identifiers

::: urauth.pipeline.Identifiers
