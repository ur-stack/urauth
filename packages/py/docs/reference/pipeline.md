# Pipeline

Declarative auth configuration. The `Pipeline` class lets you compose authentication strategies, login methods, OAuth providers, and security features into a single configuration object that wires everything together.

## Pipeline


> **`urauth.pipeline.Pipeline`** — See source code for full API.


## Strategies

Token and session strategies that control how authentication state is managed.

### JWTStrategy


> **`urauth.pipeline.JWTStrategy`** — See source code for full API.


### SessionStrategy


> **`urauth.pipeline.SessionStrategy`** — See source code for full API.


### BasicAuthStrategy


> **`urauth.pipeline.BasicAuthStrategy`** — See source code for full API.


### APIKeyStrategy


> **`urauth.pipeline.APIKeyStrategy`** — See source code for full API.


### FallbackStrategy


> **`urauth.pipeline.FallbackStrategy`** — See source code for full API.


## Login Methods

Pluggable login method configurations.

### PasswordLogin


> **`urauth.pipeline.PasswordLogin`** — See source code for full API.


### OAuthLogin


> **`urauth.pipeline.OAuthLogin`** — See source code for full API.


### MagicLinkLogin


> **`urauth.pipeline.MagicLinkLogin`** — See source code for full API.


### OTPLogin


> **`urauth.pipeline.OTPLogin`** — See source code for full API.


### PasskeyLogin


> **`urauth.pipeline.PasskeyLogin`** — See source code for full API.


## OAuth Providers

Pre-configured OAuth provider definitions.

### OAuthProvider


> **`urauth.pipeline.OAuthProvider`** — See source code for full API.


### Google


> **`urauth.pipeline.Google`** — See source code for full API.


### GitHub


> **`urauth.pipeline.GitHub`** — See source code for full API.


### Microsoft


> **`urauth.pipeline.Microsoft`** — See source code for full API.


### Apple


> **`urauth.pipeline.Apple`** — See source code for full API.


### Discord


> **`urauth.pipeline.Discord`** — See source code for full API.


### GitLab


> **`urauth.pipeline.GitLab`** — See source code for full API.


## Features

Additional security features that can be composed into the pipeline.

### MFAMethod


> **`urauth.pipeline.MFAMethod`** — See source code for full API.


### PasswordReset


> **`urauth.pipeline.PasswordReset`** — See source code for full API.


### AccountLinking


> **`urauth.pipeline.AccountLinking`** — See source code for full API.


### Identifiers


> **`urauth.pipeline.Identifiers`** — See source code for full API.

