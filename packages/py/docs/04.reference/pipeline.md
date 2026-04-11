# Auth Methods & Login Methods

Auth methods and login methods are defined in `urauth.methods`. They configure how authentication state is managed and how users prove their identity.

## Auth Methods

Auth methods control how authenticated state is maintained per request. Set via `method=` on `Auth()`.

### JWT


> **`urauth.methods.JWT`** -- See source code for full API.


### Session


> **`urauth.methods.Session`** -- See source code for full API.


### BasicAuth


> **`urauth.methods.BasicAuth`** -- See source code for full API.


### APIKey


> **`urauth.methods.APIKey`** -- See source code for full API.


### Fallback


> **`urauth.methods.Fallback`** -- See source code for full API.


## Login Methods

Pluggable login method configurations. Set as flat parameters on `Auth()`.

### Password


> **`urauth.methods.Password`** -- See source code for full API.


### ResetablePassword


> **`urauth.methods.ResetablePassword`** -- See source code for full API.


### OAuth


> **`urauth.methods.OAuth`** -- See source code for full API.


### MagicLink


> **`urauth.methods.MagicLink`** -- See source code for full API.


### OTP


> **`urauth.methods.OTP`** -- See source code for full API.


### Passkey


> **`urauth.methods.Passkey`** -- See source code for full API.


## OAuth Providers

Pre-configured OAuth provider definitions.

### OAuthProvider


> **`urauth.methods.OAuthProvider`** -- See source code for full API.


### Google


> **`urauth.methods.Google`** -- See source code for full API.


### GitHub


> **`urauth.methods.GitHub`** -- See source code for full API.


### Microsoft


> **`urauth.methods.Microsoft`** -- See source code for full API.


### Apple


> **`urauth.methods.Apple`** -- See source code for full API.


### Discord


> **`urauth.methods.Discord`** -- See source code for full API.


### GitLab


> **`urauth.methods.GitLab`** -- See source code for full API.


## Features

Additional security features.

### MFA


> **`urauth.methods.MFA`** -- See source code for full API.


### Identifiers


> **`urauth.methods.Identifiers`** -- See source code for full API.


## Result Types

Framework-agnostic return types for Auth endpoint methods.

### AuthResult


> **`urauth.results.AuthResult`** -- See source code for full API.


### MFARequiredResult


> **`urauth.results.MFARequiredResult`** -- See source code for full API.


### ResetSessionResult


> **`urauth.results.ResetSessionResult`** -- See source code for full API.


### MessageResult


> **`urauth.results.MessageResult`** -- See source code for full API.
