# Auth

The framework-agnostic base class for authentication. Subclass `Auth` and override methods like `get_user`, `get_user_by_username`, and `verify_password` to integrate with your user storage. Both sync and async overrides are supported transparently via internal `_maybe_await()` dispatching.


> **`urauth.auth.Auth`** — See source code for full API.

