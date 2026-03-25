# FastAuth

The FastAPI adapter that wraps the core `Auth` class. `FastAuth` is the single entry point for FastAPI integration, providing `context()`, `current_user`, `require()`, and `access_control()` as FastAPI dependencies. It handles token extraction, validation, user loading, and context building in one cached resolution path.


> **`urauth.fastapi.auth.FastAuth`** — See source code for full API.

