# AuthContext

The single identity model used throughout urauth. `AuthContext` carries the authenticated user, their roles, permissions, relations, scopes, the current token, and the originating request. Guards, checkers, and application code all operate on this one type.

::: urauth.context.AuthContext
