# Rate Limiting

Protect endpoints from abuse with IP-based, user-based, or session-based rate limiting.

## Install

Rate limiting requires the `pyrate-limiter` package:

```bash
pip install pyrate-limiter
```

## Core RateLimiter (Framework-Agnostic)

`RateLimiter` works with any framework. It wraps `pyrate-limiter` and adds key extraction strategies.

```python
from pyrate_limiter import Duration, Rate
from urauth import RateLimiter, KeyStrategy
```

### IP-Based (Default)

```python
limiter = RateLimiter(
    rates=[Rate(100, Duration.MINUTE)],
    key=KeyStrategy.IP,
)

allowed = await limiter.check_request(ip="192.168.1.1")
```

### User-Based

Rate limit per authenticated user identity:

```python
limiter = RateLimiter(
    rates=[Rate(50, Duration.MINUTE)],
    key=KeyStrategy.IDENTITY,
)

allowed = await limiter.check_request(user_id="user-42", ip="192.168.1.1")
```

When `user_id` is available it is used as the key; otherwise falls back to IP.

### Session / JWT Based

```python
# Session-based
session_limiter = RateLimiter(
    rates=[Rate(200, Duration.MINUTE)],
    key=KeyStrategy.SESSION,
)

allowed = await session_limiter.check_request(session_id="sess-abc")

# JWT-based
jwt_limiter = RateLimiter(
    rates=[Rate(100, Duration.MINUTE)],
    key=KeyStrategy.JWT,
)

allowed = await jwt_limiter.check_request(jwt_sub="user-42")
```

### Custom Key Function

For full control, provide a `key_func`:

```python
limiter = RateLimiter(
    rates=[Rate(10, Duration.MINUTE)],
    key_func=lambda ip, user_id, **kw: f"custom:{user_id or ip}",
)
```

## FastAPI RateLimit (Dual-Use)

The `RateLimit` class is a FastAPI-specific adapter that works as both a decorator and a `Depends()` dependency. It extracts request info (IP, user, session) automatically from the `Request` object.

```python
from pyrate_limiter import Duration, Rate
from urauth import KeyStrategy
from urauth.fastapi.ratelimit import RateLimit
```

### As a Dependency

```python
ip_limit = RateLimit(rates=[Rate(100, Duration.MINUTE)])

@app.get("/api/data", dependencies=[Depends(ip_limit)])
async def get_data():
    return {"data": "..."}
```

### As a Decorator

```python
ip_limit = RateLimit(rates=[Rate(10, Duration.MINUTE)])

@app.get("/api/data")
@ip_limit
async def get_data(request: Request):
    return {"data": "..."}
```


> **`info`** — See source code for full API.

When using decorator mode, the endpoint must have a `request: Request` parameter so the rate limiter can extract the client IP.

:::
### Rate Limit Per User

Pass an `Auth` instance to extract user identity from the JWT or cached `AuthContext`:

```python
user_limit = RateLimit(
    rates=[Rate(20, Duration.MINUTE)],
    key=KeyStrategy.IDENTITY,
    auth=core,  # your Auth subclass instance
)

@app.get("/api/data", dependencies=[Depends(user_limit)])
async def get_data():
    return {"data": "..."}
```

### Session-Based Rate Limit

```python
session_limit = RateLimit(
    rates=[Rate(50, Duration.MINUTE)],
    key=KeyStrategy.SESSION,
    auth=core,
)
```

### Custom Key Function (FastAPI)

The FastAPI `RateLimit` accepts a `key_func` that receives the full `Request`:

```python
RateLimit(
    rates=[Rate(10, Duration.MINUTE)],
    key_func=lambda request: request.headers.get("X-Forwarded-For", request.client.host),
)
```

## Multiple Limits

Combine IP and user limits on the same endpoint:

```python
ip_limit = RateLimit(rates=[Rate(100, Duration.MINUTE)])
user_limit = RateLimit(
    rates=[Rate(20, Duration.MINUTE)],
    key=KeyStrategy.IDENTITY,
    auth=core,
)

@app.get(
    "/api/data",
    dependencies=[Depends(ip_limit), Depends(user_limit)],
)
async def get_data():
    return {"data": "..."}
```

Both limits are checked independently. If either is exceeded, the request is rejected.

## Custom Error Response

Control the HTTP status code and error message:

```python
limit = RateLimit(
    rates=[Rate(10, Duration.MINUTE)],
    status_code=429,
    detail="Too many requests. Please try again later.",
)
```

The defaults are `status_code=429` and `detail="Rate limit exceeded"`.
