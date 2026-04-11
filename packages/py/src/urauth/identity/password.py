from __future__ import annotations

import base64
import hashlib
import hmac
import os


class PasswordHasher:
    """Password hashing using scrypt (stdlib, Python 3.10+).

    Hash format: ``$scrypt$ln=<log2_n>,r=<r>,p=<p>$<salt_b64>$<hash_b64>``

    Legacy bcrypt hashes (prefix ``$2``) are detected automatically on
    ``verify()`` and delegated to the ``bcrypt`` package. Install it with
    ``pip install urauth[bcrypt]`` if you have existing bcrypt hashes to
    migrate.
    """

    def __init__(self, n: int = 2**14, r: int = 8, p: int = 1, dklen: int = 32) -> None:
        if n < 2 or (n & (n - 1)) != 0:
            raise ValueError("n must be a power of 2 and >= 2")
        if not 1 <= r <= 2**30:
            raise ValueError("r must be between 1 and 2^30")
        if not 1 <= p <= 2**30:
            raise ValueError("p must be between 1 and 2^30")
        if dklen < 16:
            raise ValueError("dklen must be at least 16 bytes")
        self._n = n
        self._r = r
        self._p = p
        self._dklen = dklen

    def hash(self, password: str) -> str:
        salt = os.urandom(16)
        dk = hashlib.scrypt(password.encode(), salt=salt, n=self._n, r=self._r, p=self._p, dklen=self._dklen)
        ln = self._n.bit_length() - 1
        params = f"ln={ln},r={self._r},p={self._p}"
        salt_b64 = base64.b64encode(salt).decode()
        hash_b64 = base64.b64encode(dk).decode()
        return f"$scrypt${params}${salt_b64}${hash_b64}"

    def verify(self, password: str, hashed: str) -> bool:
        if hashed.startswith("$2"):
            return self._verify_bcrypt(password, hashed)
        return self._verify_scrypt(password, hashed)

    def _verify_scrypt(self, password: str, hashed: str) -> bool:
        try:
            parts = hashed.split("$")
            # ['', 'scrypt', 'ln=14,r=8,p=1', '<salt_b64>', '<hash_b64>']
            if len(parts) != 5 or parts[1] != "scrypt":
                return False
            params = dict(kv.split("=") for kv in parts[2].split(","))
            n = 2 ** int(params["ln"])
            r = int(params["r"])
            p = int(params["p"])
            salt = base64.b64decode(parts[3])
            expected = base64.b64decode(parts[4])
            dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=len(expected))
            return hmac.compare_digest(dk, expected)
        except (ValueError, KeyError, TypeError):
            return False

    def _verify_bcrypt(self, password: str, hashed: str) -> bool:
        try:
            import bcrypt  # optional — pip install urauth[bcrypt]
        except ImportError:
            raise RuntimeError(
                "bcrypt is required to verify legacy bcrypt hashes. "
                "Install with: pip install urauth[bcrypt]"
            ) from None
        return bool(bcrypt.checkpw(password.encode(), hashed.encode()))
