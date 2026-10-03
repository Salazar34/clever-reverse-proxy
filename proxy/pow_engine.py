"""
SecLab DoS Mitigation - Cryptographic Proof-of-Work (PoW) Engine
Module: proxy.pow_engine

Implements an active, stateless, request-bound Proof-of-Work defense protocol
based on RFC 6585 (HTTP 428 Precondition Required) and Hashcash principles.

Protects PostgreSQL and backend resources by imposing an asymmetric computational
penalty on clients exceeding their token bucket allowance.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from typing import Any, Mapping, Tuple

try:
    import redis.asyncio as aioredis
    from redis.exceptions import RedisError
except ImportError:  # pragma: no cover
    aioredis = None  # type: ignore
    class RedisError(Exception):  # type: ignore
        """Fallback RedisError for environments without redis-py."""
        pass

logger = logging.getLogger("proxy.pow_engine")


def _b64url_encode(data: bytes) -> str:
    """Encodes bytes into unpadded URL-safe Base64."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Decodes unpadded URL-safe Base64 strings."""
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s.encode("ascii"))


class PoWEngine:
    """
    Cryptographic Proof-of-Work Engine.

    Features:
      - Stateless Token Generation: All challenge state is contained in the HMAC-signed token.
      - Request-Binding: Binds the challenge to METHOD:PATH:QUERY to prevent cross-route replay.
      - Adaptive Difficulty: Dynamically scales based on client credit deficit.
      - Single-Hash Verification: Server validation requires exactly 1 SHA-256 evaluation.
      - Anti-Replay Cache: Uses Redis atomic SET NX EX to ensure single-use challenge consumption.
    """

    def __init__(
        self,
        secret_key: str,
        redis_client: aioredis.Redis,
        challenge_ttl_seconds: int = 60,
        base_difficulty: int = 4,
    ) -> None:
        if not secret_key or len(secret_key) < 16:
            raise ValueError("secret_key must be at least 16 characters for HMAC-SHA256")

        self._secret = secret_key.encode("utf-8")
        self.redis = redis_client
        self.ttl = int(challenge_ttl_seconds)
        self.base_difficulty = int(base_difficulty)

    @staticmethod
    def compute_request_fingerprint(
        method: str,
        path: str,
        query_params: Mapping[str, Any] | None = None,
    ) -> str:
        """
        Computes a deterministic SHA-256 digest of the normalized request parameters.
        Canonical format: METHOD:PATH:k1=v1&k2=v2 (alphabetically sorted keys).
        """
        params = query_params or {}
        # Sort query parameter keys for deterministic canonicalization
        sorted_pairs = [f"{str(k)}={str(params[k])}" for k in sorted(params.keys())]
        canonical_str = f"{method.upper().strip()}:{path.strip()}:{'&'.join(sorted_pairs)}"
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def generate_challenge(
        self,
        method: str,
        path: str,
        query_params: Mapping[str, Any] | None = None,
        deficit: float = 0.0,
    ) -> dict[str, Any]:
        """
        Issues an HMAC-SHA256 signed cryptographic challenge.

        Difficulty scaling:
          - D = base_difficulty (e.g. 4 hex zeros = 65,536 expected hashes)
          - If client deficit > 40 credits: D = base_difficulty + 1 (1,048,576 expected hashes)
        """
        # 1. Adaptive difficulty computation
        difficulty = self.base_difficulty + (1 if deficit > 40.0 else 0)

        # 2. Entropy and timestamp generation
        salt = secrets.token_hex(16)
        now_ts = int(time.time())
        fingerprint = self.compute_request_fingerprint(method, path, query_params)

        # 3. Stateless payload assembly
        payload_data = {
            "salt": salt,
            "ts": now_ts,
            "diff": difficulty,
            "fp": fingerprint,
        }
        payload_bytes = json.dumps(payload_data, separators=(",", ":")).encode("utf-8")
        payload_b64 = _b64url_encode(payload_bytes)

        # 4. Cryptographic signature (HMAC-SHA256)
        signature = hmac.digest(self._secret, payload_b64.encode("ascii"), hashlib.sha256)
        signature_b64 = _b64url_encode(signature)

        token = f"{payload_b64}.{signature_b64}"

        return {
            "token": token,
            "difficulty": difficulty,
            "algorithm": "SHA-256",
            "expires_in": self.ttl,
        }

    async def verify_solution(
        self,
        token: str,
        nonce: str,
        method: str,
        path: str,
        query_params: Mapping[str, Any] | None = None,
    ) -> Tuple[bool, str]:
        """
        Verifies client PoW solution with O(1) server-side computational overhead.

        Returns:
            Tuple[bool, str]: (is_valid, reason)
        """
        # --- Check 0: Malformed input guard ---
        if not token or not nonce or "." not in token:
            return False, "Malformed challenge token or missing nonce"

        payload_b64, signature_b64 = token.split(".", 1)

        # --- Check 1: Cryptographic HMAC Signature Verification (O(1)) ---
        expected_sig = hmac.digest(self._secret, payload_b64.encode("ascii"), hashlib.sha256)
        expected_sig_b64 = _b64url_encode(expected_sig)
        if not hmac.compare_digest(signature_b64, expected_sig_b64):
            return False, "Invalid token signature"

        # --- Check 2: Payload Deserialization & Temporal Expiration (O(1)) ---
        try:
            payload_json = _b64url_decode(payload_b64).decode("utf-8")
            payload = json.loads(payload_json)
            issued_ts = int(payload["ts"])
            difficulty = int(payload["diff"])
            expected_fp = str(payload["fp"])
        except (ValueError, KeyError, UnicodeDecodeError):
            return False, "Corrupt or unreadable token payload"

        now = int(time.time())
        elapsed = now - issued_ts
        if elapsed > self.ttl or elapsed < -5:  # Allow 5s clock skew
            return False, "Challenge token expired"

        # --- Check 3: Request-Binding Integrity Check (O(1)) ---
        actual_fp = self.compute_request_fingerprint(method, path, query_params)
        if not hmac.compare_digest(expected_fp, actual_fp):
            return False, "Token request-binding mismatch (cannot reuse tokens across distinct requests)"

        # --- Check 4: Single-Hash Proof Verification (1 SHA-256 evaluation) ---
        candidate_bytes = f"{token}:{nonce}".encode("ascii")
        computed_hash = hashlib.sha256(candidate_bytes).hexdigest()
        required_prefix = "0" * difficulty

        if not computed_hash.startswith(required_prefix):
            return False, f"Insufficient computational work (expected {difficulty} leading hex zeros)"

        # --- Check 5: Atomic Anti-Replay Store in Redis ---
        remaining_ttl = max(1, self.ttl - elapsed)
        replay_key = f"pow:used:{signature_b64}"

        try:
            # SET pow:used:<sig> 1 EX <ttl> NX
            # Returns True only if the key was set (i.e. first use)
            was_set = await self.redis.set(replay_key, "1", ex=remaining_ttl, nx=True)
            if not was_set:
                return False, "Replay attack detected: challenge token has already been consumed"
        except RedisError as exc:
            logger.error("Redis failure during PoW anti-replay check: %s", exc)
            return False, "Internal verification state error"

        return True, "OK"
