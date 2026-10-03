"""
SecLab DoS Mitigation - High-Performance Distributed Rate Limiter
Module: proxy.rate_limiter

Implements an atomic Weighted Token Bucket on Redis using Lazy Evaluation
and Lua scripting to eliminate race conditions under high concurrent loads.
"""

from __future__ import annotations

import logging
from pathlib import Path
import time
from typing import Tuple

import redis.asyncio as aioredis
from redis.exceptions import NoScriptError, RedisError

logger = logging.getLogger("proxy.rate_limiter")

DEFAULT_LUA_PATH = Path(__file__).resolve().parent / "lua" / "weighted_token_bucket.lua"


class RateLimiterError(Exception):
    """Base exception for rate limiter errors."""


class WeightedRateLimiter:
    """
    Asynchronous, distributed Weighted Token Bucket rate limiter backed by Redis.
    
    Attributes:
        redis_url: Connection URL for Redis (e.g. 'redis://redis:6379/0').
        capacity: Maximum token bucket size B (burst allowance).
        refill_rate: Sustained generation rate r in tokens/second.
        lua_script_path: Path to the compiled Lua atomic script.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        capacity: float = 100.0,
        refill_rate: float = 10.0,
        lua_script_path: str | Path | None = None,
        key_prefix: str = "ratelimit",
    ) -> None:
        self.redis_url = redis_url
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.lua_script_path = Path(lua_script_path or DEFAULT_LUA_PATH)
        self.key_prefix = key_prefix

        self.redis: aioredis.Redis | None = None
        self._lua_code: str = ""
        self._script_sha: str = ""

    async def initialize(self) -> None:
        """
        Initializes the Redis connection pool, loads the Lua script,
        and caches its SHA1 digest for zero-overhead EVALSHA execution.
        """
        if not self.lua_script_path.exists():
            raise FileNotFoundError(f"Lua script not found at: {self.lua_script_path}")

        self._lua_code = self.lua_script_path.read_text(encoding="utf-8")

        logger.info(
            "Connecting to Redis at %s and compiling Lua rate limiter script...",
            self.redis_url,
        )

        try:
            self.redis = aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
                max_connections=100,
                socket_connect_timeout=5.0,
                socket_timeout=5.0,
            )
            # Load script into Redis script cache and store SHA1
            self._script_sha = await self.redis.script_load(self._lua_code)
            logger.info(
                "WeightedRateLimiter initialized (Capacity=%.1f, Refill=%.1f/s, SHA=%s)",
                self.capacity,
                self.refill_rate,
                self._script_sha,
            )
        except RedisError as exc:
            logger.error("Failed to initialize Redis rate limiter: %s", exc)
            raise RateLimiterError(f"Redis initialization failed: {exc}") from exc

    async def check_limit(self, client_id: str, cost: float) -> Tuple[bool, float, float]:
        """
        Atomically evaluates and decrements the client's token balance by cost C(R).

        Args:
            client_id: Unique identifier for the client (IP or API key).
            cost: Computational cost C(R) estimated by CostEngine.

        Returns:
            Tuple of (allowed: bool, remaining_tokens: float, retry_after_seconds: float)
        """
        if self.redis is None or not self._script_sha:
            raise RateLimiterError("Rate limiter not initialized. Call initialize() first.")

        key = f"{self.key_prefix}:{client_id}"
        now_micro = time.time()  # Float with microsecond accuracy
        args = [self.capacity, self.refill_rate, float(cost), now_micro]

        try:
            # 1. Fast-path: Execute pre-cached Lua script by SHA1
            result = await self.redis.evalsha(self._script_sha, 1, key, *args)
        except NoScriptError:
            # 2. Transparent fallback: If Redis restarted or script cache flushed, reload and retry
            logger.warning("Lua script SHA %s missing in Redis cache. Reloading...", self._script_sha)
            self._script_sha = await self.redis.script_load(self._lua_code)
            result = await self.redis.evalsha(self._script_sha, 1, key, *args)
        except RedisError as exc:
            logger.error("Redis execution error during rate limit check: %s", exc)
            raise RateLimiterError(f"Rate limiting failed: {exc}") from exc

        # Parse Lua return: { allowed (0|1), tostring(remaining), tostring(retry_after) }
        allowed = bool(int(result[0]))
        remaining_tokens = float(result[1])
        retry_after_seconds = float(result[2])

        return allowed, remaining_tokens, retry_after_seconds

    async def close(self) -> None:
        """Closes the Redis connection pool cleanly."""
        if self.redis is not None:
            logger.info("Closing Redis connection pool...")
            if hasattr(self.redis, "aclose"):
                await self.redis.aclose()
            else:
                await self.redis.close()
            self.redis = None
            logger.info("Redis connection pool closed.")
