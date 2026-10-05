"""
SecLab DoS Mitigation - Adaptive Feedback Loop (Closed-Loop Cost Auto-Tuning)
Module: proxy.adaptive_tuner

Closes the feedback loop between the database tier and the reverse proxy gateway:
1. Intercepts real database execution times (X-DB-Execution-Time-Ms) reported by upstream.
2. Maintains an Exponential Moving Average (EMA) of DBMS execution latency per route in Redis.
3. Dynamically calculates an overload multiplier gamma >= 1.0 when EMA exceeds nominal baseline:
     gamma = min(max_multiplier, 1.0 + (EMA / baseline - 1.0) * 0.5)
4. Scales effective computational cost C_effective(R) = min(C_max, C_static(R) * gamma).
5. Decays back to 1.0 as DBMS load normalizes, preventing resource starvation and cascading failures.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("proxy.adaptive_tuner")

# Atomic Lua script for concurrent EMA and gamma computation on Redis
ADAPTIVE_EMA_LUA = """
-- KEYS[1]: adaptive:ema:<route_name>
-- KEYS[2]: adaptive:gamma:<route_name>
-- ARGV[1]: alpha (e.g. 0.2)
-- ARGV[2]: execution_time_ms (e.g. 15.4)
-- ARGV[3]: baseline_ms (e.g. 10.0)
-- ARGV[4]: max_multiplier (e.g. 3.0)
-- ARGV[5]: ttl_seconds (e.g. 120)

local ema_key = KEYS[1]
local gamma_key = KEYS[2]
local alpha = tonumber(ARGV[1])
local exec_time = tonumber(ARGV[2])
local baseline = math.max(1.0, tonumber(ARGV[3]))
local max_mult = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])

local prev_ema = redis.call('GET', ema_key)
local new_ema
if prev_ema and prev_ema ~= false then
    new_ema = (alpha * exec_time) + ((1.0 - alpha) * tonumber(prev_ema))
else
    new_ema = exec_time
end

local ratio = new_ema / baseline
local gamma = 1.0
if ratio > 1.0 then
    gamma = math.min(max_mult, 1.0 + (ratio - 1.0) * 0.5)
else
    gamma = 1.0
end

redis.call('SET', ema_key, tostring(new_ema), 'EX', ttl)
redis.call('SET', gamma_key, tostring(gamma), 'EX', ttl)

return {tostring(gamma), tostring(new_ema)}
"""


class AdaptiveTuner:
    """
    Closed-loop adaptive cost auto-tuning controller.
    
    Dynamically adjusts route cost multipliers based on real-time database execution telemetry.
    """

    def __init__(
        self,
        redis_client: Any,
        alpha: float = 0.2,
        max_multiplier: float = 3.0,
        baseline_window_s: int = 60,
        ttl_seconds: int = 120,
    ) -> None:
        self.redis = redis_client
        self.alpha = float(alpha)
        self.max_multiplier = float(max_multiplier)
        self.baseline_window_s = int(baseline_window_s)
        self.ttl_seconds = int(ttl_seconds)
        self._script_sha: str | None = None

    async def initialize(self) -> None:
        """Pre-loads the atomic Lua script into Redis for sub-millisecond evaluation."""
        if self.redis is not None:
            try:
                self._script_sha = await self.redis.script_load(ADAPTIVE_EMA_LUA)
                logger.info("AdaptiveTuner Lua script pre-loaded (SHA: %s)", self._script_sha)
            except Exception as exc:
                logger.warning("Could not pre-load AdaptiveTuner Lua script (%s); falling back to direct eval", exc)

    async def record_db_execution(
        self,
        route_name: str,
        execution_time_ms: float,
        baseline_ms: float = 10.0,
    ) -> float:
        """
        Records a real DBMS execution sample for route_name and updates the overload multiplier.

        Args:
            route_name: Identifier of the API route (e.g. 'orders_list').
            execution_time_ms: Real execution duration reported by database in milliseconds.
            baseline_ms: Nominal expected baseline latency under unstressed conditions.

        Returns:
            The newly computed overload multiplier gamma >= 1.0.
        """
        ema_key = f"adaptive:ema:{route_name}"
        gamma_key = f"adaptive:gamma:{route_name}"

        # 1. Attempt atomic execution via Lua
        if self.redis is not None:
            try:
                if self._script_sha:
                    res = await self.redis.evalsha(
                        self._script_sha,
                        2,
                        ema_key,
                        gamma_key,
                        self.alpha,
                        execution_time_ms,
                        baseline_ms,
                        self.max_multiplier,
                        self.ttl_seconds,
                    )
                else:
                    res = await self.redis.eval(
                        ADAPTIVE_EMA_LUA,
                        2,
                        ema_key,
                        gamma_key,
                        self.alpha,
                        execution_time_ms,
                        baseline_ms,
                        self.max_multiplier,
                        self.ttl_seconds,
                    )

                if isinstance(res, (list, tuple)) and len(res) >= 1:
                    gamma = float(res[0])
                    new_ema = float(res[1]) if len(res) > 1 else None
                    logger.debug(
                        "AdaptiveTuner [Lua] route=%s: exec=%.2fms baseline=%.2fms -> EMA=%.2f gamma=%.3f",
                        route_name, execution_time_ms, baseline_ms, new_ema or 0.0, gamma,
                    )
                    return round(gamma, 4)
            except Exception as exc:
                logger.debug("Lua evaluation failed (%s), running fallback logic", exc)

        # 2. Resilient Python Fallback
        return await self._record_db_execution_fallback(route_name, execution_time_ms, baseline_ms)

    async def _record_db_execution_fallback(
        self,
        route_name: str,
        execution_time_ms: float,
        baseline_ms: float,
    ) -> float:
        """Python fallback when Lua is unavailable or errors."""
        ema_key = f"adaptive:ema:{route_name}"
        gamma_key = f"adaptive:gamma:{route_name}"

        prev_ema_raw = None
        if self.redis is not None:
            try:
                prev_ema_raw = await self.redis.get(ema_key)
            except Exception as exc:
                logger.warning("Error reading EMA key '%s': %s", ema_key, exc)

        if prev_ema_raw is not None:
            try:
                prev_ema = float(prev_ema_raw)
                new_ema = (self.alpha * execution_time_ms) + ((1.0 - self.alpha) * prev_ema)
            except (ValueError, TypeError):
                new_ema = execution_time_ms
        else:
            new_ema = execution_time_ms

        ratio = new_ema / max(1.0, baseline_ms)
        if ratio > 1.0:
            gamma = min(self.max_multiplier, 1.0 + (ratio - 1.0) * 0.5)
        else:
            gamma = 1.0

        if self.redis is not None:
            try:
                await self.redis.set(ema_key, str(new_ema), ex=self.ttl_seconds)
                await self.redis.set(gamma_key, str(gamma), ex=self.ttl_seconds)
            except Exception as exc:
                logger.warning("Error persisting adaptive values to Redis: %s", exc)

        logger.debug(
            "AdaptiveTuner [Py] route=%s: exec=%.2fms baseline=%.2fms -> EMA=%.2f gamma=%.3f",
            route_name, execution_time_ms, baseline_ms, new_ema, gamma,
        )
        return round(gamma, 4)

    async def get_multiplier(self, route_name: str) -> float:
        """
        Retrieves the active overload multiplier gamma for route_name from Redis.

        Returns:
            A float >= 1.0 (defaults to 1.0 if route has no active overload).
        """
        if self.redis is None:
            return 1.0

        gamma_key = f"adaptive:gamma:{route_name}"
        try:
            val = await self.redis.get(gamma_key)
            if val is not None:
                return round(float(val), 4)
        except Exception as exc:
            logger.warning("Failed to retrieve multiplier for route '%s': %s", route_name, exc)

        return 1.0

    async def get_ema(self, route_name: str) -> float | None:
        """Retrieves the current EMA for route_name, or None if not recorded."""
        if self.redis is None:
            return None

        ema_key = f"adaptive:ema:{route_name}"
        try:
            val = await self.redis.get(ema_key)
            if val is not None:
                return round(float(val), 4)
        except Exception as exc:
            logger.warning("Failed to retrieve EMA for route '%s': %s", route_name, exc)

        return None

    async def reset(self, route_name: str | None = None) -> None:
        """Resets the adaptive state in Redis (useful for test isolation)."""
        if self.redis is None:
            return

        try:
            if route_name:
                await self.redis.delete(f"adaptive:ema:{route_name}", f"adaptive:gamma:{route_name}")
            else:
                keys = await self.redis.keys("adaptive:*")
                if keys:
                    await self.redis.delete(*keys)
        except Exception as exc:
            logger.warning("Failed to reset AdaptiveTuner keys: %s", exc)
