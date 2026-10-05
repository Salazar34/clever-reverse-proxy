"""
SecLab DoS Mitigation - Adaptive Feedback Loop Test Suite
Module: tests.test_adaptive_feedback

Tests the closed-loop control system between database telemetry (X-DB-Execution-Time-Ms)
and reverse proxy rate limiting:
  1. Low DB latency (< baseline) -> Multiplier gamma stays 1.0 (no false-positive penalty).
  2. Sustained DB latency spike (200 ms) -> EMA rises and gamma scales up (> 1.5).
  3. Elevated gamma amplifies effective cost C_eff(R), exhausting token budget faster.
  4. DBMS normalization (1 ms) -> EMA decays and gamma recovers to 1.0.
  5. Full Gateway closed-loop integration: verifies telemetry ingestion and HTTP headers
     (X-Cost-Assigned, X-Cost-Effective, X-Adaptive-Multiplier).
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import fakeredis.aioredis
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "proxy"))

from proxy.adaptive_tuner import AdaptiveTuner
from proxy.cost_engine import CostEngine
from proxy.main import app
from proxy.rate_limiter import WeightedRateLimiter


def print_test_banner(title: str) -> None:
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


async def test_low_db_latency_keeps_multiplier_unity():
    """1. With low DB response times (< baseline), gamma remains 1.0."""
    print_test_banner("1. Low DB Latency Keeps Multiplier Unity (gamma == 1.0)")
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    tuner = AdaptiveTuner(redis_client=fake_redis, alpha=0.2, max_multiplier=3.0)
    await tuner.initialize()

    route = "orders_list"
    baseline = 10.0  # 10ms nominal baseline

    # Simulate 5 fast, normal queries (1.5ms - 4.0ms)
    fast_latencies = [2.0, 3.5, 1.2, 4.0, 2.8]
    for lat in fast_latencies:
        gamma = await tuner.record_db_execution(route, lat, baseline_ms=baseline)
        assert gamma == 1.0, f"Expected gamma=1.0 for latency={lat}ms, got {gamma}"
        print(f"  Sample: {lat:4.1f} ms -> EMA: {await tuner.get_ema(route):5.2f} ms | gamma: {gamma:.2f}")

    current_gamma = await tuner.get_multiplier(route)
    assert current_gamma == 1.0
    print("  [PASS] Low DB latency correctly maintains gamma at 1.0 (no penalty applied).")


async def test_db_latency_spike_scales_multiplier_up():
    """2. Simulating a spike in DB times (200 ms for 5 calls), EMA grows and gamma > 1.5."""
    print_test_banner("2. DB Latency Spike Progressively Escalates Multiplier (gamma > 1.5)")
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    tuner = AdaptiveTuner(redis_client=fake_redis, alpha=0.2, max_multiplier=3.0)
    await tuner.initialize()

    route = "orders_list"
    baseline = 10.0

    # Start with baseline
    await tuner.record_db_execution(route, 10.0, baseline_ms=baseline)

    # Inject 5 heavy sequential queries simulating full-table Seq Scan / lock contention
    heavy_latencies = [200.0, 200.0, 200.0, 200.0, 200.0]
    previous_ema = 0.0
    previous_gamma = 1.0

    for i, lat in enumerate(heavy_latencies, 1):
        gamma = await tuner.record_db_execution(route, lat, baseline_ms=baseline)
        ema = await tuner.get_ema(route)
        assert ema > previous_ema, f"EMA should strictly increase: {ema} vs {previous_ema}"
        assert gamma >= previous_gamma, f"Gamma should non-decrease: {gamma} vs {previous_gamma}"
        print(f"  Spike #{i}: DB={lat:5.1f} ms -> EMA={ema:6.2f} ms | gamma={gamma:5.3f}x")
        previous_ema = ema
        previous_gamma = gamma

    # After 5 iterations of 200ms with alpha=0.2 and baseline=10ms:
    # EMA reaches ~138ms, ratio reaches ~13.8, gamma reaches max_multiplier (3.0)
    final_gamma = await tuner.get_multiplier(route)
    assert final_gamma > 1.5, f"Expected gamma > 1.5 under severe stress, got {final_gamma}"
    assert final_gamma <= 3.0, f"Expected gamma <= max_multiplier (3.0), got {final_gamma}"
    print(f"  [PASS] Severe DB latency spike successfully escalated gamma to {final_gamma:.3f}x.")


async def test_elevated_gamma_amplifies_effective_cost_and_drains_bucket():
    """3. Increased gamma amplifies effective cost and drains client budget faster."""
    print_test_banner("3. Elevated Multiplier Amplifies Cost and Accelerates Rate Limiting")
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)

    lua_path = PROJECT_ROOT / "proxy" / "lua" / "weighted_token_bucket.lua"
    rate_limiter = WeightedRateLimiter(
        redis_url="redis://localhost:6379",
        capacity=100.0,
        refill_rate=1.0,
        lua_script_path=lua_path,
    )
    rate_limiter.redis = fake_redis
    await rate_limiter.initialize()

    cost_engine = CostEngine()
    tuner = AdaptiveTuner(redis_client=fake_redis, alpha=0.2, max_multiplier=3.0)
    await tuner.initialize()

    route = "orders_list"
    # Query with sort_by=notes: base 5.0 + limit(20)*0.05=1.0 + notes sort 35.0 = 41.0 credits
    eval_res = cost_engine.evaluate_request("/api/v1/orders", "GET", {"sort_by": "notes"})
    static_cost = eval_res.cost
    assert static_cost == 41.0, f"Expected static cost 41.0, got {static_cost}"

    # --- Scenario 3A: Normal state (gamma = 1.0) ---
    gamma_normal = 1.0
    cost_effective_normal = min(cost_engine.max_allowed_cost, round(static_cost * gamma_normal, 2))
    assert cost_effective_normal == 41.0

    # User A performs 2 requests: 41 + 41 = 82 <= 100 -> Both succeed
    allowed_1, rem_1, _ = await rate_limiter.check_limit("user_normal", cost_effective_normal)
    allowed_2, rem_2, _ = await rate_limiter.check_limit("user_normal", cost_effective_normal)
    assert allowed_1 and allowed_2
    print(f"  [Normal State: gamma=1.00] Static Cost={static_cost} | C_eff={cost_effective_normal}")
    print(f"    Request 1: Allowed={allowed_1} (Rem={rem_1:.1f}) | Request 2: Allowed={allowed_2} (Rem={rem_2:.1f})")

    # --- Scenario 3B: Overload state (gamma = 1.6) ---
    # Simulate DB stress raising gamma to 1.6
    await fake_redis.set(f"adaptive:gamma:{route}", "1.60")
    gamma_stressed = await tuner.get_multiplier(route)
    assert gamma_stressed == 1.60

    cost_effective_stressed = min(cost_engine.max_allowed_cost, round(static_cost * gamma_stressed, 2))
    # 41.0 * 1.6 = 65.6 credits per request!
    assert cost_effective_stressed == 65.6
    print(f"  [Stressed State: gamma={gamma_stressed:.2f}] Static Cost={static_cost} -> C_eff={cost_effective_stressed:.1f}")

    # User B performs request 1: consumes 65.6 credits (remaining: 34.4)
    allowed_b1, rem_b1, _ = await rate_limiter.check_limit("user_stressed", cost_effective_stressed)
    assert allowed_b1
    print(f"    Request 1: Allowed={allowed_b1} (Rem={rem_b1:.1f})")

    # User B performs request 2: requires 65.6 credits, but only 34.4 remain -> REJECTED!
    allowed_b2, rem_b2, retry_after = await rate_limiter.check_limit("user_stressed", cost_effective_stressed)
    assert not allowed_b2
    print(f"    Request 2: Allowed={allowed_b2} (Deficit={cost_effective_stressed - rem_b2:.1f}, Retry-After={retry_after:.1f}s)")

    print("  [PASS] Closed-loop adaptive cost safely throttled the client after 1 request instead of 2.")


async def test_db_recovery_decays_multiplier_back_to_unity():
    """4. When DB times return to 1 ms, EMA drops and gamma decays back to 1.0."""
    print_test_banner("4. Database Recovery Decays Multiplier Back to Unity (gamma -> 1.0)")
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    tuner = AdaptiveTuner(redis_client=fake_redis, alpha=0.2, max_multiplier=3.0)
    await tuner.initialize()

    route = "orders_list"
    baseline = 10.0

    # Prime with high load: EMA = 150ms, gamma = 3.0
    await fake_redis.set(f"adaptive:ema:{route}", "150.0")
    await fake_redis.set(f"adaptive:gamma:{route}", "3.0")

    initial_gamma = await tuner.get_multiplier(route)
    assert initial_gamma == 3.0
    print(f"  Initial Overload State: EMA=150.00 ms | gamma={initial_gamma:.2f}x")

    # Inject healthy 1.0 ms responses
    decay_steps = 20
    for step in range(1, decay_steps + 1):
        gamma = await tuner.record_db_execution(route, 1.0, baseline_ms=baseline)
        ema = await tuner.get_ema(route)
        if step % 4 == 0 or gamma == 1.0:
            print(f"  Recovery Step #{step:02d}: DB=1.0 ms -> EMA={ema:5.2f} ms | gamma={gamma:5.3f}x")
        if gamma == 1.0:
            break

    final_gamma = await tuner.get_multiplier(route)
    assert final_gamma == 1.0
    print(f"  [PASS] Multiplier completely recovered to nominal 1.00x after DBMS stabilized.")


async def test_gateway_closed_loop_headers_and_telemetry():
    """5. Full Gateway closed-loop integration: verifies telemetry ingestion and HTTP headers."""
    print_test_banner("5. Full Gateway Closed-Loop Integration & Telemetry Response Headers")
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)

    # Initialize gateway subsystems with FakeRedis
    cost_engine = CostEngine()
    lua_path = PROJECT_ROOT / "proxy" / "lua" / "weighted_token_bucket.lua"
    rate_limiter = WeightedRateLimiter(
        redis_url="redis://localhost:6379",
        capacity=100.0,
        refill_rate=10.0,
        lua_script_path=lua_path,
    )
    rate_limiter.redis = fake_redis
    await rate_limiter.initialize()

    tuner = AdaptiveTuner(redis_client=fake_redis, alpha=0.2, max_multiplier=3.0)
    await tuner.initialize()

    # Mount on app.state
    app.state.cost_engine = cost_engine
    app.state.rate_limiter = rate_limiter
    app.state.adaptive_tuner = tuner
    app.state.pow_engine = MagicMock()
    app.state.pow_engine.verify_solution = AsyncMock(return_value=(False, "no token"))
    app.state.pow_engine.generate_challenge = MagicMock(return_value={"difficulty": 4})

    # Mock upstream HTTP client returning backend telemetry
    mock_http_client = AsyncMock()
    app.state.http_client = mock_http_client

    client = TestClient(app)

    # Request 1: Backend reports slow query (120 ms vs baseline 10 ms)
    mock_resp_1 = MagicMock()
    mock_resp_1.status_code = 200
    import httpx
    mock_resp_1.content = b'{"orders": []}'
    mock_resp_1.headers = httpx.Headers({
        "content-type": "application/json",
        "X-DB-Execution-Time-Ms": "120.00",
        "X-DB-Rows-Returned": "20",
    })
    mock_http_client.request.return_value = mock_resp_1

    res_1 = client.get("/api/v1/orders?limit=20&sort_by=id")
    assert res_1.status_code == 200

    # Check headers of Request 1:
    # Sent with initial gamma=1.00, but response records 120ms and reports the new gamma!
    assert "X-Cost-Assigned" in res_1.headers
    assert "X-Cost-Effective" in res_1.headers
    assert "X-Adaptive-Multiplier" in res_1.headers
    assert res_1.headers["X-Cost-Assigned"] == "7.00"  # base 5.0 + limit(20)*0.05=1.0 + sort_by(id)=1.0 = 7.0
    assert res_1.headers["X-Cost-Effective"] == "7.00"

    gamma_after_1 = float(res_1.headers["X-Adaptive-Multiplier"])
    assert gamma_after_1 > 1.0, f"Expected updated gamma > 1.0, got {gamma_after_1}"
    print(f"  Request 1 -> X-Cost-Assigned: {res_1.headers['X-Cost-Assigned']} | "
          f"X-Cost-Effective: {res_1.headers['X-Cost-Effective']} | "
          f"X-Adaptive-Multiplier: {res_1.headers['X-Adaptive-Multiplier']}")

    # Request 2: Gateway now evaluates request using the newly computed gamma!
    mock_resp_2 = MagicMock()
    mock_resp_2.status_code = 200
    mock_resp_2.content = b'{"orders": []}'
    mock_resp_2.headers = httpx.Headers({
        "content-type": "application/json",
        "X-DB-Execution-Time-Ms": "150.00",
    })
    mock_http_client.request.return_value = mock_resp_2

    res_2 = client.get("/api/v1/orders?limit=20&sort_by=id")
    assert res_2.status_code == 200

    # In Request 2, static cost is still 7.00, but cost_effective is now multiplied!
    cost_assigned_2 = float(res_2.headers["X-Cost-Assigned"])
    cost_effective_2 = float(res_2.headers["X-Cost-Effective"])
    gamma_2 = float(res_2.headers["X-Adaptive-Multiplier"])

    assert cost_assigned_2 == 7.00
    assert cost_effective_2 > cost_assigned_2, (
        f"Cost effective ({cost_effective_2}) should exceed assigned ({cost_assigned_2}) under stress"
    )
    assert gamma_2 >= gamma_after_1
    print(f"  Request 2 -> X-Cost-Assigned: {res_2.headers['X-Cost-Assigned']} | "
          f"X-Cost-Effective: {res_2.headers['X-Cost-Effective']} | "
          f"X-Adaptive-Multiplier: {res_2.headers['X-Adaptive-Multiplier']}")

    print("  [PASS] Closed-loop adaptive telemetry successfully transmitted and applied across requests.")


async def run_all():
    print("\n" + "=" * 80)
    print("SecLab DoS Mitigation - Closed-Loop Adaptive Feedback Verification")
    print("=" * 80)
    await test_low_db_latency_keeps_multiplier_unity()
    await test_db_latency_spike_scales_multiplier_up()
    await test_elevated_gamma_amplifies_effective_cost_and_drains_bucket()
    await test_db_recovery_decays_multiplier_back_to_unity()
    await test_gateway_closed_loop_headers_and_telemetry()
    print("\n" + "=" * 80)
    print("ALL 5 ADAPTIVE CLOSED-LOOP FEEDBACK TESTS PASSED SUCCESSFULLY!")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    asyncio.run(run_all())
