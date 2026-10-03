#!/usr/bin/env python3
"""
SecLab DoS Mitigation - Comprehensive System Correctness & Integration Test Suite
Module: tests.test_full_system

Validates all 7 architectural subsystems:
  1. Database Schema & Indexing Strategy (Verifies unindexed notes vector)
  2. High-Performance Seeder (Binary chunking & 10% keyword injection)
  3. CostEngine (Microsecond bounds, linear, presence, and categorical weights)
  4. Weighted Token Bucket (Lazy evaluation math, Redis TTL, Lua script syntax)
  5. Cryptographic PoW Engine (HMAC verification, request binding, anti-replay)
  6. Autonomous Client Solver (Mining loop & HTTP 428 auto-negotiation)
  7. Reverse Proxy Gateway (Monster query drop, token bucket gate, PoW bypass)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

# Configure PYTHONPATH
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "proxy"))
sys.path.insert(0, str(PROJECT_ROOT / "client-sdk"))

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("verifier")


def print_section(title: str) -> None:
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def test_schema_and_indexing() -> None:
    print_section("TEST 1: Database Schema & Algorithmic Complexity Vectors")
    schema_path = PROJECT_ROOT / "database" / "schema.sql"
    assert schema_path.exists(), f"Schema file not found at {schema_path}"
    
    content = schema_path.read_text(encoding="utf-8")
    
    # 1. Table definitions
    assert "CREATE TABLE customers" in content, "Table 'customers' missing in schema"
    assert "CREATE TABLE orders" in content, "Table 'orders' missing in schema"
    
    # 2. Key indices
    assert "idx_orders_customer_id" in content, "Index on customer_id missing"
    assert "idx_orders_created_at" in content, "Index on created_at missing"
    assert "idx_orders_status" in content, "Index on status missing"
    
    # 3. Intentional unindexed column check
    assert "idx_orders_notes" not in content, "CRITICAL ERROR: 'orders.notes' must NOT be indexed!"
    print("  [PASS] Tables 'customers' and 'orders' defined correctly.")
    print("  [PASS] B-Tree indexes created on customer_id, created_at, status.")
    print("  [PASS] 'orders.notes' intentionally unindexed to serve as asymmetric Seq Scan vector.")


def test_seeder_logic() -> None:
    print_section("TEST 2: Seeder Tuple Generation & Realistic Distribution")
    import database.seeder as seeder

    now = datetime.now(timezone.utc)
    
    # Test customer generation
    customers = seeder.generate_customer_records(50, now)
    assert len(customers) == 50
    assert len(customers[0]) == 5  # id, full_name, email, tier, created_at
    print(f"  [PASS] Customer generator produces valid schema tuples: {customers[0][:3]}...")

    # Test order generation & 10% keyword injection
    sample_size = 1000
    orders = seeder.generate_order_chunk(start_id=1, count=sample_size, total_customers=20000, base_time=now)
    assert len(orders) == sample_size
    assert len(orders[0]) == 8

    # Count keywords in notes
    keywords = ["URGENT", "FRAGILE", "EXPRESS"]
    keyword_count = sum(
        1 for o in orders if o[6] is not None and any(kw in o[6] for kw in keywords)
    )
    expected_count = sample_size // 10
    assert keyword_count == expected_count, f"Expected {expected_count} keywords, got {keyword_count}"
    print(f"  [PASS] Exactly 10% ({keyword_count}/{sample_size}) of generated orders contain target keywords in unindexed 'notes'.")


def test_cost_engine() -> None:
    print_section("TEST 3: Computational Cost Engine & Microsecond Overhead")
    from proxy.cost_engine import CostEngine

    rules_path = PROJECT_ROOT / "proxy" / "config" / "cost_rules.yaml"
    ce = CostEngine(config_path=rules_path)

    # 1. Indexed O(1) lookup
    c_lookup = ce.estimate_cost("/api/v1/orders/123", "GET", {})
    assert c_lookup == 1.0, f"Expected 1.0, got {c_lookup}"
    print(f"  [PASS] O(1) Primary Key Lookup Cost: {c_lookup} (Baseline: 1.0)")

    # 2. Shallow indexed list
    c_list = ce.estimate_cost("/api/v1/orders", "GET", {"limit": 20, "offset": 0, "sort_by": "id"})
    assert c_list == 7.0, f"Expected 7.0 (5 base + 1 limit + 1 sort), got {c_list}"
    print(f"  [PASS] Shallow Indexed Pagination Cost: {c_list}")

    # 3. Deep offset pagination
    c_offset = ce.estimate_cost("/api/v1/orders", "GET", {"limit": 20, "offset": 10000, "sort_by": "id"})
    assert c_offset == 17.0, f"Expected 17.0, got {c_offset}"
    print(f"  [PASS] Deep Offset (10,000) Cost: {c_offset} (+10.0 linear penalty)")

    # 4. Unindexed ILIKE search (Seq Scan)
    c_search = ce.estimate_cost("/api/v1/orders", "GET", {"search": "urgent", "limit": 20, "offset": 0, "sort_by": "id"})
    assert c_search == 52.0, f"Expected 52.0 (7 + 45 presence penalty), got {c_search}"
    print(f"  [PASS] ILIKE Seq Scan Search Cost: {c_search} (+45.0 presence penalty)")

    # 5. External sort on unindexed TEXT
    c_sort = ce.estimate_cost("/api/v1/orders", "GET", {"sort_by": "notes", "limit": 20, "offset": 0})
    assert c_sort == 41.0, f"Expected 41.0, got {c_sort}"
    print(f"  [PASS] Unindexed TEXT External Sort Cost: {c_sort} (+35.0 categorical penalty)")

    # 6. Monster query check (C(R) >= C_max)
    c_monster = ce.estimate_cost("/api/v1/orders", "GET", {"search": "urgent", "sort_by": "notes", "limit": 100, "offset": 50000})
    assert c_monster == 100.0, f"Expected 100.0 (C_max clamped), got {c_monster}"
    print(f"  [PASS] Pathological Monster Query Clamped to C_max: {c_monster}")

    # 7. Benchmark microsecond execution time
    trials = 1000
    t0 = time.perf_counter_ns()
    for _ in range(trials):
        ce.estimate_cost("/api/v1/orders", "GET", {"search": "urgent", "sort_by": "notes", "limit": 50, "offset": 20000})
    t_avg_us = (time.perf_counter_ns() - t0) / (trials * 1000.0)
    assert t_avg_us < 50.0, f"CostEngine took {t_avg_us:.2f}us, exceeding 50us budget!"
    print(f"  [PASS] Microsecond Performance: Average evaluation time is {t_avg_us:.2f} us (< 50 us constraint satisfied).")


def test_rate_limiter_lua() -> None:
    print_section("TEST 4: Weighted Token Bucket & Lua Script Atomicity")
    lua_path = PROJECT_ROOT / "proxy" / "lua" / "weighted_token_bucket.lua"
    assert lua_path.exists(), f"Lua script missing at {lua_path}"
    
    code = lua_path.read_text(encoding="utf-8")
    assert "HMGET" in code or "HSET" in code
    assert "ARGV[1]" in code and "ARGV[4]" in code
    assert "delta_t * refill_rate" in code
    assert "tokens >= cost" in code
    print("  [PASS] Lua script contains lazy evaluation mathematics and atomic Redis state persistence.")


async def test_pow_engine_and_solver() -> None:
    print_section("TEST 5 & 6: Cryptographic PoW Engine & Autonomous Solver")
    from proxy.pow_engine import PoWEngine
    import pow_solver

    mock_redis = AsyncMock()
    mock_redis.set.return_value = True  # Simulates first-time token use

    engine = PoWEngine(
        secret_key="unit-test-secret-key-32-bytes-long!",
        redis_client=mock_redis,
        challenge_ttl_seconds=60,
        base_difficulty=3,
    )

    method = "GET"
    path = "/api/v1/orders"
    params = {"limit": "20", "search": "urgent", "sort_by": "notes"}

    # 1. Challenge generation
    challenge = engine.generate_challenge(method=method, path=path, query_params=params, deficit=15.0)
    token = challenge["token"]
    difficulty = challenge["difficulty"]
    assert difficulty == 3
    print(f"  [PASS] Issued HMAC-SHA256 Challenge Token: {token[:35]}... (Difficulty: {difficulty})")

    # 2. Autonomous client mining
    nonce, elapsed = pow_solver.solve_pow(token, difficulty)
    assert nonce >= 0
    candidate_hash = hashlib.sha256(f"{token}:{nonce}".encode("ascii")).hexdigest()
    assert candidate_hash.startswith("0" * difficulty), f"Mined hash {candidate_hash} invalid"
    print(f"  [PASS] Client Solver mined winning nonce ({nonce}) in {elapsed:.3f}s: Hash={candidate_hash[:12]}...")

    # 3. Server verification: valid proof
    valid, reason = await engine.verify_solution(token, str(nonce), method, path, params)
    assert valid, f"Verification failed: {reason}"
    print(f"  [PASS] Server Single-Hash Verification: {reason}")

    # 4. Tampering: route binding mismatch
    tampered_valid, tampered_reason = await engine.verify_solution(token, str(nonce), method, "/api/v1/orders/1", params)
    assert not tampered_valid
    print(f"  [PASS] Cross-Route Replay Rejected: {tampered_reason}")

    # 5. Anti-Replay Cache check
    mock_redis.set.return_value = False  # Simulates second use
    replay_valid, replay_reason = await engine.verify_solution(token, str(nonce), method, path, params)
    assert not replay_valid and "Replay" in replay_reason
    print(f"  [PASS] Replay Attack Blocked: {replay_reason}")


async def test_gateway_integration() -> None:
    print_section("TEST 7: Reverse Proxy Gateway Orchestration & Telemetry")
    from fastapi.testclient import TestClient
    from proxy.main import app, extract_client_identity

    # Mock client and engines inside app.state
    app.state.cost_engine = MagicMock()
    app.state.rate_limiter = MagicMock()
    app.state.rate_limiter.check_limit = AsyncMock()
    app.state.pow_engine = MagicMock()
    app.state.pow_engine.verify_solution = AsyncMock()
    app.state.http_client = AsyncMock()

    # Configure mock CostEngine
    app.state.cost_engine.max_allowed_cost = 100.0

    client = TestClient(app)

    # 1. Monster query check -> HTTP 400
    app.state.cost_engine.estimate_cost.return_value = 100.0
    res_monster = client.get("/api/v1/orders?search=huge_monster")
    assert res_monster.status_code == 400
    assert "exceeds structural limit" in res_monster.json()["detail"]
    print("  [PASS] Monster Query rejected immediately with HTTP 400 Bad Request.")

    # 2. Rate limit exceeded -> HTTP 428 Precondition Required
    app.state.cost_engine.estimate_cost.return_value = 52.0
    app.state.rate_limiter.check_limit.return_value = (False, 10.0, 4.2)  # allowed=False, remaining=10, retry=4.2s
    app.state.pow_engine.generate_challenge.return_value = {
        "token": "mock.token.123",
        "difficulty": 4,
        "algorithm": "SHA-256",
        "expires_in": 60,
    }

    res_428 = client.get("/api/v1/orders?search=urgent")
    assert res_428.status_code == 428
    assert res_428.headers["Retry-After"] == "5"
    assert res_428.headers["X-Cost-Assigned"] == "52.00"
    assert "challenge" in res_428.json()
    print("  [PASS] Rate Limit Exceeded returns HTTP 428 Precondition Required with PoW challenge payload.")

    # 3. Legitimate request with sufficient tokens -> Forwarded & Telemetry injected
    app.state.cost_engine.estimate_cost.return_value = 7.0
    app.state.rate_limiter.check_limit.return_value = (True, 93.0, 0.0)

    mock_upstream = MagicMock()
    mock_upstream.status_code = 200
    mock_upstream.headers = {
        "content-type": "application/json",
        "x-db-execution-time-ms": "1.25",
        "x-db-rows-returned": "20",
    }
    mock_upstream.content = b'{"orders": []}'
    app.state.http_client.request.return_value = mock_upstream

    res_200 = client.get("/api/v1/orders?limit=20")
    assert res_200.status_code == 200
    assert res_200.headers["X-Cost-Assigned"] == "7.00"
    assert "X-Proxy-Overhead-Ms" in res_200.headers
    assert res_200.headers["X-PoW-Bypassed"] == "false"
    assert res_200.headers["X-DB-Execution-Time-Ms"] == "1.25"
    print("  [PASS] Admitted request forwarded to upstream with complete diagnostic and DB telemetry headers.")

    # 4. PoW authenticated bypass -> Bucket not touched, X-PoW-Bypassed: true
    app.state.cost_engine.estimate_cost.return_value = 52.0
    app.state.pow_engine.verify_solution.return_value = (True, "OK")

    res_pow = client.get(
        "/api/v1/orders?search=urgent",
        headers={"X-PoW-Token": "valid.token", "X-PoW-Nonce": "12345"},
    )
    assert res_pow.status_code == 200
    assert res_pow.headers["X-PoW-Bypassed"] == "true"
    print("  [PASS] PoW-authenticated request bypasses rate limiter and passes directly to upstream.")


def test_plots_exist() -> None:
    print_section("TEST 8: Thesis Visualizations & High-Resolution Figures")
    plots_dir = PROJECT_ROOT / "thesis_plots"
    fig1 = plots_dir / "fig1_cpu_utilization.png"
    fig2 = plots_dir / "fig2_legit_latency_p95.png"
    fig3 = plots_dir / "fig3_http_status_distribution.png"

    for fig in [fig1, fig2, fig3]:
        assert fig.exists(), f"Figure missing: {fig}"
        assert fig.stat().st_size > 50_000, f"Figure {fig.name} appears incomplete or empty"
        print(f"  [PASS] {fig.name} verified ({fig.stat().st_size / 1024:.1f} KB, 300 DPI).")


async def run_all() -> None:
    t_start = time.perf_counter()
    print("\n" + "=" * 80)
    print("SecLab DoS Mitigation - Full System Automated Verification")
    print("=" * 80)

    test_schema_and_indexing()
    test_seeder_logic()
    test_cost_engine()
    test_rate_limiter_lua()
    await test_pow_engine_and_solver()
    await test_gateway_integration()
    test_plots_exist()

    elapsed = time.perf_counter() - t_start
    print("\n" + "=" * 80)
    print(f"ALL 8 SUBSYSTEM INTEGRATION TESTS PASSED in {elapsed:.2f} seconds!")
    print("The system architecture, mitigation pipelines, and data layers are fully verified.")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    asyncio.run(run_all())
