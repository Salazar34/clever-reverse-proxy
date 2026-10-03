"""
SecLab DoS Mitigation - Intelligent Reverse Proxy Gateway
Stack: Python 3.11, FastAPI, httpx, redis.asyncio, PyYAML

Core Capabilities:
  1. Microsecond Computational Cost Estimation C(R)
  2. Immediate Drop of Monster Queries (C(R) >= C_max) -> HTTP 400
  3. Stateless Request-Bound Proof-of-Work Verification (Single-Hash)
  4. Distributed Weighted Token Bucket with Lazy Evaluation
  5. RFC 6585 Precondition Required (HTTP 428) Challenge Negotiation
  6. High-Throughput Upstream Forwarding with Telemetry Headers
"""

from __future__ import annotations

import logging
import math
import os
from pathlib import Path
import time
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse, Response as FastAPIResponse

try:
    from cost_engine import CostEngine
    from pow_engine import PoWEngine
    from rate_limiter import WeightedRateLimiter
except ImportError:
    from proxy.cost_engine import CostEngine
    from proxy.pow_engine import PoWEngine
    from proxy.rate_limiter import WeightedRateLimiter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("proxy.gateway")

# Environment Configurations
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000").rstrip("/")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
POW_SECRET = os.getenv("POW_SECRET", "seclab-production-grade-hmac-secret-key-32chars")
POW_BASE_DIFFICULTY = int(os.getenv("POW_BASE_DIFFICULTY", "4"))
POW_TTL = int(os.getenv("POW_TTL", "60"))
BUCKET_CAPACITY = float(os.getenv("BUCKET_CAPACITY", "100.0"))
BUCKET_REFILL_RATE = float(os.getenv("BUCKET_REFILL_RATE", "10.0"))
COST_CONFIG_PATH = os.getenv(
    "COST_CONFIG_PATH",
    str(Path(__file__).resolve().parent / "config" / "cost_rules.yaml"),
)

# RFC 2616 / 7230 Hop-by-hop headers to strip during forwarding
HOP_BY_HOP_HEADERS = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
})


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing Reverse Proxy Gateway components...")

    # 1. Initialize CostEngine
    cost_engine = CostEngine(config_path=COST_CONFIG_PATH)
    app.state.cost_engine = cost_engine

    # 2. Initialize WeightedRateLimiter on Redis
    rate_limiter = WeightedRateLimiter(
        redis_url=REDIS_URL,
        capacity=BUCKET_CAPACITY,
        refill_rate=BUCKET_REFILL_RATE,
        lua_script_path=Path(__file__).resolve().parent / "lua" / "weighted_token_bucket.lua",
    )
    await rate_limiter.initialize()
    app.state.rate_limiter = rate_limiter

    # 3. Initialize PoWEngine
    pow_engine = PoWEngine(
        secret_key=POW_SECRET,
        redis_client=rate_limiter.redis,
        challenge_ttl_seconds=POW_TTL,
        base_difficulty=POW_BASE_DIFFICULTY,
    )
    app.state.pow_engine = pow_engine

    # 4. Initialize persistent upstream HTTP client with connection pooling
    limits = httpx.Limits(max_connections=300, max_keepalive_connections=100)
    timeout = httpx.Timeout(connect=5.0, read=120.0, write=10.0, pool=10.0)
    http_client = httpx.AsyncClient(
        base_url=BACKEND_URL,
        limits=limits,
        timeout=timeout,
    )
    app.state.http_client = http_client

    logger.info(
        "Gateway successfully primed: Upstream=%s | Redis=%s | C_max=%.1f",
        BACKEND_URL,
        REDIS_URL,
        cost_engine.max_allowed_cost,
    )

    yield

    logger.info("Shutting down Reverse Proxy Gateway...")
    await app.state.http_client.aclose()
    await app.state.rate_limiter.close()
    logger.info("Gateway cleanly stopped.")


app = FastAPI(
    title="SecLab Intelligent Reverse Proxy Gateway",
    description="Cost-Based Rate Limiting & Stateless PoW Gateway for Algorithmic DoS Mitigation",
    version="1.0.0",
    lifespan=lifespan,
)


def extract_client_identity(request: Request) -> str:
    """Extracts client identity from X-Forwarded-For, X-Real-IP, or connection host."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    x_real_ip = request.headers.get("x-real-ip")
    if x_real_ip:
        return x_real_ip.strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


@app.get("/_proxy/health", summary="Gateway Liveness Probe")
async def proxy_health() -> dict[str, Any]:
    """Diagnostic endpoint checking gateway component statuses."""
    rl: WeightedRateLimiter = app.state.rate_limiter
    redis_healthy = rl.redis is not None and bool(await rl.redis.ping())
    return {
        "status": "healthy",
        "service": "reverse-proxy",
        "redis_connected": redis_healthy,
        "backend_target": BACKEND_URL,
    }


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def gateway_dispatcher(request: Request, path: str) -> Response:
    t_proxy_start = time.perf_counter()
    proxy_internal_work_s = 0.0

    cost_engine: CostEngine = app.state.cost_engine
    rate_limiter: WeightedRateLimiter = app.state.rate_limiter
    pow_engine: PoWEngine = app.state.pow_engine
    http_client: httpx.AsyncClient = app.state.http_client

    canonical_path = f"/{path}"
    method = request.method.upper()
    query_params = dict(request.query_params)
    client_id = extract_client_identity(request)

    # -------------------------------------------------------------------------
    # STEP 1: Fast in-memory Cost Estimation C(R) (< 50 us)
    # -------------------------------------------------------------------------
    cost = cost_engine.estimate_cost(path=canonical_path, method=method, query_params=query_params)

    # -------------------------------------------------------------------------
    # STEP 2: Monster Query Protection (C(R) >= C_max) -> HTTP 400 Drop
    # -------------------------------------------------------------------------
    if cost >= cost_engine.max_allowed_cost:
        logger.warning(
            "MONSTER QUERY DETECTED from %s: %s %s (Cost: %.2f >= %.2f) -> Dropping with HTTP 400",
            client_id, method, canonical_path, cost, cost_engine.max_allowed_cost,
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "Bad Request",
                "detail": (
                    f"Computational complexity C(R)={cost:.2f} exceeds structural limit "
                    f"C_max={cost_engine.max_allowed_cost:.2f}. Request rejected to safeguard DBMS resources."
                ),
                "cost_assigned": cost,
            },
            headers={"X-Cost-Assigned": f"{cost:.2f}"},
        )

    # -------------------------------------------------------------------------
    # STEP 3: Proof-of-Work (PoW) Inspection & Verification
    # -------------------------------------------------------------------------
    pow_token = request.headers.get("x-pow-token")
    pow_nonce = request.headers.get("x-pow-nonce")
    pow_authorized = False

    if pow_token and pow_nonce:
        is_valid, reason = await pow_engine.verify_solution(
            token=pow_token,
            nonce=pow_nonce,
            method=method,
            path=canonical_path,
            query_params=query_params,
        )
        if not is_valid:
            logger.warning(
                "PoW VERIFICATION FAILED for %s on %s %s: %s",
                client_id, method, canonical_path, reason,
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "error": "Forbidden",
                    "detail": f"Cryptographic Proof-of-Work validation failed: {reason}",
                },
                headers={"X-Cost-Assigned": f"{cost:.2f}"},
            )

        logger.info(
            "PoW VALIDATED for %s on %s %s (Cost: %.2f) -> Bypassing token bucket enforcement",
            client_id, method, canonical_path, cost,
        )
        pow_authorized = True

    # -------------------------------------------------------------------------
    # STEP 4: Weighted Token Bucket Enforcement (if not PoW authorized)
    # -------------------------------------------------------------------------
    if not pow_authorized:
        allowed, remaining_tokens, retry_after = await rate_limiter.check_limit(
            client_id=client_id,
            cost=cost,
        )
        if not allowed:
            # Client has exhausted their budget: issue RFC 6585 challenge
            deficit = max(0.0, cost - remaining_tokens)
            challenge = pow_engine.generate_challenge(
                method=method,
                path=canonical_path,
                query_params=query_params,
                deficit=deficit,
            )
            retry_after_int = max(1, math.ceil(retry_after))

            logger.info(
                "RATE LIMIT EXCEEDED for %s (Cost: %.2f, Remaining: %.2f) -> HTTP 428 Challenge Issued (Diff: %d)",
                client_id, cost, remaining_tokens, challenge["difficulty"],
            )

            return JSONResponse(
                status_code=status.HTTP_428_PRECONDITION_REQUIRED,
                content={
                    "error": "Precondition Required",
                    "message": "Token bucket exhausted for requested computational complexity. Solve PoW challenge.",
                    "cost_required": cost,
                    "remaining_tokens": remaining_tokens,
                    "challenge": challenge,
                },
                headers={
                    "Retry-After": str(retry_after_int),
                    "X-Cost-Assigned": f"{cost:.2f}",
                    "X-RateLimit-Remaining": f"{remaining_tokens:.2f}",
                },
            )

    # Measure pre-forwarding gateway overhead
    t_pre_forward = time.perf_counter()
    proxy_internal_work_s += (t_pre_forward - t_proxy_start)

    # -------------------------------------------------------------------------
    # STEP 5: Upstream Forwarding via persistent async client
    # -------------------------------------------------------------------------
    req_body = await request.body()
    # Strip hop-by-hop and PoW internal headers
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS and k.lower() not in {"x-pow-token", "x-pow-nonce"}
    }
    forward_headers["x-forwarded-for"] = client_id

    try:
        upstream_response = await http_client.request(
            method=method,
            url=canonical_path,
            params=query_params,
            headers=forward_headers,
            content=req_body,
        )
    except httpx.RequestError as exc:
        logger.error("Upstream communication error forwarding to %s%s: %s", BACKEND_URL, canonical_path, exc)
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={"error": "Bad Gateway", "detail": f"Upstream service unavailable: {str(exc)}"},
            headers={"X-Cost-Assigned": f"{cost:.2f}"},
        )

    # Measure post-forwarding gateway overhead
    t_post_forward = time.perf_counter()

    # -------------------------------------------------------------------------
    # STEP 6: Telemetry Headers Injection & Response Relay
    # -------------------------------------------------------------------------
    # Build clean response headers
    resp_headers = {
        k: v for k, v in upstream_response.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }

    t_final = time.perf_counter()
    proxy_internal_work_s += (t_final - t_post_forward)
    proxy_overhead_ms = proxy_internal_work_s * 1000.0

    resp_headers["X-Cost-Assigned"] = f"{cost:.2f}"
    resp_headers["X-Proxy-Overhead-Ms"] = f"{proxy_overhead_ms:.2f}"
    resp_headers["X-PoW-Bypassed"] = "true" if pow_authorized else "false"

    return FastAPIResponse(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=resp_headers,
        media_type=upstream_response.headers.get("content-type"),
    )
