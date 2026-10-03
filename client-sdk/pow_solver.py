"""
SecLab DoS Mitigation - Autonomous Proof-of-Work Client SDK & Solver
Module: client-sdk.pow_solver

Provides client-side capabilities to solve Proof-of-Work cryptographic challenges
and automatically negotiate HTTP 428 Precondition Required responses.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, Mapping, Tuple

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pow_solver")


def solve_pow(token: str, difficulty: int) -> Tuple[int, float]:
    """
    Solves the Hashcash-like Proof-of-Work challenge by incrementing an integer nonce.

    Algorithm:
        Find integer nonce such that:
            SHA256(token + ":" + nonce) begins with `difficulty` hex zeros ('0' * difficulty)

    Args:
        token: Stateless challenge token emitted by the reverse proxy.
        difficulty: Number of leading hexadecimal zeros required.

    Returns:
        Tuple[int, float]: (winning_nonce, elapsed_seconds)
    """
    target_prefix = "0" * difficulty
    prefix_bytes = f"{token}:".encode("ascii")
    nonce = 0

    logger.info(
        "Starting PoW mining (Difficulty: %d zeros, Expected hashes: ~%d)...",
        difficulty,
        16**difficulty,
    )
    t_start = time.perf_counter()

    while True:
        # Candidate format: <token>:<nonce>
        candidate = prefix_bytes + str(nonce).encode("ascii")
        digest = hashlib.sha256(candidate).hexdigest()

        if digest.startswith(target_prefix):
            elapsed = time.perf_counter() - t_start
            hashrate = nonce / elapsed if elapsed > 0 else 0.0
            logger.info(
                "PoW solved in %.3fs! Nonce: %d | Hash: %s... | Hashrate: %.0f H/s",
                elapsed,
                nonce,
                digest[:12],
                hashrate,
            )
            return nonce, elapsed

        nonce += 1


def smart_request(
    url: str,
    method: str = "GET",
    params: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    session: requests.Session | None = None,
    **kwargs: Any,
) -> requests.Response:
    """
    Dispatches an HTTP request with automatic PoW challenge negotiation.

    Behavior:
      1. Dispatches the initial request.
      2. If HTTP 200 OK: returns the response directly.
      3. If HTTP 428 Precondition Required:
         - Parses challenge JSON {token, difficulty, algorithm}.
         - Solves the PoW challenge locally (cost-shifting: client spends CPU).
         - Re-dispatches request with headers:
             X-PoW-Token: <token>
             X-PoW-Nonce: <nonce>
         - Returns authenticated backend response.

    Args:
        url: Target HTTP URL.
        method: HTTP method (GET, POST, etc.).
        params: Query string parameters.
        headers: Request headers.
        session: Optional requests.Session instance.
        **kwargs: Additional parameters passed to requests.request.

    Returns:
        requests.Response: Final HTTP response object.
    """
    client = session or requests
    req_headers = dict(headers or {})

    # 1. Dispatch initial request
    logger.debug("Dispatching initial %s request to %s (params=%s)", method.upper(), url, params)
    response = client.request(method=method, url=url, params=params, headers=req_headers, **kwargs)

    # 2. Fast-path: Success or ordinary status codes
    if response.status_code != 428:
        return response

    # 3. HTTP 428 Precondition Required intercepted
    logger.warning("Received HTTP 428 Precondition Required from Gateway. Negotiating challenge...")
    try:
        challenge_data = response.json()
        token = challenge_data.get("token") or challenge_data.get("challenge", {}).get("token")
        difficulty = challenge_data.get("difficulty") or challenge_data.get("challenge", {}).get("difficulty")

        if not token or difficulty is None:
            logger.error("HTTP 428 response missing required PoW fields: %s", challenge_data)
            return response

        difficulty = int(difficulty)

    except Exception as exc:
        logger.error("Failed to parse HTTP 428 challenge response: %s", exc)
        return response

    # 4. Solve the cryptographic puzzle on client CPU
    nonce, elapsed = solve_pow(token, difficulty)

    # 5. Attach proof headers and re-dispatch original request
    authenticated_headers = req_headers.copy()
    authenticated_headers["X-PoW-Token"] = token
    authenticated_headers["X-PoW-Nonce"] = str(nonce)

    logger.info("Resending request with Proof-of-Work headers (X-PoW-Token, X-PoW-Nonce)...")
    final_response = client.request(
        method=method,
        url=url,
        params=params,
        headers=authenticated_headers,
        **kwargs,
    )
    logger.info(
        "Final response status after PoW submission: %d %s (Total turnaround: %.3fs)",
        final_response.status_code,
        final_response.reason,
        elapsed,
    )

    return final_response


if __name__ == "__main__":
    # Self-test demonstration
    import sys

    print("=" * 60)
    print("SecLab PoW Solver - Local Verification Test")
    print("=" * 60)

    sample_token = "eyJzYWx0IjoiYWJjZCIsInRzIjoxNzAwMDAwMDAwLCJkaWZmIjo0fQ.demo_signature"
    test_difficulty = 4

    print(f"Testing local PoW mining with difficulty = {test_difficulty} hex zeros...")
    winning_nonce, duration = solve_pow(sample_token, test_difficulty)
    test_hash = hashlib.sha256(f"{sample_token}:{winning_nonce}".encode("ascii")).hexdigest()

    print(f"Result: Nonce={winning_nonce} | Duration={duration:.4f}s | Hash={test_hash}")
    assert test_hash.startswith("0" * test_difficulty), "Verification failed!"
    print("Verification successfully passed!")
