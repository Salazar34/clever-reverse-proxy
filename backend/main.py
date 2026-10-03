"""
SecLab DoS Mitigation - Mock Backend API Service
Stack: Python 3.11, FastAPI, asyncpg, uvicorn

Exposes endpoints designed to demonstrate symmetric vs asymmetric computational workloads:
  - O(1) Key-Lookup: /api/v1/orders/{order_id}
  - Parametric Query: /api/v1/orders (supports unindexed ILIKE and deep OFFSET pagination)
  - Telemetry: Injects X-DB-Execution-Time-Ms and X-DB-Rows-Returned headers
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Optional

import asyncpg
from fastapi import FastAPI, HTTPException, Path, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("backend.api")

# Configuration from Environment Variables
DB_HOST = os.getenv("DB_HOST", "postgres")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_USER = os.getenv("DB_USER", "benchuser")
DB_PASSWORD = os.getenv("DB_PASSWORD", "benchpassword")
DB_NAME = os.getenv("DB_NAME", "benchdb")

POOL_MIN_SIZE = int(os.getenv("DB_POOL_MIN_SIZE", "5"))
POOL_MAX_SIZE = int(os.getenv("DB_POOL_MAX_SIZE", "20"))
POOL_COMMAND_TIMEOUT = float(os.getenv("DB_COMMAND_TIMEOUT", "60.0"))

ALLOWED_SORT_COLUMNS = frozenset({"id", "created_at", "total_amount", "status", "notes"})
ALLOWED_SORT_DIRECTIONS = frozenset({"ASC", "DESC"})


# --------------------------------------------------------------------------- #
# Pydantic Schemas                                                            #
# --------------------------------------------------------------------------- #
class OrderDetail(BaseModel):
    id: int
    customer_id: int
    customer_name: str
    customer_email: str
    order_number: str
    total_amount: Decimal
    status: str
    shipping_address: str
    notes: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OrderSummary(BaseModel):
    id: int
    customer_id: int
    order_number: str
    total_amount: Decimal
    status: str
    shipping_address: str
    notes: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class HealthResponse(BaseModel):
    status: str
    database: str
    pool_size: int
    pool_free: int


# --------------------------------------------------------------------------- #
# Application Lifespan (Connection Pool Lifecycle)                           #
# --------------------------------------------------------------------------- #
@asynccontextmanager
async def lifespan(app: FastAPI):
    dsn = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    logger.info("Initializing asyncpg connection pool (%s:%d/%s, size: %d-%d)...",
                DB_HOST, DB_PORT, DB_NAME, POOL_MIN_SIZE, POOL_MAX_SIZE)
    try:
        pool = await asyncpg.create_pool(
            dsn=dsn,
            min_size=POOL_MIN_SIZE,
            max_size=POOL_MAX_SIZE,
            command_timeout=POOL_COMMAND_TIMEOUT,
        )
        app.state.pool = pool
        logger.info("Connection pool successfully initialized.")
    except Exception as exc:
        logger.error("Failed to initialize database pool: %s", exc)
        raise

    yield

    logger.info("Closing database connection pool...")
    await app.state.pool.close()
    logger.info("Database connection pool closed.")


app = FastAPI(
    title="SecLab Benchmark Backend Mock",
    description="Internal mock backend executing real queries against PostgreSQL 16 with execution timing telemetry.",
    version="1.0.0",
    lifespan=lifespan,
)


# --------------------------------------------------------------------------- #
# Endpoints                                                                   #
# --------------------------------------------------------------------------- #
@app.get(
    "/api/v1/orders/{order_id}",
    response_model=OrderDetail,
    summary="Lightweight O(1) Key-Lookup Query",
    description="Performs an indexed primary key lookup on orders joined with customers. Execution time is typically < 1 ms.",
)
async def get_order_by_id(
    order_id: Annotated[int, Path(ge=1, description="Primary key identifier of the order")],
    response: Response,
) -> Any:
    pool: asyncpg.Pool = app.state.pool

    query = """
        SELECT 
            o.id,
            o.customer_id,
            c.full_name AS customer_name,
            c.email AS customer_email,
            o.order_number,
            o.total_amount,
            o.status,
            o.shipping_address,
            o.notes,
            o.created_at
        FROM orders o
        JOIN customers c ON o.customer_id = c.id
        WHERE o.id = $1;
    """

    t_start = time.perf_counter()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, order_id)
    t_end = time.perf_counter()

    db_execution_time_ms = (t_end - t_start) * 1000.0
    response.headers["X-DB-Execution-Time-Ms"] = f"{db_execution_time_ms:.2f}"
    response.headers["X-DB-Rows-Returned"] = "1" if row else "0"

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Order with ID {order_id} not found",
        )

    return dict(row)


@app.get(
    "/api/v1/orders",
    response_model=list[OrderSummary],
    summary="Parametric Asymmetric Complexity Query",
    description=(
        "Executes a dynamically parameterized query over orders. When 'search' is supplied, "
        "PostgreSQL executes a full Sequential Scan on the unindexed 'notes' column. "
        "Large 'offset' values force scanning and discarding thousands of tuples."
    ),
)
async def list_orders(
    response: Response,
    limit: Annotated[int, Query(ge=1, le=1000, description="Max tuples to return")] = 20,
    offset: Annotated[int, Query(ge=0, description="Tuples to skip")] = 0,
    search: Annotated[Optional[str], Query(max_length=255, description="Search pattern against unindexed notes")] = None,
    sort_by: Annotated[str, Query(description="Column to sort by")] = "id",
    sort_dir: Annotated[str, Query(description="Sort direction (asc|desc)")] = "asc",
) -> Any:
    # 1. Strict validation of sort parameters to prevent SQL injection
    sort_by_clean = sort_by.strip().lower()
    if sort_by_clean not in ALLOWED_SORT_COLUMNS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid sort_by column '{sort_by}'. Allowed: {sorted(ALLOWED_SORT_COLUMNS)}",
        )

    sort_dir_clean = sort_dir.strip().upper()
    if sort_dir_clean not in ALLOWED_SORT_DIRECTIONS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid sort_dir '{sort_dir}'. Allowed: ['asc', 'desc']",
        )

    # 2. Dynamic, fully parameterized query assembly
    clauses: list[str] = []
    args: list[Any] = []
    arg_idx = 1

    if search:
        # If the search string doesn't contain explicit SQL wildcards, wrap it with '%'
        pattern = search if ("%" in search or "_" in search) else f"%{search}%"
        clauses.append(f"notes ILIKE ${arg_idx}")
        args.append(pattern)
        arg_idx += 1

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    order_by_sql = f"ORDER BY {sort_by_clean} {sort_dir_clean}"
    limit_offset_sql = f"LIMIT ${arg_idx} OFFSET ${arg_idx + 1}"
    args.extend([limit, offset])

    query = f"""
        SELECT 
            id,
            customer_id,
            order_number,
            total_amount,
            status,
            shipping_address,
            notes,
            created_at
        FROM orders
        {where_sql}
        {order_by_sql}
        {limit_offset_sql};
    """

    # 3. Execution and precise database timing
    pool: asyncpg.Pool = app.state.pool
    t_start = time.perf_counter()
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *args)
    t_end = time.perf_counter()

    db_execution_time_ms = (t_end - t_start) * 1000.0

    # 4. Telemetry headers
    response.headers["X-DB-Execution-Time-Ms"] = f"{db_execution_time_ms:.2f}"
    response.headers["X-DB-Rows-Returned"] = str(len(rows))

    return [dict(r) for r in rows]


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Readiness & Health Probe",
    description="Validates pool acquisition and connectivity to PostgreSQL.",
)
async def health_check() -> Any:
    pool: asyncpg.Pool = getattr(app.state, "pool", None)
    if pool is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Pool not initialized")

    try:
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1;")
        return {
            "status": "healthy",
            "database": "connected",
            "pool_size": pool.get_size(),
            "pool_free": pool.get_idle_size(),
        }
    except Exception as exc:
        logger.error("Health check failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database unreachable: {exc}",
        )
