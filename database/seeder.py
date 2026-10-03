#!/usr/bin/env python3
"""
SecLab DoS Mitigation - High-Performance Database Seeder
Stack: Python 3.11, asyncpg (Binary Protocol)

Generates:
  - 20,000 customers
  - 500,000 orders (in chunks of 25,000 tuples via conn.copy_records_to_table)
  - 10% of orders contain keywords 'URGENT', 'FRAGILE', 'EXPRESS' in unindexed 'notes'
  - Finalizes with VACUUM ANALYZE to prime the PostgreSQL query planner
"""

import asyncio
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import logging
import os
import random
import sys
import time

import asyncpg

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("seeder")

# Database connection settings
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_USER = os.getenv("DB_USER", "benchuser")
DB_PASSWORD = os.getenv("DB_PASSWORD", "benchpassword")
DB_NAME = os.getenv("DB_NAME", "benchdb")

# Volume constants
NUM_CUSTOMERS = 20_000
NUM_ORDERS = 500_000
CHUNK_SIZE = 25_000

# Domain pools for realistic synthetic generation
TIERS = ["BRONZE", "SILVER", "GOLD", "PLATINUM"]
STATUSES = ["PENDING", "PROCESSING", "SHIPPED", "DELIVERED", "CANCELLED"]
KEYWORDS = ["URGENT", "FRAGILE", "EXPRESS"]

FIRST_NAMES = [
    "Alessandro", "Marco", "Giulia", "Sofia", "Matteo", "Lorenzo", "Chiara",
    "Francesca", "Andrea", "Luca", "Elena", "Davide", "Simone", "Federica",
    "Valentina", "Antonio", "Roberto", "Gabriele", "Sara", "Martina"
]
LAST_NAMES = [
    "Rossi", "Russo", "Ferrari", "Esposito", "Bianchi", "Romano", "Colombo",
    "Ricci", "Marino", "Greco", "Bruno", "Gallo", "Conti", "De Luca",
    "Costa", "Giordano", "Mancini", "Rizzo", "Lombardi", "Moretti"
]
STREETS = [
    "Via Roma", "Corso Umberto I", "Via Garibaldi", "Via Dante Alighieri",
    "Corso Vittorio Emanuele", "Via Cavour", "Via San Francesco", "Viale Europa"
]
CITIES = ["Milano", "Roma", "Torino", "Bologna", "Napoli", "Firenze", "Padova", "Genova"]


async def get_connection_with_retry(max_retries: int = 15, delay_s: float = 2.0) -> asyncpg.Connection:
    """Establishes database connection with exponential-like polling."""
    for attempt in range(1, max_retries + 1):
        try:
            logger.info("Connecting to PostgreSQL at %s:%d/%s (attempt %d/%d)...",
                        DB_HOST, DB_PORT, DB_NAME, attempt, max_retries)
            conn = await asyncpg.connect(
                host=DB_HOST,
                port=DB_PORT,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
                timeout=10,
            )
            logger.info("Database connection established.")
            return conn
        except (OSError, asyncpg.PostgresError) as exc:
            if attempt == max_retries:
                logger.error("Unable to connect to database after %d attempts: %s", attempt, exc)
                raise
            logger.warning("PostgreSQL not ready yet (%s). Retrying in %.1fs...", exc, delay_s)
            await asyncio.sleep(delay_s)
    raise RuntimeError("Failed to connect to PostgreSQL")


def generate_customer_records(count: int, base_time: datetime) -> list[tuple]:
    """Generates synthetic customer tuples."""
    records = []
    num_fn = len(FIRST_NAMES)
    num_ln = len(LAST_NAMES)
    num_tiers = len(TIERS)

    for cid in range(1, count + 1):
        fn = FIRST_NAMES[cid % num_fn]
        ln = LAST_NAMES[(cid // num_fn) % num_ln]
        full_name = f"{fn} {ln}"
        email = f"customer.{cid}.{fn.lower()}.{ln.lower()}@benchdomain.sec"
        tier = TIERS[cid % num_tiers]
        created_at = base_time - timedelta(days=random.randint(30, 730), seconds=random.randint(0, 86400))
        records.append((cid, full_name, email, tier, created_at))
    return records


def generate_order_chunk(start_id: int, count: int, total_customers: int, base_time: datetime) -> list[tuple]:
    """
    Generates a chunk of order tuples.
    Guarantees ~10% keyword injection in unindexed 'notes'.
    """
    chunk = []
    num_statuses = len(STATUSES)
    num_keywords = len(KEYWORDS)
    num_streets = len(STREETS)
    num_cities = len(CITIES)

    for offset in range(count):
        oid = start_id + offset
        customer_id = 1 + (oid * 37) % total_customers
        order_number = f"ORD-2026-{oid:08d}"
        
        # Fast decimal creation (avoiding string parsing inside tight loop)
        amount_cents = 500 + (oid * 13) % 99500
        total_amount = Decimal(amount_cents) / Decimal(100)
        
        status = STATUSES[oid % num_statuses]
        street = STREETS[oid % num_streets]
        city = CITIES[(oid // num_streets) % num_cities]
        shipping_address = f"{street} {1 + (oid % 150)}, {city}"
        
        # 10% keyword injection ('URGENT', 'FRAGILE', 'EXPRESS')
        # Remainder: standard or empty notes
        mod10 = oid % 10
        if mod10 == 0:
            kw = KEYWORDS[(oid // 10) % num_keywords]
            notes = f"Priority shipping requested: {kw} consignment. Verify recipient ID upon delivery."
        elif mod10 == 3:
            notes = "Standard packaging. Leave parcel at front desk if absent."
        elif mod10 == 7:
            notes = "Scheduled morning delivery. Gate access code provided via phone."
        else:
            notes = None

        created_at = base_time - timedelta(days=(oid % 365), seconds=(oid * 17) % 86400)
        chunk.append((oid, customer_id, order_number, total_amount, status, shipping_address, notes, created_at))
    return chunk


async def seed() -> None:
    t_global_start = time.perf_counter()
    conn = await get_connection_with_retry()

    try:
        now = datetime.now(timezone.utc)

        # 1. Truncate preexisting data
        logger.info("Cleaning existing data from 'orders' and 'customers'...")
        await conn.execute("TRUNCATE TABLE orders, customers RESTART IDENTITY CASCADE;")

        # 2. Insert Customers (20,000 records)
        logger.info("Generating %d customers...", NUM_CUSTOMERS)
        t_cust_gen = time.perf_counter()
        customers = generate_customer_records(NUM_CUSTOMERS, now)
        logger.info("Customer tuples generated in %.2fs. Copying to table via binary protocol...",
                    time.perf_counter() - t_cust_gen)
        
        t_cust_copy = time.perf_counter()
        await conn.copy_records_to_table(
            "customers",
            records=customers,
            columns=["id", "full_name", "email", "tier", "created_at"],
        )
        logger.info("Inserted %d customers in %.2fs.", NUM_CUSTOMERS, time.perf_counter() - t_cust_copy)

        # 3. Insert Orders (500,000 records in chunks of 25,000)
        logger.info("Generating and copying %d orders in chunks of %d...", NUM_ORDERS, CHUNK_SIZE)
        t_orders_start = time.perf_counter()
        num_chunks = NUM_ORDERS // CHUNK_SIZE

        for chunk_idx in range(num_chunks):
            start_id = chunk_idx * CHUNK_SIZE + 1
            t_chunk_start = time.perf_counter()
            chunk_records = generate_order_chunk(start_id, CHUNK_SIZE, NUM_CUSTOMERS, now)
            
            await conn.copy_records_to_table(
                "orders",
                records=chunk_records,
                columns=[
                    "id",
                    "customer_id",
                    "order_number",
                    "total_amount",
                    "status",
                    "shipping_address",
                    "notes",
                    "created_at",
                ],
            )
            elapsed_chunk = time.perf_counter() - t_chunk_start
            logger.info("  Chunk %2d/%2d inserted (%d tuples) in %.2fs (cumulative: %d/%d)",
                        chunk_idx + 1, num_chunks, CHUNK_SIZE, elapsed_chunk,
                        start_id + CHUNK_SIZE - 1, NUM_ORDERS)

        logger.info("Inserted %d orders in %.2fs.", NUM_ORDERS, time.perf_counter() - t_orders_start)

        # 4. Sync PostgreSQL Serial Sequences
        logger.info("Synchronizing SERIAL sequences...")
        await conn.execute("SELECT setval('customers_id_seq', $1, true);", NUM_CUSTOMERS)
        await conn.execute("SELECT setval('orders_id_seq', $1, true);", NUM_ORDERS)

        # 5. VACUUM ANALYZE to refresh Query Planner statistics
        logger.info("Executing VACUUM ANALYZE customers...")
        t_vac = time.perf_counter()
        await conn.execute("VACUUM ANALYZE customers;")
        logger.info("Executing VACUUM ANALYZE orders...")
        await conn.execute("VACUUM ANALYZE orders;")
        logger.info("VACUUM ANALYZE completed in %.2fs.", time.perf_counter() - t_vac)

        t_total = time.perf_counter() - t_global_start
        logger.info("=" * 60)
        logger.info("SEEDING SUCCESSFULLY COMPLETED in %.2f seconds.", t_total)
        logger.info("=" * 60)

    finally:
        await conn.close()
        logger.info("Database connection closed.")


if __name__ == "__main__":
    try:
        asyncio.run(seed())
    except KeyboardInterrupt:
        logger.warning("Seeding interrupted by user.")
        sys.exit(130)
    except Exception as e:
        logger.exception("Seeding failed: %s", e)
        sys.exit(1)
