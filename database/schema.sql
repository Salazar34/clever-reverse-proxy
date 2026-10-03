-- =============================================================================
-- SecLab DoS Mitigation - Persistence Schema
-- Target RDBMS: PostgreSQL 16
-- Database: benchdb
-- =============================================================================

-- 1. Pulizia tabelle preesistenti
DROP TABLE IF EXISTS orders CASCADE;
DROP TABLE IF EXISTS customers CASCADE;

-- 2. Tabella: customers
CREATE TABLE customers (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(120) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    tier VARCHAR(20) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 3. Tabella: orders
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    customer_id INT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    order_number VARCHAR(64) UNIQUE NOT NULL,
    total_amount NUMERIC(10,2) NOT NULL,
    status VARCHAR(20) NOT NULL,
    shipping_address VARCHAR(255) NOT NULL,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 4. Strategia di Indicizzazione (B-Tree)
CREATE INDEX idx_orders_customer_id ON orders(customer_id);
CREATE INDEX idx_orders_created_at ON orders(created_at);
CREATE INDEX idx_orders_status ON orders(status);

-- =============================================================================
-- NOTA ARCHITETTURALE CRITICA PER IL BENCHMARK DOS:
-- Il campo 'orders.notes' è stato INTENZIONALMENTE lasciato PRIVATO DI INDICE.
-- Ricerche con pattern matching arbitrario (ILIKE '%keyword%') o clausole di
-- ordinamento su questa colonna costringeranno il Query Planner di PostgreSQL
-- a intraprendere una scansione sequenziale completa (Seq Scan) o un external
-- disk sort attraverso tutte le 500.000 tuple, massimizzando il consumo di
-- cicli CPU e I/O thrashing sul singolo core limitato del container.
-- =============================================================================
