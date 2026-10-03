-- =============================================================================
-- SecLab DoS Mitigation - Weighted Token Bucket with Lazy Evaluation
-- =============================================================================
-- KEYS[1]: Client rate-limit key (e.g., 'ratelimit:<client_id>')
-- ARGV[1]: Bucket capacity B (float)
-- ARGV[2]: Refill rate r in tokens/second (float)
-- ARGV[3]: Requested computational cost C(R) (float)
-- ARGV[4]: Current timestamp in seconds with microsecond precision (float)
--
-- Returns table:
--   { allowed (0|1), tostring(remaining_tokens), tostring(retry_after_seconds) }
-- =============================================================================

local key         = KEYS[1]
local capacity    = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local cost        = tonumber(ARGV[3])
local now         = tonumber(ARGV[4])

-- 1. Fetch current bucket state in an atomic round-trip
local state = redis.call('HMGET', key, 'tokens', 'last_updated')
local tokens = tonumber(state[1])
local last_updated = tonumber(state[2])

-- 2. Lazy Evaluation: replenish tokens based on elapsed wall-clock delta
if tokens == nil or last_updated == nil then
    -- First access or key expired: initialize with full capacity
    tokens = capacity
    last_updated = now
else
    local delta_t = math.max(0.0, now - last_updated)
    tokens = math.min(capacity, tokens + (delta_t * refill_rate))
    last_updated = now
end

-- Key TTL: set to 2 * ceil(capacity / refill_rate) to ensure clean memory eviction of inactive clients
local ttl_seconds = math.max(1, math.ceil(2.0 * (capacity / refill_rate)))

-- 3. Token deduction and admission decision
if tokens >= cost then
    -- ADMITTED: Deduct cost and persist new balance
    tokens = tokens - cost
    redis.call('HSET', key, 'tokens', tostring(tokens), 'last_updated', tostring(now))
    redis.call('EXPIRE', key, ttl_seconds)
    return { 1, tostring(tokens), "0" }
else
    -- REJECTED: Do not deduct tokens, compute precise wait time to accumulate missing credits
    local missing_tokens = cost - tokens
    local retry_after = missing_tokens / refill_rate
    -- Persist replenished tokens up to 'now' so accumulated credits are preserved
    redis.call('HSET', key, 'tokens', tostring(tokens), 'last_updated', tostring(now))
    redis.call('EXPIRE', key, ttl_seconds)
    return { 0, tostring(tokens), tostring(retry_after) }
end
