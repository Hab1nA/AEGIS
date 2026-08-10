# TTL cache

Repair `solution.py`. `TTLCache(ttl, clock)` supports `put(key, value)` and `get(key)`. A key expires when its age is greater than or equal to `ttl`; `get` then raises `KeyError`. Reject non-positive TTL values.
