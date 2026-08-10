# Selective retry

Repair `solution.py`. `retry(call, attempts, retry_on)` calls until success or attempts are exhausted. Reject attempts below one. Retry only exceptions matching `retry_on`; propagate all others immediately.
