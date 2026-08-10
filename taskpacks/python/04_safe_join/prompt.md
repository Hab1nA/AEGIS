# Safe filesystem join

Repair `solution.py`. `safe_join(root, user_path)` returns the resolved path only when it remains inside `root`. Reject absolute paths, traversal, and paths resolving outside the root with `ValueError`.
