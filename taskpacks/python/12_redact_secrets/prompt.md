# Secret redaction
Repair `solution.py`. `redact(text)` replaces values in `password=...`, `token=...`, and `api_key=...` assignments with `[REDACTED]`. Keys are case-insensitive; optional spaces surround `=`; values end at whitespace, comma, or semicolon. Do not redact longer unrelated keys.
