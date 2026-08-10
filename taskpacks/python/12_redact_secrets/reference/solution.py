import re
_PATTERN=re.compile(r"(?i)(?<![A-Za-z0-9_])(password|token|api_key)(\s*=\s*)([^\s,;]+)")
def redact(text): return _PATTERN.sub(lambda m:m.group(1)+m.group(2)+"[REDACTED]",text)
