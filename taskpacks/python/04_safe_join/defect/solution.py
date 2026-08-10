from pathlib import Path
def safe_join(root, user_path):
    base=Path(root).resolve(); candidate=(base/user_path).resolve()
    if not str(candidate).startswith(str(base)): raise ValueError("unsafe path")
    return candidate
