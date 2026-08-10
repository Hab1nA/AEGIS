from pathlib import Path
def safe_join(root, user_path):
    relative=Path(user_path)
    if relative.is_absolute(): raise ValueError("absolute path")
    base=Path(root).resolve(); candidate=(base/relative).resolve()
    if candidate != base and base not in candidate.parents: raise ValueError("unsafe path")
    return candidate
