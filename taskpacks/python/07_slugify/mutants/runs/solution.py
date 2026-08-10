import re,unicodedata
def slugify(s):
 s=unicodedata.normalize("NFKD",s).encode("ascii","ignore").decode().lower(); s=re.sub(r"[^a-z0-9]","-",s).strip("-")
 if not s: raise ValueError("empty")
 return s
