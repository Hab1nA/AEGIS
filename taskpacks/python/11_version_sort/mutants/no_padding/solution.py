def sort_versions(values):
 def parse(v):
  parts=v.split(".")
  if any(not p.isdigit() for p in parts): raise ValueError("version")
  return tuple(map(int,parts))
 return sorted(values,key=parse)
