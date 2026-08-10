def sort_versions(values):
 def parse(value):
  parts=value.split(".")
  if not parts or any(not p.isdigit() for p in parts): raise ValueError("version")
  return tuple(map(int,parts))
 parsed=[(parse(v),v) for v in values]
 width=max((len(p) for p,_ in parsed),default=0)
 return [v for p,v in sorted(parsed,key=lambda x:x[0]+(0,)*(width-len(x[0])))]
