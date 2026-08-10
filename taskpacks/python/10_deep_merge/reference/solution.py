from copy import deepcopy
def deep_merge(left,right):
 out=deepcopy(left)
 for key,value in right.items():
  out[key]=deep_merge(out[key],value) if key in out and isinstance(out[key],dict) and isinstance(value,dict) else deepcopy(value)
 return out
