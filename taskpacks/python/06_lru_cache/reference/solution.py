from collections import OrderedDict
class LRUCache:
    def __init__(self,n):
        if n<1: raise ValueError("capacity")
        self.n,self.d=n,OrderedDict()
    def get(self,k): v=self.d.pop(k); self.d[k]=v; return v
    def put(self,k,v):
        if k in self.d: self.d.pop(k)
        self.d[k]=v
        if len(self.d)>self.n: self.d.popitem(last=False)
