from collections import OrderedDict
class LRUCache:
    def __init__(self,n): self.n,self.d=n,OrderedDict()
    def get(self,k): return self.d[k]
    def put(self,k,v):
        self.d[k]=v
        if len(self.d)>self.n: self.d.popitem(last=False)
