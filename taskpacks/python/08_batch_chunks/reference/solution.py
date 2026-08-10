from itertools import islice
def batched(items,size):
 if size<1: raise ValueError("size")
 it=iter(items)
 while batch:=list(islice(it,size)): yield batch
