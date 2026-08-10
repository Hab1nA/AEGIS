def batched(items,size):
 if size<1: raise ValueError("size")
 batch=[]
 for x in items:
  batch.append(x)
  if len(batch)==size: yield batch; batch.clear()
 if batch: yield batch
