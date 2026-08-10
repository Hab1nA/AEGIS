def batched(items,size):
 values=list(items)
 for i in range(0,len(values)-size+1,size): yield values[i:i+size]
