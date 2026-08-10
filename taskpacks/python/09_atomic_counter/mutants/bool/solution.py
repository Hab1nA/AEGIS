from threading import Lock
class AtomicCounter:
 def __init__(self,initial=0): self._value,self._lock=initial,Lock()
 def increment(self,amount=1):
  if not isinstance(amount,int): raise TypeError("amount")
  with self._lock: self._value+=amount; return self._value
 def value(self):
  with self._lock: return self._value
