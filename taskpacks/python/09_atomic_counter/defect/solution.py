class AtomicCounter:
 def __init__(self,initial=0): self._value=initial
 def increment(self,amount=1): self._value+=amount; return self._value
 def value(self): return self._value
