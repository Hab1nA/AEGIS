# Thread-safe counter
Repair `solution.py`. `AtomicCounter(initial=0)` provides linearizable `increment(amount=1)` returning the new value and `value()`. Concurrent increments must not be lost; reject non-integer amounts.
