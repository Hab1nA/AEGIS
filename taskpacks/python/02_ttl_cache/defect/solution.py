class TTLCache:
    def __init__(self, ttl, clock): self.ttl, self.clock, self.data = ttl, clock, {}
    def put(self, key, value): self.data[key] = (value, self.clock())
    def get(self, key):
        value, created = self.data[key]
        if self.clock() - created > self.ttl: raise KeyError(key)
        return value
