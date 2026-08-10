def retry(call, attempts, retry_on):
    if attempts < 1: raise ValueError("attempts must be positive")
    for index in range(attempts + 1):
        try: return call()
        except retry_on:
            if index == attempts: raise
