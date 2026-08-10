def retry(call, attempts, retry_on):
    if attempts < 1: raise ValueError("attempts must be positive")
    for index in range(attempts):
        try: return call()
        except retry_on:
            if index + 1 == attempts: raise
