def retry(call, attempts, retry_on):
    for index in range(attempts):
        try: return call()
        except Exception:
            if index + 1 == attempts: raise
