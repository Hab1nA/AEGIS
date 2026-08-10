import math

def clamp(value, lower, upper):
    if lower > upper:
        raise ValueError("lower must not exceed upper")
    if isinstance(value, float) and math.isnan(value):
        return value
    return min(upper, max(lower, value))
