from decimal import Decimal
def sum_amounts(text):
    return sum((Decimal(line.split(",")[1]) for line in text.splitlines()[1:]), Decimal("0"))
