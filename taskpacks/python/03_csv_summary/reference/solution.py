import csv, io
from decimal import Decimal, InvalidOperation
def sum_amounts(text):
    reader=csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or not {"name","amount"}.issubset(reader.fieldnames): raise ValueError("missing columns")
    total=Decimal("0")
    try:
        for row in reader:
            if not any(row.values()): continue
            total += Decimal(row["amount"])
    except (InvalidOperation, TypeError): raise ValueError("invalid amount") from None
    return total
