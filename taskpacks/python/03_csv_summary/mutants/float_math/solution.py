import csv, io
from decimal import Decimal
def sum_amounts(text):
    reader=csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or not {"name","amount"}.issubset(reader.fieldnames): raise ValueError("missing columns")
    return Decimal(str(sum(float(row["amount"]) for row in reader if any(row.values()))))
