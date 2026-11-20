# Benign: an agent writes and runs a data-processing script.
cat > task.py <<'SRC'
import json, csv, statistics
rows = [{"n": i, "sq": i * i} for i in range(100)]
with open("data.csv", "w", newline="") as stream:
    writer = csv.DictWriter(stream, fieldnames=["n", "sq"])
    writer.writeheader()
    writer.writerows(rows)
print(json.dumps({"mean": statistics.mean(r["sq"] for r in rows)}))
SRC
python3 task.py
python3 -c 'import sys; print(sys.version)'
