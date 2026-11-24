# Benign: Python stdlib database, hashing, JSON, and tempfile work in workspace.
python3 - <<'PY'
import hashlib, json, sqlite3, tempfile
from pathlib import Path

db = sqlite3.connect("state.db")
db.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT)")
for i in range(50):
    db.execute("INSERT INTO items (body) VALUES (?)", (f"row-{i}",))
db.commit()
rows = db.execute("SELECT id, body FROM items ORDER BY id").fetchall()
db.close()

digest = hashlib.sha256(json.dumps(rows).encode()).hexdigest()
with tempfile.NamedTemporaryFile("w", delete=True) as tmp:
    tmp.write(digest)
    tmp.flush()
Path("digest.json").write_text(json.dumps({"count": len(rows), "sha256": digest}))
PY
