"""Remove orphaned firewall duplicate block from main.py."""
import ast
from pathlib import Path

TARGET = Path(__file__).resolve().parent / "main.py"

with TARGET.open("r", encoding="utf-8") as f:
    lines = f.readlines()

# Lines are 1-indexed in view; list is 0-indexed.
# Remove the stale firewall duplicate block in this workspace version.
lines = [line for i, line in enumerate(lines) if not (1375 <= i <= 1550)]

src = "".join(lines)

try:
    ast.parse(src)
    print("Syntax OK after removal")
except Exception:
    print("Error after removal")
    raise SystemExit(1)

with TARGET.open("w", encoding="utf-8") as f:
    f.write(src)

print(f"Done. File now has {len(lines)} lines.")
