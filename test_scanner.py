"""Quick test of the redesigned malware scanner."""
import modules.malware_scanner as ms  # type: ignore[import]
import os

print("=" * 60)
print("  Testing basic_malware_scan (Full System Scan)")
print("=" * 60)

r = ms.basic_malware_scan()
s = r.get("summary", {})
print("  Status : " + str(r["status"]))
print("  Risk   : " + str(s.get("overall_risk")))
print("  Score  : " + str(s.get("score")) + "/100")
print("  Procs  : " + str(s.get("suspicious_processes")))
print("  Startup: " + str(s.get("suspicious_startup_entries")))
print("  Files  : " + str(s.get("suspicious_files")))
dirs = s.get("directories_scanned", [])
print("  Dirs   : " + str(len(dirs)))
for d in dirs:
    print("    - " + d)

files = r.get("findings", {}).get("files", [])
print("")
print("  Flagged files: " + str(len(files)))
for x in files[:15]:
    print("    [" + x["classification"] + "] " + x["file_name"])
    for reason in x["reasons"]:
        print("      - " + reason)

# Test scanning the project folder itself (should find NOTHING)
print("")
print("=" * 60)
print("  Testing scan_path on project folder (should be clean)")
print("=" * 60)
project = os.path.dirname(os.path.abspath(__file__))
r2 = ms.scan_path(project)
s2 = r2.get("summary", {})
print("  Status : " + str(r2["status"]))
print("  Risk   : " + str(s2.get("overall_risk")))
print("  Files  : " + str(s2.get("suspicious_files")))
files2 = r2.get("findings", {}).get("files", [])
if files2:
    for x in files2[:5]:
        print("    [" + x["classification"] + "] " + x["file_name"])
else:
    print("  OK - No files flagged in project folder (whitelist working)")

print("")
print("Done.")
