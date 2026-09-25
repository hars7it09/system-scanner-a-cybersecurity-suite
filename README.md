# System Security Scanner (Desktop)
This is a Python desktop application (Tkinter) that:
- Scans ports on a given host.
- Fetches the system password policy (Windows: `net accounts`; Linux: `/etc/login.defs`).
- Retrieves connected Wi‑Fi device info (Windows: `netsh wlan show interfaces`; Linux: `nmcli`/`iwconfig`).
- Retrieves connected USB devices (best-effort) and provides event/log hints for connection times.
- Generates a `.docx` report containing the results.

## How to run
1. Create a Python environment and install requirements:
   pip install -r requirements.txt
2. Run:
   python main.py

## Notes
- Some USB and event queries may require administrator privileges.
- Commands used depend on OS utilities (wmic, netsh, lsusb, dmesg, powershell).
- Run scans only on systems/networks you own or have permission to scan.
