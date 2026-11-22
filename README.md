# Flow Monitor

Flow Monitor is a privacy-first network visibility dashboard for understanding local host activity and devices discovered in an authorized private LAN.

It presents live connection metadata, throughput, device inventory, and local-network insights without installing an agent on every endpoint.

> This prototype is for authorized networks only. It does not capture packet payloads.

## Highlights

- Live inbound and outbound throughput with hover values.
- Active and historical TCP connection explorer.
- Local LAN device inventory using passive ARP data plus rate-limited active discovery.
- Device details: IP address, MAC address, hostname when resolvable, discovery source, first/last seen, and connection history.
- Source health, discovery scope, and retention visibility.
- Light and dark themes.
- Local SQLite history with no external telemetry transmission.

## Quick start

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -B server.py
```

Open `http://127.0.0.1:4173`.

## Verification

Run the local automated checks before committing changes:

```powershell
python -m unittest discover -s tests -v
node --check app.js
```

## Project structure

```text
flow_monitor/
  discovery.py      # Passive ARP and bounded private-LAN discovery
  storage.py        # SQLite device and connection history
  telemetry.py      # Local host telemetry collector
server.py           # Local HTTP server and read-only API routes
index.html          # Dashboard shell
app.js              # Dashboard interactions and drill-downs
styles.css          # Light and dark dashboard styling
docs/ARCHITECTURE.md
```

## Privacy and safety boundaries

- Binds to `127.0.0.1` only.
- Serves an explicit allowlist of dashboard assets; source files, databases, logs, and screenshots are not available through the dashboard server.
- Stores metadata, not packet payloads.
- Active discovery is restricted to the detected private `/24` LAN and is rate-limited to once per minute.
- `flow_monitor.db` and runtime logs are excluded from Git because they can contain private network metadata.

## Roadmap

- Authorized DHCP, DNS, firewall, router, cloud-flow, and Wi-Fi-controller integrations.
- Coverage and blind-spot reporting.
- Searchable investigation timelines and explainable detection rules.
- Authentication, role-based access, and encrypted storage for team deployments.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). For the architecture, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
