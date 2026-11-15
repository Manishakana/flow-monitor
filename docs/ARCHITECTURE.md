# Architecture

```text
Browser dashboard
      │ HTTP (localhost)
      ▼
Python server
      ├── Local telemetry collector
      │   └── psutil: interface counters and established TCP metadata
      ├── LAN discovery
      │   ├── Passive ARP-cache observation
      │   └── Rate-limited private /24 active discovery
      ├── SQLite repository
      │   ├── device inventory
      │   └── connection history
      └── Read-only JSON APIs
```

## Collection boundaries

- The server binds to `127.0.0.1`.
- Active discovery is limited to the detected private `/24` network and runs no more than once per minute.
- Packet payloads are not collected.
- Historical values begin only after the local service starts.

## Next production stages

1. Authentication, role-based access, and encrypted storage.
2. Authorized router, firewall, DNS, DHCP, cloud-flow, and Wi-Fi-controller connectors.
3. Clear source coverage and blind-spot reporting.
4. Explainable detection rules and investigation exports.
