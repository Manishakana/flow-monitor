# Contributing to SignalGuard

## Development setup

1. Create and activate a Python virtual environment.
2. Install dependencies with `python -m pip install -r requirements.txt`.
3. Start the dashboard with `python -B server.py`.
4. Open `http://127.0.0.1:4173`.

## Contribution rules

- Preserve metadata-only collection by default; do not add payload capture without explicit privacy and retention controls.
- Keep active discovery bounded to an explicitly authorized private network scope.
- Never commit `signalguard.db`, logs, personal IP addresses, MAC addresses, or screenshots containing real telemetry.
- Add or update verification for backend changes and run `python -m py_compile server.py signalguard/*.py` plus `node --check app.js` before opening a pull request.
