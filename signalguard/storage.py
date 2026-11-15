from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


class Repository:
    """Durable local store for observed peer and connection metadata."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    host TEXT PRIMARY KEY,
                    mac_address TEXT,
                    hostname TEXT,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    active_connections INTEGER NOT NULL DEFAULT 0,
                    discovery_source TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS connections (
                    connection_key TEXT PRIMARY KEY,
                    local_host TEXT,
                    local_port INTEGER,
                    remote_host TEXT NOT NULL,
                    remote_port INTEGER,
                    protocol TEXT NOT NULL,
                    state TEXT NOT NULL,
                    process_id INTEGER,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    closed_at INTEGER
                );
                CREATE INDEX IF NOT EXISTS connections_state_idx ON connections(state, last_seen DESC);
                CREATE INDEX IF NOT EXISTS connections_remote_idx ON connections(remote_host, last_seen DESC);
                """
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(devices)")}
            if "mac_address" not in columns:
                connection.execute("ALTER TABLE devices ADD COLUMN mac_address TEXT")
            if "hostname" not in columns:
                connection.execute("ALTER TABLE devices ADD COLUMN hostname TEXT")

    def record_observation(self, observed_at: int, connections: list[dict[str, Any]]) -> None:
        active_keys = {item["connection_key"] for item in connections}
        with self._connect() as connection:
            if active_keys:
                placeholders = ",".join("?" for _ in active_keys)
                connection.execute(
                    f"UPDATE connections SET state = 'closed', closed_at = ? WHERE state = 'active' AND connection_key NOT IN ({placeholders})",
                    (observed_at, *active_keys),
                )
            else:
                connection.execute("UPDATE connections SET state = 'closed', closed_at = ? WHERE state = 'active'", (observed_at,))
            connection.execute("UPDATE devices SET active_connections = 0")
            for item in connections:
                connection.execute(
                    """
                    INSERT INTO connections(connection_key, local_host, local_port, remote_host, remote_port, protocol, state, process_id, first_seen, last_seen, closed_at)
                    VALUES(:connection_key, :local_host, :local_port, :remote_host, :remote_port, 'tcp', 'active', :process_id, :observed_at, :observed_at, NULL)
                    ON CONFLICT(connection_key) DO UPDATE SET state = 'active', last_seen = excluded.last_seen, closed_at = NULL, process_id = excluded.process_id
                    """,
                    {**item, "observed_at": observed_at},
                )
                connection.execute(
                    """
                    INSERT INTO devices(host, first_seen, last_seen, active_connections, discovery_source)
                    VALUES(:remote_host, :observed_at, :observed_at, 1, 'local-host-telemetry')
                    ON CONFLICT(host) DO UPDATE SET last_seen = excluded.last_seen, active_connections = devices.active_connections + 1
                    """,
                    {**item, "observed_at": observed_at},
                )

    def record_neighbors(self, observed_at: int, neighbors: list[dict[str, str]]) -> None:
        """Persist passive ARP-cache observations without initiating a network scan."""
        with self._connect() as connection:
            for item in neighbors:
                connection.execute(
                    """
                    INSERT INTO devices(host, mac_address, hostname, first_seen, last_seen, active_connections, discovery_source)
                    VALUES(:host, :mac_address, :hostname, :observed_at, :observed_at, 0, :discovery_source)
                    ON CONFLICT(host) DO UPDATE SET last_seen = excluded.last_seen,
                    mac_address = CASE WHEN excluded.mac_address <> '' THEN excluded.mac_address ELSE devices.mac_address END,
                    hostname = CASE WHEN excluded.hostname <> '' THEN excluded.hostname ELSE devices.hostname END,
                    discovery_source = CASE WHEN devices.discovery_source = 'local-host-telemetry'
                    THEN 'local-host-telemetry,passive-arp-cache' ELSE devices.discovery_source END
                    """,
                    {**item, "observed_at": observed_at},
                )

    @staticmethod
    def _rows(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
        return [dict(row) for row in rows]

    def connections(self, status: str, limit: int) -> list[dict[str, Any]]:
        if status not in {"active", "closed", "all"}:
            raise ValueError("status must be active, closed, or all")
        query = "SELECT * FROM connections"
        arguments: list[Any] = []
        if status != "all":
            query += " WHERE state = ?"
            arguments.append(status)
        query += " ORDER BY last_seen DESC LIMIT ?"
        arguments.append(limit)
        with self._connect() as connection:
            return self._rows(connection.execute(query, arguments).fetchall())

    def devices(self, limit: int) -> list[dict[str, Any]]:
        with self._connect() as connection:
            return self._rows(connection.execute("SELECT * FROM devices ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall())

    def device(self, host: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            device = connection.execute("SELECT * FROM devices WHERE host = ?", (host,)).fetchone()
            if not device:
                return None
            recent = connection.execute("SELECT * FROM connections WHERE remote_host = ? ORDER BY last_seen DESC LIMIT 100", (host,)).fetchall()
        return {"device": dict(device), "connections": self._rows(recent)}

    def insights(self) -> dict[str, Any]:
        with self._connect() as connection:
            local_devices = connection.execute("SELECT COUNT(*) FROM devices WHERE discovery_source LIKE '%arp-cache%' OR discovery_source LIKE '%active-private-lan-discovery%'").fetchone()[0]
            active = connection.execute("SELECT COUNT(*) FROM connections WHERE state = 'active'").fetchone()[0]
            closed = connection.execute("SELECT COUNT(*) FROM connections WHERE state = 'closed'").fetchone()[0]
            new_devices = self._rows(connection.execute("SELECT * FROM devices WHERE discovery_source LIKE '%arp-cache%' OR discovery_source LIKE '%active-private-lan-discovery%' ORDER BY first_seen DESC LIMIT 5").fetchall())
            top_ports = self._rows(connection.execute("SELECT remote_port, COUNT(*) AS connections FROM connections WHERE remote_port IS NOT NULL GROUP BY remote_port ORDER BY connections DESC LIMIT 5").fetchall())
        return {"local_devices": local_devices, "active_connections": active, "closed_connections": closed, "new_devices": new_devices, "top_remote_ports": top_ports}
