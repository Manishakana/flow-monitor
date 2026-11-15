from __future__ import annotations

import time
from typing import Any

import psutil

from .discovery import active_private_lan_discovery, passive_neighbors
from .storage import Repository


def human(value: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return "0 B"


class LocalTelemetryCollector:
    """Collects aggregate, local-host network metadata without packet payloads."""

    def __init__(self, repository: Repository) -> None:
        self.repository = repository
        self.previous: tuple[float, int, int] | None = None
        self.last_active_discovery = 0.0
        self.authorized_range: str | None = None

    @staticmethod
    def _address(address: Any) -> tuple[str | None, int | None]:
        if not address:
            return None, None
        return address.ip, address.port

    def _connections(self) -> list[dict[str, Any]]:
        try:
            raw = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, OSError):
            return []
        observed: list[dict[str, Any]] = []
        for item in raw:
            if item.status != "ESTABLISHED" or not item.raddr:
                continue
            local_host, local_port = self._address(item.laddr)
            remote_host, remote_port = self._address(item.raddr)
            key = f"{local_host}:{local_port}>{remote_host}:{remote_port}:{item.pid}"
            observed.append({"connection_key": key, "local_host": local_host, "local_port": local_port, "remote_host": remote_host, "remote_port": remote_port, "process_id": item.pid})
        return observed

    def snapshot(self) -> dict[str, Any]:
        now_monotonic = time.monotonic()
        now_epoch = int(time.time())
        counters = psutil.net_io_counters()
        if self.previous is None:
            inbound = outbound = 0.0
        else:
            duration = max(now_monotonic - self.previous[0], 0.1)
            inbound = max(0.0, (counters.bytes_recv - self.previous[1]) / duration)
            outbound = max(0.0, (counters.bytes_sent - self.previous[2]) / duration)
        self.previous = (now_monotonic, counters.bytes_recv, counters.bytes_sent)
        active = self._connections()
        self.repository.record_observation(now_epoch, active)
        neighbors = passive_neighbors()
        self.repository.record_neighbors(now_epoch, neighbors)
        lan_hosts = {item["host"] for item in neighbors}
        active_discovery_count = 0
        if now_monotonic - self.last_active_discovery >= 60:
            active_neighbors, self.authorized_range = active_private_lan_discovery()
            self.repository.record_neighbors(now_epoch, active_neighbors)
            lan_hosts.update(item["host"] for item in active_neighbors)
            self.last_active_discovery = now_monotonic
            active_discovery_count = len(active_neighbors)
        peer_counts: dict[str, int] = {}
        for item in active:
            peer_counts[item["remote_host"]] = peer_counts.get(item["remote_host"], 0) + 1
        interfaces = [name for name, stats in psutil.net_if_stats().items() if stats.isup]
        return {"timestamp": now_epoch, "interfaces": len(interfaces), "connections": len(active), "peers": [{"host": host, "count": count} for host, count in sorted(peer_counts.items(), key=lambda pair: pair[1], reverse=True)[:5]], "peer_count": len(peer_counts), "lan_neighbors": len(lan_hosts), "active_discovery_count": active_discovery_count, "authorized_range": self.authorized_range, "inbound": inbound, "outbound": outbound, "inbound_text": f"{human(inbound)}/s", "outbound_text": f"{human(outbound)}/s", "total_text": human(counters.bytes_recv + counters.bytes_sent)}
