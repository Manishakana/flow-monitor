"""Passive, local-network neighbor discovery. No probes are sent."""
from __future__ import annotations

import re
import subprocess
import ipaddress
import platform
import time
import socket
from concurrent.futures import ThreadPoolExecutor

import psutil


_IPV4 = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
_MAC = re.compile(r"\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", re.IGNORECASE)


def _command() -> list[str]:
    return ["arp", "-a"]


def passive_neighbors() -> list[dict[str, str]]:
    """Return neighbors already present in the operating system ARP cache."""
    try:
        result = subprocess.run(_command(), capture_output=True, text=True, timeout=4, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    devices: dict[str, dict[str, str]] = {}
    for line in result.stdout.splitlines():
        ip = _IPV4.search(line)
        if not ip or ip.group() in {"0.0.0.0", "255.255.255.255"}:
            continue
        mac = _MAC.search(line)
        devices[ip.group()] = {"host": ip.group(), "mac_address": mac.group().replace("-", ":").lower() if mac else "", "hostname": "", "discovery_source": "passive-arp-cache"}
    return list(devices.values())


def _private_local_subnet() -> ipaddress.IPv4Network | None:
    """Return a bounded /24 discovery range for the current private LAN."""
    for addresses in psutil.net_if_addrs().values():
        for address in addresses:
            if address.family.name != "AF_INET" or not address.netmask:
                continue
            host = ipaddress.ip_address(address.address)
            if not host.is_private or host.is_loopback:
                continue
            # Deliberately bound discovery to 254 addresses, even on larger networks.
            return ipaddress.ip_network(f"{host}/24", strict=False)
    return None


def _ping(host: str) -> str | None:
    command = ["ping", "-n", "1", "-w", "300", host] if platform.system() == "Windows" else ["ping", "-c", "1", "-W", "1", host]
    try:
        result = subprocess.run(command, capture_output=True, timeout=2, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return host if result.returncode == 0 else None


def active_private_lan_discovery() -> tuple[list[dict[str, str]], str | None]:
    """Rate-controlled ICMP discovery limited to the current private /24 LAN."""
    subnet = _private_local_subnet()
    if subnet is None:
        return [], None
    hosts = [str(host) for host in subnet.hosts()]
    with ThreadPoolExecutor(max_workers=20) as pool:
        responding = {host for host in pool.map(_ping, hosts) if host}
    by_host = {item["host"]: item for item in passive_neighbors()}
    discovered = []
    for host in responding:
        try:
            hostname = socket.gethostbyaddr(host)[0]
        except (OSError, socket.herror):
            hostname = ""
        item = by_host.get(host, {"host": host, "mac_address": "", "hostname": hostname, "discovery_source": "active-private-lan-discovery"})
        item.setdefault("hostname", hostname)
        item["discovery_source"] = "active-private-lan-discovery"
        discovered.append(item)
    return discovered, str(subnet)
