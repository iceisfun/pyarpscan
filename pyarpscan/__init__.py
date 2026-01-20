"""Fast ARP network scanner with OUI vendor lookup.

This module provides functions to scan local network segments using ARP
and identify hosts along with their hardware vendors.

Requirements:
    Requires CAP_NET_RAW capability or root privileges to send raw packets.
    Grant capability with: sudo setcap cap_net_raw+eip $(which python3)

Example:
    >>> import pyarpscan
    >>> interfaces = pyarpscan.list_interfaces()
    >>> hosts = pyarpscan.scan_network("eth0")
    >>> for host in hosts:
    ...     print(f"{host.ip} -> {host.mac} ({host.vendor})")
"""

from pyarpscan._pyarpscan import Host, list_interfaces, scan_network

__all__ = ["Host", "list_interfaces", "scan_network"]
__version__ = "0.1.0"
