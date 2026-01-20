# pyarpscan

A fast ARP network scanner Python module written in Rust. It discovers hosts on local IPv4 networks using ARP requests and identifies device vendors via an embedded OUI database.

## Features

- **Fast ARP Scanning**: Scans entire IPv4 CIDR ranges efficiently
- **Layer 2 Operation**: Discovers hosts directly via ARP, no ICMP/ping required
- **Vendor Lookup**: Identifies device manufacturers using an embedded OUI database
- **Auto-detection**: Automatically detects network range from interface if not specified
- **GIL Release**: Network operations release Python's GIL for better concurrency

## Requirements

- Linux (uses raw sockets via `pnet`)
- Python 3.8+
- `CAP_NET_RAW` capability or root privileges

## Installation

### From source (requires Rust toolchain)

```bash
pip install maturin
maturin develop --release
```

### Setting up permissions

The module requires raw socket access. Choose one of these options:

**Option 1: Grant CAP_NET_RAW to Python** (recommended for development)
```bash
sudo setcap cap_net_raw+eip $(readlink -f $(which python3))
```

**Option 2: Run with sudo**
```bash
sudo python your_script.py
```

## Quick Start

```python
import pyarpscan

# List available network interfaces
interfaces = pyarpscan.list_interfaces()
print(f"Interfaces: {interfaces}")

# Scan a network (auto-detect network from interface)
hosts = pyarpscan.scan_network("eth0")
for host in hosts:
    print(f"{host.ip} -> {host.mac} ({host.vendor})")

# Scan a specific network range with custom timeout
hosts = pyarpscan.scan_network("eth0", network="192.168.1.0/24", timeout=5)
```

## API Reference

### `scan_network(interface, network=None, timeout=3)`

Scan a network for hosts using ARP.

**Parameters:**
- `interface` (str): Network interface name (e.g., "eth0", "enp3s0")
- `network` (str, optional): CIDR network to scan (e.g., "192.168.1.0/24"). If not provided, auto-detects from the interface.
- `timeout` (int): Seconds to wait for ARP replies (default: 3)

**Returns:**
- `list[Host]`: List of discovered hosts

**Raises:**
- `PermissionError`: If CAP_NET_RAW capability is missing
- `ValueError`: If interface not found or invalid network CIDR

### `list_interfaces()`

List available network interfaces.

**Returns:**
- `list[str]`: Names of available network interfaces

### `Host`

Represents a discovered host on the network.

**Attributes:**
- `ip` (str): IPv4 address (e.g., "192.168.1.100")
- `mac` (str): MAC address in colon-separated format (e.g., "aa:bb:cc:dd:ee:ff")
- `vendor` (str): Hardware vendor name from OUI lookup, or "Unknown"

## Example Output

```python
>>> import pyarpscan
>>> hosts = pyarpscan.scan_network("eth0", timeout=2)
>>> for h in hosts:
...     print(h)
192.168.1.1 at 74:4d:28:aa:bb:cc (Routerboard.com)
192.168.1.32 at cc:88:26:dd:ee:ff (LG Innotek)
192.168.1.45 at 3c:7c:3f:11:22:33 (ASUSTek COMPUTER INC.)
```

## Limitations

- **IPv4 Only**: Does not support IPv6 or Neighbor Discovery Protocol
- **Same Broadcast Domain**: Must be on the same L2 network segment as targets
- **Requires Privileges**: Needs `CAP_NET_RAW` or root access
- **Static OUI Database**: Vendor mapping is compiled into the module

## Development

### Running tests

```bash
# Rust tests
cargo test

# Python tests (requires module to be built)
maturin develop
pytest tests/
```

### Building

```bash
# Development build
maturin develop

# Release build
maturin build --release
```

## Vendor Data

The OUI database is embedded at build time from `data/mac-vendors-export.csv`. To update the vendor list, replace this file with a newer version and rebuild.

Data source: [maclookup.app](https://maclookup.app/downloads/csv-database) (derived from IEEE OUI public registry)
