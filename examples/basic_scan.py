#!/usr/bin/env python3
"""Basic example demonstrating arp_scanner module usage.

This script shows how to:
1. List available network interfaces
2. Scan a network for hosts
3. Process and display results
4. Handle common errors

Requirements:
    The Python interpreter needs CAP_NET_RAW capability to send raw packets:

        sudo setcap cap_net_raw+eip $(readlink -f $(which python3))

    Alternatively, run this script with sudo.
"""

import sys
import arp_scanner


def main():
    # List available interfaces
    print("Available network interfaces:")
    interfaces = arp_scanner.list_interfaces()
    for iface in interfaces:
        print(f"  - {iface}")
    print()

    # Determine which interface to scan
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    else:
        # Try to find a non-loopback interface
        non_loopback = [i for i in interfaces if i != "lo"]
        if non_loopback:
            interface = non_loopback[0]
        else:
            print("Error: No suitable network interface found.")
            print("Usage: python basic_scan.py <interface> [network]")
            sys.exit(1)

    # Optional: specify network CIDR
    network = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"Scanning on interface: {interface}")
    if network:
        print(f"Network: {network}")
    else:
        print("Network: (auto-detect from interface)")
    print()

    try:
        # Perform the scan
        hosts = arp_scanner.scan_network(
            interface=interface,
            network=network,
            timeout=3,
        )

        # Display results
        if hosts:
            print(f"Found {len(hosts)} host(s):\n")
            print(f"{'IP Address':<16} {'MAC Address':<18} {'Vendor'}")
            print("-" * 60)
            for host in hosts:
                print(f"{host.ip:<16} {host.mac:<18} {host.vendor}")
        else:
            print("No hosts found on the network.")

    except PermissionError as e:
        print(f"Permission denied: {e}")
        print()
        print("To fix this, either:")
        print("  1. Run with sudo: sudo python basic_scan.py")
        print("  2. Grant CAP_NET_RAW to Python:")
        print("     sudo setcap cap_net_raw+eip $(readlink -f $(which python3))")
        sys.exit(1)

    except ValueError as e:
        print(f"Invalid input: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
