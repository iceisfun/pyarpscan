//! Fast ARP network scanner with OUI vendor lookup.
//!
//! This module provides functions to scan local network segments using ARP
//! (Address Resolution Protocol) and identify hosts along with their
//! hardware vendors via OUI (Organizationally Unique Identifier) lookup.
//!
//! # Requirements
//!
//! This module requires the `CAP_NET_RAW` capability to send raw network packets.
//! You can grant this capability to the Python interpreter:
//!
//! ```bash
//! sudo setcap cap_net_raw+eip $(readlink -f $(which python3))
//! ```
//!
//! Alternatively, run your script with `sudo`.
//!
//! # Example
//!
//! ```python
//! import arp_scanner
//!
//! # List available interfaces
//! interfaces = arp_scanner.list_interfaces()
//! print(f"Available interfaces: {interfaces}")
//!
//! # Scan a network (auto-detect network from interface)
//! hosts = arp_scanner.scan_network("eth0")
//! for host in hosts:
//!     print(f"{host.ip} -> {host.mac} ({host.vendor})")
//!
//! # Scan a specific network range
//! hosts = arp_scanner.scan_network("eth0", network="192.168.1.0/24", timeout=5)
//! ```

use pnet::datalink::{self, Channel::Ethernet, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use pnet::ipnetwork::IpNetwork;
use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, Instant};
use cidr::Ipv4Cidr;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use pyo3::exceptions::{PyPermissionError, PyValueError};

// Static OUI database, generated at build time
include!(concat!(env!("OUT_DIR"), "/oui_table.rs"));

/// A discovered host on the network.
///
/// Represents a single host discovered during an ARP scan, containing
/// its IP address, MAC address, and vendor information.
///
/// Attributes:
///     ip (str): The IPv4 address of the host (e.g., "192.168.1.100").
///     mac (str): The MAC address in colon-separated format (e.g., "aa:bb:cc:dd:ee:ff").
///     vendor (str): The hardware vendor name based on OUI lookup, or "Unknown" if not found.
#[pyclass]
#[derive(Clone)]
pub struct Host {
    /// The IPv4 address of the discovered host
    #[pyo3(get)]
    pub ip: String,
    /// The MAC address of the discovered host
    #[pyo3(get)]
    pub mac: String,
    /// The vendor name from OUI lookup
    #[pyo3(get)]
    pub vendor: String,
}

#[pymethods]
impl Host {
    fn __repr__(&self) -> String {
        format!("Host(ip='{}', mac='{}', vendor='{}')", self.ip, self.mac, self.vendor)
    }

    fn __str__(&self) -> String {
        format!("{} at {} ({})", self.ip, self.mac, self.vendor)
    }
}

/// Scan error types
#[derive(Debug)]
pub enum ScanError {
    InterfaceNotFound(String),
    NoMacAddress(String),
    NoIpv4Address(String),
    InvalidNetwork(String),
    ChannelError(String),
    PermissionDenied(String),
}

impl From<ScanError> for PyErr {
    fn from(err: ScanError) -> PyErr {
        match err {
            ScanError::InterfaceNotFound(msg) => PyValueError::new_err(msg),
            ScanError::NoMacAddress(msg) => PyValueError::new_err(msg),
            ScanError::NoIpv4Address(msg) => PyValueError::new_err(msg),
            ScanError::InvalidNetwork(msg) => PyValueError::new_err(msg),
            ScanError::ChannelError(msg) => PyPermissionError::new_err(msg),
            ScanError::PermissionDenied(msg) => PyPermissionError::new_err(msg),
        }
    }
}

fn normalize_mac_prefix(mac: MacAddr) -> u32 {
    ((mac.0 as u32) << 16) | ((mac.1 as u32) << 8) | (mac.2 as u32)
}

fn send_arp(
    tx: &mut Box<dyn DataLinkSender>,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    iface: &NetworkInterface,
) {
    let mut buf = [0u8; 42];

    let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
    eth.set_destination(MacAddr::broadcast());
    eth.set_source(source_mac);
    eth.set_ethertype(EtherTypes::Arp);

    {
        let mut arp = MutableArpPacket::new(eth.payload_mut()).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(source_mac);
        arp.set_sender_proto_addr(source_ip);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(target_ip);
    }

    let _ = tx.send_to(eth.packet(), Some(iface.clone()));
}

fn listen_replies(
    mut rx: Box<dyn DataLinkReceiver>,
    timeout: u64,
    hosts: Arc<Mutex<Vec<Host>>>,
) {
    let oui_map: HashMap<u32, &str> = OUI_TABLE.iter().cloned().collect();
    let start = Instant::now();

    while start.elapsed() < Duration::from_secs(timeout) {
        match rx.next() {
            Ok(pkt) => {
                if let Some(eth) = EthernetPacket::new(pkt) {
                    if eth.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = ArpPacket::new(eth.payload()) {
                            if arp.get_operation() == ArpOperations::Reply {
                                let sender_mac = arp.get_sender_hw_addr();
                                let prefix = normalize_mac_prefix(sender_mac);

                                let vendor = oui_map
                                    .get(&prefix)
                                    .copied()
                                    .unwrap_or("Unknown");

                                let ip_str = arp.get_sender_proto_addr().to_string();
                                let mac_str = sender_mac.to_string();

                                let mut hosts_list = hosts.lock().unwrap();
                                hosts_list.push(Host {
                                    ip: ip_str,
                                    mac: mac_str,
                                    vendor: vendor.to_string(),
                                });
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }
    }
}

/// Core scanning function (Rust API)
pub fn scan_network_impl(
    interface: &str,
    network: Option<&str>,
    timeout: u64,
) -> Result<Vec<Host>, ScanError> {
    // Find interface
    let iface = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == interface)
        .ok_or_else(|| ScanError::InterfaceNotFound(format!("Interface '{}' not found", interface)))?;

    let source_mac = iface.mac
        .ok_or_else(|| ScanError::NoMacAddress(format!("Interface '{}' has no MAC address", interface)))?;

    // Auto-detect network if not provided
    let network_str = match network {
        Some(n) => n.to_string(),
        None => {
            iface.ips
                .iter()
                .find_map(|ip| match ip {
                    IpNetwork::V4(v4net) => {
                        let net_addr: Ipv4Addr = v4net.network();
                        let prefix = v4net.prefix();
                        Ipv4Cidr::new(net_addr, prefix)
                            .ok()
                            .map(|c| c.to_string())
                    }
                    _ => None,
                })
                .ok_or_else(|| ScanError::NoIpv4Address(format!("Interface '{}' has no IPv4 network", interface)))?
        }
    };

    let source_ip = iface.ips
        .iter()
        .find_map(|ip| match ip.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .ok_or_else(|| ScanError::NoIpv4Address(format!("Interface '{}' has no IPv4 address", interface)))?;

    // Open datalink channel
    let (mut tx, rx) = match datalink::channel(&iface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(ScanError::ChannelError("Unhandled channel type".to_string())),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("permission") || msg.contains("Operation not permitted") {
                return Err(ScanError::PermissionDenied(
                    format!("Permission denied opening raw socket. Ensure CAP_NET_RAW capability: {}", msg)
                ));
            }
            return Err(ScanError::ChannelError(format!("Failed to open datalink channel: {}", msg)));
        }
    };

    // Parse CIDR
    let cidr: Ipv4Cidr = network_str.parse()
        .map_err(|_| ScanError::InvalidNetwork(format!("Invalid CIDR: {}", network_str)))?;

    // Spawn listener thread
    let hosts: Arc<Mutex<Vec<Host>>> = Arc::new(Mutex::new(Vec::new()));
    let hosts_for_thread = Arc::clone(&hosts);
    let listener = thread::spawn(move || listen_replies(rx, timeout, hosts_for_thread));

    // Send ARP requests
    for target_ip in cidr.iter().map(|inet| inet.address()) {
        if target_ip == source_ip {
            continue;
        }
        send_arp(&mut tx, source_mac, source_ip, target_ip, &iface);
        thread::sleep(Duration::from_millis(2));
    }

    // Wait for listener
    listener.join().unwrap();

    // Return results
    let result = hosts.lock().unwrap().clone();
    Ok(result)
}

/// Scan a network for hosts using ARP
///
/// Args:
///     interface: Network interface name (e.g., "eth0", "vlan.99")
///     network: CIDR network to scan (e.g., "192.168.1.0/24"). If None, auto-detect from interface.
///     timeout: Seconds to wait for ARP replies (default: 3)
///
/// Returns:
///     List of Host objects found on the network
///
/// Raises:
///     PermissionError: If CAP_NET_RAW capability is missing
///     ValueError: If interface not found or invalid network
///     RuntimeError: For other scanning errors
#[pyfunction]
#[pyo3(signature = (interface, network=None, timeout=3))]
fn scan_network(
    py: Python<'_>,
    interface: &str,
    network: Option<&str>,
    timeout: u64,
) -> PyResult<Vec<Host>> {
    // Release the GIL during the blocking network scan
    py.allow_threads(|| {
        scan_network_impl(interface, network, timeout)
            .map_err(|e| e.into())
    })
}

/// List available network interfaces.
///
/// Returns a list of network interface names available on the system.
/// Use these names with `scan_network()` to specify which interface to scan from.
///
/// Returns:
///     list[str]: Names of available network interfaces (e.g., ["lo", "eth0", "wlan0"]).
///
/// Example:
///     >>> import arp_scanner
///     >>> interfaces = arp_scanner.list_interfaces()
///     >>> print(interfaces)
///     ['lo', 'eth0', 'wlan0']
#[pyfunction]
fn list_interfaces() -> Vec<String> {
    datalink::interfaces()
        .into_iter()
        .map(|i| i.name)
        .collect()
}

/// Fast ARP network scanner with OUI vendor lookup.
///
/// This module provides functions to scan local network segments using ARP
/// and identify hosts along with their hardware vendors.
///
/// Requirements:
///     Requires CAP_NET_RAW capability or root privileges to send raw packets.
///     Grant capability with: sudo setcap cap_net_raw+eip $(which python3)
///
/// Functions:
///     scan_network: Scan a network for hosts using ARP
///     list_interfaces: List available network interfaces
///
/// Classes:
///     Host: Represents a discovered host with ip, mac, and vendor attributes
#[pymodule]
fn arp_scanner(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Host>()?;
    m.add_function(wrap_pyfunction!(scan_network, m)?)?;
    m.add_function(wrap_pyfunction!(list_interfaces, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_mac_prefix() {
        // Test MAC prefix extraction from MacAddr
        let mac = MacAddr(0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33);
        let prefix = normalize_mac_prefix(mac);
        // Expected: (0xAA << 16) | (0xBB << 8) | 0xCC = 0xAABBCC
        assert_eq!(prefix, 0xAABBCC);
    }

    #[test]
    fn test_normalize_mac_prefix_zeros() {
        let mac = MacAddr(0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF);
        let prefix = normalize_mac_prefix(mac);
        assert_eq!(prefix, 0x000000);
    }

    #[test]
    fn test_normalize_mac_prefix_max() {
        let mac = MacAddr(0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00);
        let prefix = normalize_mac_prefix(mac);
        assert_eq!(prefix, 0xFFFFFF);
    }

    #[test]
    fn test_oui_lookup() {
        // Verify OUI_TABLE is accessible and searchable
        let oui_map: HashMap<u32, &str> = OUI_TABLE.iter().cloned().collect();
        // The table should have entries
        assert!(!oui_map.is_empty());
    }

    #[test]
    fn test_scan_error_interface_not_found() {
        let err = ScanError::InterfaceNotFound("test0".to_string());
        let msg = format!("{:?}", err);
        assert!(msg.contains("test0"));
    }

    #[test]
    fn test_scan_error_invalid_network() {
        let err = ScanError::InvalidNetwork("bad_cidr".to_string());
        let msg = format!("{:?}", err);
        assert!(msg.contains("bad_cidr"));
    }

    #[test]
    fn test_host_repr() {
        let host = Host {
            ip: "192.168.1.1".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            vendor: "TestVendor".to_string(),
        };
        let repr = host.__repr__();
        assert!(repr.contains("192.168.1.1"));
        assert!(repr.contains("aa:bb:cc:dd:ee:ff"));
        assert!(repr.contains("TestVendor"));
    }

    #[test]
    fn test_host_str() {
        let host = Host {
            ip: "10.0.0.1".to_string(),
            mac: "11:22:33:44:55:66".to_string(),
            vendor: "Acme Corp".to_string(),
        };
        let s = host.__str__();
        assert!(s.contains("10.0.0.1"));
        assert!(s.contains("11:22:33:44:55:66"));
        assert!(s.contains("Acme Corp"));
    }

    #[test]
    fn test_scan_nonexistent_interface() {
        let result = scan_network_impl("nonexistent_iface_xyz123", None, 1);
        assert!(result.is_err());
        match result {
            Err(ScanError::InterfaceNotFound(_)) => {}
            _ => panic!("Expected InterfaceNotFound error"),
        }
    }
}
