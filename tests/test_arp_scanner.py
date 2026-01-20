"""Tests for the arp_scanner module."""

import pytest
import arp_scanner


class TestListInterfaces:
    """Tests for list_interfaces function."""

    def test_returns_list(self):
        """list_interfaces should return a list."""
        result = arp_scanner.list_interfaces()
        assert isinstance(result, list)

    def test_returns_non_empty(self):
        """list_interfaces should return at least one interface (lo)."""
        result = arp_scanner.list_interfaces()
        assert len(result) > 0

    def test_contains_strings(self):
        """list_interfaces should return interface names as strings."""
        result = arp_scanner.list_interfaces()
        for iface in result:
            assert isinstance(iface, str)

    def test_contains_loopback(self):
        """list_interfaces should include the loopback interface on Linux."""
        result = arp_scanner.list_interfaces()
        assert "lo" in result


class TestHostClass:
    """Tests for Host class."""

    def test_host_attributes_exist(self):
        """Host objects from scan should have ip, mac, vendor attributes."""
        # We can't easily create Host objects directly from Python,
        # so we test that the attributes are documented and accessible
        # by checking the class has the expected attribute getters
        assert hasattr(arp_scanner.Host, "ip")
        assert hasattr(arp_scanner.Host, "mac")
        assert hasattr(arp_scanner.Host, "vendor")


class TestScanNetworkErrors:
    """Tests for scan_network error handling."""

    def test_invalid_interface_raises_value_error(self):
        """scan_network should raise ValueError for non-existent interface."""
        with pytest.raises(ValueError) as exc_info:
            arp_scanner.scan_network("nonexistent_interface_xyz123")
        assert "not found" in str(exc_info.value).lower()

    def test_invalid_cidr_raises_error(self):
        """scan_network should raise an error for invalid CIDR.

        Note: Due to validation order, this may raise PermissionError first
        if running without CAP_NET_RAW, or ValueError for invalid CIDR.
        """
        # Use loopback which exists but provide invalid CIDR
        with pytest.raises((ValueError, PermissionError)):
            arp_scanner.scan_network("lo", network="invalid_cidr")

    def test_permission_error_without_cap_net_raw(self):
        """scan_network should raise PermissionError without CAP_NET_RAW.

        Note: This test may pass if running as root or with CAP_NET_RAW.
        It verifies proper error handling when permissions are missing.
        """
        # Use loopback with explicit network to test permission handling
        # This should either succeed (if running with privileges) or raise PermissionError
        try:
            result = arp_scanner.scan_network("lo", network="127.0.0.0/8", timeout=1)
            # If we get here, we have permissions - that's fine, test passes
            assert isinstance(result, list)
        except PermissionError as e:
            # Expected when running without CAP_NET_RAW
            assert "permission" in str(e).lower() or "cap_net_raw" in str(e).lower()


class TestScanNetworkSignature:
    """Tests for scan_network function signature and defaults."""

    def test_timeout_parameter_accepts_integer(self):
        """scan_network timeout parameter should accept integers."""
        # This should raise ValueError for interface, not TypeError for timeout
        with pytest.raises(ValueError):
            arp_scanner.scan_network("nonexistent_xyz", timeout=5)

    def test_network_parameter_is_optional(self):
        """scan_network network parameter should be optional."""
        # This should raise ValueError for interface, not missing network
        with pytest.raises(ValueError):
            arp_scanner.scan_network("nonexistent_xyz")


class TestModuleAttributes:
    """Tests for module-level attributes."""

    def test_module_has_scan_network(self):
        """Module should export scan_network function."""
        assert hasattr(arp_scanner, "scan_network")
        assert callable(arp_scanner.scan_network)

    def test_module_has_list_interfaces(self):
        """Module should export list_interfaces function."""
        assert hasattr(arp_scanner, "list_interfaces")
        assert callable(arp_scanner.list_interfaces)

    def test_module_has_host_class(self):
        """Module should export Host class."""
        assert hasattr(arp_scanner, "Host")
