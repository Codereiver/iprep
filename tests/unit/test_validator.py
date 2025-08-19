"""
Unit tests for IP address validator.
"""

import pytest
from iprep.validator import IPValidator


class TestIPValidator:
    """Test cases for IPValidator class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.validator = IPValidator()
    
    def test_valid_ipv4_addresses(self):
        """Test validation of valid IPv4 addresses."""
        valid_ipv4 = [
            "192.168.1.1",
            "8.8.8.8",
            "1.1.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "255.255.255.255",
            "0.0.0.0"
        ]
        
        for ip in valid_ipv4:
            assert self.validator.is_valid_ip(ip), f"IPv4 {ip} should be valid"
            assert self.validator.is_ipv4(ip), f"{ip} should be recognized as IPv4"
            assert not self.validator.is_ipv6(ip), f"{ip} should not be recognized as IPv6"
    
    def test_valid_ipv6_addresses(self):
        """Test validation of valid IPv6 addresses."""
        valid_ipv6 = [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "2001:db8:85a3::8a2e:370:7334",
            "::1",
            "::",
            "2001:db8::1",
            "fe80::1%lo0"
        ]
        
        for ip in valid_ipv6:
            assert self.validator.is_valid_ip(ip), f"IPv6 {ip} should be valid"
            assert self.validator.is_ipv6(ip), f"{ip} should be recognized as IPv6"
            assert not self.validator.is_ipv4(ip), f"{ip} should not be recognized as IPv4"
    
    def test_invalid_ip_addresses(self):
        """Test validation of invalid IP addresses."""
        invalid_ips = [
            "256.256.256.256",
            "192.168.1",
            "192.168.1.1.1",
            "not_an_ip",
            "",
            "192.168.1.256",
            "2001:0db8:85a3::8a2e::7334",
            "gggg::1",
            "192.168.1.-1"
        ]
        
        for ip in invalid_ips:
            assert not self.validator.is_valid_ip(ip), f"{ip} should be invalid"
            assert not self.validator.is_ipv4(ip), f"{ip} should not be valid IPv4"
            assert not self.validator.is_ipv6(ip), f"{ip} should not be valid IPv6"
    
    def test_ip_normalization(self):
        """Test IP address normalization."""
        test_cases = [
            ("192.168.1.1", "192.168.1.1"),
            ("  192.168.1.1  ", "192.168.1.1"),
            ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:db8:85a3::8a2e:370:7334"),
            ("::1", "::1"),
            ("::", "::")
        ]
        
        for input_ip, expected in test_cases:
            result = self.validator.normalize_ip(input_ip)
            assert result == expected, f"Normalization of {input_ip} failed"
    
    def test_normalize_invalid_ip(self):
        """Test normalization of invalid IP addresses raises ValueError."""
        invalid_ips = ["not_an_ip", "256.256.256.256", ""]
        
        for ip in invalid_ips:
            with pytest.raises(ValueError):
                self.validator.normalize_ip(ip)
    
    def test_private_ip_detection(self):
        """Test detection of private IP addresses."""
        private_ipv4 = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "127.0.0.1"
        ]
        
        public_ipv4 = [
            "8.8.8.8",
            "1.1.1.1",
            "208.67.222.222"
        ]
        
        for ip in private_ipv4:
            assert self.validator.is_private_ip(ip), f"{ip} should be private"
            assert not self.validator.is_public_ip(ip), f"{ip} should not be public"
        
        for ip in public_ipv4:
            assert not self.validator.is_private_ip(ip), f"{ip} should not be private"
            assert self.validator.is_public_ip(ip), f"{ip} should be public"
    
    def test_private_ip_invalid_raises_error(self):
        """Test that invalid IPs raise ValueError for private/public checks."""
        invalid_ips = ["not_an_ip", "256.256.256.256"]
        
        for ip in invalid_ips:
            with pytest.raises(ValueError):
                self.validator.is_private_ip(ip)
            with pytest.raises(ValueError):
                self.validator.is_public_ip(ip)
    
    def test_whitespace_handling(self):
        """Test handling of whitespace in IP addresses."""
        test_cases = [
            "  192.168.1.1  ",
            "\t192.168.1.1\n",
            " 2001:db8::1 "
        ]
        
        for ip in test_cases:
            assert self.validator.is_valid_ip(ip), f"IP with whitespace should be valid: '{ip}'"
    
    def test_edge_cases(self):
        """Test edge cases for IP validation."""
        edge_cases = [
            ("0.0.0.0", True),
            ("255.255.255.255", True),
            ("127.0.0.1", True),
            ("169.254.1.1", True),
            ("224.0.0.1", True)
        ]
        
        for ip, expected in edge_cases:
            result = self.validator.is_valid_ip(ip)
            assert result == expected, f"Edge case {ip} validation failed"