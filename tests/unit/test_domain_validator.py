"""
Unit tests for domain validation functionality.
"""

import pytest
from iprep.validator import InputValidator


class TestInputValidator:
    """Test cases for InputValidator domain functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.validator = InputValidator()
    
    def test_valid_domains(self):
        """Test validation of valid domain names."""
        valid_domains = [
            'example.com',
            'subdomain.example.com',
            'test.co.uk',
            'long-domain-name.example.org',
            'numbers123.com',
            'a.com',
            'example-with-hyphens.net',
            'deep.subdomain.example.com'
        ]
        
        for domain in valid_domains:
            assert self.validator.is_valid_domain(domain), f"Domain should be valid: {domain}"
    
    def test_invalid_domains(self):
        """Test validation of invalid domain names."""
        invalid_domains = [
            '',
            'example',
            '.com',
            'example.',
            'example..com',
            '-example.com',
            'example-.com',
            'example.c',
            'spaces in domain.com',
            'http://example.com',
            'https://example.com'
        ]
        
        for domain in invalid_domains:
            assert not self.validator.is_valid_domain(domain), f"Domain should be invalid: {domain}"
    
    def test_normalize_domain(self):
        """Test domain normalization."""
        test_cases = [
            ('Example.COM', 'example.com'),
            ('SUBDOMAIN.EXAMPLE.COM', 'subdomain.example.com'),
            ('  example.com  ', 'example.com'),
            ('example.com.', 'example.com'),
            ('ExAmPlE.cOm', 'example.com')
        ]
        
        for input_domain, expected in test_cases:
            result = self.validator.normalize_domain(input_domain)
            assert result == expected, f"Normalization failed: {input_domain} -> {result} (expected {expected})"
    
    def test_is_valid_input_ip(self):
        """Test input validation for IP addresses."""
        valid_ips = [
            '192.168.1.1',
            '8.8.8.8',
            '2001:db8::1',
            '::1'
        ]
        
        for ip in valid_ips:
            assert self.validator.is_valid_input(ip), f"IP should be valid input: {ip}"
    
    def test_is_valid_input_domain(self):
        """Test input validation for domain names."""
        valid_domains = [
            'example.com',
            'subdomain.example.org',
            'test.co.uk'
        ]
        
        for domain in valid_domains:
            assert self.validator.is_valid_input(domain), f"Domain should be valid input: {domain}"
    
    def test_is_valid_input_invalid(self):
        """Test input validation for invalid inputs."""
        invalid_inputs = [
            '',
            'invalid',
            'not-a-domain-or-ip',
            '999.999.999.999',
            'http://example.com'
        ]
        
        for invalid_input in invalid_inputs:
            assert not self.validator.is_valid_input(invalid_input), f"Input should be invalid: {invalid_input}"
    
    def test_domain_edge_cases(self):
        """Test edge cases for domain validation."""
        # International domain names (basic ASCII test)
        assert self.validator.is_valid_domain('test.xn--fiqs8s')  # Chinese TLD
        
        # Very short domains
        assert self.validator.is_valid_domain('a.co')
        
        # Numeric domains
        assert self.validator.is_valid_domain('123.com')
        
        # Mixed case with numbers and hyphens
        assert self.validator.is_valid_domain('Test-123.Example.COM')
    
    def test_normalize_edge_cases(self):
        """Test edge cases for domain normalization."""
        # Multiple trailing dots
        assert self.validator.normalize_domain('example.com...') == 'example.com'
        
        # Mixed whitespace
        assert self.validator.normalize_domain('\t  example.com \n ') == 'example.com'
        
        # Empty string
        assert self.validator.normalize_domain('') == ''
        
        # Only whitespace
        assert self.validator.normalize_domain('   ') == ''