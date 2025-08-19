"""
Input validation utilities.

This module provides validation functionality for IPv4 and IPv6 addresses
and domain names to ensure input sanitization before processing.
"""

import ipaddress
import re
from typing import Union


class InputValidator:
    """Validator for IP addresses and domain names."""
    
    def is_valid_ip(self, ip_string: str) -> bool:
        """
        Validate if a string represents a valid IP address.
        
        Args:
            ip_string: String representation of an IP address
            
        Returns:
            True if valid IPv4 or IPv6 address, False otherwise
        """
        try:
            ipaddress.ip_address(ip_string.strip())
            return True
        except ValueError:
            return False
    
    def is_ipv4(self, ip_string: str) -> bool:
        """
        Check if string represents a valid IPv4 address.
        
        Args:
            ip_string: String representation of an IP address
            
        Returns:
            True if valid IPv4 address, False otherwise
        """
        try:
            ipaddress.IPv4Address(ip_string.strip())
            return True
        except ValueError:
            return False
    
    def is_ipv6(self, ip_string: str) -> bool:
        """
        Check if string represents a valid IPv6 address.
        
        Args:
            ip_string: String representation of an IP address
            
        Returns:
            True if valid IPv6 address, False otherwise
        """
        try:
            ipaddress.IPv6Address(ip_string.strip())
            return True
        except ValueError:
            return False
    
    def normalize_ip(self, ip_string: str) -> str:
        """
        Normalize IP address to standard format.
        
        Args:
            ip_string: String representation of an IP address
            
        Returns:
            Normalized IP address string
            
        Raises:
            ValueError: If IP address is invalid
        """
        try:
            ip_obj = ipaddress.ip_address(ip_string.strip())
            return str(ip_obj)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {ip_string}") from e
    
    def is_private_ip(self, ip_string: str) -> bool:
        """
        Check if IP address is in private address space.
        
        Args:
            ip_string: String representation of an IP address
            
        Returns:
            True if private IP address, False otherwise
            
        Raises:
            ValueError: If IP address is invalid
        """
        try:
            ip_obj = ipaddress.ip_address(ip_string.strip())
            return ip_obj.is_private
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {ip_string}") from e
    
    def is_public_ip(self, ip_string: str) -> bool:
        """
        Check if IP address is in public address space.
        
        Args:
            ip_string: String representation of an IP address
            
        Returns:
            True if public IP address, False otherwise
            
        Raises:
            ValueError: If IP address is invalid
        """
        try:
            ip_obj = ipaddress.ip_address(ip_string.strip())
            return not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_reserved
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {ip_string}") from e
    
    def is_valid_domain(self, domain_string: str) -> bool:
        """
        Validate if a string represents a valid domain name.
        
        Args:
            domain_string: String representation of a domain name
            
        Returns:
            True if valid domain name, False otherwise
        """
        if not domain_string or len(domain_string.strip()) == 0:
            return False
        
        domain = domain_string.strip().lower()
        
        # Basic length checks
        if len(domain) > 253 or len(domain) < 1:
            return False
        
        # Remove trailing dot if present
        if domain.endswith('.'):
            domain = domain[:-1]
        
        # Check if it's an IP address (not a domain)
        if self.is_valid_ip(domain):
            return False
        
        # Domain name regex pattern
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        if not domain_pattern.match(domain):
            return False
        
        # Check each label length (max 63 characters) and validity
        labels = domain.split('.')
        for label in labels:
            if len(label) > 63 or len(label) == 0:
                return False
            # Check for all-numeric labels that look like IP octets
            if label.isdigit() and int(label) > 255:
                return False
        
        # Must have at least one dot (except for single-label domains like localhost)
        if '.' not in domain and domain not in ['localhost']:
            return False
        
        # Reject domains that look like IP addresses with invalid octets
        if '.' in domain:
            parts = domain.split('.')
            if len(parts) == 4 and all(part.isdigit() for part in parts):
                # This looks like an IP address, reject it
                return False
        
        # Check TLD length (must be at least 2 characters)
        if '.' in domain:
            tld = domain.split('.')[-1]
            if len(tld) < 2:
                return False
            # TLD should not be all numeric
            if tld.isdigit():
                return False
        
        # Check for invalid characters and patterns
        if '..' in domain_string or domain_string.startswith('.') or domain_string.endswith('..'):
            return False
        
        # Check for URL schemes
        if '://' in domain_string:
            return False
        
        # Check for spaces
        if ' ' in domain_string:
            return False
        
        return True
    
    def normalize_domain(self, domain_string: str) -> str:
        """
        Normalize domain name to standard format.
        
        Args:
            domain_string: String representation of a domain name
            
        Returns:
            Normalized domain name string
            
        Raises:
            ValueError: If domain name is invalid
        """
        if not domain_string or len(domain_string.strip()) == 0:
            return ''
        
        domain = domain_string.strip().lower()
        
        # Remove multiple trailing dots
        while domain.endswith('.'):
            domain = domain[:-1]
        
        # If domain is empty after cleaning, return empty string
        if not domain:
            return ''
        
        # Only validate if we have something to validate
        if not self.is_valid_domain(domain):
            raise ValueError(f"Invalid domain name: {domain_string}")
        
        return domain
    
    def is_valid_input(self, input_string: str) -> bool:
        """
        Determine if input is a valid IP address or domain name.
        
        Args:
            input_string: String to validate
            
        Returns:
            True if valid IP address or domain name, False otherwise
        """
        if not input_string or len(input_string.strip()) == 0:
            return False
        
        input_string = input_string.strip()
        
        return self.is_valid_ip(input_string) or self.is_valid_domain(input_string)
    
    def get_input_type(self, input_string: str) -> str:
        """
        Determine the type of input (IP address or domain name).
        
        Args:
            input_string: String to classify
            
        Returns:
            'ip' if valid IP address, 'domain' if valid domain, 'invalid' if neither
        """
        if not input_string or len(input_string.strip()) == 0:
            return 'invalid'
        
        input_string = input_string.strip()
        
        if self.is_valid_ip(input_string):
            return 'ip'
        elif self.is_valid_domain(input_string):
            return 'domain'
        else:
            return 'invalid'


# Keep the old class name for backward compatibility
class IPValidator(InputValidator):
    """Backward compatibility alias for InputValidator."""
    pass