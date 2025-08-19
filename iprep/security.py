"""
Security utilities for iprep.

This module provides security-related utilities including input sanitization,
URL validation, and protection against common attacks.
"""

import re
import html
import ipaddress
import logging
from urllib.parse import urlparse, urlunparse
from typing import Optional, Set

logger = logging.getLogger(__name__)

class SecurityValidator:
    """Security validation utilities."""
    
    def __init__(self):
        """Initialize security validator."""
        # Private/internal network ranges to block
        self._private_networks = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'), 
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('127.0.0.0/8'),
            ipaddress.ip_network('169.254.0.0/16'),  # Link-local
            ipaddress.ip_network('224.0.0.0/4'),     # Multicast
            ipaddress.ip_network('::1/128'),         # IPv6 loopback
            ipaddress.ip_network('fc00::/7'),        # IPv6 private
            ipaddress.ip_network('fe80::/10'),       # IPv6 link-local
        ]
        
        # Blocked ports for SSRF protection
        self._blocked_ports: Set[int] = {
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            110,   # POP3
            143,   # IMAP
            993,   # IMAPS
            995,   # POP3S
            1433,  # SQL Server
            3306,  # MySQL
            5432,  # PostgreSQL
            6379,  # Redis
            27017, # MongoDB
        }
        
        # Allowed schemes
        self._allowed_schemes: Set[str] = {'https'}
        
    def validate_url_for_request(self, url: str, domain: str) -> tuple[bool, str]:
        """
        Validate URL for making external requests (SSRF protection).
        
        Args:
            url: URL to validate
            domain: Expected domain for validation
            
        Returns:
            Tuple of (is_valid, validated_url_or_error_message)
        """
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in self._allowed_schemes:
                return False, f"Scheme '{parsed.scheme}' not allowed. Only HTTPS is permitted."
            
            # Check hostname matches expected domain
            if not parsed.hostname:
                return False, "No hostname found in URL"
                
            # Basic domain validation
            if not self._is_domain_safe(parsed.hostname, domain):
                return False, f"Hostname '{parsed.hostname}' does not match expected domain '{domain}'"
            
            # Check for IP addresses (prevent direct IP access)
            if self._is_ip_address(parsed.hostname):
                # Allow only if it's a public IP
                if not self._is_public_ip(parsed.hostname):
                    return False, f"Private/internal IP address not allowed: {parsed.hostname}"
            
            # Check port
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            if port in self._blocked_ports:
                return False, f"Port {port} is blocked for security reasons"
            
            # Reconstruct clean URL
            clean_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                ''  # Remove fragment for security
            ))
            
            return True, clean_url
            
        except Exception as e:
            logger.warning(f"URL validation error: {e}")
            return False, f"Invalid URL format: {str(e)}"
    
    def _is_domain_safe(self, hostname: str, expected_domain: str) -> bool:
        """
        Check if hostname is safe relative to expected domain.
        
        Args:
            hostname: Hostname from URL
            expected_domain: Expected domain
            
        Returns:
            True if safe, False otherwise
        """
        # Normalize both domains
        hostname = hostname.lower().strip()
        expected_domain = expected_domain.lower().strip()
        
        # Exact match
        if hostname == expected_domain:
            return True
        
        # Allow www subdomain
        if hostname == f"www.{expected_domain}":
            return True
        
        # Prevent domain confusion attacks
        # Block domains that could be confused with the expected domain
        suspicious_patterns = [
            f"{expected_domain}.",  # Trailing dot
            f".{expected_domain}",  # Leading dot
            expected_domain.replace('.', '-'),  # Dash instead of dot
            expected_domain.replace('.', ''),   # No dot
        ]
        
        for pattern in suspicious_patterns:
            if hostname == pattern:
                return False
        
        return False  # Default to reject for security
    
    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address."""
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False
    
    def _is_public_ip(self, ip_str: str) -> bool:
        """Check if IP address is public (not private/internal)."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return not any(ip in network for network in self._private_networks)
        except ValueError:
            return False
    
    def sanitize_output_text(self, text: str, max_length: int = 1000) -> str:
        """
        Sanitize text for safe output (prevent injection attacks).
        
        Args:
            text: Text to sanitize
            max_length: Maximum allowed length
            
        Returns:
            Sanitized text
        """
        if not text:
            return ""
        
        # Truncate to maximum length
        text = str(text)[:max_length]
        
        # HTML escape to prevent XSS-like attacks in logs
        text = html.escape(text, quote=True)
        
        # Remove/replace control characters that could be used for injection
        # Keep only printable ASCII and common whitespace
        sanitized = ""
        for char in text:
            if char.isprintable() or char in {' ', '\t', '\n'}:
                sanitized += char
            else:
                sanitized += f"\\x{ord(char):02x}"  # Hex escape
        
        return sanitized
    
    def sanitize_error_message(self, error_msg: str, ip_or_domain: str) -> str:
        """
        Sanitize error messages to prevent information disclosure.
        
        Args:
            error_msg: Original error message
            ip_or_domain: IP address or domain being processed
            
        Returns:
            Sanitized error message safe for logging
        """
        # Remove potentially sensitive information
        sanitized = str(error_msg)
        
        # Remove API keys and tokens
        api_patterns = [
            r'[Aa]pi[_\s-]*[Kk]ey[:\s=]+[\w\-]{8,}',
            r'[Tt]oken[:\s=]+[\w\-]{8,}',
            r'[Aa]uthorization[:\s=]+[\w\-]{8,}',
            r'sk-[\w\d]+',  # Common API key formats
            r'Bearer\s+[\w\-]{8,}',
        ]
        
        for pattern in api_patterns:
            sanitized = re.sub(pattern, '[REDACTED]', sanitized)
        
        # Remove internal paths
        sanitized = re.sub(r'/[a-zA-Z0-9/_\-\.]+\.py', '[PATH]', sanitized)
        
        # Remove internal IP addresses (but keep the target)
        for network in ['192.168.', '10.', '172.']:
            if network not in ip_or_domain:  # Don't redact the target
                sanitized = sanitized.replace(network, '[INTERNAL_IP]')
        
        return self.sanitize_output_text(sanitized, 500)
    
    def validate_content_type(self, content_type: str) -> bool:
        """
        Validate content type for processing.
        
        Args:
            content_type: Content-Type header value
            
        Returns:
            True if safe to process, False otherwise
        """
        if not content_type:
            return False
        
        # Allow only safe content types
        safe_types = {
            'text/html',
            'text/plain',
            'application/json',
            'application/xml',
            'text/xml',
        }
        
        # Extract main content type (ignore charset, etc.)
        main_type = content_type.split(';')[0].strip().lower()
        
        return main_type in safe_types

# Global security validator instance
security = SecurityValidator()