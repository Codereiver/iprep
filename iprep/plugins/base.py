"""
Base plugin interface for IP reputation and geolocation services.

This module defines the standard interface that all plugins must implement
to ensure consistency across different data sources.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from enum import Enum
import time


class PluginTrafficType(Enum):
    """Enumeration of plugin traffic behaviors."""
    PASSIVE = "passive"  # Only queries third-party APIs/databases about the target
    ACTIVE = "active"    # Directly contacts the target (generates traffic to target)
    
    def __str__(self):
        return self.value


class BasePlugin(ABC):
    """Base class for all IP analysis plugins."""
    
    def __init__(self, name: str, timeout: int = 10, rate_limit_delay: float = 0.0, 
                 traffic_type: PluginTrafficType = PluginTrafficType.PASSIVE):
        """
        Initialize the plugin.
        
        Args:
            name: Human-readable name of the plugin
            timeout: Request timeout in seconds
            rate_limit_delay: Delay between requests in seconds
            traffic_type: Whether plugin generates traffic to target (ACTIVE) or only queries APIs (PASSIVE)
        """
        self.name = name
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self.traffic_type = traffic_type
        self._last_request_time = 0.0
    
    @abstractmethod
    def check_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Perform IP analysis using this plugin.
        
        Args:
            ip_address: The IP address to analyze
            
        Returns:
            Dictionary containing analysis results or None if no data available
            Expected format:
            {
                'source': str,  # Plugin identifier
                'ip_address': str,  # The analyzed IP
                'geolocation': {  # Optional geolocation data
                    'country': str,
                    'country_code': str,
                    'region': str,
                    'city': str,
                    'latitude': float,
                    'longitude': float,
                    'timezone': str,
                    'accuracy_radius': int
                },
                'reputation': {  # Optional reputation data
                    'is_malicious': bool,
                    'threat_types': List[str],
                    'confidence_score': float,  # 0.0 to 1.0
                    'last_seen': str  # ISO date string
                },
                'metadata': {  # Optional metadata
                    'asn': str,
                    'organization': str,
                    'isp': str,
                    'domain': str,
                    'whois': Dict[str, Any]
                }
            }
        """
        pass
    
    def _enforce_rate_limit(self):
        """Enforce rate limiting by waiting if necessary."""
        if self.rate_limit_delay > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.rate_limit_delay:
                time.sleep(self.rate_limit_delay - elapsed)
        self._last_request_time = time.time()
    
    def _handle_request_error(self, error: Exception, target: str) -> None:
        """
        Handle request errors consistently.
        
        Args:
            error: The exception that occurred
            target: The IP address or domain being processed
        """
        # Import here to avoid circular dependency
        try:
            from ..security import security
            sanitized_error = security.sanitize_error_message(str(error), target)
            print(f"Error in {self.name} plugin for target {target}: {sanitized_error}")
        except ImportError:
            # Fallback if security module not available
            print(f"Error in {self.name} plugin: Request failed")
    
    def is_available(self) -> bool:
        """
        Check if the plugin service is available.
        
        Returns:
            True if service is available, False otherwise
        """
        return True
    
    def is_passive(self) -> bool:
        """
        Check if this is a passive plugin (only queries APIs about target).
        
        Returns:
            True if passive, False if active
        """
        return self.traffic_type == PluginTrafficType.PASSIVE
    
    def is_active(self) -> bool:
        """
        Check if this is an active plugin (directly contacts target).
        
        Returns:
            True if active, False if passive
        """
        return self.traffic_type == PluginTrafficType.ACTIVE
    
    def get_traffic_description(self) -> str:
        """
        Get a human-readable description of the plugin's traffic behavior.
        
        Returns:
            Description string
        """
        if self.is_passive():
            return "Queries third-party APIs/databases about the target (no direct target contact)"
        else:
            return "Directly contacts the target (generates network traffic to target)"


class GeolocationPlugin(BasePlugin):
    """Base class for geolocation-specific plugins."""
    
    def __init__(self, name: str, timeout: int = 10, rate_limit_delay: float = 0.0):
        """Initialize geolocation plugin (typically passive)."""
        super().__init__(name, timeout, rate_limit_delay, PluginTrafficType.PASSIVE)
    
    @abstractmethod
    def get_geolocation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get geolocation data for an IP address.
        
        Args:
            ip_address: The IP address to locate
            
        Returns:
            Geolocation data dictionary or None
        """
        pass
    
    def check_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Implementation of base check_ip method for geolocation plugins."""
        geo_data = self.get_geolocation(ip_address)
        if geo_data is not None:
            return {
                'source': self.name,
                'ip_address': ip_address,
                'geolocation': geo_data
            }
        return None


class ReputationPlugin(BasePlugin):
    """Base class for reputation-specific plugins."""
    
    def __init__(self, name: str, timeout: int = 10, rate_limit_delay: float = 0.0):
        """Initialize reputation plugin (typically passive)."""
        super().__init__(name, timeout, rate_limit_delay, PluginTrafficType.PASSIVE)
    
    @abstractmethod
    def get_reputation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get reputation data for an IP address.
        
        Args:
            ip_address: The IP address to check
            
        Returns:
            Reputation data dictionary or None
        """
        pass
    
    def check_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Implementation of base check_ip method for reputation plugins."""
        rep_data = self.get_reputation(ip_address)
        if rep_data is not None:
            return {
                'source': self.name,
                'ip_address': ip_address,
                'reputation': rep_data
            }
        return None


class DomainReputationPlugin(BasePlugin):
    """Base class for domain reputation-specific plugins."""
    
    def __init__(self, name: str, timeout: int = 10, rate_limit_delay: float = 0.0):
        """Initialize domain reputation plugin (typically passive)."""
        super().__init__(name, timeout, rate_limit_delay, PluginTrafficType.PASSIVE)
    
    @abstractmethod
    def get_domain_reputation(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Get reputation data for a domain.
        
        Args:
            domain: The domain name to check
            
        Returns:
            Reputation data dictionary or None
            Expected format:
            {
                'is_malicious': bool,
                'threat_types': List[str],
                'confidence_score': float,  # 0.0 to 1.0
                'categories': List[str],  # e.g., ['phishing', 'malware']
                'last_seen': str,  # ISO date string
                'registrar': str,
                'creation_date': str,
                'expiration_date': str
            }
        """
        pass
    
    def check_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Domain reputation plugins don't handle IP addresses."""
        return None
    
    def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Implementation of base check method for domain reputation plugins."""
        rep_data = self.get_domain_reputation(domain)
        if rep_data is not None:
            return {
                'source': self.name,
                'domain': domain,
                'domain_reputation': rep_data
            }
        return None


class DomainContentPlugin(BasePlugin):
    """Base class for domain content analysis plugins."""
    
    def __init__(self, name: str, timeout: int = 10, rate_limit_delay: float = 0.0,
                 traffic_type: PluginTrafficType = PluginTrafficType.ACTIVE):
        """Initialize domain content plugin (typically active)."""
        super().__init__(name, timeout, rate_limit_delay, traffic_type)
    
    @abstractmethod
    def analyze_domain_content(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Analyze content and technical details of a domain.
        
        Args:
            domain: The domain name to analyze
            
        Returns:
            Content analysis data dictionary or None
            Expected format:
            {
                'status_code': int,
                'title': str,
                'description': str,
                'technologies': List[str],
                'ssl_certificate': Dict[str, Any],
                'dns_records': Dict[str, List[str]],
                'content_categories': List[str],
                'language': str,
                'redirects': List[str],
                'external_links': int,
                'suspicious_content': bool
            }
        """
        pass
    
    def check_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Domain content plugins don't handle IP addresses."""
        return None
    
    def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Implementation of base check method for domain content plugins."""
        content_data = self.analyze_domain_content(domain)
        if content_data is not None:
            return {
                'source': self.name,
                'domain': domain,
                'domain_content': content_data
            }
        return None