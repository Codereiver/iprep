"""
Secure configuration management for iprep.

This module provides secure handling of configuration values including
API keys, endpoints, and other sensitive data.
"""

import os
import logging
from typing import Optional, Dict, Any
from pathlib import Path

# Set up logging for security events
logger = logging.getLogger(__name__)

class SecureConfig:
    """Secure configuration manager for sensitive data."""
    
    def __init__(self):
        """Initialize secure configuration manager."""
        self._config_cache: Dict[str, Any] = {}
        self._sensitive_keys = {
            'abuseipdb_api_key', 'virustotal_api_key', 'urlvoid_api_key',
            'ipinfo_token', 'api_key', 'token', 'secret'
        }
        
    def get_api_key(self, service: str) -> Optional[str]:
        """
        Securely retrieve API key for a service.
        
        Args:
            service: Service name (e.g., 'abuseipdb', 'virustotal')
            
        Returns:
            API key if available, None otherwise
        """
        env_var = f"IPREP_{service.upper()}_API_KEY"
        api_key = os.getenv(env_var)
        
        if api_key:
            # Validate API key format (basic validation)
            if self._validate_api_key_format(api_key, service):
                logger.info(f"API key loaded for service: {service}")
                return api_key.strip()
            else:
                logger.warning(f"Invalid API key format for service: {service}")
                return None
        
        # Try alternative environment variable names
        alt_names = self._get_alternative_env_names(service)
        for alt_name in alt_names:
            api_key = os.getenv(alt_name)
            if api_key and self._validate_api_key_format(api_key, service):
                logger.info(f"API key loaded for service: {service} (via {alt_name})")
                return api_key.strip()
        
        logger.debug(f"No API key found for service: {service}")
        return None
    
    def get_config_value(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value with caching.
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        if key in self._config_cache:
            return self._config_cache[key]
        
        # Try environment variable
        env_key = f"IPREP_{key.upper()}"
        value = os.getenv(env_key, default)
        
        # Cache non-sensitive values
        if not any(sensitive in key.lower() for sensitive in self._sensitive_keys):
            self._config_cache[key] = value
        
        return value
    
    def _validate_api_key_format(self, api_key: str, service: str) -> bool:
        """
        Validate API key format for security.
        
        Args:
            api_key: The API key to validate
            service: Service name for service-specific validation
            
        Returns:
            True if format is valid, False otherwise
        """
        if not api_key or not api_key.strip():
            return False
        
        # Basic validation - no whitespace, reasonable length
        api_key = api_key.strip()
        if len(api_key) < 8 or len(api_key) > 128:
            return False
        
        # Check for suspicious patterns
        if any(char in api_key for char in [' ', '\t', '\n', '\r']):
            return False
        
        # Service-specific validation
        service_validators = {
            'abuseipdb': lambda k: len(k) >= 20 and len(k) <= 80,
            'virustotal': lambda k: len(k) >= 32 and len(k) <= 64,
            'urlvoid': lambda k: len(k) >= 10 and len(k) <= 50,
        }
        
        validator = service_validators.get(service.lower())
        if validator:
            return validator(api_key)
        
        return True  # Default to valid for unknown services
    
    def _get_alternative_env_names(self, service: str) -> list:
        """
        Get alternative environment variable names for a service.
        
        Args:
            service: Service name
            
        Returns:
            List of alternative environment variable names
        """
        alternatives = {
            'abuseipdb': ['ABUSEIPDB_API_KEY', 'ABUSE_IP_DB_KEY'],
            'virustotal': ['VIRUSTOTAL_API_KEY', 'VT_API_KEY'],
            'urlvoid': ['URLVOID_API_KEY', 'UV_API_KEY'],
            'ipinfo': ['IPINFO_TOKEN', 'IPINFO_API_KEY'],
        }
        
        return alternatives.get(service.lower(), [])
    
    def get_endpoint_url(self, service: str, endpoint_type: str = 'primary') -> Optional[str]:
        """
        Get secure endpoint URL for a service.
        
        Args:
            service: Service name
            endpoint_type: Type of endpoint (primary, backup, etc.)
            
        Returns:
            HTTPS URL if available, None otherwise
        """
        endpoints = {
            'abuseipdb': {
                'primary': 'https://api.abuseipdb.com/api/v2/check',
            },
            'ipapi': {
                'primary': 'https://ipapi.co/json',  # Use HTTPS version
                'backup': 'https://ip-api.com/json',  # Alternative HTTPS endpoint
            },
            'ipinfo': {
                'primary': 'https://ipinfo.io',
            },
            'urlvoid': {
                'primary': 'https://api.urlvoid.com/v1/scan',
            },
            'virustotal': {
                'primary': 'https://www.virustotal.com/vtapi/v2/domain/report',
            }
        }
        
        service_endpoints = endpoints.get(service.lower(), {})
        url = service_endpoints.get(endpoint_type)
        
        # Ensure all URLs use HTTPS
        if url and not url.startswith('https://'):
            logger.warning(f"Non-HTTPS endpoint configured for {service}: {url}")
            return None
        
        return url
    
    def is_development_mode(self) -> bool:
        """
        Check if running in development mode.
        
        Returns:
            True if in development mode, False otherwise
        """
        return os.getenv('IPREP_DEV_MODE', '').lower() in ('1', 'true', 'yes')
    
    def allow_active_plugins(self) -> bool:
        """
        Check if active plugins (that contact targets directly) are allowed.
        
        Returns:
            True if active plugins are allowed, False otherwise
        """
        # Check environment variable (default: False for security/privacy)
        env_value = os.getenv('IPREP_ALLOW_ACTIVE_PLUGINS', 'false').lower()
        return env_value in ('1', 'true', 'yes', 'on')
    
    def get_allowed_traffic_types(self) -> list:
        """
        Get list of allowed plugin traffic types.
        
        Returns:
            List of allowed traffic types ('passive', 'active')
        """
        allowed = ['passive']  # Always allow passive plugins
        
        if self.allow_active_plugins():
            allowed.append('active')
        
        return allowed
    
    def get_request_timeout(self, default: float = 10.0) -> float:
        """
        Get request timeout with security bounds.
        
        Args:
            default: Default timeout value
            
        Returns:
            Bounded timeout value
        """
        try:
            timeout = float(self.get_config_value('request_timeout', default))
            # Enforce security bounds: 1-30 seconds
            return max(1.0, min(30.0, timeout))
        except (ValueError, TypeError):
            return default
    
    def get_passive_only_mode(self) -> bool:
        """
        Check if running in passive-only mode (no active scanning).
        
        Returns:
            True if passive-only mode is enabled
        """
        # Inverse of allow_active_plugins for clarity
        return not self.allow_active_plugins()
    
    def is_debug_mode(self) -> bool:
        """
        Check if debug mode is enabled.
        
        Returns:
            True if debug mode is enabled
        """
        debug_value = os.getenv('IPREP_DEBUG', 'false').lower()
        return debug_value in ('true', '1', 'yes', 'on')
    
    def get_debug_level(self) -> str:
        """
        Get debug level for controlling verbosity.
        
        Returns:
            Debug level: 'basic', 'detailed', or 'verbose'
        """
        if not self.is_debug_mode():
            return 'off'
        
        level = os.getenv('IPREP_DEBUG_LEVEL', 'basic').lower()
        if level in ('basic', 'detailed', 'verbose'):
            return level
        return 'basic'

# Global configuration instance
config = SecureConfig()