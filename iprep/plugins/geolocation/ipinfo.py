"""
IPinfo geolocation plugin.

This plugin uses the free IPinfo service (ipinfo.io) to get geolocation
and network data for IP addresses. No API key required for basic usage.
"""

import requests
from typing import Dict, Any, Optional
from ..base import GeolocationPlugin


class IPinfoPlugin(GeolocationPlugin):
    """Geolocation plugin using IPinfo service."""
    
    def __init__(self):
        """Initialize the IPinfo plugin."""
        super().__init__("IPinfo", timeout=10, rate_limit_delay=1.0)
        self.base_url = "https://ipinfo.io"
    
    def get_geolocation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get geolocation data from IPinfo.
        
        Args:
            ip_address: The IP address to locate
            
        Returns:
            Geolocation data dictionary or None if not available
        """
        self._enforce_rate_limit()
        
        try:
            url = f"{self.base_url}/{ip_address}/json"
            
            headers = {
                'User-Agent': 'iprep/1.0'
            }
            
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            
            if 'error' in data:
                return None
            
            loc = data.get('loc', '').split(',') if data.get('loc') else [None, None]
            try:
                latitude = float(loc[0]) if loc[0] else None
                longitude = float(loc[1]) if loc[1] and len(loc) > 1 else None
            except (ValueError, IndexError):
                latitude = None
                longitude = None
            
            return {
                'country': data.get('country'),
                'region': data.get('region'),
                'city': data.get('city'),
                'latitude': latitude,
                'longitude': longitude,
                'timezone': data.get('timezone'),
                'postal_code': data.get('postal'),
                'organization': data.get('org'),
                'hostname': data.get('hostname')
            }
            
        except requests.exceptions.RequestException as e:
            self._handle_request_error(e, ip_address)
            return None
        except Exception as e:
            self._handle_request_error(e, ip_address)
            return None