"""
IP-API geolocation plugin.

This plugin uses the free IP-API service (ip-api.com) to get geolocation
data for IP addresses. No API key required.
"""

import requests
from typing import Dict, Any, Optional
from ..base import GeolocationPlugin
from ...config import config


class IPApiPlugin(GeolocationPlugin):
    """Geolocation plugin using IP-API service."""
    
    def __init__(self):
        """Initialize the IP-API plugin."""
        timeout = config.get_request_timeout(10.0)
        super().__init__("IP-API", timeout=timeout, rate_limit_delay=1.0)
        
        # Use secure HTTPS endpoint
        self.base_url = config.get_endpoint_url('ipapi', 'primary')
        if not self.base_url:
            # Fallback to backup HTTPS endpoint
            self.base_url = config.get_endpoint_url('ipapi', 'backup') or "https://ipapi.co"
            
        # Ensure HTTPS is used
        if not self.base_url.startswith('https://'):
            raise ValueError("Only HTTPS endpoints are allowed for security")
    
    def get_geolocation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get geolocation data from IP-API.
        
        Args:
            ip_address: The IP address to locate
            
        Returns:
            Geolocation data dictionary or None if not available
        """
        self._enforce_rate_limit()
        
        try:
            url = f"{self.base_url}/{ip_address}"
            
            params = {
                'fields': 'status,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query'
            }
            
            headers = {
                'User-Agent': 'iprep/1.0'
            }
            
            response = requests.get(url, params=params, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') != 'success':
                return None
            
            return {
                'country': data.get('country'),
                'country_code': data.get('countryCode'),
                'region': data.get('regionName'),
                'city': data.get('city'),
                'latitude': data.get('lat'),
                'longitude': data.get('lon'),
                'timezone': data.get('timezone'),
                'isp': data.get('isp'),
                'organization': data.get('org'),
                'asn': data.get('as')
            }
            
        except requests.exceptions.RequestException as e:
            self._handle_request_error(e, ip_address)
            return None
        except Exception as e:
            self._handle_request_error(e, ip_address)
            return None