"""
AbuseIPDB reputation plugin.

This plugin checks IP addresses against the AbuseIPDB database
for malicious activity reports. Uses the free API tier.
"""

import requests
from typing import Dict, Any, Optional
from ..base import ReputationPlugin
from ...config import config
from ...debug import debug_plugin_method


class AbuseIPDBPlugin(ReputationPlugin):
    """Reputation plugin using AbuseIPDB service."""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the AbuseIPDB plugin.
        
        Args:
            api_key: Optional API key (deprecated - use environment variable IPREP_ABUSEIPDB_API_KEY)
        """
        timeout = config.get_request_timeout(10.0)
        super().__init__("AbuseIPDB", timeout=timeout, rate_limit_delay=1.0)
        
        # Prefer secure configuration over constructor parameter
        self.api_key = config.get_api_key('abuseipdb') or api_key
        self.base_url = config.get_endpoint_url('abuseipdb', 'primary')
        
        if not self.base_url:
            raise ValueError("No secure endpoint available for AbuseIPDB service")
    
    @debug_plugin_method
    def get_reputation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get reputation data from AbuseIPDB.
        
        Args:
            ip_address: The IP address to check
            
        Returns:
            Reputation data dictionary or None if not available
        """
        if not self.api_key:
            return {
                'error': 'API key not configured',
                'message': 'AbuseIPDB requires an API key. Set IPREP_ABUSEIPDB_API_KEY environment variable.',
                'plugin': 'AbuseIPDB'
            }
        
        self._enforce_rate_limit()
        
        try:
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json',
                'User-Agent': 'iprep/1.0'
            }
            
            response = requests.get(self.base_url, params=params, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            
            if 'data' not in data:
                return None
            
            result = data['data']
            confidence_percent = result.get('abuseConfidencePercentage', 0)
            
            return {
                'is_malicious': confidence_percent > 25,
                'confidence_score': confidence_percent / 100.0,
                'abuse_confidence': confidence_percent,
                'usage_type': result.get('usageType'),
                'isp': result.get('isp'),
                'domain': result.get('domain'),
                'country_code': result.get('countryCode'),
                'is_whitelisted': result.get('isWhitelisted', False),
                'total_reports': result.get('totalReports', 0),
                'last_reported': result.get('lastReportedAt')
            }
            
        except requests.exceptions.RequestException as e:
            self._handle_request_error(e, ip_address)
            return None
        except Exception as e:
            self._handle_request_error(e, ip_address)
            return None
    
    def is_available(self) -> bool:
        """Check if the plugin is available (requires API key)."""
        return bool(self.api_key)