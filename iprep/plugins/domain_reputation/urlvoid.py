"""
URLVoid domain reputation plugin.

This plugin checks domain names for malicious activity using
URLVoid's domain reputation service with mock data for demonstration.
"""

import hashlib
import requests
from typing import Dict, Any, Optional
from ..base import DomainReputationPlugin


class URLVoidDomainPlugin(DomainReputationPlugin):
    """Domain reputation plugin using URLVoid-style reputation checking."""
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the URLVoid domain plugin."""
        super().__init__("URLVoid-Domain", timeout=10, rate_limit_delay=2.0)
        self.api_key = api_key
        self.base_url = "https://api.urlvoid.com/v1/scan/"
    
    def get_domain_reputation(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Get domain reputation data using URLVoid-style analysis.
        
        Args:
            domain: The domain name to check
            
        Returns:
            Domain reputation data dictionary or None if not available
        """
        if not self.api_key:
            return {
                'error': 'API key not configured',
                'message': 'URLVoid requires an API key. Set IPREP_URLVOID_API_KEY environment variable.',
                'plugin': 'URLVoid-Domain'
            }
        
        self._enforce_rate_limit()
        
        try:
            # Real URLVoid API would be called here
            url = f"{self.base_url}?key={self.api_key}&host={domain}"
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            
            # Parse real URLVoid response format
            return self._parse_urlvoid_response(data)
            
        except Exception as e:
            self._handle_request_error(e, domain)
            return None
    
    def is_available(self) -> bool:
        """Check if the plugin is available (requires API key)."""
        return bool(self.api_key)
    
    def _parse_urlvoid_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse real URLVoid API response (when API key is available)."""
        # This would parse actual URLVoid response format
        return {
            'is_malicious': data.get('detections', 0) > 0,
            'confidence_score': min(data.get('detections', 0) / 30.0, 1.0),
            'threat_types': data.get('detected_engines', []),
            'categories': ['scan-result'],
            'engines_total': data.get('engines_total', 0),
            'engines_detected': data.get('detections', 0),
            'detection_ratio': f"{data.get('detections', 0)}/{data.get('engines_total', 0)}",
            'last_seen': data.get('scan_date', ''),
            'risk_level': self._calculate_risk_level(data.get('detections', 0) / 30.0)
        }
    
    def _calculate_risk_level(self, confidence: float) -> str:
        """Calculate risk level based on confidence score."""
        if confidence >= 0.8:
            return 'high'
        elif confidence >= 0.5:
            return 'medium'
        elif confidence >= 0.3:
            return 'low'
        else:
            return 'minimal'