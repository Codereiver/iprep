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
            return self._get_mock_domain_reputation(domain)
        
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
            return self._get_mock_domain_reputation(domain)
    
    def _get_mock_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """
        Provide mock domain reputation data for demonstration.
        
        Args:
            domain: The domain name to analyze
            
        Returns:
            Mock domain reputation analysis results
        """
        domain_hash = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)
        
        threat_types = []
        categories = []
        is_malicious = False
        confidence = 0.1
        
        # Deterministic "analysis" based on domain hash
        if domain_hash % 12 == 0:
            threat_types.extend(['phishing', 'credential-theft'])
            categories.append('malicious')
            is_malicious = True
            confidence = 0.9
        elif domain_hash % 8 == 0:
            threat_types.append('malware')
            categories.append('malicious')
            is_malicious = True
            confidence = 0.85
        elif domain_hash % 6 == 0:
            threat_types.append('spam')
            categories.append('suspicious')
            confidence = 0.6
        elif domain_hash % 4 == 0:
            categories.append('newly-registered')
            confidence = 0.3
        else:
            categories.append('legitimate')
        
        engines_count = (domain_hash % 20) + 10
        detections = max(0, int(engines_count * (confidence - 0.1)))
        
        # Mock WHOIS-style data
        mock_dates = [
            '2020-01-15',
            '2021-06-20',
            '2022-11-30',
            '2023-03-10'
        ]
        creation_date = mock_dates[domain_hash % len(mock_dates)]
        
        return {
            'is_malicious': is_malicious,
            'confidence_score': confidence,
            'threat_types': threat_types,
            'categories': categories,
            'engines_total': engines_count,
            'engines_detected': detections,
            'detection_ratio': f"{detections}/{engines_count}",
            'registrar': 'Mock Registrar Inc.',
            'creation_date': creation_date,
            'expiration_date': '2025-12-31',
            'last_seen': '2024-01-15T10:30:00Z',
            'risk_level': self._calculate_risk_level(confidence),
            'note': 'Simulated domain reputation data for demonstration'
        }
    
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