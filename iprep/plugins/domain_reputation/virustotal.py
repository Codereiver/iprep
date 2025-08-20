"""
VirusTotal domain reputation plugin.

This plugin checks domain names against VirusTotal's database
for malicious activity reports. Uses mock data for demonstration.
"""

import hashlib
import requests
from typing import Dict, Any, Optional, List
from ..base import DomainReputationPlugin


class VirusTotalDomainPlugin(DomainReputationPlugin):
    """Domain reputation plugin using VirusTotal-style analysis."""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the VirusTotal domain plugin.
        
        Args:
            api_key: Optional API key for VirusTotal access
        """
        super().__init__("VirusTotal-Domain", timeout=10, rate_limit_delay=15.0)
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2/domain/report"
    
    def get_domain_reputation(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Get domain reputation data from VirusTotal-style analysis.
        
        Args:
            domain: The domain name to check
            
        Returns:
            Domain reputation data dictionary or None if not available
        """
        if not self.api_key:
            return {
                'error': 'API key not configured',
                'message': 'VirusTotal requires an API key. Set IPREP_VIRUSTOTAL_API_KEY environment variable.',
                'plugin': 'VirusTotal-Domain'
            }
        
        self._enforce_rate_limit()
        
        try:
            params = {
                'apikey': self.api_key,
                'domain': domain
            }
            
            response = requests.get(self.base_url, params=params, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            
            return self._parse_virustotal_response(data)
            
        except Exception as e:
            self._handle_request_error(e, domain)
            return None
    
    def is_available(self) -> bool:
        """Check if the plugin is available (requires API key)."""
        return bool(self.api_key)
    
    def _parse_virustotal_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse real VirusTotal API response (when API key is available)."""
        if data.get('response_code') != 1:
            return None
        
        # Parse actual VirusTotal response format
        scans = data.get('scans', {})
        total_engines = len(scans)
        detections = sum(1 for scan in scans.values() if scan.get('detected', False))
        
        detecting_vendors = [
            vendor for vendor, scan in scans.items() 
            if scan.get('detected', False)
        ]
        
        threat_types = []
        if detections > total_engines * 0.7:
            threat_types.extend(['malware', 'phishing'])
        elif detections > total_engines * 0.3:
            threat_types.append('suspicious')
        elif detections > 0:
            threat_types.append('potentially-unwanted')
        
        detection_rate = detections / max(total_engines, 1)
        
        return {
            'is_malicious': detection_rate > 0.3,
            'confidence_score': min(detection_rate * 1.2, 1.0),
            'threat_types': threat_types,
            'categories': data.get('categories', []),
            'engines_total': total_engines,
            'engines_detected': detections,
            'detection_ratio': f"{detections}/{total_engines}",
            'detecting_vendors': detecting_vendors,
            'scan_date': data.get('scan_date', ''),
            'reputation_score': data.get('reputation', 0),
            'harmless_votes': data.get('harmless_votes', 0),
            'malicious_votes': data.get('malicious_votes', 0)
        }