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
            return self._get_mock_domain_reputation(domain)
        
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
            return self._get_mock_domain_reputation(domain)
    
    def _get_mock_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """
        Provide mock VirusTotal-style domain reputation data.
        
        Args:
            domain: The domain name to analyze
            
        Returns:
            Mock domain reputation analysis results
        """
        domain_hash = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)
        
        # Generate mock engines and detections
        total_engines = 70  # VirusTotal typically has ~70 engines
        detection_rate = self._calculate_detection_rate(domain_hash)
        detections = int(total_engines * detection_rate)
        
        threat_types = []
        categories = []
        
        # Determine threat types based on detection rate
        if detection_rate > 0.7:
            threat_types.extend(['malware', 'phishing'])
            categories.extend(['malicious', 'phishing'])
        elif detection_rate > 0.4:
            threat_types.append('suspicious')
            categories.append('suspicious')
        elif detection_rate > 0.1:
            threat_types.append('potentially-unwanted')
            categories.append('potentially-harmful')
        else:
            categories.append('harmless')
        
        # Mock additional VirusTotal-style data
        sample_vendors = [
            'Kaspersky', 'Bitdefender', 'Avira', 'ESET-NOD32', 'F-Secure',
            'McAfee', 'Symantec', 'Sophos', 'Trend Micro', 'Panda'
        ]
        
        detecting_vendors = []
        if detections > 0:
            # Select some vendors that "detected" the domain
            vendor_count = min(detections, len(sample_vendors))
            step = len(sample_vendors) // max(vendor_count, 1)
            detecting_vendors = sample_vendors[::step][:vendor_count]
        
        return {
            'is_malicious': detection_rate > 0.3,
            'confidence_score': min(detection_rate * 1.2, 1.0),
            'threat_types': threat_types,
            'categories': categories,
            'engines_total': total_engines,
            'engines_detected': detections,
            'detection_ratio': f"{detections}/{total_engines}",
            'detecting_vendors': detecting_vendors,
            'scan_date': '2024-01-15T14:30:00Z',
            'last_seen': '2024-01-15T10:30:00Z',
            'reputation_score': int((1 - detection_rate) * 100),
            'harmless_votes': max(0, 50 - detections),
            'malicious_votes': detections,
            'note': 'Simulated VirusTotal-style domain reputation data'
        }
    
    def _calculate_detection_rate(self, domain_hash: int) -> float:
        """Calculate mock detection rate based on domain hash."""
        # Create deterministic but varied detection rates
        base_rate = (domain_hash % 100) / 100.0
        
        # Apply some logic to make certain patterns more/less suspicious
        if domain_hash % 15 == 0:  # Simulate known bad domains
            return min(0.8 + (base_rate * 0.2), 1.0)
        elif domain_hash % 7 == 0:  # Simulate suspicious domains
            return min(0.4 + (base_rate * 0.4), 0.7)
        elif domain_hash % 3 == 0:  # Simulate potentially unwanted
            return min(0.1 + (base_rate * 0.3), 0.4)
        else:  # Mostly clean domains
            return min(base_rate * 0.2, 0.15)
    
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