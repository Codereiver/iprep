"""
URLVoid IP reputation plugin.

This plugin checks IP addresses for malicious activity using
URLVoid's IP reputation service with mock data for demonstration.
"""

import hashlib
from typing import Dict, Any, Optional
from ..base import ReputationPlugin


class URLVoidPlugin(ReputationPlugin):
    """Reputation plugin using URLVoid-style reputation checking."""
    
    def __init__(self):
        """Initialize the URLVoid plugin."""
        super().__init__("URLVoid", timeout=10, rate_limit_delay=1.5)
    
    def get_reputation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get reputation data using mock URLVoid-style analysis.
        
        Args:
            ip_address: The IP address to check
            
        Returns:
            Reputation data dictionary or None if not available
        """
        self._enforce_rate_limit()
        
        try:
            return self._analyze_ip_reputation(ip_address)
            
        except Exception as e:
            self._handle_request_error(e, ip_address)
            return None
    
    def _analyze_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Analyze IP reputation using deterministic mock logic.
        
        Args:
            ip_address: The IP address to analyze
            
        Returns:
            Reputation analysis results
        """
        ip_hash = int(hashlib.md5(ip_address.encode()).hexdigest()[:8], 16)
        
        threat_indicators = []
        is_malicious = False
        confidence = 0.1
        
        if ip_hash % 10 == 0:
            threat_indicators.append('botnet')
            is_malicious = True
            confidence = 0.85
        elif ip_hash % 7 == 0:
            threat_indicators.append('malware')
            is_malicious = True
            confidence = 0.75
        elif ip_hash % 5 == 0:
            threat_indicators.append('suspicious_activity')
            confidence = 0.45
        elif ip_hash % 3 == 0:
            threat_indicators.append('scanning')
            confidence = 0.30
        
        engines_count = (ip_hash % 15) + 5
        detections = max(0, int(engines_count * (confidence - 0.1)))
        
        return {
            'is_malicious': is_malicious,
            'confidence_score': confidence,
            'threat_types': threat_indicators,
            'engines_total': engines_count,
            'engines_detected': detections,
            'detection_ratio': f"{detections}/{engines_count}",
            'risk_level': self._calculate_risk_level(confidence),
            'last_analysis': '2024-01-15T10:30:00Z',
            'note': 'Simulated reputation data for demonstration'
        }
    
    def _calculate_risk_level(self, confidence: float) -> str:
        """
        Calculate risk level based on confidence score.
        
        Args:
            confidence: Confidence score (0.0 to 1.0)
            
        Returns:
            Risk level string
        """
        if confidence >= 0.8:
            return 'high'
        elif confidence >= 0.5:
            return 'medium'
        elif confidence >= 0.3:
            return 'low'
        else:
            return 'minimal'