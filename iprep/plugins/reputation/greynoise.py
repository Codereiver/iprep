"""
GreyNoise reputation plugin.

This plugin queries the GreyNoise Community API to identify if an IP address
is part of internet background noise (scanning/opportunistic traffic) vs 
targeted malicious activity.
"""

import requests
import hashlib
from typing import Dict, Any, Optional
from ..base import ReputationPlugin
from ...config import config
from ...security import security


class GreyNoisePlugin(ReputationPlugin):
    """GreyNoise IP reputation plugin."""
    
    def __init__(self):
        """Initialize the GreyNoise plugin."""
        timeout = config.get_request_timeout(10.0)
        super().__init__("GreyNoise", timeout=timeout, rate_limit_delay=1.0)
        self.api_url = "https://api.greynoise.io/v3/community"
        self.user_agent = 'iprep/1.0 (Security Research Tool)'
    
    def is_available(self) -> bool:
        """Check if GreyNoise service is available."""
        # GreyNoise Community API is free and doesn't require API key
        return True
    
    def get_reputation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get IP reputation from GreyNoise Community API.
        
        Args:
            ip_address: The IP address to check
            
        Returns:
            Reputation data dictionary or None if not available
        """
        self._enforce_rate_limit()
        
        try:
            url = f"{self.api_url}/{ip_address}"
            
            # Basic URL validation for API endpoints (less strict than target validation)
            if not url.startswith('https://'):
                self._handle_request_error(Exception("Only HTTPS URLs are allowed"), ip_address)
                return self._get_mock_reputation(ip_address)
            
            headers = {
                'User-Agent': self.user_agent,
                'Accept': 'application/json'
            }
            
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=True
            )
            
            # Validate content type
            content_type = response.headers.get('Content-Type', '')
            if not security.validate_content_type(content_type):
                raise ValueError(f"Unsafe content type: {content_type}")
            
            response.raise_for_status()
            data = response.json()
            
            return self._parse_greynoise_response(data, ip_address)
            
        except requests.exceptions.RequestException as e:
            self._handle_request_error(e, ip_address)
            return self._get_mock_reputation(ip_address)
        except Exception as e:
            self._handle_request_error(e, ip_address)
            return self._get_mock_reputation(ip_address)
    
    def _parse_greynoise_response(self, data: Dict[str, Any], ip_address: str) -> Dict[str, Any]:
        """
        Parse GreyNoise API response.
        
        Args:
            data: Raw API response data
            ip_address: The IP address being analyzed
            
        Returns:
            Parsed reputation data
        """
        # Sanitize all text outputs
        noise = data.get('noise', False)
        riot = data.get('riot', False)
        classification = security.sanitize_output_text(data.get('classification', ''), 50)
        name = security.sanitize_output_text(data.get('name', ''), 100)
        link = security.sanitize_output_text(data.get('link', ''), 200)
        last_seen = security.sanitize_output_text(data.get('last_seen', ''), 50)
        message = security.sanitize_output_text(data.get('message', ''), 500)
        
        # Determine threat level based on GreyNoise data
        is_malicious = False
        threat_types = []
        confidence_score = 0.0
        
        if noise:
            # IP is making background internet noise
            if classification in ['malicious', 'suspicious']:
                is_malicious = True
                threat_types.append('scanning')
                confidence_score = 0.7 if classification == 'malicious' else 0.5
            elif classification == 'benign':
                confidence_score = 0.2
                threat_types.append('benign-scanning')
        
        if riot:
            # IP belongs to a known service provider
            threat_types.append('service-provider')
            confidence_score = max(confidence_score, 0.1)
        
        # If no specific data, but has message, it might be an error or no data
        if not noise and not riot and message:
            confidence_score = 0.0
        
        return {
            'is_malicious': is_malicious,
            'threat_types': threat_types,
            'confidence_score': confidence_score,
            'last_seen': last_seen,
            'classification': classification,
            'noise': noise,
            'riot': riot,
            'service_name': name,
            'link': link,
            'message': message,
            'source': 'GreyNoise Community API'
        }
    
    def _get_mock_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Provide mock reputation data when API is unavailable.
        
        Args:
            ip_address: The IP address being analyzed
            
        Returns:
            Mock reputation data
        """
        ip_hash = int(hashlib.md5(ip_address.encode()).hexdigest()[:8], 16)
        
        # Generate deterministic mock data
        classifications = ['benign', 'unknown', 'malicious', 'suspicious']
        classification = classifications[ip_hash % len(classifications)]
        
        is_malicious = classification in ['malicious', 'suspicious']
        noise = ip_hash % 3 == 0
        riot = ip_hash % 5 == 0
        
        threat_types = []
        if is_malicious:
            threat_types.append('scanning')
        if riot:
            threat_types.append('service-provider')
        
        return {
            'is_malicious': is_malicious,
            'threat_types': threat_types,
            'confidence_score': 0.3 if is_malicious else 0.1,
            'last_seen': '2024-01-01',
            'classification': classification,
            'noise': noise,
            'riot': riot,
            'service_name': 'Mock Service' if riot else '',
            'link': '',
            'message': 'Mock data - GreyNoise API unavailable',
            'source': 'GreyNoise Community API (Mock)'
        }