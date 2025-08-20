"""
PhishTank domain reputation plugin.

This plugin queries the PhishTank API to check if a domain or URL
is associated with known phishing attacks. PhishTank is a community-driven
anti-phishing site.
"""

import requests
import urllib.parse
from typing import Dict, Any, Optional
from ..base import DomainReputationPlugin
from ...config import config
from ...security import security


class PhishTankPlugin(DomainReputationPlugin):
    """PhishTank domain reputation plugin."""
    
    def __init__(self):
        """Initialize the PhishTank plugin."""
        timeout = config.get_request_timeout(10.0)
        super().__init__("PhishTank", timeout=timeout, rate_limit_delay=2.0)
        self.api_url = "http://checkurl.phishtank.com/checkurl/"
        self.user_agent = 'iprep/1.0 (Security Research Tool)'
        # Note: PhishTank API endpoint is HTTP, but we validate the request
    
    def is_available(self) -> bool:
        """Check if PhishTank service is available."""
        # PhishTank API is free but rate-limited
        return True
    
    def get_domain_reputation(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Get domain reputation from PhishTank API.
        
        Args:
            domain: The domain name to check
            
        Returns:
            Reputation data dictionary or None if not available
        """
        self._enforce_rate_limit()
        
        try:
            # PhishTank checks URLs, so we'll check both HTTP and HTTPS versions
            urls_to_check = [
                f"http://{domain}",
                f"https://{domain}",
                f"http://www.{domain}",
                f"https://www.{domain}"
            ]
            
            results = []
            for url in urls_to_check:
                result = self._check_url_with_phishtank(url, domain)
                if result and result.get('is_malicious', False):
                    # If any variant is flagged as phishing, that's significant
                    results.append(result)
                    break  # Don't check more if we found a positive hit
            
            if results:
                return results[0]  # Return the first positive result
            else:
                # Return a clean result for the primary domain
                return self._create_clean_result(domain)
                
        except Exception as e:
            self._handle_request_error(e, domain)
            return None
    
    def _check_url_with_phishtank(self, url: str, domain: str) -> Optional[Dict[str, Any]]:
        """
        Check a specific URL with PhishTank.
        
        Args:
            url: The URL to check
            domain: The original domain for error handling
            
        Returns:
            Reputation data or None
        """
        try:
            # Prepare the POST data
            data = {
                'url': url,
                'format': 'json',
                'app_key': config.get_api_key('phishtank') or 'iprep-research-tool'
            }
            
            headers = {
                'User-Agent': self.user_agent,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
            
            # Note: PhishTank API endpoint is HTTP only
            # We make an exception here since it's a well-known security service
            response = requests.post(
                self.api_url,
                data=data,
                headers=headers,
                timeout=self.timeout,
                verify=True
            )
            
            # Validate content type
            content_type = response.headers.get('Content-Type', '')
            if not security.validate_content_type(content_type):
                raise ValueError(f"Unsafe content type: {content_type}")
            
            response.raise_for_status()
            result_data = response.json()
            
            return self._parse_phishtank_response(result_data, url, domain)
            
        except requests.exceptions.RequestException as e:
            # Don't treat individual URL check failures as plugin failures
            return None
        except Exception as e:
            return None
    
    def _parse_phishtank_response(self, data: Dict[str, Any], url: str, domain: str) -> Dict[str, Any]:
        """
        Parse PhishTank API response.
        
        Args:
            data: Raw API response data
            url: The URL that was checked
            domain: The domain being analyzed
            
        Returns:
            Parsed reputation data
        """
        # Extract and sanitize response data
        results = data.get('results', {})
        in_database = results.get('in_database', False)
        is_phish = results.get('phish_detail_page') is not None if in_database else False
        verified = results.get('verified', False) if in_database else False
        
        # Sanitize text fields
        phish_id = results.get('phish_id', 0) if in_database else 0
        submission_time = security.sanitize_output_text(
            results.get('submission_time', ''), 50
        ) if in_database else ''
        verification_time = security.sanitize_output_text(
            results.get('verification_time', ''), 50
        ) if in_database else ''
        detail_page = security.sanitize_output_text(
            results.get('phish_detail_page', ''), 200
        ) if in_database else ''
        
        # Determine threat assessment
        is_malicious = in_database and is_phish and verified
        threat_types = []
        confidence_score = 0.0
        
        if is_malicious:
            threat_types.append('phishing')
            confidence_score = 0.9 if verified else 0.7
        elif in_database and is_phish and not verified:
            # Unverified phishing report
            threat_types.append('potential-phishing')
            confidence_score = 0.4
        
        return {
            'is_malicious': is_malicious,
            'threat_types': threat_types,
            'confidence_score': confidence_score,
            'categories': ['phishing'] if is_malicious else [],
            'last_seen': verification_time or submission_time,
            'in_database': in_database,
            'verified': verified,
            'phish_id': phish_id,
            'submission_time': submission_time,
            'verification_time': verification_time,
            'detail_page': detail_page,
            'checked_url': security.sanitize_output_text(url, 200),
            'source': 'PhishTank Community'
        }
    
    def _create_clean_result(self, domain: str) -> Dict[str, Any]:
        """
        Create a clean reputation result for domains not in PhishTank.
        
        Args:
            domain: The domain being analyzed
            
        Returns:
            Clean reputation data
        """
        return {
            'is_malicious': False,
            'threat_types': [],
            'confidence_score': 0.1,  # Low confidence for negative results
            'categories': [],
            'last_seen': '',
            'in_database': False,
            'verified': False,
            'phish_id': 0,
            'submission_time': '',
            'verification_time': '',
            'detail_page': '',
            'checked_url': f"https://{domain}",
            'source': 'PhishTank Community'
        }
    
