"""
HTTP content analyser plugin.

This plugin analyses the HTTP response, content, and technical
characteristics of domain names and websites.
"""

import requests
import re
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin, urlparse
from ..base import DomainContentPlugin, PluginTrafficType
from ...config import config
from ...security import security


class HTTPAnalyserPlugin(DomainContentPlugin):
    """Domain content analysis plugin using HTTP requests."""
    
    def __init__(self):
        """Initialize the HTTP analyser plugin."""
        timeout = config.get_request_timeout(15.0)
        super().__init__("HTTP-Analyser", timeout=timeout, rate_limit_delay=2.0, 
                         traffic_type=PluginTrafficType.ACTIVE)
        self.user_agent = 'iprep/1.0 (Security Research Bot)'
    
    def analyze_domain_content(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Analyse domain content via HTTP requests.
        
        Args:
            domain: The domain name to analyse
            
        Returns:
            Content analysis data dictionary or None if not available
        """
        self._enforce_rate_limit()
        
        try:
            # Try HTTPS only (security requirement)
            results = {}
            for scheme in ['https']:  # Only HTTPS for security
                url = f"{scheme}://{domain}"
                
                # Validate URL for SSRF protection
                is_valid, validated_url_or_error = security.validate_url_for_request(url, domain)
                if not is_valid:
                    self._handle_request_error(Exception(f"URL validation failed: {validated_url_or_error}"), domain)
                    continue
                
                try:
                    response = self._fetch_url(validated_url_or_error, domain)
                    if response:
                        results[scheme] = response
                        break  # Use first successful response
                except Exception as e:
                    self._handle_request_error(e, domain)
                    continue
            
            if not results:
                return None
            
            # Analyze the successful response
            scheme, response_data = next(iter(results.items()))
            return self._analyze_response(domain, scheme, response_data)
            
        except Exception as e:
            self._handle_request_error(e, domain)
            return None
    
    def _fetch_url(self, url: str, domain: str) -> Optional[Dict[str, Any]]:
        """
        Fetch URL and return response data.
        
        Args:
            url: The validated URL to fetch
            domain: The domain being analysed (for validation)
            
        Returns:
            Response data dictionary or None
        """
        headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        response = requests.get(
            url, 
            headers=headers, 
            timeout=self.timeout,
            allow_redirects=False,  # Disable redirects for security
            verify=True  # Verify SSL certificates
        )
        
        # Validate response content type
        content_type = response.headers.get('Content-Type', '')
        if not security.validate_content_type(content_type):
            raise ValueError(f"Unsafe content type: {content_type}")
        
        return {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content': response.text[:10000],  # Limit content size, sanitize later after extraction
            'final_url': response.url,
            'history': []  # Disable redirect history for security
        }
    
    def _analyze_response(self, domain: str, scheme: str, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse HTTP response data.
        
        Args:
            domain: The domain name
            scheme: The URL scheme used (http/https)
            response_data: Response data from _fetch_url
            
        Returns:
            Analyzed content data
        """
        content = response_data.get('content', '')
        headers = response_data.get('headers', {})
        
        # Extract and sanitize title
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
        title = security.sanitize_output_text(title_match.group(1).strip() if title_match else '', 200)
        
        # Extract and sanitize meta description
        desc_match = re.search(
            r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)["\']',
            content, re.IGNORECASE
        )
        description = security.sanitize_output_text(desc_match.group(1).strip() if desc_match else '', 500)
        
        # Detect technologies
        technologies = self._detect_technologies(content, headers)
        
        # Analyze SSL if HTTPS
        ssl_info = self._analyze_ssl(scheme, headers) if scheme == 'https' else None
        
        # Count external links
        external_links = self._count_external_links(content, domain)
        
        # Detect suspicious content
        suspicious_content = self._detect_suspicious_content(content, title)
        
        # Determine content categories
        categories = self._categorize_content(content, title, description)
        
        # Detect language
        language = self._detect_language(content)
        
        return {
            'status_code': response_data.get('status_code'),
            'title': title,  # Already sanitized and limited
            'description': description,  # Already sanitized and limited
            'technologies': technologies,
            'ssl_certificate': ssl_info,
            'content_categories': categories,
            'language': security.sanitize_output_text(language, 10),
            'redirects': [],  # Disabled for security
            'external_links': min(external_links, 1000),  # Limit count
            'suspicious_content': suspicious_content,
            'scheme_used': scheme,
            'content_length': len(content),
            'server': security.sanitize_output_text(headers.get('Server', ''), 100),
            'powered_by': security.sanitize_output_text(headers.get('X-Powered-By', ''), 100),
            'last_modified': security.sanitize_output_text(headers.get('Last-Modified', ''), 50),
            'content_type': security.sanitize_output_text(headers.get('Content-Type', ''), 100)
        }
    
    def _detect_technologies(self, content: str, headers: Dict[str, str]) -> List[str]:
        """Detect web technologies used."""
        technologies = []
        
        # Server header
        server = headers.get('Server', '').lower()
        if 'nginx' in server:
            technologies.append('nginx')
        elif 'apache' in server:
            technologies.append('apache')
        elif 'cloudflare' in server:
            technologies.append('cloudflare')
        
        # Powered by header
        powered_by = headers.get('X-Powered-By', '').lower()
        if 'php' in powered_by:
            technologies.append('php')
        elif 'asp.net' in powered_by:
            technologies.append('asp.net')
        
        # Content analysis
        content_lower = content.lower()
        if 'wp-content' in content_lower or 'wordpress' in content_lower:
            technologies.append('wordpress')
        if 'drupal' in content_lower:
            technologies.append('drupal')
        if 'joomla' in content_lower:
            technologies.append('joomla')
        if 'jquery' in content_lower:
            technologies.append('jquery')
        if 'bootstrap' in content_lower:
            technologies.append('bootstrap')
        if 'react' in content_lower or 'reactjs' in content_lower:
            technologies.append('react')
        if 'angular' in content_lower:
            technologies.append('angular')
        if 'vue' in content_lower or 'vuejs' in content_lower:
            technologies.append('vue')
        
        return technologies
    
    def _analyze_ssl(self, scheme: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyse SSL certificate information."""
        if scheme != 'https':
            return None
        
        ssl_info = {
            'enabled': True,
            'hsts_enabled': 'Strict-Transport-Security' in headers,
            'hsts_header': headers.get('Strict-Transport-Security', ''),
        }
        
        return ssl_info
    
    def _count_external_links(self, content: str, domain: str) -> int:
        """Count external links in the content."""
        # Simple regex to find links
        links = re.findall(r'href=["\']([^"\']+)["\']', content, re.IGNORECASE)
        external_count = 0
        
        for link in links:
            if link.startswith('http') and domain not in link:
                external_count += 1
        
        return external_count
    
    def _detect_suspicious_content(self, content: str, title: str) -> bool:
        """Detect potentially suspicious content patterns."""
        suspicious_patterns = [
            r'click here to win',
            r'congratulations.*winner',
            r'urgent.*action.*required',
            r'verify.*account.*immediately',
            r'suspended.*account',
            r'update.*payment.*information',
            r'claim.*prize',
            r'limited.*time.*offer',
            r'act.*now.*expires',
        ]
        
        text_to_check = (content + ' ' + title).lower()
        
        for pattern in suspicious_patterns:
            if re.search(pattern, text_to_check, re.IGNORECASE):
                return True
        
        return False
    
    def _categorize_content(self, content: str, title: str, description: str) -> List[str]:
        """Categorize website content."""
        categories = []
        text = (content + ' ' + title + ' ' + description).lower()
        
        # E-commerce indicators
        if any(word in text for word in ['shop', 'buy', 'cart', 'checkout', 'product', 'store']):
            categories.append('e-commerce')
        
        # News/blog indicators
        if any(word in text for word in ['news', 'article', 'blog', 'post', 'published']):
            categories.append('news/blog')
        
        # Social media indicators
        if any(word in text for word in ['social', 'follow', 'share', 'like', 'tweet']):
            categories.append('social-media')
        
        # Technology indicators
        if any(word in text for word in ['technology', 'software', 'tech', 'programming', 'code']):
            categories.append('technology')
        
        # Business/corporate indicators
        if any(word in text for word in ['company', 'business', 'corporate', 'services', 'solutions']):
            categories.append('business')
        
        # Personal/portfolio indicators
        if any(word in text for word in ['portfolio', 'resume', 'personal', 'about me']):
            categories.append('personal')
        
        return categories if categories else ['general']
    
    def _detect_language(self, content: str) -> str:
        """Detect content language (simple heuristic)."""
        # Very basic language detection
        if re.search(r'<html[^>]*lang=["\']([^"\']+)["\']', content, re.IGNORECASE):
            lang_match = re.search(r'<html[^>]*lang=["\']([^"\']+)["\']', content, re.IGNORECASE)
            return lang_match.group(1)[:5]  # Limit language code length
        
        # Default to English if no detection
        return 'en'
    
