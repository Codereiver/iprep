"""
Unit tests for domain reputation and content plugins.
"""

import pytest
from unittest.mock import patch, MagicMock
from iprep.plugins.domain_reputation.urlvoid import URLVoidDomainPlugin
from iprep.plugins.domain_reputation.virustotal import VirusTotalDomainPlugin
from iprep.plugins.domain_content.http_analyser import HTTPAnalyserPlugin
from iprep.plugins.domain_content.dns_analyser import DNSAnalyserPlugin


class TestURLVoidDomainPlugin:
    """Test cases for URLVoid domain reputation plugin."""
    
    def test_initialization_without_api_key(self):
        """Test plugin initialization without API key."""
        plugin = URLVoidDomainPlugin()
        assert plugin.name == "URLVoid-Domain"
        assert plugin.api_key is None
        assert not plugin.is_available()  # Should be False without API key
    
    def test_initialization_with_api_key(self):
        """Test plugin initialization with API key."""
        plugin = URLVoidDomainPlugin(api_key="test_key")
        assert plugin.api_key == "test_key"
    
    def test_no_api_key_returns_error(self):
        """Test that plugin returns error without API key."""
        plugin = URLVoidDomainPlugin()
        result = plugin.get_domain_reputation("google.com")
        
        assert result is not None
        assert 'error' in result
        assert result['error'] == 'API key not configured'
        assert 'IPREP_URLVOID_API_KEY' in result['message']
        assert result['plugin'] == 'URLVoid-Domain'
    
    def test_consistent_error_without_api_key(self):
        """Test that plugin returns consistent error for any domain without API key."""
        plugin = URLVoidDomainPlugin()
        
        domains = ["example.com", "google.com", "test.org"]
        for domain in domains:
            result = plugin.get_domain_reputation(domain)
            assert result is not None
            assert 'error' in result
            assert result['error'] == 'API key not configured'
    
    def test_availability_with_api_key(self):
        """Test plugin availability with API key."""
        plugin = URLVoidDomainPlugin(api_key="test_api_key_123456")
        assert plugin.is_available() is True
    
    def test_initialization_with_api_key(self):
        """Test plugin initialization with API key."""
        plugin = URLVoidDomainPlugin(api_key="test_api_key_123456")
        assert plugin.api_key == "test_api_key_123456"
        assert plugin.is_available() is True


class TestVirusTotalDomainPlugin:
    """Test cases for VirusTotal domain reputation plugin."""
    
    def test_initialization_without_api_key(self):
        """Test plugin initialization without API key."""
        plugin = VirusTotalDomainPlugin()
        assert plugin.name == "VirusTotal-Domain"
        assert plugin.api_key is None
        assert not plugin.is_available()  # Should be False without API key
    
    def test_initialization_with_api_key(self):
        """Test plugin initialization with API key."""
        plugin = VirusTotalDomainPlugin(api_key="test_key")
        assert plugin.api_key == "test_key"
    
    def test_no_api_key_returns_error(self):
        """Test that plugin returns error without API key."""
        plugin = VirusTotalDomainPlugin()
        result = plugin.get_domain_reputation("example.com")
        
        assert result is not None
        assert 'error' in result
        assert result['error'] == 'API key not configured'
        assert 'IPREP_VIRUSTOTAL_API_KEY' in result['message']
        assert result['plugin'] == 'VirusTotal-Domain'
    
    def test_availability_with_api_key(self):
        """Test plugin availability with API key."""
        plugin = VirusTotalDomainPlugin(api_key="test_api_key_123456789012345678901234")
        assert plugin.is_available() is True
    
    def test_consistent_error_without_api_key(self):
        """Test that plugin returns consistent error for any domain without API key."""
        plugin = VirusTotalDomainPlugin()
        
        domains = ["example.com", "google.com", "test.org"]
        for domain in domains:
            result = plugin.get_domain_reputation(domain)
            assert result is not None
            assert 'error' in result
            assert result['error'] == 'API key not configured'


class TestHTTPAnalyserPlugin:
    """Test cases for HTTP content analyser plugin."""
    
    def test_initialization(self):
        """Test plugin initialization."""
        plugin = HTTPAnalyserPlugin()
        assert plugin.name == "HTTP-Analyser"
        assert 1.0 <= plugin.timeout <= 30.0  # Should be within security bounds
        assert plugin.rate_limit_delay == 2.0
        assert plugin.is_available()
    
    @patch('iprep.security.security.validate_url_for_request')
    @patch('requests.get')
    def test_successful_http_analysis(self, mock_get, mock_validate):
        """Test successful HTTP content analysis."""
        # Mock URL validation to pass
        mock_validate.return_value = (True, 'https://example.com')
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Server': 'nginx/1.18.0',
            'Content-Type': 'text/html; charset=utf-8'
        }
        mock_response.text = """
        <html>
        <head><title>Test Website</title></head>
        <body>
            <h1>Welcome to our test site</h1>
            <script src="jquery.min.js"></script>
        </body>
        </html>
        """
        mock_response.url = 'https://example.com'
        mock_response.history = []
        mock_get.return_value = mock_response
        
        plugin = HTTPAnalyserPlugin()
        result = plugin.analyze_domain_content("example.com")
        
        assert result is not None
        assert result['status_code'] == 200
        assert result['title'] == 'Test Website'  # Should extract and sanitize title
        assert 'nginx' in result['technologies']
        assert result['scheme_used'] == 'https'
    
    @patch('requests.get')
    def test_http_error_fallback_to_mock(self, mock_get):
        """Test fallback to mock data when HTTP request fails."""
        mock_get.side_effect = Exception("Connection failed")
        
        plugin = HTTPAnalyserPlugin()
        result = plugin.analyze_domain_content("example.com")
        
        assert result is not None
        assert 'note' in result
        assert result['note'] == 'Mock content analysis - HTTP request failed'
    
    def test_mock_content_analysis_deterministic(self):
        """Test that mock content analysis is deterministic."""
        plugin = HTTPAnalyserPlugin()
        
        result1 = plugin._get_mock_content_analysis("example.com")
        result2 = plugin._get_mock_content_analysis("example.com")
        
        assert result1 == result2
    
    def test_detect_technologies(self):
        """Test technology detection from content and headers."""
        plugin = HTTPAnalyserPlugin()
        
        content = """
        <html>
        <body>
            <script src="wp-content/themes/theme.js"></script>
            <script src="jquery.min.js"></script>
            <link rel="stylesheet" href="bootstrap.css">
        </body>
        </html>
        """
        headers = {
            'Server': 'nginx/1.18.0',
            'X-Powered-By': 'PHP/7.4'
        }
        
        technologies = plugin._detect_technologies(content, headers)
        
        assert 'wordpress' in technologies
        assert 'jquery' in technologies
        assert 'bootstrap' in technologies
        assert 'nginx' in technologies
        assert 'php' in technologies
    
    def test_categorize_content(self):
        """Test content categorization."""
        plugin = HTTPAnalyserPlugin()
        
        # Test e-commerce content
        ecommerce_content = "Buy now! Add to cart. Checkout here. Our store offers great products."
        categories = plugin._categorize_content(ecommerce_content, "", "")
        assert 'e-commerce' in categories
        
        # Test technology content
        tech_content = "Software development and programming tutorials. Code examples."
        categories = plugin._categorize_content(tech_content, "", "")
        assert 'technology' in categories
    
    def test_detect_suspicious_content(self):
        """Test suspicious content detection."""
        plugin = HTTPAnalyserPlugin()
        
        # Test suspicious patterns
        suspicious_content = "Click here to win a prize! Urgent action required!"
        assert plugin._detect_suspicious_content(suspicious_content, "")
        
        # Test clean content
        clean_content = "Welcome to our website. Learn more about our services."
        assert not plugin._detect_suspicious_content(clean_content, "")


class TestDNSAnalyserPlugin:
    """Test cases for DNS analyser plugin."""
    
    def test_initialization(self):
        """Test plugin initialization."""
        plugin = DNSAnalyserPlugin()
        assert plugin.name == "DNS-Analyser"
        assert plugin.timeout == 10
        assert plugin.rate_limit_delay == 1.0
        assert plugin.is_available()
    
    @patch('socket.getaddrinfo')
    def test_successful_dns_analysis(self, mock_getaddrinfo):
        """Test successful DNS analysis."""
        # Mock DNS responses
        mock_getaddrinfo.side_effect = [
            # A records for main domain
            [('', '', '', '', ('192.0.2.1', 0))],
            # AAAA records (IPv6)
            [('', '', '', '', ('2001:db8::1', 0))],
            # MX records check
            [('', '', '', '', ('192.0.2.2', 0))],
            # CNAME/www check
            [('', '', '', '', ('192.0.2.1', 0))]
        ]
        
        plugin = DNSAnalyserPlugin()
        result = plugin.analyze_domain_content("example.com")
        
        assert result is not None
        assert 'dns_records' in result
        assert 'infrastructure_analysis' in result
        assert result['dns_records']['A'] == ['192.0.2.1']
        assert result['dns_records']['AAAA'] == ['2001:db8::1']
    
    @patch('socket.getaddrinfo')
    def test_dns_error_fallback_to_mock(self, mock_getaddrinfo):
        """Test fallback to mock data when DNS queries fail."""
        mock_getaddrinfo.side_effect = Exception("DNS resolution failed")
        
        plugin = DNSAnalyserPlugin()
        result = plugin.analyze_domain_content("example.com")
        
        assert result is not None
        assert 'note' in result
        assert result['note'] == 'Mock DNS analysis - DNS queries failed'
    
    def test_infrastructure_analysis(self):
        """Test DNS infrastructure analysis."""
        plugin = DNSAnalyserPlugin()
        
        dns_records = {
            'A': ['192.0.2.1', '192.0.2.2'],
            'AAAA': ['2001:db8::1'],
            'MX': ['10 mail.example.com'],
            'CNAME': ['www']
        }
        
        analysis = plugin._analyze_infrastructure(dns_records)
        
        assert analysis['ip_count'] == 2
        assert analysis['ipv6_enabled'] is True
        assert analysis['multiple_a_records'] is True
        assert analysis['has_mail_records'] is True
        assert analysis['has_www_subdomain'] is True
    
    def test_ip_range_analysis(self):
        """Test IP range analysis."""
        plugin = DNSAnalyserPlugin()
        
        # Test same Class C subnet
        same_subnet_ips = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
        analysis = plugin._analyze_ip_ranges(same_subnet_ips)
        assert analysis['same_class_c_subnet'] is True
        assert analysis['same_class_b_subnet'] is True
        
        # Test different subnets
        different_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1']
        analysis = plugin._analyze_ip_ranges(different_ips)
        assert analysis['same_class_c_subnet'] is False
        assert analysis['same_class_b_subnet'] is False
    
    def test_detect_cdn_usage(self):
        """Test CDN detection logic."""
        plugin = DNSAnalyserPlugin()
        
        # Test Cloudflare detection
        cloudflare_records = {'A': ['104.16.1.1', '104.16.2.2']}
        cdn_result = plugin._detect_cdn_usage(cloudflare_records)
        assert cdn_result['cdn_detected'] is True
        assert 'cloudflare' in cdn_result['cdn_providers']
        
        # Test no CDN
        regular_records = {'A': ['192.168.1.1']}
        cdn_result = plugin._detect_cdn_usage(regular_records)
        assert cdn_result['cdn_detected'] is False
    
    def test_hosting_provider_identification(self):
        """Test hosting provider identification."""
        plugin = DNSAnalyserPlugin()
        
        # Test GitHub Pages
        github_records = {'A': ['185.199.108.153']}
        provider = plugin._identify_hosting_provider(github_records)
        assert provider == 'github-pages'
        
        # Test Cloudflare
        cloudflare_records = {'A': ['104.16.1.1']}
        provider = plugin._identify_hosting_provider(cloudflare_records)
        assert provider == 'cloudflare'
        
        # Test unknown
        unknown_records = {'A': ['192.168.1.1']}
        provider = plugin._identify_hosting_provider(unknown_records)
        assert provider == 'unknown'
    
    def test_mock_dns_analysis_deterministic(self):
        """Test that mock DNS analysis is deterministic."""
        plugin = DNSAnalyserPlugin()
        
        result1 = plugin._get_mock_dns_analysis("example.com")
        result2 = plugin._get_mock_dns_analysis("example.com")
        
        assert result1 == result2