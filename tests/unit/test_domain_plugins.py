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
        assert plugin.is_available()
    
    def test_initialization_with_api_key(self):
        """Test plugin initialization with API key."""
        plugin = URLVoidDomainPlugin(api_key="test_key")
        assert plugin.api_key == "test_key"
    
    def test_mock_reputation_legitimate_domain(self):
        """Test mock reputation for legitimate domain."""
        plugin = URLVoidDomainPlugin()
        result = plugin.get_domain_reputation("google.com")
        
        assert result is not None
        assert 'is_malicious' in result
        assert 'confidence_score' in result
        assert 'threat_types' in result
        assert 'categories' in result
        assert 'note' in result
        assert result['note'] == 'Simulated domain reputation data for demonstration'
    
    def test_mock_reputation_deterministic(self):
        """Test that mock reputation is deterministic."""
        plugin = URLVoidDomainPlugin()
        
        # Same domain should return same results
        result1 = plugin.get_domain_reputation("example.com")
        result2 = plugin.get_domain_reputation("example.com")
        
        assert result1 == result2
    
    def test_mock_reputation_various_domains(self):
        """Test mock reputation for various domains to ensure variety."""
        plugin = URLVoidDomainPlugin()
        domains = ["test1.com", "test2.com", "test3.com", "test4.com"]
        results = [plugin.get_domain_reputation(domain) for domain in domains]
        
        # Should have some variation in results
        malicious_flags = [r['is_malicious'] for r in results]
        confidence_scores = [r['confidence_score'] for r in results]
        
        # Not all results should be identical
        assert len(set(malicious_flags)) > 1 or len(set(confidence_scores)) > 1
    
    def test_calculate_risk_level(self):
        """Test risk level calculation."""
        plugin = URLVoidDomainPlugin()
        
        assert plugin._calculate_risk_level(0.9) == 'high'
        assert plugin._calculate_risk_level(0.7) == 'medium'
        assert plugin._calculate_risk_level(0.4) == 'low'
        assert plugin._calculate_risk_level(0.1) == 'minimal'


class TestVirusTotalDomainPlugin:
    """Test cases for VirusTotal domain reputation plugin."""
    
    def test_initialization_without_api_key(self):
        """Test plugin initialization without API key."""
        plugin = VirusTotalDomainPlugin()
        assert plugin.name == "VirusTotal-Domain"
        assert plugin.api_key is None
        assert plugin.is_available()
    
    def test_initialization_with_api_key(self):
        """Test plugin initialization with API key."""
        plugin = VirusTotalDomainPlugin(api_key="test_key")
        assert plugin.api_key == "test_key"
    
    def test_mock_reputation_structure(self):
        """Test mock reputation data structure."""
        plugin = VirusTotalDomainPlugin()
        result = plugin.get_domain_reputation("example.com")
        
        expected_keys = [
            'is_malicious', 'confidence_score', 'threat_types', 'categories',
            'engines_total', 'engines_detected', 'detection_ratio',
            'detecting_vendors', 'scan_date', 'reputation_score',
            'harmless_votes', 'malicious_votes', 'note'
        ]
        
        for key in expected_keys:
            assert key in result, f"Missing key: {key}"
    
    def test_detection_rate_calculation(self):
        """Test detection rate calculation logic."""
        plugin = VirusTotalDomainPlugin()
        
        # Test different hash values to verify rate calculation logic
        test_domains = [
            "malicious-test.com",  # Should potentially trigger high detection
            "clean-test.com",      # Should potentially be clean
            "suspicious-test.com"  # Should potentially be suspicious
        ]
        
        results = [plugin.get_domain_reputation(domain) for domain in test_domains]
        
        # Verify all results have valid detection ratios
        for result in results:
            engines_total = result['engines_total']
            engines_detected = result['engines_detected']
            assert 0 <= engines_detected <= engines_total
            assert engines_total > 0
    
    def test_threat_type_logic(self):
        """Test threat type assignment logic."""
        plugin = VirusTotalDomainPlugin()
        
        # Test many domains to see variety in threat types
        domains = [f"test{i}.com" for i in range(20)]
        results = [plugin.get_domain_reputation(domain) for domain in domains]
        
        # Collect all threat types seen
        all_threat_types = set()
        for result in results:
            all_threat_types.update(result['threat_types'])
        
        # Should see some variety in threat types
        possible_types = ['malware', 'phishing', 'suspicious', 'potentially-unwanted']
        assert len(all_threat_types.intersection(possible_types)) > 0


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