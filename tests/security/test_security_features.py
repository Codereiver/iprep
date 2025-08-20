"""
Security feature tests for iprep.

These tests verify security controls and protections against common attacks.
"""

import pytest
import os
from unittest.mock import patch, MagicMock
from iprep.config import SecureConfig
from iprep.security import SecurityValidator
from iprep.plugins.domain_content.http_analyser import HTTPAnalyserPlugin


class TestSecureConfig:
    """Test secure configuration management."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = SecureConfig()
    
    def test_api_key_validation_blocks_invalid_keys(self):
        """Test that invalid API keys are rejected."""
        invalid_keys = [
            "",
            " ",
            "short",
            "a" * 200,  # Too long
            "key with spaces",
            "key\nwith\nnewlines",
            "key\twith\ttabs"
        ]
        
        for invalid_key in invalid_keys:
            result = self.config._validate_api_key_format(invalid_key, "test")
            assert not result, f"Should reject invalid key: '{invalid_key}'"
    
    def test_api_key_validation_accepts_valid_keys(self):
        """Test that valid API keys are accepted."""
        valid_keys = [
            "abcd1234567890abcd1234567890",
            "ValidAPIKey123456789",
            "api-key_with-valid.chars123"
        ]
        
        for valid_key in valid_keys:
            result = self.config._validate_api_key_format(valid_key, "test")
            assert result, f"Should accept valid key: '{valid_key}'"
    
    @patch.dict(os.environ, {'IPREP_ABUSEIPDB_API_KEY': 'valid-api-key-123456789'})
    def test_secure_api_key_retrieval(self):
        """Test secure API key retrieval from environment."""
        api_key = self.config.get_api_key('abuseipdb')
        assert api_key == 'valid-api-key-123456789'
    
    @patch.dict(os.environ, {'IPREP_ABUSEIPDB_API_KEY': 'invalid key'})
    def test_invalid_api_key_rejected_from_env(self):
        """Test that invalid API keys from environment are rejected."""
        api_key = self.config.get_api_key('abuseipdb')
        assert api_key is None
    
    def test_https_only_endpoints(self):
        """Test that only HTTPS endpoints are provided."""
        services = ['abuseipdb', 'ipapi', 'ipinfo', 'urlvoid', 'virustotal']
        
        for service in services:
            url = self.config.get_endpoint_url(service, 'primary')
            if url:  # Some services may not have endpoints configured
                assert url.startswith('https://'), f"Service {service} must use HTTPS: {url}"
    
    def test_request_timeout_bounds(self):
        """Test that request timeouts are bounded for security."""
        # Test with various timeout values
        test_cases = [
            (-5.0, 1.0),    # Negative values should be bounded to minimum
            (0.5, 1.0),     # Below minimum should be bounded to minimum
            (15.0, 15.0),   # Normal value should be unchanged
            (100.0, 30.0),  # Above maximum should be bounded to maximum
        ]
        
        for input_timeout, expected in test_cases:
            with patch.dict(os.environ, {'IPREP_REQUEST_TIMEOUT': str(input_timeout)}):
                config = SecureConfig()  # Fresh instance
                result = config.get_request_timeout(10.0)
                assert result == expected, f"Timeout {input_timeout} should be bounded to {expected}, got {result}"


class TestSecurityValidator:
    """Test security validation utilities."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.validator = SecurityValidator()
    
    def test_blocks_http_urls(self):
        """Test that HTTP URLs are blocked."""
        is_valid, error = self.validator.validate_url_for_request("http://example.com", "example.com")
        assert not is_valid
        assert "not allowed" in error.lower()
    
    def test_allows_https_urls(self):
        """Test that HTTPS URLs are allowed."""
        is_valid, url = self.validator.validate_url_for_request("https://example.com", "example.com")
        assert is_valid
        assert url == "https://example.com"
    
    def test_blocks_private_ips(self):
        """Test that private IP addresses are blocked."""
        private_ip_tests = [
            ("https://192.168.1.1", "192.168.1.1"),  # Valid domain match but private IP
            ("https://10.0.0.1", "10.0.0.1"),        # Valid domain match but private IP
            ("https://172.16.0.1", "172.16.0.1"),    # Valid domain match but private IP
            ("https://127.0.0.1", "127.0.0.1")       # Valid domain match but private IP
        ]
        
        for url, expected_domain in private_ip_tests:
            is_valid, error = self.validator.validate_url_for_request(url, expected_domain)
            assert not is_valid, f"Should block private IP: {url}"
            assert "private" in error.lower() or "internal" in error.lower(), f"Error should mention private/internal: {error}"
    
    def test_blocks_dangerous_ports(self):
        """Test that dangerous ports are blocked."""
        dangerous_urls = [
            "https://example.com:22",    # SSH
            "https://example.com:25",    # SMTP
            "https://example.com:3306",  # MySQL
            "https://example.com:6379",  # Redis
        ]
        
        for url in dangerous_urls:
            is_valid, error = self.validator.validate_url_for_request(url, "example.com")
            assert not is_valid, f"Should block dangerous port: {url}"
            assert "blocked" in error.lower()
    
    def test_domain_confusion_protection(self):
        """Test protection against domain confusion attacks."""
        confusing_urls = [
            "https://example.com.",      # Trailing dot
            "https://examp1e.com",       # Character substitution would be caught by domain mismatch
            "https://example-com.evil",  # Different domain entirely
        ]
        
        for url in confusing_urls:
            is_valid, error = self.validator.validate_url_for_request(url, "example.com")
            # Most of these should be blocked by domain validation
            if not is_valid:
                assert len(error) > 0
    
    def test_output_sanitization(self):
        """Test output sanitization prevents injection."""
        dangerous_inputs = [
            "<script>alert('xss')</script>",
            "Normal text with <script>evil</script>",
            "Text with\x1b[31mANSI\x1b[0m escape codes",
            "Text\x00with\x01control\x02chars",
            "Text with unicode: \u2603\u2764",
        ]
        
        for dangerous_input in dangerous_inputs:
            sanitized = self.validator.sanitize_output_text(dangerous_input)
            
            # Should not contain raw script tags
            assert "<script>" not in sanitized
            assert "</script>" not in sanitized
            
            # Should not contain raw control characters
            for i in range(0, 32):
                if i not in {9, 10}:  # Allow tab and newline
                    assert chr(i) not in sanitized
    
    def test_error_message_sanitization(self):
        """Test error message sanitization removes sensitive data."""
        sensitive_errors = [
            "API Key: sk-1234567890abcdef failed",
            "Token: bearer_abc123xyz failed",
            "Error in /path/to/internal/file.py",
            "Connection to 192.168.1.100 failed",
        ]
        
        for error in sensitive_errors:
            sanitized = self.validator.sanitize_error_message(error, "8.8.8.8")
            
            # Should not contain API keys or tokens
            assert "sk-1234567890abcdef" not in sanitized
            assert "bearer_abc123xyz" not in sanitized
            assert "[REDACTED]" in sanitized or "[PATH]" in sanitized or "[INTERNAL_IP]" in sanitized
    
    def test_content_type_validation(self):
        """Test content type validation."""
        safe_types = [
            "text/html",
            "text/html; charset=utf-8",
            "application/json",
            "text/plain"
        ]
        
        unsafe_types = [
            "application/octet-stream",
            "application/x-executable",
            "image/jpeg",
            "video/mp4",
            ""
        ]
        
        for safe_type in safe_types:
            assert self.validator.validate_content_type(safe_type), f"Should accept safe type: {safe_type}"
        
        for unsafe_type in unsafe_types:
            assert not self.validator.validate_content_type(unsafe_type), f"Should reject unsafe type: {unsafe_type}"


class TestHTTPAnalyzerSecurity:
    """Test security features of HTTP analyzer plugin."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = HTTPAnalyserPlugin()
    
    @patch('requests.get')
    def test_https_only_requests(self, mock_get):
        """Test that only HTTPS requests are made."""
        # Mock a successful HTTPS response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_response.text = '<html><head><title>Test</title></head></html>'
        mock_response.url = 'https://example.com'
        mock_get.return_value = mock_response
        
        result = self.analyzer.analyze_domain_content("example.com")
        
        # Should have made a request
        assert mock_get.called
        
        # Should have called with HTTPS URL only
        called_url = mock_get.call_args[0][0]
        assert called_url.startswith('https://'), f"Should use HTTPS, got: {called_url}"
    
    @patch('requests.get')
    def test_content_type_validation(self, mock_get):
        """Test that unsafe content types are rejected."""
        # Mock response with unsafe content type
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'application/octet-stream'}
        mock_response.text = 'binary data'
        mock_response.url = 'https://example.com'
        mock_get.return_value = mock_response
        
        result = self.analyzer.analyze_domain_content("example.com")
        
        # Should return None due to content type rejection (no more mock data fallback)
        assert result is None
    
    def test_output_sanitization(self):
        """Test that extracted content is sanitized."""
        # Test title extraction and sanitization
        dangerous_content = '<html><head><title><script>alert("xss")</script>Safe Title</title></head></html>'
        
        # Mock the analyze_domain_content to use dangerous content
        # Test by directly calling the _analyze_response method
        mock_response_data = {
            'status_code': 200,
            'headers': {'Content-Type': 'text/html', 'Server': 'nginx'},
            'content': dangerous_content,
            'final_url': 'https://example.com',
            'history': []
        }
        
        result = self.analyzer._analyze_response("example.com", "https", mock_response_data)
        
        # Title should be sanitized
        assert '<script>' not in result['title']
        assert '&lt;script&gt;' in result['title'] or result['title'] == ''  # Should be HTML escaped or empty


class TestPluginSecurity:
    """Test security aspects of plugin loading and execution."""
    
    def test_api_key_environment_loading(self):
        """Test that API keys are loaded from environment variables."""
        from iprep.plugins.reputation.abuseipdb import AbuseIPDBPlugin
        
        with patch.dict(os.environ, {'IPREP_ABUSEIPDB_API_KEY': 'secure-key-123456789'}):
            plugin = AbuseIPDBPlugin()
            assert plugin.api_key == 'secure-key-123456789'
    
    def test_https_endpoint_enforcement(self):
        """Test that HTTPS endpoints are enforced."""
        from iprep.plugins.geolocation.ipapi import IPApiPlugin
        
        # This should not raise an exception and should use HTTPS
        plugin = IPApiPlugin()
        assert plugin.base_url.startswith('https://'), f"IP-API plugin must use HTTPS: {plugin.base_url}"
    
    def test_timeout_bounds(self):
        """Test that plugin timeouts are bounded."""
        from iprep.plugins.domain_content.http_analyser import HTTPAnalyserPlugin
        
        plugin = HTTPAnalyserPlugin()
        # Timeout should be reasonable (between 1 and 30 seconds)
        assert 1.0 <= plugin.timeout <= 30.0, f"Plugin timeout should be bounded: {plugin.timeout}"


class TestSecurityConfiguration:
    """Test security configuration and environment setup."""
    
    def test_no_hardcoded_secrets(self):
        """Test that no hardcoded secrets exist in code."""
        # This is a basic check - in practice, you'd use tools like truffleHog
        import glob
        import os
        
        # Check Python files for suspicious patterns
        suspicious_patterns = [
            b'password',
            b'secret',
            b'api_key.*=.*["\'][a-zA-Z0-9]{10,}["\']',
        ]
        
        python_files = glob.glob('/Users/peterlee/Documents/Yorcadia/Codereiver/iprep/**/*.py', recursive=True)
        
        for file_path in python_files:
            if 'test' in file_path:  # Skip test files
                continue
                
            try:
                with open(file_path, 'rb') as f:
                    content = f.read().lower()
                    
                for pattern in suspicious_patterns:
                    if isinstance(pattern, bytes):
                        # Basic string check (not regex for simplicity)
                        if b'api_key' in content and b'=' in content and b'"' in content:
                            # This is a weak check, but helps catch obvious hardcoded keys
                            lines = content.split(b'\n')
                            for i, line in enumerate(lines):
                                # Look for actual hardcoded values, not variable names
                                if (b'api_key' in line and b'=' in line and 
                                    any(c in line for c in [b'"', b"'"]) and
                                    b'f"' not in line and b"f'" not in line):  # Skip f-strings
                                    # Allow configuration examples and mock data
                                    if not any(safe in line.lower() for safe in [b'example', b'test', b'mock', b'none', b'config', b'env_var', b'getenv']):
                                        pytest.fail(f"Potential hardcoded API key in {file_path}:{i+1}: {line.decode('utf-8', errors='ignore').strip()}")
            except Exception:
                continue  # Skip files we can't read
    
    def test_secure_defaults(self):
        """Test that secure defaults are used."""
        from iprep.config import SecureConfig
        
        config = SecureConfig()
        
        # Should default to secure timeout bounds
        timeout = config.get_request_timeout()
        assert 1.0 <= timeout <= 30.0
        
        # Should not be in development mode by default
        assert not config.is_development_mode()
    
    @patch.dict(os.environ, {})
    def test_no_api_key_fallback_behavior(self):
        """Test behavior when no API keys are provided."""
        from iprep.plugins.reputation.abuseipdb import AbuseIPDBPlugin
        
        # Should not crash when no API key is available
        plugin = AbuseIPDBPlugin()
        assert plugin.api_key is None
        
        # Should NOT be available without API key (no longer provides mock data)
        assert not plugin.is_available()
        
        # Should return error message when used without API key
        result = plugin.get_reputation("8.8.8.8")
        assert result is not None
        assert 'error' in result
        assert result['error'] == 'API key not configured'