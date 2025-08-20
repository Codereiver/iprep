"""
Tests for reputation plugins.
"""

import pytest
import json
from unittest.mock import patch, MagicMock
import requests
from iprep.plugins.reputation.abuseipdb import AbuseIPDBPlugin
from iprep.plugins.reputation.urlvoid import URLVoidPlugin


class TestAbuseIPDBPlugin:
    """Test cases for AbuseIPDBPlugin."""
    
    def test_initialization_without_api_key(self):
        """Test plugin initialization without API key."""
        plugin = AbuseIPDBPlugin()
        
        assert plugin.name == "AbuseIPDB"
        assert plugin.timeout == 10
        assert plugin.rate_limit_delay == 1.0
        assert plugin.api_key is None
        assert plugin.base_url == "https://api.abuseipdb.com/api/v2/check"
    
    def test_initialization_with_api_key(self):
        """Test plugin initialization with API key."""
        plugin = AbuseIPDBPlugin(api_key="test_key")
        
        assert plugin.api_key == "test_key"
    
    def test_no_api_key_returns_error(self):
        """Test that plugin returns error when no API key is provided."""
        plugin = AbuseIPDBPlugin()
        
        result = plugin.get_reputation("1.2.3.4")
        
        assert result is not None
        assert 'error' in result
        assert result['error'] == 'API key not configured'
        assert 'IPREP_ABUSEIPDB_API_KEY' in result['message']
        assert result['plugin'] == 'AbuseIPDB'
    
    def test_no_api_key_consistent_error(self):
        """Test that plugin returns consistent error for any IP without API key."""
        plugin = AbuseIPDBPlugin()
        
        # Test different IPs all return same error
        ips = ["192.168.1.1", "8.8.8.8", "1.1.1.1"]
        for ip in ips:
            result = plugin.get_reputation(ip)
            assert result is not None
            assert 'error' in result
            assert result['error'] == 'API key not configured'
            assert 'IPREP_ABUSEIPDB_API_KEY' in result['message']
    
    def test_is_available_without_api_key(self):
        """Test that plugin is not available without API key."""
        plugin = AbuseIPDBPlugin()
        assert plugin.is_available() is False
    
    @patch('requests.get')
    def test_api_successful_response(self, mock_get):
        """Test successful API response with API key."""
        # Use a valid-length API key
        plugin = AbuseIPDBPlugin(api_key="test123456789012345678901234567890")
        
        mock_response_data = {
            "data": {
                "ipAddress": "1.2.3.4",
                "isPublic": True,
                "ipVersion": 4,
                "isWhitelisted": False,
                "abuseConfidencePercentage": 75,
                "countryCode": "US",
                "usageType": "datacenter",
                "isp": "Test ISP",
                "domain": "test.com",
                "totalReports": 10,
                "numDistinctUsers": 5,
                "lastReportedAt": "2024-01-15T10:30:00+00:00"
            }
        }
        
        mock_response = MagicMock()
        mock_response.json.return_value = mock_response_data
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        result = plugin.get_reputation("1.2.3.4")
        
        assert result is not None
        assert result['is_malicious'] is True
        assert result['confidence_score'] == 0.75
        assert result['abuse_confidence'] == 75
        assert result['usage_type'] == 'datacenter'
        assert result['isp'] == 'Test ISP'
        assert result['domain'] == 'test.com'
        assert result['country_code'] == 'US'
        assert result['is_whitelisted'] is False
        assert result['total_reports'] == 10
        assert result['last_reported'] == "2024-01-15T10:30:00+00:00"
    
    @patch('requests.get')
    def test_api_low_confidence_response(self, mock_get):
        """Test API response with low confidence (clean IP)."""
        plugin = AbuseIPDBPlugin(api_key="test123456789012345678901234567890")
        
        mock_response_data = {
            "data": {
                "ipAddress": "8.8.8.8",
                "abuseConfidencePercentage": 10,
                "totalReports": 1,
                "isWhitelisted": False
            }
        }
        
        mock_response = MagicMock()
        mock_response.json.return_value = mock_response_data
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        result = plugin.get_reputation("8.8.8.8")
        
        assert result is not None
        assert result['is_malicious'] is False
        assert result['confidence_score'] == 0.10
    
    @patch('urllib.request.urlopen')
    def test_api_invalid_response(self, mock_urlopen):
        """Test handling of invalid API response."""
        plugin = AbuseIPDBPlugin(api_key="test123456789012345678901234567890")
        
        mock_response_data = {
            "error": "Invalid API key"
        }
        
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(mock_response_data).encode('utf-8')
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response
        
        result = plugin.get_reputation("1.2.3.4")
        
        assert result is None
    
    @patch('requests.get')
    def test_api_network_error(self, mock_get):
        """Test handling of network errors with API key."""
        plugin = AbuseIPDBPlugin(api_key="test123456789012345678901234567890")
        mock_get.side_effect = requests.exceptions.RequestException("Network error")
        
        with patch.object(plugin, '_handle_request_error') as mock_handle_error:
            result = plugin.get_reputation("1.2.3.4")
            
            assert result is None
            mock_handle_error.assert_called_once()
    
    def test_is_available_with_api_key(self):
        """Test availability check with API key."""
        plugin = AbuseIPDBPlugin(api_key="test123456789012345678901234567890")
        assert plugin.is_available() is True
    
    def test_check_ip_integration_mock(self):
        """Test check_ip method returns error without API key."""
        plugin = AbuseIPDBPlugin()
        
        result = plugin.check_ip("1.2.3.4")
        
        assert result is not None
        assert result['source'] == 'AbuseIPDB'
        assert result['ip_address'] == '1.2.3.4'
        assert 'error' in result['reputation']
        assert result['reputation']['error'] == 'API key not configured'


class TestURLVoidPlugin:
    """Test cases for URLVoidPlugin."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.plugin = URLVoidPlugin()
    
    def test_initialization(self):
        """Test plugin initialization."""
        assert self.plugin.name == "URLVoid"
        assert self.plugin.timeout == 10
        assert self.plugin.rate_limit_delay == 1.5
    
    def test_returns_none(self):
        """Test that plugin returns None (not implemented)."""
        ip = "192.168.1.100"
        
        result = self.plugin.get_reputation(ip)
        
        assert result is None
    
    def test_botnet_detection_not_implemented(self):
        """Test that plugin returns None for all IPs (not implemented)."""
        test_ips = ["192.168.1.1", "10.0.0.2", "172.16.0.3"]
        
        for ip in test_ips:
            result = self.plugin.get_reputation(ip)
            assert result is None
    
    def test_malware_detection_not_implemented(self):
        """Test that plugin returns None for all IPs (not implemented)."""
        test_ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        
        for ip in test_ips:
            result = self.plugin.get_reputation(ip)
            assert result is None
    
    def test_suspicious_activity_detection_not_implemented(self):
        """Test that plugin returns None for all IPs (not implemented)."""
        test_ips = ["203.0.113.5", "198.51.100.10"]
        
        for ip in test_ips:
            result = self.plugin.get_reputation(ip)
            assert result is None
    
    def test_scanning_detection_not_implemented(self):
        """Test that plugin returns None for all IPs (not implemented)."""
        test_ips = ["10.1.1.3", "172.31.255.6"]
        
        for ip in test_ips:
            result = self.plugin.get_reputation(ip)
            assert result is None
    
    def test_clean_ip_not_implemented(self):
        """Test that plugin returns None for all IPs (not implemented)."""
        ip = "127.0.0.1"
        result = self.plugin.get_reputation(ip)
        assert result is None
    
    def test_engines_calculation_not_implemented(self):
        """Test that plugin returns None (not implemented)."""
        ip = "192.0.2.1"
        result = self.plugin.get_reputation(ip)
        assert result is None
    
    def test_risk_level_calculation_not_implemented(self):
        """Test that plugin no longer implements risk level calculation (not implemented)."""
        # Plugin is not implemented, no risk level calculation exists
        result = self.plugin.get_reputation("1.2.3.4")
        assert result is None
    
    def test_metadata_fields_not_implemented(self):
        """Test that plugin returns None (not implemented)."""
        result = self.plugin.get_reputation("203.0.113.100")
        assert result is None
    
    def test_rate_limiting(self):
        """Test that rate limiting is enforced."""
        with patch.object(self.plugin, '_enforce_rate_limit') as mock_rate_limit:
            self.plugin.get_reputation("8.8.8.8")
            mock_rate_limit.assert_called_once()
    
    def test_error_handling(self):
        """Test error handling in plugin."""
        # Plugin already returns None by default, test that no exceptions are raised
        result = self.plugin.get_reputation("1.1.1.1")
        assert result is None
    
    def test_check_ip_integration(self):
        """Test check_ip method integration."""
        result = self.plugin.check_ip("198.51.100.200")
        
        # Plugin returns None instead of a result structure
        assert result is None