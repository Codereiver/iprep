"""
Tests for geolocation plugins using requests library.
"""

import pytest
from unittest.mock import patch, MagicMock
import requests
from iprep.plugins.geolocation.ipapi import IPApiPlugin
from iprep.plugins.geolocation.ipinfo import IPinfoPlugin


class TestIPApiPlugin:
    """Test cases for IPApiPlugin."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.plugin = IPApiPlugin()
    
    def test_initialization(self):
        """Test plugin initialization."""
        assert self.plugin.name == "IP-API"
        assert self.plugin.timeout == 10
        assert self.plugin.rate_limit_delay == 1.0
        assert self.plugin.base_url.startswith("https://")  # Should use secure HTTPS endpoint
    
    @patch('requests.get')
    def test_successful_geolocation(self, mock_get):
        """Test successful geolocation lookup."""
        mock_response_data = {
            "status": "success",
            "country": "United States",
            "countryCode": "US",
            "regionName": "California",
            "city": "Mountain View",
            "lat": 37.4056,
            "lon": -122.0775,
            "timezone": "America/Los_Angeles",
            "isp": "Google LLC",
            "org": "Google LLC",
            "as": "AS15169 Google LLC",
            "query": "8.8.8.8"
        }
        
        mock_response = MagicMock()
        mock_response.json.return_value = mock_response_data
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        result = self.plugin.get_geolocation("8.8.8.8")
        
        assert result is not None
        assert result['country'] == 'United States'
        assert result['country_code'] == 'US'
        assert result['region'] == 'California'
        assert result['city'] == 'Mountain View'
        assert result['latitude'] == 37.4056
        assert result['longitude'] == -122.0775
        assert result['timezone'] == 'America/Los_Angeles'
        assert result['isp'] == 'Google LLC'
        assert result['organization'] == 'Google LLC'
        assert result['asn'] == 'AS15169 Google LLC'
    
    @patch('requests.get')
    def test_failed_status_response(self, mock_get):
        """Test handling of failed status response."""
        mock_response_data = {
            "status": "fail",
            "message": "invalid query",
            "query": "invalid_ip"
        }
        
        mock_response = MagicMock()
        mock_response.json.return_value = mock_response_data
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        result = self.plugin.get_geolocation("invalid_ip")
        
        assert result is None
    
    @patch('requests.get')
    def test_network_error(self, mock_get):
        """Test handling of network errors."""
        mock_get.side_effect = requests.exceptions.RequestException("Network error")
        
        with patch.object(self.plugin, '_handle_request_error') as mock_handle_error:
            result = self.plugin.get_geolocation("8.8.8.8")
            
            assert result is None
            mock_handle_error.assert_called_once()
    
    @patch('requests.get')
    def test_http_error(self, mock_get):
        """Test handling of HTTP errors."""
        mock_get.side_effect = requests.exceptions.HTTPError("Too Many Requests")
        
        with patch.object(self.plugin, '_handle_request_error') as mock_handle_error:
            result = self.plugin.get_geolocation("8.8.8.8")
            
            assert result is None
            mock_handle_error.assert_called_once()
    
    @patch('requests.get')
    def test_json_decode_error(self, mock_get):
        """Test handling of JSON decode errors."""
        mock_response = MagicMock()
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        with patch.object(self.plugin, '_handle_request_error') as mock_handle_error:
            result = self.plugin.get_geolocation("8.8.8.8")
            
            assert result is None
            mock_handle_error.assert_called_once()
    
    @patch('requests.get')
    def test_check_ip_integration(self, mock_get):
        """Test check_ip method integration."""
        mock_response_data = {
            "status": "success",
            "country": "Germany",
            "countryCode": "DE",
            "query": "1.1.1.1"
        }
        
        mock_response = MagicMock()
        mock_response.json.return_value = mock_response_data
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        result = self.plugin.check_ip("1.1.1.1")
        
        assert result is not None
        assert result['source'] == 'IP-API'
        assert result['ip_address'] == '1.1.1.1'
        assert result['geolocation']['country'] == 'Germany'
    
    def test_rate_limiting(self):
        """Test that rate limiting is enforced."""
        with patch.object(self.plugin, '_enforce_rate_limit') as mock_rate_limit:
            with patch('requests.get') as mock_get:
                mock_response = MagicMock()
                mock_response.json.return_value = {"status": "success"}
                mock_response.raise_for_status.return_value = None
                mock_get.return_value = mock_response
                
                self.plugin.get_geolocation("8.8.8.8")
                
                mock_rate_limit.assert_called_once()


class TestIPinfoPlugin:
    """Test cases for IPinfoPlugin."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.plugin = IPinfoPlugin()
    
    def test_initialization(self):
        """Test plugin initialization."""
        assert self.plugin.name == "IPinfo"
        assert self.plugin.timeout == 10
        assert self.plugin.rate_limit_delay == 1.0
        assert self.plugin.base_url == "https://ipinfo.io"
    
    @patch('requests.get')
    def test_successful_geolocation(self, mock_get):
        """Test successful geolocation lookup."""
        mock_response_data = {
            "ip": "8.8.8.8",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "loc": "37.4056,-122.0775",
            "postal": "94043",
            "timezone": "America/Los_Angeles",
            "org": "AS15169 Google LLC",
            "hostname": "dns.google"
        }
        
        mock_response = MagicMock()
        mock_response.json.return_value = mock_response_data
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        result = self.plugin.get_geolocation("8.8.8.8")
        
        assert result is not None
        assert result['country'] == 'US'
        assert result['region'] == 'California'
        assert result['city'] == 'Mountain View'
        assert result['latitude'] == 37.4056
        assert result['longitude'] == -122.0775
        assert result['timezone'] == 'America/Los_Angeles'
        assert result['postal_code'] == '94043'
        assert result['organization'] == 'AS15169 Google LLC'
        assert result['hostname'] == 'dns.google'
    
    @patch('requests.get')
    def test_coordinates_parsing(self, mock_get):
        """Test parsing of location coordinates."""
        mock_response_data = {
            "ip": "1.1.1.1",
            "loc": "-33.8688,151.2093"
        }
        
        mock_response = MagicMock()
        mock_response.json.return_value = mock_response_data
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        result = self.plugin.get_geolocation("1.1.1.1")
        
        assert result['latitude'] == -33.8688
        assert result['longitude'] == 151.2093
    
    @patch('requests.get')
    def test_missing_coordinates(self, mock_get):
        """Test handling of missing coordinates."""
        mock_response_data = {
            "ip": "192.168.1.1",
            "city": "Private"
        }
        
        mock_response = MagicMock()
        mock_response.json.return_value = mock_response_data
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        result = self.plugin.get_geolocation("192.168.1.1")
        
        assert result['latitude'] is None
        assert result['longitude'] is None
        assert result['city'] == 'Private'
    
    @patch('requests.get')
    def test_error_response(self, mock_get):
        """Test handling of error responses."""
        mock_response_data = {
            "error": {
                "title": "Wrong ip",
                "message": "Please provide a valid IP address"
            }
        }
        
        mock_response = MagicMock()
        mock_response.json.return_value = mock_response_data
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        result = self.plugin.get_geolocation("invalid_ip")
        
        assert result is None
    
    @patch('requests.get')
    def test_malformed_coordinates(self, mock_get):
        """Test handling of malformed coordinates."""
        mock_response_data = {
            "ip": "1.1.1.1",
            "loc": "invalid_coordinates"
        }
        
        mock_response = MagicMock()
        mock_response.json.return_value = mock_response_data
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        result = self.plugin.get_geolocation("1.1.1.1")
        
        assert result['latitude'] is None
        assert result['longitude'] is None
    
    @patch('requests.get')
    def test_network_error(self, mock_get):
        """Test handling of network errors."""
        mock_get.side_effect = requests.exceptions.RequestException("Network error")
        
        with patch.object(self.plugin, '_handle_request_error') as mock_handle_error:
            result = self.plugin.get_geolocation("8.8.8.8")
            
            assert result is None
            mock_handle_error.assert_called_once()
    
    @patch('requests.get')
    def test_check_ip_integration(self, mock_get):
        """Test check_ip method integration."""
        mock_response_data = {
            "ip": "9.9.9.9",
            "country": "US",
            "city": "San Francisco"
        }
        
        mock_response = MagicMock()
        mock_response.json.return_value = mock_response_data
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        result = self.plugin.check_ip("9.9.9.9")
        
        assert result is not None
        assert result['source'] == 'IPinfo'
        assert result['ip_address'] == '9.9.9.9'
        assert result['geolocation']['country'] == 'US'
        assert result['geolocation']['city'] == 'San Francisco'