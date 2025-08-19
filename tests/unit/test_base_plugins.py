"""
Unit tests for base plugin classes.
"""

import time
import pytest
from unittest.mock import patch, MagicMock
from iprep.plugins.base import BasePlugin, GeolocationPlugin, ReputationPlugin


class MockBasePlugin(BasePlugin):
    """Mock implementation of BasePlugin for testing."""
    
    def __init__(self, name="MockPlugin", timeout=10, rate_limit_delay=0.0):
        super().__init__(name, timeout, rate_limit_delay)
        self.check_ip_called = False
        self.mock_result = None
    
    def check_ip(self, ip_address):
        self.check_ip_called = True
        return self.mock_result


class MockGeolocationPlugin(GeolocationPlugin):
    """Mock implementation of GeolocationPlugin for testing."""
    
    def __init__(self):
        super().__init__("MockGeo", timeout=5, rate_limit_delay=0.1)
        self.get_geolocation_called = False
        self.mock_geo_data = None
    
    def get_geolocation(self, ip_address):
        self.get_geolocation_called = True
        return self.mock_geo_data


class MockReputationPlugin(ReputationPlugin):
    """Mock implementation of ReputationPlugin for testing."""
    
    def __init__(self):
        super().__init__("MockRep", timeout=5, rate_limit_delay=0.1)
        self.get_reputation_called = False
        self.mock_rep_data = None
    
    def get_reputation(self, ip_address):
        self.get_reputation_called = True
        return self.mock_rep_data


class TestBasePlugin:
    """Test cases for BasePlugin class."""
    
    def test_initialization(self):
        """Test plugin initialization."""
        plugin = MockBasePlugin("TestPlugin", timeout=15, rate_limit_delay=0.5)
        
        assert plugin.name == "TestPlugin"
        assert plugin.timeout == 15
        assert plugin.rate_limit_delay == 0.5
        assert plugin._last_request_time == 0.0
    
    def test_rate_limiting(self):
        """Test rate limiting functionality."""
        plugin = MockBasePlugin(rate_limit_delay=0.1)
        
        start_time = time.time()
        plugin._enforce_rate_limit()
        first_call_time = time.time()
        
        plugin._enforce_rate_limit()
        second_call_time = time.time()
        
        elapsed = second_call_time - first_call_time
        assert elapsed >= 0.1, "Rate limiting should enforce delay"
    
    def test_no_rate_limiting(self):
        """Test behavior when rate limiting is disabled."""
        plugin = MockBasePlugin(rate_limit_delay=0.0)
        
        start_time = time.time()
        plugin._enforce_rate_limit()
        plugin._enforce_rate_limit()
        end_time = time.time()
        
        elapsed = end_time - start_time
        assert elapsed < 0.05, "No delay should be enforced when rate_limit_delay is 0"
    
    @patch('builtins.print')
    def test_handle_request_error(self, mock_print):
        """Test error handling."""
        plugin = MockBasePlugin()
        error = Exception("Test error")
        
        plugin._handle_request_error(error, "192.168.1.1")
        
        mock_print.assert_called_once()
        call_args = mock_print.call_args[0][0]
        assert "MockPlugin" in call_args
        assert "192.168.1.1" in call_args
        assert "Test error" in call_args
    
    def test_is_available_default(self):
        """Test default availability check."""
        plugin = MockBasePlugin()
        assert plugin.is_available() is True
    
    def test_abstract_check_ip(self):
        """Test that BasePlugin can have concrete check_ip implementation."""
        plugin = MockBasePlugin()
        plugin.mock_result = {"test": "data"}
        
        result = plugin.check_ip("8.8.8.8")
        
        assert plugin.check_ip_called is True
        assert result == {"test": "data"}


class TestGeolocationPlugin:
    """Test cases for GeolocationPlugin class."""
    
    def test_check_ip_with_geolocation_data(self):
        """Test check_ip method with valid geolocation data."""
        plugin = MockGeolocationPlugin()
        plugin.mock_geo_data = {
            'country': 'United States',
            'city': 'Mountain View',
            'latitude': 37.4056,
            'longitude': -122.0775
        }
        
        result = plugin.check_ip("8.8.8.8")
        
        assert plugin.get_geolocation_called is True
        assert result is not None
        assert result['source'] == 'MockGeo'
        assert result['ip_address'] == '8.8.8.8'
        assert result['geolocation']['country'] == 'United States'
        assert result['geolocation']['city'] == 'Mountain View'
    
    def test_check_ip_with_no_geolocation_data(self):
        """Test check_ip method when no geolocation data is available."""
        plugin = MockGeolocationPlugin()
        plugin.mock_geo_data = None
        
        result = plugin.check_ip("192.168.1.1")
        
        assert plugin.get_geolocation_called is True
        assert result is None
    
    def test_check_ip_with_empty_geolocation_data(self):
        """Test check_ip method with empty geolocation data."""
        plugin = MockGeolocationPlugin()
        plugin.mock_geo_data = {}
        
        result = plugin.check_ip("10.0.0.1")
        
        assert plugin.get_geolocation_called is True
        assert result is not None
        assert result['geolocation'] == {}
    
    def test_abstract_get_geolocation(self):
        """Test that get_geolocation is properly implemented in mock."""
        plugin = MockGeolocationPlugin()
        plugin.mock_geo_data = {'country': 'Test Country'}
        
        result = plugin.get_geolocation("1.1.1.1")
        
        assert result == {'country': 'Test Country'}


class TestReputationPlugin:
    """Test cases for ReputationPlugin class."""
    
    def test_check_ip_with_reputation_data(self):
        """Test check_ip method with valid reputation data."""
        plugin = MockReputationPlugin()
        plugin.mock_rep_data = {
            'is_malicious': True,
            'threat_types': ['malware', 'botnet'],
            'confidence_score': 0.85
        }
        
        result = plugin.check_ip("1.2.3.4")
        
        assert plugin.get_reputation_called is True
        assert result is not None
        assert result['source'] == 'MockRep'
        assert result['ip_address'] == '1.2.3.4'
        assert result['reputation']['is_malicious'] is True
        assert result['reputation']['threat_types'] == ['malware', 'botnet']
    
    def test_check_ip_with_no_reputation_data(self):
        """Test check_ip method when no reputation data is available."""
        plugin = MockReputationPlugin()
        plugin.mock_rep_data = None
        
        result = plugin.check_ip("8.8.8.8")
        
        assert plugin.get_reputation_called is True
        assert result is None
    
    def test_check_ip_with_empty_reputation_data(self):
        """Test check_ip method with empty reputation data."""
        plugin = MockReputationPlugin()
        plugin.mock_rep_data = {}
        
        result = plugin.check_ip("127.0.0.1")
        
        assert plugin.get_reputation_called is True
        assert result is not None
        assert result['reputation'] == {}
    
    def test_abstract_get_reputation(self):
        """Test that get_reputation is properly implemented in mock."""
        plugin = MockReputationPlugin()
        plugin.mock_rep_data = {'is_malicious': False}
        
        result = plugin.get_reputation("9.9.9.9")
        
        assert result == {'is_malicious': False}


class TestPluginInheritance:
    """Test plugin inheritance behavior."""
    
    def test_geolocation_plugin_inherits_base(self):
        """Test that GeolocationPlugin inherits from BasePlugin."""
        plugin = MockGeolocationPlugin()
        
        assert isinstance(plugin, BasePlugin)
        assert isinstance(plugin, GeolocationPlugin)
        assert hasattr(plugin, 'name')
        assert hasattr(plugin, 'timeout')
        assert hasattr(plugin, 'rate_limit_delay')
        assert hasattr(plugin, '_enforce_rate_limit')
    
    def test_reputation_plugin_inherits_base(self):
        """Test that ReputationPlugin inherits from BasePlugin."""
        plugin = MockReputationPlugin()
        
        assert isinstance(plugin, BasePlugin)
        assert isinstance(plugin, ReputationPlugin)
        assert hasattr(plugin, 'name')
        assert hasattr(plugin, 'timeout')
        assert hasattr(plugin, 'rate_limit_delay')
        assert hasattr(plugin, '_enforce_rate_limit')
    
    def test_rate_limiting_inheritance(self):
        """Test that rate limiting works in inherited plugins."""
        geo_plugin = MockGeolocationPlugin()
        rep_plugin = MockReputationPlugin()
        
        start_time = time.time()
        geo_plugin._enforce_rate_limit()
        geo_plugin._enforce_rate_limit()
        geo_time = time.time()
        
        rep_plugin._enforce_rate_limit()
        rep_plugin._enforce_rate_limit()
        rep_time = time.time()
        
        geo_elapsed = geo_time - start_time
        rep_elapsed = rep_time - geo_time
        
        assert geo_elapsed >= 0.1, "Geolocation plugin should enforce rate limit"
        assert rep_elapsed >= 0.1, "Reputation plugin should enforce rate limit"