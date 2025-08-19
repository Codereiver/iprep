"""
Unit tests for IP reputation agent.
"""

import pytest
from unittest.mock import patch, MagicMock, Mock
from iprep.agent import IPRepAgent
from iprep.plugins.base import BasePlugin


class MockPlugin(BasePlugin):
    """Mock plugin for testing."""
    
    def __init__(self, name="MockPlugin", should_fail=False, return_data=None):
        super().__init__(name)
        self.should_fail = should_fail
        self.return_data = return_data
        self.check_ip_called_with = None
    
    def check_ip(self, ip_address):
        self.check_ip_called_with = ip_address
        if self.should_fail:
            raise Exception("Mock plugin failure")
        return self.return_data


class TestIPRepAgent:
    """Test cases for IPRepAgent class."""
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_initialization(self, mock_load_plugins):
        """Test agent initialization."""
        agent = IPRepAgent()
        
        assert agent.validator is not None
        assert agent.aggregator is not None
        assert agent.plugins == []
        mock_load_plugins.assert_called_once()
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_register_plugin(self, mock_load_plugins):
        """Test plugin registration."""
        agent = IPRepAgent()
        plugin = MockPlugin("TestPlugin")
        
        agent.register_plugin(plugin)
        
        assert len(agent.plugins) == 1
        assert agent.plugins[0] == plugin
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_analyze_valid_ip(self, mock_load_plugins):
        """Test IP analysis with valid IP address."""
        agent = IPRepAgent()
        
        mock_plugin = MockPlugin(
            "TestPlugin",
            return_data={
                'source': 'TestPlugin',
                'ip_address': '8.8.8.8',
                'geolocation': {'country': 'United States'}
            }
        )
        agent.register_plugin(mock_plugin)
        
        result = agent.analyze_ip("8.8.8.8")
        
        assert mock_plugin.check_ip_called_with == "8.8.8.8"
        assert 'geolocation' in result
        assert result['geolocation']['country'] == 'United States'
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_analyze_invalid_ip(self, mock_load_plugins):
        """Test IP analysis with invalid IP address."""
        agent = IPRepAgent()
        
        with pytest.raises(ValueError, match="Invalid IP address"):
            agent.analyze_ip("not_an_ip")
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    @patch('builtins.print')
    def test_plugin_failure_handling(self, mock_print, mock_load_plugins):
        """Test handling of plugin failures."""
        agent = IPRepAgent()
        
        good_plugin = MockPlugin(
            "GoodPlugin",
            return_data={'source': 'GoodPlugin', 'ip_address': '1.1.1.1'}
        )
        bad_plugin = MockPlugin("BadPlugin", should_fail=True)
        
        agent.register_plugin(good_plugin)
        agent.register_plugin(bad_plugin)
        
        result = agent.analyze_ip("1.1.1.1")
        
        mock_print.assert_called_once()
        assert "MockPlugin failed" in mock_print.call_args[0][0]
        assert result['sources'] == ['GoodPlugin']
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_no_plugins_registered(self, mock_load_plugins):
        """Test behavior when no plugins are registered."""
        agent = IPRepAgent()
        
        result = agent.analyze_ip("8.8.8.8")
        
        assert result == {}
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_plugin_returns_none(self, mock_load_plugins):
        """Test behavior when plugin returns None."""
        agent = IPRepAgent()
        
        plugin = MockPlugin("NonePlugin", return_data=None)
        agent.register_plugin(plugin)
        
        result = agent.analyze_ip("192.168.1.1")
        
        assert result == {}
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_multiple_plugins(self, mock_load_plugins):
        """Test analysis with multiple plugins."""
        agent = IPRepAgent()
        
        geo_plugin = MockPlugin(
            "GeoPlugin",
            return_data={
                'source': 'GeoPlugin',
                'ip_address': '1.2.3.4',
                'geolocation': {'country': 'Test Country'}
            }
        )
        
        rep_plugin = MockPlugin(
            "RepPlugin",
            return_data={
                'source': 'RepPlugin',
                'ip_address': '1.2.3.4',
                'reputation': {'is_malicious': False}
            }
        )
        
        agent.register_plugin(geo_plugin)
        agent.register_plugin(rep_plugin)
        
        result = agent.analyze_ip("1.2.3.4")
        
        assert 'geolocation' in result
        assert 'reputation' in result
        assert set(result['sources']) == {'GeoPlugin', 'RepPlugin'}
    
    @patch('iprep.agent.IPRepAgent._load_plugins')  
    @patch('builtins.print')
    def test_discover_and_load_plugins(self, mock_print, mock_load_plugins):
        """Test plugin discovery and loading functionality."""
        agent = IPRepAgent()
        
        # Test error handling in _discover_and_load_plugins
        with patch('iprep.agent.importlib.import_module') as mock_import:
            mock_import.side_effect = ImportError("Module not found")
            
            # Should handle ImportError gracefully
            agent._discover_and_load_plugins('nonexistent.package')
            mock_print.assert_called()
        
        # Test successful plugin loading is covered by integration tests
        mock_load_plugins.assert_called_once()
    
    @patch('iprep.agent.IPRepAgent._discover_and_load_plugins')
    def test_load_plugins_calls_discover(self, mock_discover):
        """Test that _load_plugins calls discover for both plugin types."""
        agent = IPRepAgent()
        
        assert mock_discover.call_count == 2
        mock_discover.assert_any_call('iprep.plugins.geolocation')
        mock_discover.assert_any_call('iprep.plugins.reputation')
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_edge_case_whitespace_ip(self, mock_load_plugins):
        """Test IP analysis with whitespace around IP."""
        agent = IPRepAgent()
        
        plugin = MockPlugin(
            "TestPlugin",
            return_data={'source': 'TestPlugin', 'ip_address': '8.8.8.8'}
        )
        agent.register_plugin(plugin)
        
        result = agent.analyze_ip("  8.8.8.8  ")
        
        assert plugin.check_ip_called_with == "  8.8.8.8  "
        assert 'sources' in result
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_ipv6_analysis(self, mock_load_plugins):
        """Test analysis of IPv6 addresses."""
        agent = IPRepAgent()
        
        plugin = MockPlugin(
            "IPv6Plugin",
            return_data={
                'source': 'IPv6Plugin',
                'ip_address': '2001:4860:4860::8888',
                'geolocation': {'country': 'United States'}
            }
        )
        agent.register_plugin(plugin)
        
        result = agent.analyze_ip("2001:4860:4860::8888")
        
        assert plugin.check_ip_called_with == "2001:4860:4860::8888"
        assert result['geolocation']['country'] == 'United States'


class TestAgentMain:
    """Test cases for agent main function."""
    
    @patch('sys.argv', ['agent.py', '8.8.8.8'])
    @patch('iprep.agent.IPRepAgent')
    @patch('builtins.print')
    def test_main_success(self, mock_print, mock_agent_class):
        """Test successful main function execution with IP address."""
        from iprep.agent import main
        
        mock_agent = MagicMock()
        mock_agent.analyze_input.return_value = {
            'input_type': 'ip',
            'input': '8.8.8.8',
            'analysis': {
                'ip_address': '8.8.8.8',
                'geolocation': {'country': 'United States'}
            }
        }
        mock_agent_class.return_value = mock_agent
        
        main()
        
        mock_agent.analyze_input.assert_called_once_with('8.8.8.8')
        assert mock_print.call_count >= 1
    
    @patch('sys.argv', ['agent.py'])
    @patch('sys.exit')
    @patch('builtins.print')
    def test_main_missing_args(self, mock_print, mock_exit):
        """Test main function with missing arguments."""
        from iprep.agent import main
        
        main()
        
        # Check that exit was called (might be called twice due to argument handling)
        assert mock_exit.call_count >= 1
        # Verify exit was called with status code 1
        mock_exit.assert_called_with(1)
        # Print should be called multiple times now (plugin loading + help/error message)
        assert mock_print.call_count >= 1
    
    @patch('sys.argv', ['agent.py', 'invalid_input'])
    @patch('iprep.agent.IPRepAgent')
    @patch('sys.exit')
    @patch('builtins.print')
    def test_main_invalid_input(self, mock_print, mock_exit, mock_agent_class):
        """Test main function with invalid input."""
        from iprep.agent import main
        
        mock_agent = MagicMock()
        mock_agent.analyze_input.side_effect = ValueError("Invalid input: invalid_input (not a valid IP address or domain name)")
        mock_agent_class.return_value = mock_agent
        
        main()
        
        mock_print.assert_called_with("Error: Invalid input: invalid_input (not a valid IP address or domain name)")
        mock_exit.assert_called_once_with(1)
    
    @patch('sys.argv', ['agent.py', '8.8.8.8'])
    @patch('iprep.agent.IPRepAgent')
    @patch('sys.exit')
    @patch('builtins.print')
    def test_main_unexpected_error(self, mock_print, mock_exit, mock_agent_class):
        """Test main function with unexpected error."""
        from iprep.agent import main
        
        mock_agent = MagicMock()
        mock_agent.analyze_input.side_effect = Exception("Unexpected error")
        mock_agent_class.return_value = mock_agent
        
        main()
        
        mock_print.assert_called_with("Unexpected error: Unexpected error")
        mock_exit.assert_called_once_with(1)
    
    @patch('sys.argv', ['agent.py', 'example.com'])
    @patch('iprep.agent.IPRepAgent')
    @patch('builtins.print')
    def test_main_domain_success(self, mock_print, mock_agent_class):
        """Test successful main function execution with domain."""
        from iprep.agent import main
        
        mock_agent = MagicMock()
        mock_agent.analyze_input.return_value = {
            'input_type': 'domain',
            'input': 'example.com',
            'analysis': {
                'domain': 'example.com',
                'reputation_analysis': [{
                    'plugin_name': 'VirusTotal-Domain',
                    'is_malicious': False,
                    'threat_types': []
                }],
                'content_analysis': [{
                    'plugin_name': 'HTTP-Analyzer',
                    'title': 'Example Domain',
                    'technologies': ['nginx']
                }],
                'summary': {
                    'is_potentially_malicious': False,
                    'malicious_detections': 0,
                    'total_reputation_checks': 1,
                    'technologies_detected': ['nginx']
                }
            }
        }
        mock_agent_class.return_value = mock_agent
        
        main()
        
        mock_agent.analyze_input.assert_called_once_with('example.com')
        assert mock_print.call_count >= 1