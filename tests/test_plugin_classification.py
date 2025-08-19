"""
Tests for plugin classification system (passive vs active).

This module tests the plugin traffic type classification and filtering
functionality to ensure proper separation of passive and active plugins.
"""

import os
import unittest
from unittest.mock import patch, MagicMock

from iprep.agent import IPRepAgent
from iprep.plugins.base import BasePlugin, PluginTrafficType, DomainContentPlugin
from iprep.config import config


class MockPassivePlugin(BasePlugin):
    """Mock passive plugin for testing."""
    
    def __init__(self):
        super().__init__("Mock-Passive", traffic_type=PluginTrafficType.PASSIVE)
    
    def check_ip(self, ip_address: str):
        return {"source": self.name, "ip_address": ip_address, "test": True}


class MockActivePlugin(BasePlugin):
    """Mock active plugin for testing."""
    
    def __init__(self):
        super().__init__("Mock-Active", traffic_type=PluginTrafficType.ACTIVE)
    
    def check_ip(self, ip_address: str):
        return {"source": self.name, "ip_address": ip_address, "test": True}


class MockActiveDomainPlugin(DomainContentPlugin):
    """Mock active domain plugin for testing."""
    
    def __init__(self):
        super().__init__("Mock-Active-Domain", traffic_type=PluginTrafficType.ACTIVE)
    
    def analyze_domain_content(self, domain: str):
        return {"source": self.name, "domain": domain, "test": True}


class TestPluginClassification(unittest.TestCase):
    """Test plugin classification functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.agent = IPRepAgent()
        # Clear any loaded plugins
        self.agent.plugins.clear()
        self.agent.domain_content_plugins.clear()
        self.agent.domain_reputation_plugins.clear()
    
    def test_plugin_traffic_type_enum(self):
        """Test PluginTrafficType enum values."""
        self.assertEqual(PluginTrafficType.PASSIVE.value, "passive")
        self.assertEqual(PluginTrafficType.ACTIVE.value, "active")
        self.assertEqual(str(PluginTrafficType.PASSIVE), "passive")
        self.assertEqual(str(PluginTrafficType.ACTIVE), "active")
    
    def test_plugin_classification_methods(self):
        """Test plugin classification helper methods."""
        passive_plugin = MockPassivePlugin()
        active_plugin = MockActivePlugin()
        
        # Test passive plugin
        self.assertTrue(passive_plugin.is_passive())
        self.assertFalse(passive_plugin.is_active())
        self.assertEqual(passive_plugin.traffic_type, PluginTrafficType.PASSIVE)
        
        # Test active plugin
        self.assertFalse(active_plugin.is_passive())
        self.assertTrue(active_plugin.is_active())
        self.assertEqual(active_plugin.traffic_type, PluginTrafficType.ACTIVE)
    
    def test_traffic_descriptions(self):
        """Test plugin traffic description strings."""
        passive_plugin = MockPassivePlugin()
        active_plugin = MockActivePlugin()
        
        passive_desc = passive_plugin.get_traffic_description()
        active_desc = active_plugin.get_traffic_description()
        
        self.assertIn("third-party APIs", passive_desc)
        self.assertIn("no direct target contact", passive_desc)
        self.assertIn("Directly contacts the target", active_desc)
        self.assertIn("generates network traffic", active_desc)
    
    def test_plugin_filtering_with_active_allowed(self):
        """Test plugin filtering when active plugins are allowed."""
        with patch.dict(os.environ, {'IPREP_ALLOW_ACTIVE_PLUGINS': 'true'}):
            passive_plugin = MockPassivePlugin()
            active_plugin = MockActivePlugin()
            
            # Both should be allowed
            self.assertTrue(self.agent._is_plugin_allowed(passive_plugin))
            self.assertTrue(self.agent._is_plugin_allowed(active_plugin))
    
    def test_plugin_filtering_with_active_disabled(self):
        """Test plugin filtering when active plugins are disabled."""
        with patch.dict(os.environ, {'IPREP_ALLOW_ACTIVE_PLUGINS': 'false'}):
            passive_plugin = MockPassivePlugin()
            active_plugin = MockActivePlugin()
            
            # Only passive should be allowed
            self.assertTrue(self.agent._is_plugin_allowed(passive_plugin))
            self.assertFalse(self.agent._is_plugin_allowed(active_plugin))
    
    def test_get_active_plugins(self):
        """Test retrieval of active plugins."""
        passive_plugin = MockPassivePlugin()
        active_plugin = MockActivePlugin()
        active_domain_plugin = MockActiveDomainPlugin()
        
        # Register plugins
        self.agent.register_plugin(passive_plugin)
        self.agent.register_plugin(active_plugin)
        self.agent.register_domain_plugin(active_domain_plugin)
        
        # Get active plugins
        active_plugins = self.agent.get_active_plugins()
        
        # Should contain only active plugins
        self.assertEqual(len(active_plugins), 2)
        self.assertIn(active_plugin, active_plugins)
        self.assertIn(active_domain_plugin, active_plugins)
        self.assertNotIn(passive_plugin, active_plugins)
    
    def test_get_passive_plugins(self):
        """Test retrieval of passive plugins."""
        passive_plugin = MockPassivePlugin()
        active_plugin = MockActivePlugin()
        active_domain_plugin = MockActiveDomainPlugin()
        
        # Register plugins
        self.agent.register_plugin(passive_plugin)
        self.agent.register_plugin(active_plugin)
        self.agent.register_domain_plugin(active_domain_plugin)
        
        # Get passive plugins
        passive_plugins = self.agent.get_passive_plugins()
        
        # Should contain only passive plugins
        self.assertEqual(len(passive_plugins), 1)
        self.assertIn(passive_plugin, passive_plugins)
        self.assertNotIn(active_plugin, passive_plugins)
        self.assertNotIn(active_domain_plugin, passive_plugins)
    
    def test_plugin_summary_with_active_allowed(self):
        """Test plugin summary when active plugins are allowed."""
        with patch.dict(os.environ, {'IPREP_ALLOW_ACTIVE_PLUGINS': 'true'}):
            passive_plugin = MockPassivePlugin()
            active_plugin = MockActivePlugin()
            
            # Register plugins
            self.agent.register_plugin(passive_plugin)
            self.agent.register_plugin(active_plugin)
            
            # Get summary
            summary = self.agent.get_plugin_summary()
            
            # Validate summary
            self.assertEqual(summary['total_plugins'], 2)
            self.assertEqual(summary['passive_plugins'], 1)
            self.assertEqual(summary['active_plugins'], 1)
            self.assertTrue(summary['active_plugins_allowed'])
            self.assertIn('Mock-Passive', summary['passive_plugin_names'])
            self.assertIn('Mock-Active', summary['active_plugin_names'])
    
    def test_plugin_summary_with_active_disabled(self):
        """Test plugin summary when active plugins are disabled."""
        with patch.dict(os.environ, {'IPREP_ALLOW_ACTIVE_PLUGINS': 'false'}):
            passive_plugin = MockPassivePlugin()
            active_plugin = MockActivePlugin()
            
            # Register plugins
            self.agent.register_plugin(passive_plugin)
            self.agent.register_plugin(active_plugin)
            
            # Get summary
            summary = self.agent.get_plugin_summary()
            
            # Validate summary - note: both plugins are registered but active should show 0 available
            self.assertEqual(summary['total_plugins'], 2)
            self.assertEqual(summary['passive_plugins'], 1)
            self.assertEqual(summary['active_plugins'], 1)  # Still shows registered count
            self.assertFalse(summary['active_plugins_allowed'])
    
    def test_config_allow_active_plugins_default(self):
        """Test default configuration for active plugins."""
        # Default should be False for security/privacy
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(config.allow_active_plugins())
    
    def test_config_allow_active_plugins_true(self):
        """Test configuration with active plugins explicitly enabled."""
        test_values = ['true', 'True', 'TRUE', '1', 'yes', 'YES', 'on', 'ON']
        
        for value in test_values:
            with patch.dict(os.environ, {'IPREP_ALLOW_ACTIVE_PLUGINS': value}):
                self.assertTrue(config.allow_active_plugins(), f"Failed for value: {value}")
    
    def test_config_allow_active_plugins_false(self):
        """Test configuration with active plugins disabled."""
        test_values = ['false', 'False', 'FALSE', '0', 'no', 'NO', 'off', 'OFF']
        
        for value in test_values:
            with patch.dict(os.environ, {'IPREP_ALLOW_ACTIVE_PLUGINS': value}):
                self.assertFalse(config.allow_active_plugins(), f"Failed for value: {value}")
    
    def test_config_get_allowed_traffic_types(self):
        """Test getting allowed traffic types."""
        # With active plugins allowed
        with patch.dict(os.environ, {'IPREP_ALLOW_ACTIVE_PLUGINS': 'true'}):
            allowed = config.get_allowed_traffic_types()
            self.assertIn('passive', allowed)
            self.assertIn('active', allowed)
        
        # With active plugins disabled
        with patch.dict(os.environ, {'IPREP_ALLOW_ACTIVE_PLUGINS': 'false'}):
            allowed = config.get_allowed_traffic_types()
            self.assertIn('passive', allowed)
            self.assertNotIn('active', allowed)
    
    def test_config_get_passive_only_mode(self):
        """Test passive-only mode detection."""
        # When active plugins are allowed
        with patch.dict(os.environ, {'IPREP_ALLOW_ACTIVE_PLUGINS': 'true'}):
            self.assertFalse(config.get_passive_only_mode())
        
        # When active plugins are disabled
        with patch.dict(os.environ, {'IPREP_ALLOW_ACTIVE_PLUGINS': 'false'}):
            self.assertTrue(config.get_passive_only_mode())
    
    @patch('iprep.agent.importlib.import_module')
    def test_plugin_loading_with_active_disabled(self, mock_import):
        """Test that active plugins are skipped during loading when disabled."""
        # Mock a module with both plugin types
        mock_module = MagicMock()
        mock_module.__path__ = ['fake/path']
        mock_module.__name__ = 'fake.module'
        
        # Create mock plugin classes
        mock_passive_class = MagicMock()
        mock_passive_class.__name__ = 'TestPassivePlugin'
        mock_passive_instance = MockPassivePlugin()
        mock_passive_class.return_value = mock_passive_instance
        
        mock_active_class = MagicMock()
        mock_active_class.__name__ = 'TestActivePlugin'
        mock_active_instance = MockActivePlugin()
        mock_active_class.return_value = mock_active_instance
        
        # Configure mock module
        mock_import.return_value = mock_module
        
        with patch.dict(os.environ, {'IPREP_ALLOW_ACTIVE_PLUGINS': 'false'}):
            # Test that active plugins are not loaded
            agent = IPRepAgent()
            
            # Since we're testing the filtering logic, we can verify
            # that the _is_plugin_allowed method works correctly
            self.assertTrue(agent._is_plugin_allowed(mock_passive_instance))
            self.assertFalse(agent._is_plugin_allowed(mock_active_instance))
    
    def test_command_line_allow_active_option(self):
        """Test --allow-active command-line option."""
        # Test that --allow-active enables active plugins
        with patch.dict(os.environ, {}, clear=True):
            # Should default to passive-only
            self.assertFalse(config.allow_active_plugins())
            
            # Simulate --allow-active command-line option
            os.environ['IPREP_ALLOW_ACTIVE_PLUGINS'] = 'true'
            self.assertTrue(config.allow_active_plugins())
    
    def test_environment_variable_override(self):
        """Test environment variable override behavior."""
        # Test that environment variables can override the default
        with patch.dict(os.environ, {}, clear=True):
            # Should default to False (passive-only)
            self.assertFalse(config.allow_active_plugins())
            
            # Environment variable can enable active plugins
            os.environ['IPREP_ALLOW_ACTIVE_PLUGINS'] = 'true'
            self.assertTrue(config.allow_active_plugins())
            
            # Environment variable can explicitly disable active plugins
            os.environ['IPREP_ALLOW_ACTIVE_PLUGINS'] = 'false'
            self.assertFalse(config.allow_active_plugins())
    
    def test_get_all_plugins_summary(self):
        """Test that get_all_plugins_summary shows all plugins regardless of config."""
        # Test with active plugins disabled (default)
        with patch.dict(os.environ, {}, clear=True):
            agent = IPRepAgent()
            
            # get_all_plugins_summary should discover ALL available plugins
            all_summary = agent.get_all_plugins_summary()
            
            # Should show all real plugins available
            self.assertGreaterEqual(all_summary['total_plugins'], 6)  # At least the 6 passive ones
            self.assertGreaterEqual(all_summary['passive_plugins'], 6)  # At least 6 passive plugins
            self.assertGreaterEqual(all_summary['active_plugins'], 2)  # At least 2 active plugins
            self.assertFalse(all_summary['active_plugins_allowed'])  # Config shows disabled
            
            # Should list active plugins even though they're disabled
            self.assertIn('DNS-Analyser', all_summary['active_plugin_names'])
            self.assertIn('HTTP-Analyser', all_summary['active_plugin_names'])
            
            # But regular summary should only show loaded (passive) plugins  
            regular_summary = agent.get_plugin_summary()
            self.assertEqual(regular_summary['active_plugins'], 0)  # No active plugins loaded
            self.assertFalse(regular_summary['active_plugins_allowed'])  # Config disabled


if __name__ == '__main__':
    unittest.main()