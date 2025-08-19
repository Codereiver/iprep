"""
Tests for debug mode functionality.
"""

import unittest
import os
import sys
from io import StringIO
from unittest.mock import patch, MagicMock
from iprep.config import config
from iprep.debug import debug_logger, debug_plugin_method
from iprep.plugins.base import BasePlugin


class TestDebugConfiguration(unittest.TestCase):
    """Test debug configuration functionality."""
    
    def test_debug_mode_disabled_by_default(self):
        """Test that debug mode is disabled by default."""
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(config.is_debug_mode())
            self.assertEqual(config.get_debug_level(), 'off')
    
    def test_debug_mode_enabled_by_environment(self):
        """Test debug mode enabled by environment variable."""
        test_cases = [
            ('true', True),
            ('1', True),
            ('yes', True),
            ('on', True),
            ('false', False),
            ('0', False),
            ('no', False),
            ('off', False),
        ]
        
        for value, expected in test_cases:
            with patch.dict(os.environ, {'IPREP_DEBUG': value}):
                self.assertEqual(config.is_debug_mode(), expected)
    
    def test_debug_levels(self):
        """Test different debug levels."""
        with patch.dict(os.environ, {'IPREP_DEBUG': 'true'}):
            # Test default level
            with patch.dict(os.environ, {}, clear=False):
                self.assertEqual(config.get_debug_level(), 'basic')
            
            # Test valid levels
            for level in ['basic', 'detailed', 'verbose']:
                with patch.dict(os.environ, {'IPREP_DEBUG_LEVEL': level}):
                    self.assertEqual(config.get_debug_level(), level)
            
            # Test invalid level falls back to basic
            with patch.dict(os.environ, {'IPREP_DEBUG_LEVEL': 'invalid'}):
                self.assertEqual(config.get_debug_level(), 'basic')


class TestDebugLogger(unittest.TestCase):
    """Test debug logger functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.original_stderr = sys.stderr
        self.captured_stderr = StringIO()
        sys.stderr = self.captured_stderr
    
    def tearDown(self):
        """Clean up test fixtures."""
        sys.stderr = self.original_stderr
    
    @patch.dict(os.environ, {'IPREP_DEBUG': 'true', 'IPREP_DEBUG_LEVEL': 'basic'})
    def test_basic_logging(self):
        """Test basic debug logging."""
        debug_logger.log('basic', 'Test message')
        
        output = self.captured_stderr.getvalue()
        self.assertIn('[DEBUG', output)
        self.assertIn('Test message', output)
    
    @patch.dict(os.environ, {'IPREP_DEBUG': 'false'})
    def test_logging_disabled_when_debug_off(self):
        """Test that logging is disabled when debug mode is off."""
        debug_logger.log('basic', 'Test message')
        
        output = self.captured_stderr.getvalue()
        self.assertEqual(output, '')
    
    @patch.dict(os.environ, {'IPREP_DEBUG': 'true', 'IPREP_DEBUG_LEVEL': 'basic'})
    def test_log_level_filtering(self):
        """Test that higher level messages are filtered out."""
        debug_logger.log('detailed', 'Detailed message')
        debug_logger.log('verbose', 'Verbose message')
        
        output = self.captured_stderr.getvalue()
        self.assertNotIn('Detailed message', output)
        self.assertNotIn('Verbose message', output)
    
    @patch.dict(os.environ, {'IPREP_DEBUG': 'true', 'IPREP_DEBUG_LEVEL': 'detailed'})
    def test_detailed_logging_with_data(self):
        """Test detailed logging with data."""
        test_data = {'key1': 'value1', 'key2': {'nested': 'data'}}
        debug_logger.log('detailed', 'Test with data', test_data)
        
        output = self.captured_stderr.getvalue()
        self.assertIn('Test with data', output)
        self.assertIn('key1: value1', output)
        self.assertIn('key2: 1 items', output)
    
    @patch.dict(os.environ, {'IPREP_DEBUG': 'true', 'IPREP_DEBUG_LEVEL': 'basic'})
    def test_plugin_call_logging(self):
        """Test plugin call logging."""
        debug_logger.log_plugin_call('TestPlugin', 'test_method', ('arg1', 'arg2'), {'param': 'value'})
        
        output = self.captured_stderr.getvalue()
        self.assertIn('Plugin call #', output)
        self.assertIn('TestPlugin.test_method', output)
        self.assertIn('arg1, arg2', output)
        self.assertIn('param=value', output)
    
    @patch.dict(os.environ, {'IPREP_DEBUG': 'true', 'IPREP_DEBUG_LEVEL': 'basic'})
    def test_plugin_result_logging(self):
        """Test plugin result logging."""
        result = {'status': 'success', 'data': [1, 2, 3]}
        debug_logger.log_plugin_result('TestPlugin', 'test_method', result, 0.5)
        
        output = self.captured_stderr.getvalue()
        self.assertIn('Plugin result: TestPlugin.test_method', output)
        self.assertIn('dict(2 keys)', output)
        self.assertIn('0.500s', output)
    
    @patch.dict(os.environ, {'IPREP_DEBUG': 'true', 'IPREP_DEBUG_LEVEL': 'basic'})
    def test_plugin_error_logging(self):
        """Test plugin error logging."""
        error = ValueError("Test error message")
        debug_logger.log_plugin_error('TestPlugin', 'test_method', error, 0.2)
        
        output = self.captured_stderr.getvalue()
        self.assertIn('Plugin error: TestPlugin.test_method', output)
        self.assertIn('ValueError: Test error message', output)
        self.assertIn('0.200s', output)
    
    @patch.dict(os.environ, {'IPREP_DEBUG': 'true', 'IPREP_DEBUG_LEVEL': 'basic'})
    def test_analysis_logging(self):
        """Test analysis start/complete logging."""
        debug_logger.log_analysis_start('8.8.8.8', 'IP')
        debug_logger.log_analysis_complete('8.8.8.8', 'IP', 1.5, 3)
        
        output = self.captured_stderr.getvalue()
        self.assertIn('Starting IP analysis for: 8.8.8.8', output)
        self.assertIn('Completed IP analysis for 8.8.8.8: 3 plugins, 1.500s total', output)


class MockPlugin(BasePlugin):
    """Mock plugin for testing debug decorator."""
    
    def __init__(self):
        super().__init__("MockPlugin")
    
    def check_ip(self, ip_address):
        return None
    
    @debug_plugin_method
    def test_method(self, arg1, arg2=None):
        """Test method for debug decorator."""
        return {'arg1': arg1, 'arg2': arg2}
    
    @debug_plugin_method
    def error_method(self):
        """Test method that raises an error."""
        raise ValueError("Test error")


class TestDebugDecorator(unittest.TestCase):
    """Test debug decorator functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.original_stderr = sys.stderr
        self.captured_stderr = StringIO()
        sys.stderr = self.captured_stderr
        self.plugin = MockPlugin()
    
    def tearDown(self):
        """Clean up test fixtures."""
        sys.stderr = self.original_stderr
    
    @patch.dict(os.environ, {'IPREP_DEBUG': 'false'})
    def test_decorator_disabled_when_debug_off(self):
        """Test that decorator does nothing when debug is off."""
        result = self.plugin.test_method('value1', arg2='value2')
        
        self.assertEqual(result, {'arg1': 'value1', 'arg2': 'value2'})
        output = self.captured_stderr.getvalue()
        self.assertEqual(output, '')
    
    @patch.dict(os.environ, {'IPREP_DEBUG': 'true', 'IPREP_DEBUG_LEVEL': 'basic'})
    def test_decorator_logs_successful_call(self):
        """Test that decorator logs successful method calls."""
        result = self.plugin.test_method('value1', arg2='value2')
        
        self.assertEqual(result, {'arg1': 'value1', 'arg2': 'value2'})
        output = self.captured_stderr.getvalue()
        self.assertIn('Plugin call #', output)
        self.assertIn('MockPlugin.test_method', output)
        self.assertIn('Plugin result: MockPlugin.test_method', output)
    
    @patch.dict(os.environ, {'IPREP_DEBUG': 'true', 'IPREP_DEBUG_LEVEL': 'basic'})
    def test_decorator_logs_errors(self):
        """Test that decorator logs method errors."""
        with self.assertRaises(ValueError):
            self.plugin.error_method()
        
        output = self.captured_stderr.getvalue()
        self.assertIn('Plugin call #', output)
        self.assertIn('MockPlugin.error_method', output)
        self.assertIn('Plugin error: MockPlugin.error_method', output)
        self.assertIn('ValueError: Test error', output)


if __name__ == '__main__':
    unittest.main()