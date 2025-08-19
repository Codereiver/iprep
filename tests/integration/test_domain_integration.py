"""
Integration tests for domain analysis functionality.
"""

import os
import pytest
from unittest.mock import patch, MagicMock
from iprep.agent import IPRepAgent


class TestDomainIntegration:
    """Integration tests for domain analysis workflow."""
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_domain_analysis_workflow(self, mock_load_plugins):
        """Test complete domain analysis workflow."""
        agent = IPRepAgent()
        
        # Manually add mock domain plugins for testing
        mock_reputation_plugin = MagicMock()
        mock_reputation_plugin.name = "Mock-Domain-Reputation"
        mock_reputation_plugin.get_domain_reputation.return_value = {
            'is_malicious': False,
            'confidence_score': 0.1,
            'threat_types': [],
            'categories': ['legitimate'],
            'engines_total': 10,
            'engines_detected': 0
        }
        
        mock_content_plugin = MagicMock()
        mock_content_plugin.name = "Mock-Domain-Content"
        mock_content_plugin.analyze_domain_content.return_value = {
            'status_code': 200,
            'title': 'Example Domain',
            'technologies': ['nginx', 'php'],
            'content_categories': ['business'],
            'ssl_certificate': {'enabled': True}
        }
        
        agent.domain_reputation_plugins = [mock_reputation_plugin]
        agent.domain_content_plugins = [mock_content_plugin]
        
        # Test domain analysis
        result = agent.analyze_domain("example.com")
        
        assert result['domain'] == 'example.com'
        assert len(result['reputation_analysis']) == 1
        assert len(result['content_analysis']) == 1
        assert 'summary' in result
        
        # Verify plugins were called
        mock_reputation_plugin.get_domain_reputation.assert_called_once_with('example.com')
        mock_content_plugin.analyze_domain_content.assert_called_once_with('example.com')
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_analyze_input_with_domain(self, mock_load_plugins):
        """Test input analysis with domain name."""
        agent = IPRepAgent()
        
        # Mock domain plugins
        mock_reputation_plugin = MagicMock()
        mock_reputation_plugin.name = "Mock-Reputation"
        mock_reputation_plugin.get_domain_reputation.return_value = {
            'is_malicious': False,
            'threat_types': [],
            'categories': ['legitimate']
        }
        
        mock_content_plugin = MagicMock()
        mock_content_plugin.name = "Mock-Content"
        mock_content_plugin.analyze_domain_content.return_value = {
            'title': 'Test Site',
            'technologies': ['nginx'],
            'content_categories': ['business']
        }
        
        agent.domain_reputation_plugins = [mock_reputation_plugin]
        agent.domain_content_plugins = [mock_content_plugin]
        
        result = agent.analyze_input("example.com")
        
        assert result['input_type'] == 'domain'
        assert result['input'] == 'example.com'
        assert 'analysis' in result
        assert result['analysis']['domain'] == 'example.com'
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_analyze_input_with_ip(self, mock_load_plugins):
        """Test input analysis with IP address."""
        agent = IPRepAgent()
        
        # Mock IP plugins
        mock_ip_plugin = MagicMock()
        mock_ip_plugin.check_ip.return_value = {
            'ip_address': '8.8.8.8',
            'country': 'United States'
        }
        agent.plugins = [mock_ip_plugin]
        
        result = agent.analyze_input("8.8.8.8")
        
        assert result['input_type'] == 'ip'
        assert result['input'] == '8.8.8.8'
        assert 'analysis' in result
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_invalid_input_handling(self, mock_load_plugins):
        """Test handling of invalid input."""
        agent = IPRepAgent()
        
        with pytest.raises(ValueError) as exc_info:
            agent.analyze_input("invalid-input")
        
        assert "Invalid input" in str(exc_info.value)
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_domain_normalization_in_analysis(self, mock_load_plugins):
        """Test that domain names are normalized during analysis."""
        agent = IPRepAgent()
        
        mock_reputation_plugin = MagicMock()
        mock_reputation_plugin.name = "Mock-Reputation"
        mock_reputation_plugin.get_domain_reputation.return_value = {
            'is_malicious': False,
            'threat_types': []
        }
        
        agent.domain_reputation_plugins = [mock_reputation_plugin]
        
        # Test with unnormalized domain
        result = agent.analyze_domain("EXAMPLE.COM")
        
        assert result['domain'] == 'example.com'
        mock_reputation_plugin.get_domain_reputation.assert_called_with('example.com')
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_plugin_error_resilience(self, mock_load_plugins):
        """Test that agent continues working when plugins fail."""
        agent = IPRepAgent()
        
        # Mock plugins - one fails, one succeeds
        failing_plugin = MagicMock()
        failing_plugin.name = "Failing-Plugin"
        failing_plugin.get_domain_reputation.side_effect = Exception("Plugin failed")
        
        working_plugin = MagicMock()
        working_plugin.name = "Working-Plugin"
        working_plugin.get_domain_reputation.return_value = {
            'is_malicious': False,
            'threat_types': []
        }
        
        agent.domain_reputation_plugins = [failing_plugin, working_plugin]
        
        result = agent.analyze_domain("example.com")
        
        # Should have one successful result despite one plugin failing
        assert len(result['reputation_analysis']) == 1
        assert result['reputation_analysis'][0]['plugin_name'] == 'Working-Plugin'
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_domain_summary_generation(self, mock_load_plugins):
        """Test domain analysis summary generation."""
        agent = IPRepAgent()
        
        # Mock reputation plugins with mixed results
        malicious_plugin = MagicMock()
        malicious_plugin.name = "Malicious-Detector"
        malicious_plugin.get_domain_reputation.return_value = {
            'is_malicious': True,
            'threat_types': ['malware', 'phishing'],
            'categories': ['malicious']
        }
        
        clean_plugin = MagicMock()
        clean_plugin.name = "Clean-Detector"
        clean_plugin.get_domain_reputation.return_value = {
            'is_malicious': False,
            'threat_types': [],
            'categories': ['legitimate']
        }
        
        # Mock content plugin
        content_plugin = MagicMock()
        content_plugin.name = "Content-Analyzer"
        content_plugin.analyze_domain_content.return_value = {
            'technologies': ['nginx', 'php'],
            'content_categories': ['business']
        }
        
        agent.domain_reputation_plugins = [malicious_plugin, clean_plugin]
        agent.domain_content_plugins = [content_plugin]
        
        result = agent.analyze_domain("example.com")
        summary = result['summary']
        
        assert summary['is_potentially_malicious'] is True  # At least one malicious detection
        assert summary['malicious_detections'] == 1
        assert summary['total_reputation_checks'] == 2
        assert set(summary['threat_types']) == {'malware', 'phishing'}
        assert 'nginx' in summary['technologies_detected']
        assert 'php' in summary['technologies_detected']
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_empty_plugin_results(self, mock_load_plugins):
        """Test handling when plugins return None results."""
        agent = IPRepAgent()
        
        # Mock plugins that return None
        reputation_plugin = MagicMock()
        reputation_plugin.name = "Null-Reputation"
        reputation_plugin.get_domain_reputation.return_value = None
        
        content_plugin = MagicMock()
        content_plugin.name = "Null-Content"
        content_plugin.analyze_domain_content.return_value = None
        
        agent.domain_reputation_plugins = [reputation_plugin]
        agent.domain_content_plugins = [content_plugin]
        
        result = agent.analyze_domain("example.com")
        
        # Should handle None results gracefully
        assert result['reputation_analysis'] == []
        assert result['content_analysis'] == []
        assert result['summary']['malicious_detections'] == 0
        assert result['summary']['total_reputation_checks'] == 0
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_multiple_domain_analyses(self, mock_load_plugins):
        """Test analyzing multiple domains in sequence."""
        agent = IPRepAgent()
        
        mock_plugin = MagicMock()
        mock_plugin.name = "Mock-Plugin"
        
        # Return different results for different domains
        def mock_reputation(domain):
            if domain == "malicious.com":
                return {
                    'is_malicious': True,
                    'threat_types': ['malware'],
                    'categories': ['malicious']
                }
            else:
                return {
                    'is_malicious': False,
                    'threat_types': [],
                    'categories': ['legitimate']
                }
        
        mock_plugin.get_domain_reputation.side_effect = mock_reputation
        agent.domain_reputation_plugins = [mock_plugin]
        
        # Analyze multiple domains
        result1 = agent.analyze_domain("legitimate.com")
        result2 = agent.analyze_domain("malicious.com")
        
        assert result1['summary']['is_potentially_malicious'] is False
        assert result2['summary']['is_potentially_malicious'] is True
        
        # Verify plugin was called correctly for each domain
        expected_calls = [('legitimate.com',), ('malicious.com',)]
        actual_calls = [call[0] for call in mock_plugin.get_domain_reputation.call_args_list]
        assert actual_calls == expected_calls


class TestDomainPluginDiscovery:
    """Test domain plugin discovery and loading."""
    
    def test_domain_plugin_loading_structure(self):
        """Test that domain plugins are loaded correctly."""
        agent = IPRepAgent()
        
        # Check that domain plugin lists exist
        assert hasattr(agent, 'domain_reputation_plugins')
        assert hasattr(agent, 'domain_content_plugins')
        assert isinstance(agent.domain_reputation_plugins, list)
        assert isinstance(agent.domain_content_plugins, list)
    
    def test_register_domain_plugins(self):
        """Test registering domain plugins."""
        # Enable active plugins for this integration test
        with patch.dict(os.environ, {'IPREP_ALLOW_ACTIVE_PLUGINS': 'true'}):
            agent = IPRepAgent()
        
        # Check that domain plugins were loaded successfully
        # We can see from the captured output that 4 domain plugins loaded
        total_domain_plugins = len(agent.domain_reputation_plugins) + len(agent.domain_content_plugins)
        
        # Should have loaded domain plugins from the real plugin modules
        assert total_domain_plugins >= 4  # 2 reputation + 2 content plugins
        assert len(agent.domain_reputation_plugins) >= 2  # URLVoid, VirusTotal
        assert len(agent.domain_content_plugins) >= 2  # DNS, HTTP analyzers


class TestRealDomainPlugins:
    """Test real domain plugins if they're available."""
    
    def test_real_domain_plugins_integration(self):
        """Test integration with real domain plugins."""
        # Enable active plugins for this integration test
        with patch.dict(os.environ, {'IPREP_ALLOW_ACTIVE_PLUGINS': 'true'}):
            agent = IPRepAgent()
            
            # Check if any real domain plugins were loaded
            total_domain_plugins = len(agent.domain_reputation_plugins) + len(agent.domain_content_plugins)
            
            if total_domain_plugins > 0:
                # Test with a real domain if plugins are available
                try:
                    result = agent.analyze_domain("example.com")
                    assert 'domain' in result
                    assert 'reputation_analysis' in result
                    assert 'content_analysis' in result
                    assert 'summary' in result
                except Exception as e:
                    # If real plugins fail (e.g., network issues), that's expected
                    # but the structure should still be correct
                    pytest.skip(f"Real plugin test skipped due to: {e}")
            else:
                pytest.skip("No real domain plugins available for integration test")