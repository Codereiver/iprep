"""
Integration tests for the complete IP analysis workflow.
"""

import pytest
from unittest.mock import patch, MagicMock
from iprep.agent import IPRepAgent
from iprep.plugins.geolocation.ipapi import IPApiPlugin
from iprep.plugins.geolocation.ipinfo import IPinfoPlugin
from iprep.plugins.reputation.abuseipdb import AbuseIPDBPlugin
from iprep.plugins.reputation.urlvoid import URLVoidPlugin


class TestFullWorkflow:
    """Integration tests for complete IP analysis workflow."""
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_complete_analysis_workflow(self, mock_load_plugins):
        """Test complete analysis workflow with multiple plugins."""
        agent = IPRepAgent()
        
        geo_plugin = IPApiPlugin()
        rep_plugin = URLVoidPlugin()
        
        agent.register_plugin(geo_plugin)
        agent.register_plugin(rep_plugin)
        
        with patch.object(geo_plugin, 'get_geolocation') as mock_geo:
            with patch.object(rep_plugin, 'get_reputation') as mock_rep:
                mock_geo.return_value = {
                    'country': 'United States',
                    'city': 'Mountain View',
                    'latitude': 37.4056,
                    'longitude': -122.0775,
                    'isp': 'Google LLC'
                }
                
                mock_rep.return_value = {
                    'is_malicious': False,
                    'confidence_score': 0.1,
                    'threat_types': [],
                    'risk_level': 'minimal'
                }
                
                result = agent.analyze_ip("8.8.8.8")
                
                assert result['ip_address'] == '8.8.8.8'
                assert result['geolocation']['country'] == 'United States'
                assert result['geolocation']['city'] == 'Mountain View'
                assert result['reputation']['is_malicious'] is False
                assert set(result['sources']) == {'IP-API', 'URLVoid'}
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_mixed_plugin_results(self, mock_load_plugins):
        """Test workflow with mixed success/failure from plugins."""
        agent = IPRepAgent()
        
        good_geo = IPApiPlugin()
        bad_geo = IPinfoPlugin()
        rep_plugin = AbuseIPDBPlugin()
        
        agent.register_plugin(good_geo)
        agent.register_plugin(bad_geo)
        agent.register_plugin(rep_plugin)
        
        with patch.object(good_geo, 'get_geolocation') as mock_good_geo:
            with patch.object(bad_geo, 'get_geolocation') as mock_bad_geo:
                with patch.object(rep_plugin, 'get_reputation') as mock_rep:
                    mock_good_geo.return_value = {
                        'country': 'Germany',
                        'city': 'Frankfurt',
                        'latitude': 50.1109,
                        'longitude': 8.6821
                    }
                    
                    mock_bad_geo.side_effect = Exception("Network error")
                    
                    mock_rep.return_value = {
                        'is_malicious': True,
                        'confidence_score': 0.8,
                        'threat_types': ['malware']
                    }
                    
                    with patch('builtins.print') as mock_print:
                        result = agent.analyze_ip("1.2.3.4")
                    
                    assert result['geolocation']['country'] == 'Germany'
                    assert result['reputation']['is_malicious'] is True
                    assert 'IP-API' in result['sources']
                    assert 'AbuseIPDB' in result['sources']
                    assert 'IPinfo' not in result['sources']
                    mock_print.assert_called()
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_multiple_geolocation_aggregation(self, mock_load_plugins):
        """Test aggregation of multiple geolocation sources."""
        agent = IPRepAgent()
        
        geo1 = IPApiPlugin()
        geo2 = IPinfoPlugin()
        
        agent.register_plugin(geo1)
        agent.register_plugin(geo2)
        
        with patch.object(geo1, 'get_geolocation') as mock_geo1:
            with patch.object(geo2, 'get_geolocation') as mock_geo2:
                mock_geo1.return_value = {
                    'country': 'United States',
                    'city': 'Mountain View',
                    'latitude': 37.4056,
                    'longitude': -122.0775
                }
                
                mock_geo2.return_value = {
                    'country': 'United States',
                    'city': 'Mountain View',
                    'latitude': 37.4000,
                    'longitude': -122.0800
                }
                
                result = agent.analyze_ip("8.8.8.8")
                
                assert result['geolocation']['country'] == 'United States'
                assert result['geolocation']['city'] == 'Mountain View'
                assert abs(result['geolocation']['latitude'] - 37.4028) < 0.001
                assert abs(result['geolocation']['longitude'] - (-122.07875)) < 0.001
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_multiple_reputation_aggregation(self, mock_load_plugins):
        """Test aggregation of multiple reputation sources."""
        agent = IPRepAgent()
        
        rep1 = AbuseIPDBPlugin()
        rep2 = URLVoidPlugin()
        
        agent.register_plugin(rep1)
        agent.register_plugin(rep2)
        
        with patch.object(rep1, 'get_reputation') as mock_rep1:
            with patch.object(rep2, 'get_reputation') as mock_rep2:
                mock_rep1.return_value = {
                    'is_malicious': True,
                    'confidence_score': 0.8,
                    'threat_types': ['botnet']
                }
                
                mock_rep2.return_value = {
                    'is_malicious': True,
                    'confidence_score': 0.9,
                    'threat_types': ['malware']
                }
                
                result = agent.analyze_ip("1.2.3.4")
                
                assert result['reputation']['is_malicious'] is True
                assert result['reputation']['malicious_ratio'] == 1.0
                assert set(result['reputation']['threat_types']) == {'botnet', 'malware'}
                assert abs(result['reputation']['confidence_score'] - 0.85) < 0.001
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_conflicting_reputation_votes(self, mock_load_plugins):
        """Test handling of conflicting reputation votes."""
        agent = IPRepAgent()
        
        rep1 = AbuseIPDBPlugin()
        rep2 = URLVoidPlugin()
        
        agent.register_plugin(rep1)
        agent.register_plugin(rep2)
        
        with patch.object(rep1, 'get_reputation') as mock_rep1:
            with patch.object(rep2, 'get_reputation') as mock_rep2:
                mock_rep1.return_value = {
                    'is_malicious': True,
                    'confidence_score': 0.7
                }
                
                mock_rep2.return_value = {
                    'is_malicious': False,
                    'confidence_score': 0.3
                }
                
                result = agent.analyze_ip("5.6.7.8")
                
                assert result['reputation']['is_malicious'] is True
                assert result['reputation']['malicious_ratio'] == 0.5
                assert result['reputation']['confidence_score'] == 0.5
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_invalid_ip_handling(self, mock_load_plugins):
        """Test handling of invalid IP addresses."""
        agent = IPRepAgent()
        
        with pytest.raises(ValueError, match="Invalid IP address"):
            agent.analyze_ip("not_an_ip")
        
        with pytest.raises(ValueError, match="Invalid IP address"):
            agent.analyze_ip("256.256.256.256")
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_empty_plugin_results(self, mock_load_plugins):
        """Test handling when all plugins return empty results."""
        agent = IPRepAgent()
        
        geo_plugin = IPApiPlugin()
        rep_plugin = AbuseIPDBPlugin()
        
        agent.register_plugin(geo_plugin)
        agent.register_plugin(rep_plugin)
        
        with patch.object(geo_plugin, 'get_geolocation', return_value=None):
            with patch.object(rep_plugin, 'get_reputation', return_value=None):
                result = agent.analyze_ip("127.0.0.1")
                
                assert result == {}
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_ipv6_analysis(self, mock_load_plugins):
        """Test analysis of IPv6 addresses."""
        agent = IPRepAgent()
        
        geo_plugin = IPApiPlugin()
        
        agent.register_plugin(geo_plugin)
        
        with patch.object(geo_plugin, 'get_geolocation') as mock_geo:
            mock_geo.return_value = {
                'country': 'United States',
                'city': 'Mountain View',
                'isp': 'Google LLC'
            }
            
            result = agent.analyze_ip("2001:4860:4860::8888")
            
            assert result['ip_address'] == '2001:4860:4860::8888'
            assert result['geolocation']['country'] == 'United States'
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_private_ip_analysis(self, mock_load_plugins):
        """Test analysis of private IP addresses."""
        agent = IPRepAgent()
        
        geo_plugin = IPApiPlugin()
        
        agent.register_plugin(geo_plugin)
        
        with patch.object(geo_plugin, 'get_geolocation') as mock_geo:
            mock_geo.return_value = {
                'country': 'Private',
                'city': 'Local Network'
            }
            
            result = agent.analyze_ip("192.168.1.100")
            
            assert result['ip_address'] == '192.168.1.100'
            assert result['geolocation']['country'] == 'Private'
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_comprehensive_analysis(self, mock_load_plugins):
        """Test comprehensive analysis with all data types."""
        agent = IPRepAgent()
        
        geo_plugin = IPApiPlugin()
        rep_plugin = AbuseIPDBPlugin()
        
        agent.register_plugin(geo_plugin)
        agent.register_plugin(rep_plugin)
        
        with patch.object(geo_plugin, 'check_ip') as mock_geo_check:
            with patch.object(rep_plugin, 'check_ip') as mock_rep_check:
                mock_geo_check.return_value = {
                    'source': 'IP-API',
                    'ip_address': '203.0.113.1',
                    'geolocation': {
                        'country': 'Australia',
                        'city': 'Sydney',
                        'latitude': -33.8688,
                        'longitude': 151.2093,
                        'timezone': 'Australia/Sydney'
                    },
                    'metadata': {
                        'asn': 'AS1234',
                        'organization': 'Test Org',
                        'isp': 'Test ISP'
                    }
                }
                
                mock_rep_check.return_value = {
                    'source': 'AbuseIPDB',
                    'ip_address': '203.0.113.1',
                    'reputation': {
                        'is_malicious': False,
                        'confidence_score': 0.1,
                        'threat_types': [],
                        'total_reports': 0
                    }
                }
                
                result = agent.analyze_ip("203.0.113.1")
                
                assert result['ip_address'] == '203.0.113.1'
                assert result['geolocation']['country'] == 'Australia'
                assert result['geolocation']['city'] == 'Sydney'
                assert result['reputation']['is_malicious'] is False
                assert result['metadata']['asn'] == 'AS1234'
                assert result['metadata']['organization'] == 'Test Org'
                assert set(result['sources']) == {'IP-API', 'AbuseIPDB'}


class TestRealPluginIntegration:
    """Integration tests with actual plugin implementations (using mock data)."""
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_real_plugin_integration(self, mock_load_plugins):
        """Test integration with real plugin implementations."""
        agent = IPRepAgent()
        
        abuse_plugin = AbuseIPDBPlugin()
        urlvoid_plugin = URLVoidPlugin()
        
        agent.register_plugin(abuse_plugin)
        agent.register_plugin(urlvoid_plugin)
        
        result = agent.analyze_ip("1.2.3.4")
        
        assert result is not None
        assert 'ip_address' in result
        assert 'reputation' in result
        assert 'sources' in result
        assert len(result['sources']) == 2
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_plugin_error_resilience(self, mock_load_plugins):
        """Test system resilience when plugins encounter errors."""
        agent = IPRepAgent()
        
        good_plugin = AbuseIPDBPlugin()
        bad_plugin = URLVoidPlugin()
        
        agent.register_plugin(good_plugin)
        agent.register_plugin(bad_plugin)
        
        with patch.object(bad_plugin, 'get_reputation', side_effect=Exception("Mock error")):
            with patch('builtins.print') as mock_print:
                result = agent.analyze_ip("8.8.8.8")
            
            assert 'AbuseIPDB' in result['sources']
            assert 'URLVoid' not in result['sources']
            mock_print.assert_called()
    
    @patch('iprep.agent.IPRepAgent._load_plugins')
    def test_performance_with_multiple_plugins(self, mock_load_plugins):
        """Test performance characteristics with multiple plugins."""
        import time
        
        agent = IPRepAgent()
        
        for i in range(5):
            plugin = AbuseIPDBPlugin()
            plugin.name = f"Plugin_{i}"
            agent.register_plugin(plugin)
        
        start_time = time.time()
        result = agent.analyze_ip("192.0.2.1")
        end_time = time.time()
        
        execution_time = end_time - start_time
        assert execution_time < 5.0
        assert len(result['sources']) == 5