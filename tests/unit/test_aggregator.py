"""
Unit tests for result aggregator.
"""

import pytest
from iprep.aggregator import ResultAggregator


class TestResultAggregator:
    """Test cases for ResultAggregator class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.aggregator = ResultAggregator()
    
    def test_empty_results(self):
        """Test aggregation with empty results."""
        result = self.aggregator.aggregate_results([])
        assert result == {}
    
    def test_single_geolocation_result(self):
        """Test aggregation with single geolocation result."""
        results = [{
            'source': 'TestGeo',
            'ip_address': '8.8.8.8',
            'geolocation': {
                'country': 'United States',
                'city': 'Mountain View',
                'latitude': 37.4056,
                'longitude': -122.0775
            }
        }]
        
        aggregated = self.aggregator.aggregate_results(results)
        
        assert aggregated['ip_address'] == '8.8.8.8'
        assert aggregated['geolocation']['country'] == 'United States'
        assert aggregated['geolocation']['city'] == 'Mountain View'
        assert aggregated['geolocation']['latitude'] == 37.4056
        assert aggregated['sources'] == ['TestGeo']
    
    def test_single_reputation_result(self):
        """Test aggregation with single reputation result."""
        results = [{
            'source': 'TestRep',
            'ip_address': '1.2.3.4',
            'reputation': {
                'is_malicious': True,
                'threat_types': ['malware', 'botnet'],
                'confidence_score': 0.85
            }
        }]
        
        aggregated = self.aggregator.aggregate_results(results)
        
        assert aggregated['ip_address'] == '1.2.3.4'
        assert aggregated['reputation']['is_malicious'] is True
        assert set(aggregated['reputation']['threat_types']) == {'malware', 'botnet'}
        assert aggregated['reputation']['confidence_score'] == 0.85
        assert aggregated['sources'] == ['TestRep']
    
    def test_multiple_geolocation_results(self):
        """Test aggregation with multiple geolocation sources."""
        results = [
            {
                'source': 'Geo1',
                'ip_address': '8.8.8.8',
                'geolocation': {
                    'country': 'United States',
                    'city': 'Mountain View',
                    'latitude': 37.4056,
                    'longitude': -122.0775
                }
            },
            {
                'source': 'Geo2',
                'ip_address': '8.8.8.8',
                'geolocation': {
                    'country': 'United States',
                    'city': 'Mountain View',
                    'latitude': 37.4000,
                    'longitude': -122.0800
                }
            }
        ]
        
        aggregated = self.aggregator.aggregate_results(results)
        
        assert aggregated['geolocation']['country'] == 'United States'
        assert aggregated['geolocation']['city'] == 'Mountain View'
        assert abs(aggregated['geolocation']['latitude'] - 37.4028) < 0.001
        assert abs(aggregated['geolocation']['longitude'] - (-122.07875)) < 0.001
        assert set(aggregated['sources']) == {'Geo1', 'Geo2'}
    
    def test_multiple_reputation_results(self):
        """Test aggregation with multiple reputation sources."""
        results = [
            {
                'source': 'Rep1',
                'ip_address': '1.2.3.4',
                'reputation': {
                    'is_malicious': True,
                    'threat_types': ['malware'],
                    'confidence_score': 0.8
                }
            },
            {
                'source': 'Rep2',
                'ip_address': '1.2.3.4',
                'reputation': {
                    'is_malicious': True,
                    'threat_types': ['botnet'],
                    'confidence_score': 0.9
                }
            }
        ]
        
        aggregated = self.aggregator.aggregate_results(results)
        
        assert aggregated['reputation']['is_malicious'] is True
        assert aggregated['reputation']['malicious_ratio'] == 1.0
        assert set(aggregated['reputation']['threat_types']) == {'malware', 'botnet'}
        assert abs(aggregated['reputation']['confidence_score'] - 0.85) < 0.001
        assert len(aggregated['reputation']['reports']) == 2
    
    def test_mixed_reputation_votes(self):
        """Test aggregation with mixed malicious/benign votes."""
        results = [
            {
                'source': 'Rep1',
                'ip_address': '5.6.7.8',
                'reputation': {
                    'is_malicious': True,
                    'confidence_score': 0.7
                }
            },
            {
                'source': 'Rep2',
                'ip_address': '5.6.7.8',
                'reputation': {
                    'is_malicious': False,
                    'confidence_score': 0.3
                }
            }
        ]
        
        aggregated = self.aggregator.aggregate_results(results)
        
        assert aggregated['reputation']['is_malicious'] is True
        assert aggregated['reputation']['malicious_ratio'] == 0.5
        assert aggregated['reputation']['confidence_score'] == 0.5
    
    def test_metadata_aggregation(self):
        """Test aggregation of metadata from multiple sources."""
        results = [
            {
                'source': 'Source1',
                'ip_address': '8.8.8.8',
                'metadata': {
                    'asn': 'AS15169',
                    'organization': 'Google LLC'
                }
            },
            {
                'source': 'Source2',
                'ip_address': '8.8.8.8',
                'metadata': {
                    'isp': 'Google',
                    'domain': 'google.com'
                }
            }
        ]
        
        aggregated = self.aggregator.aggregate_results(results)
        
        assert aggregated['metadata']['asn'] == 'AS15169'
        assert aggregated['metadata']['organization'] == 'Google LLC'
        assert aggregated['metadata']['isp'] == 'Google'
        assert aggregated['metadata']['domain'] == 'google.com'
    
    def test_comprehensive_aggregation(self):
        """Test aggregation with all data types."""
        results = [
            {
                'source': 'GeoSource',
                'ip_address': '1.1.1.1',
                'geolocation': {
                    'country': 'Australia',
                    'city': 'Sydney',
                    'latitude': -33.8688,
                    'longitude': 151.2093
                }
            },
            {
                'source': 'RepSource',
                'ip_address': '1.1.1.1',
                'reputation': {
                    'is_malicious': False,
                    'confidence_score': 0.1
                }
            },
            {
                'source': 'MetaSource',
                'ip_address': '1.1.1.1',
                'metadata': {
                    'asn': 'AS13335',
                    'organization': 'Cloudflare'
                }
            }
        ]
        
        aggregated = self.aggregator.aggregate_results(results)
        
        assert aggregated['ip_address'] == '1.1.1.1'
        assert aggregated['geolocation']['country'] == 'Australia'
        assert aggregated['reputation']['is_malicious'] is False
        assert aggregated['metadata']['organization'] == 'Cloudflare'
        assert set(aggregated['sources']) == {'GeoSource', 'RepSource', 'MetaSource'}
    
    def test_none_values_handling(self):
        """Test handling of None values in results."""
        results = [
            {
                'source': 'TestSource',
                'ip_address': '192.168.1.1',
                'geolocation': {
                    'country': 'United States',
                    'city': None,
                    'latitude': None,
                    'longitude': None
                }
            }
        ]
        
        aggregated = self.aggregator.aggregate_results(results)
        
        assert aggregated['geolocation']['country'] == 'United States'
        assert 'city' not in aggregated['geolocation'] or aggregated['geolocation']['city'] is None
    
    def test_most_common_value(self):
        """Test the _most_common_value helper method."""
        assert self.aggregator._most_common_value(['a', 'b', 'a', 'c', 'a']) == 'a'
        assert self.aggregator._most_common_value(['x']) == 'x'
        assert self.aggregator._most_common_value([]) is None
    
    def test_average_coordinates(self):
        """Test the _average_coordinates helper method."""
        assert abs(self.aggregator._average_coordinates([10.0, 20.0, 30.0]) - 20.0) < 0.001
        assert self.aggregator._average_coordinates([]) is None
        assert self.aggregator._average_coordinates([None, None]) is None
        assert abs(self.aggregator._average_coordinates([10.0, None, 20.0]) - 15.0) < 0.001
    
    def test_invalid_coordinate_values(self):
        """Test handling of invalid coordinate values."""
        result = self.aggregator._average_coordinates(['invalid', 10.0, 'bad'])
        assert result is None
    
    def test_empty_sections_not_included(self):
        """Test that empty sections are not included in final result."""
        results = [{
            'source': 'TestSource',
            'ip_address': '127.0.0.1'
        }]
        
        aggregated = self.aggregator.aggregate_results(results)
        
        assert 'geolocation' not in aggregated
        assert 'reputation' not in aggregated
        assert 'metadata' not in aggregated
        assert aggregated['sources'] == ['TestSource']