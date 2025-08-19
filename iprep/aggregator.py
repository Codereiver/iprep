"""
Result aggregation utilities for combining data from multiple sources.

This module provides functionality to combine and normalize results from
various IP reputation and geolocation plugins.
"""

from typing import Dict, List, Any, Optional, Set
from collections import defaultdict, Counter


class ResultAggregator:
    """Aggregates results from multiple IP analysis plugins."""
    
    def aggregate_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Combine results from multiple plugins into a unified format.
        
        Args:
            results: List of result dictionaries from various plugins
            
        Returns:
            Aggregated result dictionary with combined data
        """
        if not results:
            return {}
        
        aggregated = {
            'ip_address': self._get_ip_address(results),
            'geolocation': self._aggregate_geolocation(results),
            'reputation': self._aggregate_reputation(results),
            'metadata': self._aggregate_metadata(results),
            'sources': self._get_sources(results)
        }
        
        return {k: v for k, v in aggregated.items() if v is not None}
    
    def _get_ip_address(self, results: List[Dict[str, Any]]) -> Optional[str]:
        """Extract IP address from results."""
        for result in results:
            if 'ip_address' in result:
                return result['ip_address']
        return None
    
    def _aggregate_geolocation(self, results: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Aggregate geolocation data from multiple sources."""
        geo_data = defaultdict(list)
        
        for result in results:
            if 'geolocation' in result and result['geolocation']:
                geo = result['geolocation']
                for key, value in geo.items():
                    if value is not None:
                        geo_data[key].append(value)
        
        if not geo_data:
            return None
        
        aggregated_geo = {}
        
        for key, values in geo_data.items():
            if key in ['latitude', 'longitude']:
                aggregated_geo[key] = self._average_coordinates(values)
            elif key in ['country', 'country_code', 'region', 'city', 'timezone']:
                aggregated_geo[key] = self._most_common_value(values)
            elif key == 'accuracy_radius':
                aggregated_geo[key] = max(values) if values else None
            else:
                aggregated_geo[key] = self._most_common_value(values)
        
        return aggregated_geo if aggregated_geo else None
    
    def _aggregate_reputation(self, results: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Aggregate security reputation data from multiple sources."""
        rep_data = {
            'is_malicious': False,
            'threat_types': set(),
            'confidence_score': 0.0,
            'last_seen': None,
            'reports': []
        }
        
        malicious_votes = 0
        total_votes = 0
        confidence_scores = []
        
        for result in results:
            if 'reputation' in result and result['reputation']:
                rep = result['reputation']
                
                if 'is_malicious' in rep:
                    total_votes += 1
                    if rep['is_malicious']:
                        malicious_votes += 1
                
                if 'threat_types' in rep and rep['threat_types']:
                    rep_data['threat_types'].update(rep['threat_types'])
                
                if 'confidence_score' in rep and rep['confidence_score'] is not None:
                    confidence_scores.append(rep['confidence_score'])
                
                if 'last_seen' in rep and rep['last_seen']:
                    if not rep_data['last_seen'] or rep['last_seen'] > rep_data['last_seen']:
                        rep_data['last_seen'] = rep['last_seen']
                
                if 'source' in result:
                    rep_data['reports'].append({
                        'source': result['source'],
                        'is_malicious': rep.get('is_malicious', False),
                        'threat_types': rep.get('threat_types', []),
                        'confidence': rep.get('confidence_score', 0.0)
                    })
        
        if total_votes == 0:
            return None
        
        rep_data['is_malicious'] = malicious_votes > 0
        rep_data['malicious_ratio'] = malicious_votes / total_votes
        rep_data['threat_types'] = list(rep_data['threat_types'])
        rep_data['confidence_score'] = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
        
        return rep_data
    
    def _aggregate_metadata(self, results: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Aggregate metadata from multiple sources."""
        metadata = {
            'asn': None,
            'organization': None,
            'isp': None,
            'domain': None,
            'whois': {}
        }
        
        for result in results:
            if 'metadata' in result and result['metadata']:
                meta = result['metadata']
                
                if 'asn' in meta and not metadata['asn']:
                    metadata['asn'] = meta['asn']
                
                if 'organization' in meta and not metadata['organization']:
                    metadata['organization'] = meta['organization']
                
                if 'isp' in meta and not metadata['isp']:
                    metadata['isp'] = meta['isp']
                
                if 'domain' in meta and not metadata['domain']:
                    metadata['domain'] = meta['domain']
                
                if 'whois' in meta and meta['whois']:
                    metadata['whois'].update(meta['whois'])
        
        return metadata if any(v for v in metadata.values()) else None
    
    def _get_sources(self, results: List[Dict[str, Any]]) -> List[str]:
        """Extract list of data sources used."""
        sources = set()
        for result in results:
            if 'source' in result:
                sources.add(result['source'])
        return list(sources)
    
    def _most_common_value(self, values: List[Any]) -> Any:
        """Return the most common value from a list."""
        if not values:
            return None
        counter = Counter(values)
        return counter.most_common(1)[0][0]
    
    def _average_coordinates(self, values: List[float]) -> Optional[float]:
        """Calculate average of coordinate values."""
        if not values:
            return None
        try:
            numeric_values = [float(v) for v in values if v is not None]
            return sum(numeric_values) / len(numeric_values) if numeric_values else None
        except (ValueError, TypeError):
            return None