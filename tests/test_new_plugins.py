"""
Tests for new plugins: GreyNoise, PhishTank, TLS-Analyser, and WHOIS-Analyser.
"""

import unittest
from unittest.mock import patch, MagicMock
import requests
import socket
import ssl

from iprep.plugins.reputation.greynoise import GreyNoisePlugin
from iprep.plugins.domain_reputation.phishtank import PhishTankPlugin
from iprep.plugins.domain_content.tls_analyser import TLSAnalyserPlugin
from iprep.plugins.domain_content.whois_analyser import WHOISAnalyserPlugin
from iprep.plugins.base import PluginTrafficType


class TestGreyNoisePlugin(unittest.TestCase):
    """Test GreyNoise IP reputation plugin."""
    
    def setUp(self):
        self.plugin = GreyNoisePlugin()
    
    def test_initialization(self):
        """Test plugin initialization."""
        self.assertEqual(self.plugin.name, "GreyNoise")
        self.assertEqual(self.plugin.traffic_type, PluginTrafficType.PASSIVE)
        self.assertTrue(self.plugin.is_passive())
        self.assertFalse(self.plugin.is_active())
    
    def test_is_available(self):
        """Test availability check."""
        self.assertTrue(self.plugin.is_available())
    
    @patch('requests.get')
    def test_successful_reputation_check(self, mock_get):
        """Test successful GreyNoise API response."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'noise': True,
            'classification': 'malicious',
            'name': 'Test Scanner',
            'link': 'https://example.com',
            'last_seen': '2024-01-01',
            'riot': False
        }
        mock_response.headers.get.return_value = 'application/json'
        mock_get.return_value = mock_response
        
        result = self.plugin.get_reputation('1.2.3.4')
        
        self.assertIsNotNone(result)
        self.assertTrue(result['is_malicious'])
        self.assertIn('scanning', result['threat_types'])
        self.assertEqual(result['classification'], 'malicious')
        self.assertEqual(result['source'], 'GreyNoise Community API')
    
    @patch('requests.get')
    def test_benign_classification(self, mock_get):
        """Test benign classification response."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'noise': True,
            'classification': 'benign',
            'name': 'Benign Service',
            'riot': True
        }
        mock_response.headers.get.return_value = 'application/json'
        mock_get.return_value = mock_response
        
        result = self.plugin.get_reputation('8.8.8.8')
        
        self.assertIsNotNone(result)
        self.assertFalse(result['is_malicious'])
        self.assertIn('benign-scanning', result['threat_types'])
        self.assertIn('service-provider', result['threat_types'])
        self.assertTrue(result['riot'])
    
    @patch('requests.get')
    def test_request_error(self, mock_get):
        """Test handling of request errors."""
        mock_get.side_effect = requests.exceptions.RequestException("Connection failed")
        
        result = self.plugin.get_reputation('1.2.3.4')
        
        # Plugin now returns None on error instead of mock data
        self.assertIsNone(result)
    
    def test_no_mock_reputation(self):
        """Test that mock reputation generation method was removed."""
        # Verify the mock method no longer exists
        self.assertFalse(hasattr(self.plugin, '_get_mock_reputation'))


class TestPhishTankPlugin(unittest.TestCase):
    """Test PhishTank domain reputation plugin."""
    
    def setUp(self):
        self.plugin = PhishTankPlugin()
    
    def test_initialization(self):
        """Test plugin initialization."""
        self.assertEqual(self.plugin.name, "PhishTank")
        self.assertEqual(self.plugin.traffic_type, PluginTrafficType.PASSIVE)
        self.assertTrue(self.plugin.is_passive())
    
    @patch('requests.post')
    def test_phishing_detection(self, mock_post):
        """Test phishing domain detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'results': {
                'in_database': True,
                'phish_detail_page': 'https://phishtank.org/phish_detail.php?phish_id=12345',
                'verified': True,
                'phish_id': 12345,
                'submission_time': '2024-01-01T12:00:00Z',
                'verification_time': '2024-01-01T12:30:00Z'
            }
        }
        mock_response.headers.get.return_value = 'application/json'
        mock_post.return_value = mock_response
        
        result = self.plugin.get_domain_reputation('phishing-site.com')
        
        self.assertIsNotNone(result)
        self.assertTrue(result['is_malicious'])
        self.assertIn('phishing', result['threat_types'])
        self.assertTrue(result['verified'])
        self.assertEqual(result['phish_id'], 12345)
    
    @patch('requests.post')
    def test_clean_domain(self, mock_post):
        """Test clean domain response."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'results': {
                'in_database': False
            }
        }
        mock_response.headers.get.return_value = 'application/json'
        mock_post.return_value = mock_response
        
        result = self.plugin.get_domain_reputation('example.com')
        
        self.assertIsNotNone(result)
        self.assertFalse(result['is_malicious'])
        self.assertEqual(result['threat_types'], [])
        self.assertFalse(result['in_database'])


class TestTLSAnalyserPlugin(unittest.TestCase):
    """Test TLS/SSL Certificate Analyser plugin."""
    
    def setUp(self):
        self.plugin = TLSAnalyserPlugin()
    
    def test_initialization(self):
        """Test plugin initialization."""
        self.assertEqual(self.plugin.name, "TLS-Analyser")
        self.assertEqual(self.plugin.traffic_type, PluginTrafficType.ACTIVE)
        self.assertTrue(self.plugin.is_active())
        self.assertFalse(self.plugin.is_passive())
    
    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_certificate_analysis(self, mock_ssl_context, mock_socket):
        """Test TLS certificate analysis."""
        # Mock SSL connection
        mock_sock = MagicMock()
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = {
            'subject': [
                [['commonName', 'example.com']],
                [['organizationName', 'Example Corp']]
            ],
            'issuer': [
                [['commonName', 'Test CA']],
                [['organizationName', 'Test Certificate Authority']]
            ],
            'notBefore': 'Jan  1 00:00:00 2024 GMT',
            'notAfter': 'Jan  1 00:00:00 2025 GMT',
            'subjectAltName': [('DNS', 'example.com'), ('DNS', 'www.example.com')],
            'signatureAlgorithm': 'sha256WithRSAEncryption'
        }
        mock_ssl_sock.version.return_value = 'TLSv1.3'
        mock_ssl_sock.cipher.return_value = ('ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1.3', 256)
        
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value.__enter__ = lambda x: mock_ssl_sock
        mock_context.wrap_socket.return_value.__exit__ = lambda *args: None
        mock_ssl_context.return_value = mock_context
        
        mock_socket.return_value.__enter__ = lambda x: mock_sock
        mock_socket.return_value.__exit__ = lambda *args: None
        
        result = self.plugin.analyze_domain_content('example.com')
        
        self.assertIsNotNone(result)
        self.assertIn('certificate', result)
        self.assertIn('connection', result)
        self.assertEqual(result['certificate']['common_name'], 'example.com')
        self.assertEqual(result['connection']['protocol_version'], 'TLSv1.3')
    
    def test_domain_validation(self):
        """Test certificate domain validation."""
        # Test exact match
        self.assertTrue(self.plugin._domain_matches('example.com', 'example.com'))
        
        # Test wildcard match
        self.assertTrue(self.plugin._domain_matches('sub.example.com', '*.example.com'))
        
        # Test no match
        self.assertFalse(self.plugin._domain_matches('different.com', 'example.com'))
    
    def test_no_mock_analysis(self):
        """Test that mock TLS analysis generation method was removed."""
        # Verify the mock method no longer exists
        self.assertFalse(hasattr(self.plugin, '_get_mock_tls_analysis'))


class TestWHOISAnalyserPlugin(unittest.TestCase):
    """Test WHOIS Analyser plugin."""
    
    def setUp(self):
        self.plugin = WHOISAnalyserPlugin()
    
    def test_initialization(self):
        """Test plugin initialization."""
        self.assertEqual(self.plugin.name, "WHOIS-Analyser")
        self.assertEqual(self.plugin.traffic_type, PluginTrafficType.ACTIVE)
        self.assertTrue(self.plugin.is_active())
    
    def test_whois_server_selection(self):
        """Test WHOIS server selection."""
        self.assertEqual(self.plugin._get_whois_server('example.com'), 'whois.verisign-grs.com')
        self.assertEqual(self.plugin._get_whois_server('example.org'), 'whois.pir.org')
        self.assertEqual(self.plugin._get_whois_server('example.co.uk'), 'whois.nic.uk')
        self.assertEqual(self.plugin._get_whois_server('example.xyz'), 'whois.iana.org')
    
    def test_date_parsing(self):
        """Test date parsing from WHOIS data."""
        self.assertEqual(self.plugin._parse_date('2024-01-01'), '2024-01-01')
        self.assertEqual(self.plugin._parse_date('01-01-2024'), '01-01-2024')
        self.assertEqual(self.plugin._parse_date('2024/01/01'), '2024/01/01')
        self.assertEqual(self.plugin._parse_date('2024-01-01T12:00:00Z'), '2024-01-01')
    
    @patch('socket.socket')
    def test_whois_query(self, mock_socket):
        """Test WHOIS query functionality."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [
            b"Domain Name: EXAMPLE.COM\r\n",
            b"Registrar: Test Registrar\r\n",
            b"Creation Date: 2024-01-01\r\n",
            b""  # End of data
        ]
        mock_socket.return_value.__enter__ = lambda x: mock_sock
        mock_socket.return_value.__exit__ = lambda *args: None
        
        result = self.plugin._get_whois_data('example.com')
        
        self.assertIsNotNone(result)
        self.assertIn('EXAMPLE.COM', result)
        self.assertIn('Test Registrar', result)
    
    def test_no_mock_analysis(self):
        """Test that mock WHOIS analysis generation method was removed."""
        # Verify the mock method no longer exists
        self.assertFalse(hasattr(self.plugin, '_get_mock_whois_analysis'))


if __name__ == '__main__':
    unittest.main()