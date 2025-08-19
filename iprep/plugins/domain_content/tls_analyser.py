"""
TLS/SSL Certificate Analyser plugin.

This plugin performs active TLS/SSL certificate analysis by connecting
directly to the target domain to examine certificate details, cipher suites,
and security configuration. Certificate validation is bypassed to analyse
whatever certificate is presented, regardless of validity.
"""

import ssl
import socket
import hashlib
import datetime
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
from ..base import DomainContentPlugin, PluginTrafficType
from ...config import config
from ...security import security
from ...debug import debug_plugin_method


class TLSAnalyserPlugin(DomainContentPlugin):
    """TLS/SSL Certificate analysis plugin."""
    
    def __init__(self):
        """Initialize the TLS analyser plugin.
        
        This plugin analyses whatever TLS certificate is presented during
        the handshake, bypassing certificate validation for analysis purposes.
        """
        timeout = config.get_request_timeout(15.0)
        super().__init__("TLS-Analyser", timeout=timeout, rate_limit_delay=2.0, 
                         traffic_type=PluginTrafficType.ACTIVE)
        self.default_ports = [443, 8443]  # Common HTTPS ports
    
    @debug_plugin_method
    def analyze_domain_content(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Analyse TLS/SSL configuration for a domain.
        
        Args:
            domain: The domain name to analyse
            
        Returns:
            TLS analysis data dictionary or None if not available
        """
        self._enforce_rate_limit()
        
        try:
            # Try to connect on standard HTTPS ports
            cert_data = None
            connection_info = None
            
            for port in self.default_ports:
                try:
                    cert_data, connection_info = self._get_certificate_info(domain, port)
                    if cert_data:
                        break
                except Exception:
                    continue
            
            if not cert_data:
                return self._get_mock_tls_analysis(domain)
            
            # Analyse the certificate and connection
            analysis = self._analyze_certificate(cert_data, domain)
            analysis.update(self._analyze_connection(connection_info))
            
            return analysis
            
        except Exception as e:
            self._handle_request_error(e, domain)
            return self._get_mock_tls_analysis(domain)
    
    def _get_certificate_info(self, domain: str, port: int = 443) -> tuple:
        """
        Get certificate information by connecting to the domain.
        
        Args:
            domain: Domain to connect to
            port: Port to connect on
            
        Returns:
            Tuple of (certificate_data, connection_info)
        """
        # Create SSL context that retrieves certificate data
        # Try with verification first, then fall back if needed
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED  # Need this to get cert data populated
        
        # Store connection details
        connection_info = {
            'port': port,
            'domain': domain,
            'protocol_version': None,
            'cipher_suite': None,
            'server_hostname': domain,
            'certificate_validation_bypassed': True
        }
        
        try:
            # Connect to the server with certificate verification enabled to get cert data
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # Get certificate data (should be populated with CERT_REQUIRED)
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
                    
                    # Get connection details
                    connection_info['protocol_version'] = ssock.version()
                    connection_info['cipher_suite'] = ssock.cipher()
                    connection_info['certificate_verified'] = True
                    
                    return (cert_dict, cert_der), connection_info
                    
        except ssl.SSLError as ssl_err:
            # SSL verification failed, but try to get certificate data anyway
            try:
                # Create a new context with no verification for analysis
                no_verify_context = ssl.create_default_context()
                no_verify_context.check_hostname = False
                no_verify_context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                    with no_verify_context.wrap_socket(sock, server_hostname=domain) as ssock:
                        # Get whatever certificate data we can
                        cert_der = ssock.getpeercert(binary_form=True)
                        cert_dict = ssock.getpeercert()  # This will be None with CERT_NONE
                        
                        # Debug logging for certificate analysis
                        if __debug__:
                            from ...debug import debug_logger
                            debug_logger.log('basic', f"Fallback: cert_dict={'None' if cert_dict is None else 'present'}, cert_der={len(cert_der) if cert_der else 0} bytes")
                            if cert_dict:
                                debug_logger.log('basic', f"Certificate dict keys: {list(cert_dict.keys())}")
                                debug_logger.log('basic', f"Certificate subject: {cert_dict.get('subject', 'Missing')}")
                        
                        # Get connection details
                        connection_info['protocol_version'] = ssock.version()
                        connection_info['cipher_suite'] = ssock.cipher()
                        connection_info['certificate_verified'] = False
                        connection_info['ssl_error'] = str(ssl_err)
                        
                        # If cert_dict is None or empty but we have DER data, try to parse basic info from DER
                        if (cert_dict is None or not cert_dict) and cert_der:
                            if __debug__:
                                from ...debug import debug_logger
                                debug_logger.log('basic', f"Parsing DER certificate data ({len(cert_der)} bytes)")
                            cert_dict = self._parse_basic_cert_info_from_der(cert_der)
                        
                        return (cert_dict, cert_der), connection_info
                        
            except Exception as fallback_err:
                # Both approaches failed
                connection_info['ssl_error'] = str(ssl_err)
                connection_info['fallback_error'] = str(fallback_err)
                raise ssl_err
        except Exception as e:
            # If connection fails entirely, re-raise the exception
            raise e
    
    def _analyze_certificate(self, cert_data: tuple, domain: str) -> Dict[str, Any]:
        """
        Analyse certificate details.
        
        Args:
            cert_data: Tuple of (cert_dict, cert_der)
            domain: Domain being analysed
            
        Returns:
            Certificate analysis results
        """
        cert_dict, cert_der = cert_data
        
        # Certificate analysis debug logging (only in debug mode)
        if __debug__ and cert_der:
            from ...debug import debug_logger
            debug_logger.log('verbose', f"Analyzing certificate: {len(cert_der)} bytes DER data")
        
        # Basic certificate information
        subject = cert_dict.get('subject', [])
        issuer = cert_dict.get('issuer', [])
        
        # Extract common name and subject alternative names
        common_name = self._extract_name_from_subject(subject, 'commonName')
        organization = self._extract_name_from_subject(subject, 'organizationName')
        san_list = cert_dict.get('subjectAltName', [])
        
        # Certificate validity
        not_before = cert_dict.get('notBefore')
        not_after = cert_dict.get('notAfter')
        
        # Debug date parsing
        if __debug__:
            from ...debug import debug_logger
            debug_logger.log('verbose', f"Date parsing input - Before: '{not_before}', After: '{not_after}'")
        
        # Parse dates
        valid_from, valid_until, is_expired, days_until_expiry = self._parse_validity_dates(
            not_before, not_after
        )
        
        # Certificate chain and trust analysis
        issuer_cn = self._extract_name_from_subject(issuer, 'commonName')
        issuer_org = self._extract_name_from_subject(issuer, 'organizationName')
        
        # Security analysis
        key_size = self._estimate_key_size(cert_der)
        signature_algorithm = cert_dict.get('signatureAlgorithm', 'unknown')
        
        # Domain validation
        domain_match = self._validate_certificate_domain(domain, common_name, san_list)
        
        # Format SAN list for output
        formatted_san_list = []
        if san_list:
            for san in san_list:
                if san[0] == 'DNS':
                    formatted_san_list.append(security.sanitize_output_text(san[1], 100))
            formatted_san_list = formatted_san_list[:10]  # Limit to 10 SANs
        
        # Create title based on CN, full SAN field, and days to expiry
        title_parts = []
        if common_name:
            title_parts.append(f"CN: {common_name}")
        if formatted_san_list:
            san_display = ", ".join(formatted_san_list)  # Show ALL SANs
            title_parts.append(f"SAN: {san_display}")
        
        # Add expiry information
        if days_until_expiry is not None:
            if is_expired:
                title_parts.append(f"EXPIRED {abs(days_until_expiry)} days ago")
            elif days_until_expiry <= 30:
                title_parts.append(f"Expires in {days_until_expiry} days")
            else:
                title_parts.append(f"Expires in {days_until_expiry} days")
        
        title = "; ".join(title_parts) if title_parts else "Certificate Present"
        
        return {
            'title': security.sanitize_output_text(title, 500),  # Allow full SAN display
            'certificate': {
                'common_name': security.sanitize_output_text(common_name, 100) if common_name else '',
                'organization': security.sanitize_output_text(organization, 100) if organization else '',
                'issuer_common_name': security.sanitize_output_text(issuer_cn, 100) if issuer_cn else '',
                'issuer_organization': security.sanitize_output_text(issuer_org, 100) if issuer_org else '',
                'subject_alternative_names': formatted_san_list,
                'valid_from': valid_from,
                'valid_until': valid_until,
                'is_expired': is_expired,
                'days_until_expiry': days_until_expiry,
                'signature_algorithm': security.sanitize_output_text(signature_algorithm, 50),
                'estimated_key_size': key_size,
                'domain_match': domain_match
            }
        }
    
    def _analyze_connection(self, connection_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse TLS connection details.
        
        Args:
            connection_info: Connection information
            
        Returns:
            Connection analysis results
        """
        protocol_version = connection_info.get('protocol_version', 'unknown')
        cipher_info = connection_info.get('cipher_suite')
        
        cipher_suite = 'unknown'
        key_exchange = 'unknown'
        encryption = 'unknown'
        
        if cipher_info and len(cipher_info) >= 3:
            cipher_suite = cipher_info[0]
            protocol_version = cipher_info[1] or protocol_version
            key_exchange = cipher_info[2] if len(cipher_info) > 2 else 'unknown'
        
        # Security assessment
        security_issues = []
        security_score = 100
        
        # Check protocol version
        if protocol_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
            security_issues.append('Weak TLS protocol version')
            security_score -= 30
        elif protocol_version == 'TLSv1.2':
            security_score -= 5  # Slight deduction, prefer 1.3
        
        # Note: Certificate validation is bypassed for analysis purposes
        # We analyse whatever certificate is presented, regardless of validity
        certificate_validation_bypassed = connection_info.get('certificate_validation_bypassed', False)
        
        return {
            'connection': {
                'port': connection_info.get('port', 443),
                'protocol_version': security.sanitize_output_text(protocol_version, 20),
                'cipher_suite': security.sanitize_output_text(cipher_suite, 100),
                'key_exchange': security.sanitize_output_text(key_exchange, 50),
                'encryption': security.sanitize_output_text(encryption, 50),
                'certificate_validation_bypassed': certificate_validation_bypassed,
                'security_score': max(0, security_score),
                'security_issues': security_issues[:5]  # Limit issues list
            }
        }
    
    def _extract_name_from_subject(self, subject: List[tuple], field_name: str) -> str:
        """Extract a specific field from certificate subject."""
        for field_tuple in subject:
            for field in field_tuple:
                if field[0] == field_name:
                    return field[1]
        return ''
    
    def _parse_validity_dates(self, not_before: str, not_after: str) -> tuple:
        """Parse certificate validity dates."""
        try:
            # Debug date parsing
            if __debug__:
                from ...debug import debug_logger
                debug_logger.log('verbose', f"Parsing dates - Before: '{not_before}', After: '{not_after}'")
                
            if not_before:
                valid_from = datetime.datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                # Make timezone-aware (GMT means UTC)
                valid_from = valid_from.replace(tzinfo=datetime.timezone.utc)
            else:
                valid_from = None
                
            if not_after:
                valid_until = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                # Make timezone-aware (GMT means UTC)
                valid_until = valid_until.replace(tzinfo=datetime.timezone.utc)
            else:
                valid_until = None
            
            now = datetime.datetime.now(datetime.timezone.utc)
            is_expired = valid_until < now if valid_until else True
            
            if valid_until:
                days_until_expiry = (valid_until - now).days
            else:
                days_until_expiry = 0
            
            return (
                valid_from.isoformat() if valid_from else '',
                valid_until.isoformat() if valid_until else '',
                is_expired,
                days_until_expiry
            )
        except Exception as e:
            # Debug date parsing errors
            if __debug__:
                from ...debug import debug_logger
                debug_logger.log('verbose', f"Date parsing failed: {str(e)}")
            return '', '', True, 0
    
    def _estimate_key_size(self, cert_der: bytes) -> int:
        """Estimate key size from certificate (simplified)."""
        # This is a very rough estimation based on certificate size
        # A proper implementation would parse the ASN.1 structure
        cert_size = len(cert_der)
        if cert_size < 800:
            return 1024  # Likely RSA 1024
        elif cert_size < 1200:
            return 2048  # Likely RSA 2048
        elif cert_size < 1600:
            return 3072  # Likely RSA 3072
        else:
            return 4096  # Likely RSA 4096 or ECC
    
    def _validate_certificate_domain(self, domain: str, common_name: str, san_list: List[tuple]) -> bool:
        """Check if certificate is valid for the domain."""
        # Check common name
        if self._domain_matches(domain, common_name):
            return True
        
        # Check subject alternative names
        for san_type, san_value in san_list:
            if san_type == 'DNS' and self._domain_matches(domain, san_value):
                return True
        
        return False
    
    def _domain_matches(self, domain: str, cert_domain: str) -> bool:
        """Check if domain matches certificate domain (including wildcards)."""
        if not cert_domain:
            return False
        
        domain = domain.lower()
        cert_domain = cert_domain.lower()
        
        if domain == cert_domain:
            return True
        
        # Handle wildcard certificates
        if cert_domain.startswith('*.'):
            wildcard_domain = cert_domain[2:]
            if domain.endswith('.' + wildcard_domain):
                return True
        
        return False
    
    def _parse_basic_cert_info_from_der(self, cert_der: bytes) -> Dict[str, Any]:
        """
        Parse basic certificate information from DER-encoded certificate data.
        
        This is a fallback method when getpeercert() returns None but we have DER data.
        We'll extract what we can using basic ASN.1 parsing or create a minimal structure.
        
        Args:
            cert_der: DER-encoded certificate data
            
        Returns:
            Dictionary with basic certificate info
        """
        try:
            # Try to use cryptography library if available for proper parsing
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                
                # Extract subject information
                subject_attrs = []
                for attribute in cert.subject:
                    # Map OID names to expected format
                    oid_name = attribute.oid._name
                    # Convert OID names to match expected format
                    if oid_name == 'commonName':
                        subject_attrs.append([(oid_name, attribute.value)])
                    elif oid_name == 'organizationName':
                        subject_attrs.append([(oid_name, attribute.value)])
                    elif oid_name == 'organizationalUnitName':
                        subject_attrs.append([(oid_name, attribute.value)])
                    elif oid_name == 'countryName':
                        subject_attrs.append([(oid_name, attribute.value)])
                    elif oid_name == 'stateOrProvinceName':
                        subject_attrs.append([(oid_name, attribute.value)])
                    elif oid_name == 'localityName':
                        subject_attrs.append([(oid_name, attribute.value)])
                    else:
                        subject_attrs.append([(oid_name, attribute.value)])
                
                # Extract issuer information  
                issuer_attrs = []
                for attribute in cert.issuer:
                    # Map OID names to expected format
                    oid_name = attribute.oid._name
                    # Convert OID names to match expected format
                    if oid_name == 'commonName':
                        issuer_attrs.append([(oid_name, attribute.value)])
                    elif oid_name == 'organizationName':
                        issuer_attrs.append([(oid_name, attribute.value)])
                    elif oid_name == 'organizationalUnitName':
                        issuer_attrs.append([(oid_name, attribute.value)])
                    elif oid_name == 'countryName':
                        issuer_attrs.append([(oid_name, attribute.value)])
                    elif oid_name == 'stateOrProvinceName':
                        issuer_attrs.append([(oid_name, attribute.value)])
                    elif oid_name == 'localityName':
                        issuer_attrs.append([(oid_name, attribute.value)])
                    else:
                        issuer_attrs.append([(oid_name, attribute.value)])
                
                # Extract SAN
                san_list = []
                try:
                    san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    for san in san_ext.value:
                        if isinstance(san, x509.DNSName):
                            san_list.append(('DNS', san.value))
                except x509.ExtensionNotFound:
                    pass
                
                # Format certificate validity dates
                not_before_str = cert.not_valid_before_utc.strftime('%b %d %H:%M:%S %Y GMT')
                not_after_str = cert.not_valid_after_utc.strftime('%b %d %H:%M:%S %Y GMT')
                
                # Debug certificate parsing
                if __debug__:
                    from ...debug import debug_logger
                    debug_logger.log('verbose', f"Certificate dates - Before: {not_before_str}, After: {not_after_str}")
                
                return {
                    'subject': subject_attrs,
                    'issuer': issuer_attrs,
                    'subjectAltName': san_list,
                    'notBefore': not_before_str,
                    'notAfter': not_after_str,
                    'serialNumber': str(cert.serial_number),
                    'version': cert.version.value
                }
                
            except ImportError:
                # Cryptography library not available, create basic structure
                # We can at least provide the certificate size and a basic structure
                return {
                    'subject': [[('commonName', 'Unknown (DER parsing limited)')]],
                    'issuer': [[('commonName', 'Unknown (DER parsing limited)')]],
                    'subjectAltName': [],
                    'notBefore': 'Unknown',
                    'notAfter': 'Unknown', 
                    'serialNumber': 'Unknown',
                    'version': 3,
                    'note': f'Parsed from DER data ({len(cert_der)} bytes) - install cryptography for full parsing'
                }
                
        except Exception as e:
            # Fallback: return minimal structure
            return {
                'subject': [[('commonName', 'Parse Error')]],
                'issuer': [[('commonName', 'Parse Error')]],
                'subjectAltName': [],
                'notBefore': 'Unknown',
                'notAfter': 'Unknown',
                'serialNumber': 'Unknown', 
                'version': 3,
                'note': f'DER parsing failed: {str(e)}'
            }

    def _get_mock_tls_analysis(self, domain: str) -> Dict[str, Any]:
        """
        Provide mock TLS analysis when connection fails.
        
        Args:
            domain: The domain being analysed
            
        Returns:
            Mock TLS analysis data
        """
        domain_hash = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)
        
        # Generate deterministic mock data
        protocols = ['TLSv1.2', 'TLSv1.3', 'TLSv1.1']
        protocol = protocols[domain_hash % len(protocols)]
        
        cipher_suites = [
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'DHE-RSA-AES256-SHA256'
        ]
        cipher = cipher_suites[domain_hash % len(cipher_suites)]
        
        is_expired = domain_hash % 10 == 0
        days_until_expiry = (domain_hash % 365) if not is_expired else -(domain_hash % 30)
        
        san_list = [domain, f'www.{domain}']
        
        # Create title with CN, full SAN, and expiry info
        title_parts = [f"CN: {domain}", f"SAN: {', '.join(san_list)}"]
        if is_expired:
            title_parts.append(f"EXPIRED {abs(days_until_expiry)} days ago")
        elif days_until_expiry <= 30:
            title_parts.append(f"Expires in {days_until_expiry} days")
        else:
            title_parts.append(f"Expires in {days_until_expiry} days")
        
        title = "; ".join(title_parts)
        
        return {
            'title': title,
            'certificate': {
                'common_name': domain,
                'organization': 'Mock Organization',
                'issuer_common_name': 'Mock CA',
                'issuer_organization': 'Mock Certificate Authority',
                'subject_alternative_names': san_list,
                'valid_from': '2024-01-01T00:00:00',
                'valid_until': '2025-01-01T00:00:00',
                'is_expired': is_expired,
                'days_until_expiry': days_until_expiry,
                'signature_algorithm': 'sha256WithRSAEncryption',
                'estimated_key_size': 2048,
                'domain_match': True
            },
            'connection': {
                'port': 443,
                'protocol_version': protocol,
                'cipher_suite': cipher,
                'key_exchange': 'ECDHE',
                'encryption': 'AES256-GCM',
                'certificate_validation_bypassed': True,
                'security_score': 85 if protocol == 'TLSv1.3' else 75,
                'security_issues': ['Weak TLS protocol version'] if protocol == 'TLSv1.1' else []
            },
            'note': 'Mock TLS analysis - connection failed'
        }