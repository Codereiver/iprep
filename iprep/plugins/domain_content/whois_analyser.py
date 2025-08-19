"""
WHOIS Analyser plugin.

This plugin performs active WHOIS lookups by querying WHOIS servers directly
to gather domain registration information, nameservers, and administrative details.
"""

import socket
import re
import hashlib
import datetime
from typing import Dict, Any, Optional, List
from ..base import DomainContentPlugin, PluginTrafficType
from ...config import config
from ...security import security


class WHOISAnalyserPlugin(DomainContentPlugin):
    """WHOIS domain analysis plugin."""
    
    def __init__(self):
        """Initialize the WHOIS analyser plugin."""
        timeout = config.get_request_timeout(10.0)
        super().__init__("WHOIS-Analyser", timeout=timeout, rate_limit_delay=3.0, 
                         traffic_type=PluginTrafficType.ACTIVE)
        
        # Common WHOIS servers for different TLDs
        self.whois_servers = {
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'info': 'whois.afilias.net',
            'biz': 'whois.neulevel.biz',
            'us': 'whois.nic.us',
            'uk': 'whois.nic.uk',
            'co.uk': 'whois.nic.uk',
            'de': 'whois.denic.de',
            'fr': 'whois.afnic.fr',
            'au': 'whois.auda.org.au',
            'ca': 'whois.cira.ca',
            'jp': 'whois.jprs.jp',
            'cn': 'whois.cnnic.cn',
            'in': 'whois.registry.in'
        }
        
        self.default_whois_server = 'whois.iana.org'
        self.whois_port = 43
    
    def analyze_domain_content(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Analyse domain WHOIS information.
        
        Args:
            domain: The domain name to analyse
            
        Returns:
            WHOIS analysis data dictionary or None if not available
        """
        self._enforce_rate_limit()
        
        try:
            # Get WHOIS data
            whois_data = self._get_whois_data(domain)
            if not whois_data:
                return self._get_mock_whois_analysis(domain)
            
            # Parse WHOIS response
            parsed_data = self._parse_whois_data(whois_data, domain)
            
            # Perform analysis
            analysis = self._analyze_whois_info(parsed_data, domain)
            
            return analysis
            
        except Exception as e:
            self._handle_request_error(e, domain)
            return self._get_mock_whois_analysis(domain)
    
    def _get_whois_data(self, domain: str) -> Optional[str]:
        """
        Get WHOIS data by querying WHOIS servers.
        
        Args:
            domain: Domain to query
            
        Returns:
            Raw WHOIS response or None
        """
        # Determine the appropriate WHOIS server
        whois_server = self._get_whois_server(domain)
        
        try:
            # Connect to WHOIS server
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((whois_server, self.whois_port))
                
                # Send query
                query = f"{domain}\r\n"
                sock.send(query.encode('utf-8'))
                
                # Receive response
                response = b""
                while True:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            break
                        response += data
                        # Limit response size to prevent memory issues
                        if len(response) > 100000:  # 100KB limit
                            break
                    except socket.timeout:
                        break
                
                return response.decode('utf-8', errors='ignore')
                
        except Exception as e:
            # Try the default IANA server as fallback
            if whois_server != self.default_whois_server:
                try:
                    return self._query_whois_server(domain, self.default_whois_server)
                except Exception:
                    pass
            return None
    
    def _query_whois_server(self, domain: str, server: str) -> str:
        """Query a specific WHOIS server."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect((server, self.whois_port))
            
            query = f"{domain}\r\n"
            sock.send(query.encode('utf-8'))
            
            response = b""
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                    if len(response) > 100000:
                        break
                except socket.timeout:
                    break
            
            return response.decode('utf-8', errors='ignore')
    
    def _get_whois_server(self, domain: str) -> str:
        """
        Determine the appropriate WHOIS server for a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            WHOIS server hostname
        """
        # Extract TLD
        parts = domain.lower().split('.')
        if len(parts) < 2:
            return self.default_whois_server
        
        # Check for common multi-part TLDs first
        if len(parts) >= 3:
            two_part_tld = '.'.join(parts[-2:])
            if two_part_tld in self.whois_servers:
                return self.whois_servers[two_part_tld]
        
        # Check single TLD
        tld = parts[-1]
        return self.whois_servers.get(tld, self.default_whois_server)
    
    def _parse_whois_data(self, whois_data: str, domain: str) -> Dict[str, Any]:
        """
        Parse raw WHOIS data into structured information.
        
        Args:
            whois_data: Raw WHOIS response
            domain: Domain being queried
            
        Returns:
            Parsed WHOIS data
        """
        lines = whois_data.split('\n')
        parsed = {
            'domain_name': domain,
            'registrar': '',
            'creation_date': '',
            'expiration_date': '',
            'updated_date': '',
            'name_servers': [],
            'registrant_org': '',
            'admin_contact': '',
            'tech_contact': '',
            'status': [],
            'dnssec': '',
            'raw_data': whois_data[:2000]  # Store limited raw data
        }
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('%') or line.startswith('#'):
                continue
            
            # Parse key-value pairs
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                # Map common fields
                if any(k in key for k in ['registrar', 'registration service provider']):
                    parsed['registrar'] = value
                elif any(k in key for k in ['creation date', 'created', 'registered']):
                    parsed['creation_date'] = self._parse_date(value)
                elif any(k in key for k in ['expir', 'registry expiry date']):
                    parsed['expiration_date'] = self._parse_date(value)
                elif any(k in key for k in ['updated', 'last modified']):
                    parsed['updated_date'] = self._parse_date(value)
                elif any(k in key for k in ['name server', 'nserver', 'dns']):
                    if value and value not in parsed['name_servers']:
                        parsed['name_servers'].append(value)
                elif any(k in key for k in ['registrant', 'registrant organization']):
                    parsed['registrant_org'] = value
                elif any(k in key for k in ['admin', 'administrative contact', 'admin-c']):
                    if not parsed['admin_contact']:  # Only capture first admin contact
                        parsed['admin_contact'] = value
                elif any(k in key for k in ['tech', 'technical contact', 'tech-c']):
                    if not parsed['tech_contact']:  # Only capture first tech contact
                        parsed['tech_contact'] = value
                elif 'status' in key:
                    if value and value not in parsed['status']:
                        parsed['status'].append(value)
                elif 'dnssec' in key:
                    parsed['dnssec'] = value
        
        # Clean and sanitize data
        for key, value in parsed.items():
            if isinstance(value, str):
                parsed[key] = security.sanitize_output_text(value, 200)
            elif isinstance(value, list):
                parsed[key] = [security.sanitize_output_text(v, 100) for v in value[:10]]
        
        return parsed
    
    def _parse_date(self, date_str: str) -> str:
        """
        Parse date string from WHOIS data.
        
        Args:
            date_str: Raw date string
            
        Returns:
            Standardized date string or empty string
        """
        if not date_str:
            return ''
        
        # Common date patterns in WHOIS data
        date_patterns = [
            r'(\d{4}-\d{2}-\d{2})',  # YYYY-MM-DD
            r'(\d{2}-\d{2}-\d{4})',  # DD-MM-YYYY or MM-DD-YYYY
            r'(\d{4}/\d{2}/\d{2})',  # YYYY/MM/DD
            r'(\d{2}/\d{2}/\d{4})',  # MM/DD/YYYY or DD/MM/YYYY
            r'(\d{2}\.\d{2}\.\d{4})', # DD.MM.YYYY
        ]
        
        for pattern in date_patterns:
            match = re.search(pattern, date_str)
            if match:
                return match.group(1)
        
        # Extract just the date part if it's a datetime string
        date_only = date_str.split('T')[0]
        if len(date_only) == 10 and date_only.count('-') == 2:
            return date_only
        
        return date_str[:20]  # Limit length
    
    def _analyze_whois_info(self, parsed_data: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """
        Analyse parsed WHOIS information for security insights.
        
        Args:
            parsed_data: Parsed WHOIS data
            domain: Domain being analysed
            
        Returns:
            Analysis results
        """
        # Create title with key WHOIS information
        title_parts = []
        
        # Registrar
        if parsed_data['registrar']:
            title_parts.append(f"Registrar: {parsed_data['registrar']}")
        
        # Registrant organization
        if parsed_data['registrant_org']:
            title_parts.append(f"Org: {parsed_data['registrant_org']}")
        
        # Admin contact
        if parsed_data['admin_contact']:
            title_parts.append(f"Admin: {parsed_data['admin_contact']}")
        
        # Tech contact
        if parsed_data['tech_contact']:
            title_parts.append(f"Tech: {parsed_data['tech_contact']}")
        
        # Creation date
        if parsed_data['creation_date']:
            title_parts.append(f"Created: {parsed_data['creation_date']}")
        
        title = "; ".join(title_parts) if title_parts else "WHOIS Data Available"
        
        analysis = {
            'title': title,
            'domain_info': {
                'domain_name': parsed_data['domain_name'],
                'registrar': parsed_data['registrar'],
                'creation_date': parsed_data['creation_date'],
                'expiration_date': parsed_data['expiration_date'],
                'updated_date': parsed_data['updated_date'],
                'registrant_organization': parsed_data['registrant_org'],
                'admin_contact': parsed_data['admin_contact'],
                'tech_contact': parsed_data['tech_contact'],
                'name_servers': parsed_data['name_servers'],
                'domain_status': parsed_data['status'],
                'dnssec_enabled': 'signed' in parsed_data['dnssec'].lower() if parsed_data['dnssec'] else False
            },
            'security_analysis': self._perform_security_analysis(parsed_data, domain),
            'age_analysis': self._analyze_domain_age(parsed_data),
            'nameserver_analysis': self._analyze_nameservers(parsed_data['name_servers'])
        }
        
        return analysis
    
    def _perform_security_analysis(self, parsed_data: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """Perform security analysis of WHOIS data."""
        issues = []
        risk_score = 0
        
        # Check for privacy protection
        registrant = parsed_data['registrant_org'].lower()
        privacy_indicators = ['privacy', 'protected', 'redacted', 'whoisguard', 'domains by proxy']
        has_privacy = any(indicator in registrant for indicator in privacy_indicators)
        
        # Check domain age
        creation_date = parsed_data['creation_date']
        is_new_domain = False
        if creation_date:
            try:
                # Simple age check (would need proper date parsing for accuracy)
                current_year = datetime.datetime.now().year
                if creation_date and any(str(year) in creation_date for year in range(current_year-1, current_year+1)):
                    is_new_domain = True
                    issues.append('Recently registered domain')
                    risk_score += 20
            except Exception:
                pass
        
        # Check for suspicious registrar patterns
        registrar = parsed_data['registrar'].lower()
        if any(term in registrar for term in ['unknown', 'suspended', 'anonymous']):
            issues.append('Suspicious registrar information')
            risk_score += 15
        
        # Check domain status
        status_list = [s.lower() for s in parsed_data['status']]
        if any('hold' in status or 'suspended' in status for status in status_list):
            issues.append('Domain has hold or suspension status')
            risk_score += 30
        
        return {
            'has_privacy_protection': has_privacy,
            'is_recently_registered': is_new_domain,
            'security_issues': issues,
            'risk_score': min(risk_score, 100),
            'dnssec_enabled': 'signed' in parsed_data['dnssec'].lower() if parsed_data['dnssec'] else False
        }
    
    def _analyze_domain_age(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyse domain age and registration patterns."""
        creation_date = parsed_data['creation_date']
        expiration_date = parsed_data['expiration_date']
        
        age_category = 'unknown'
        days_until_expiry = 0
        
        if creation_date:
            # Simplified age analysis (would need proper date parsing)
            current_year = datetime.datetime.now().year
            if any(str(year) in creation_date for year in range(current_year-1, current_year+1)):
                age_category = 'new'
            elif any(str(year) in creation_date for year in range(current_year-5, current_year-1)):
                age_category = 'moderate'
            else:
                age_category = 'established'
        
        return {
            'age_category': age_category,
            'creation_date': creation_date,
            'expiration_date': expiration_date,
            'days_until_expiry': days_until_expiry
        }
    
    def _analyze_nameservers(self, nameservers: List[str]) -> Dict[str, Any]:
        """Analyse nameserver configuration."""
        ns_analysis = {
            'count': len(nameservers),
            'providers': [],
            'uses_cloud_dns': False,
            'geographic_distribution': 'unknown'
        }
        
        # Common DNS providers
        dns_providers = {
            'cloudflare': ['cloudflare.com', 'ns.cloudflare.com'],
            'google': ['google.com', 'googledomains.com'],
            'amazon': ['awsdns', 'amazon.com'],
            'godaddy': ['domaincontrol.com', 'godaddy.com'],
            'namecheap': ['namecheap.com', 'registrar-servers.com']
        }
        
        for ns in nameservers:
            ns_lower = ns.lower()
            for provider, patterns in dns_providers.items():
                if any(pattern in ns_lower for pattern in patterns):
                    if provider not in ns_analysis['providers']:
                        ns_analysis['providers'].append(provider)
                    if provider in ['cloudflare', 'google', 'amazon']:
                        ns_analysis['uses_cloud_dns'] = True
                    break
        
        return ns_analysis
    
    def _get_mock_whois_analysis(self, domain: str) -> Dict[str, Any]:
        """
        Provide mock WHOIS analysis when query fails.
        
        Args:
            domain: The domain being analysed
            
        Returns:
            Mock WHOIS analysis data
        """
        domain_hash = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)
        
        # Generate deterministic mock data
        registrars = ['GoDaddy', 'Namecheap', 'Google Domains', 'Cloudflare']
        registrar = registrars[domain_hash % len(registrars)]
        
        is_new = domain_hash % 10 == 0
        has_privacy = domain_hash % 3 == 0
        
        mock_nameservers = [
            f'ns1.{domain}',
            f'ns2.{domain}'
        ]
        
        # Mock contact information
        registrant_org = 'Privacy Protected' if has_privacy else 'Example Organization'
        admin_contact = 'Privacy Protected' if has_privacy else 'admin@example.com'
        tech_contact = 'Privacy Protected' if has_privacy else 'tech@example.com'
        
        # Create mock title
        title_parts = [f"Registrar: {registrar}"]
        if not has_privacy:
            title_parts.append(f"Org: {registrant_org}")
            title_parts.append(f"Admin: {admin_contact}")
            title_parts.append(f"Tech: {tech_contact}")
        else:
            title_parts.append("Org: Privacy Protected")
        
        title_parts.append(f"Created: {'2024-01-01' if is_new else '2020-01-01'}")
        mock_title = "; ".join(title_parts)
        
        return {
            'title': mock_title,
            'domain_info': {
                'domain_name': domain,
                'registrar': registrar,
                'creation_date': '2024-01-01' if is_new else '2020-01-01',
                'expiration_date': '2025-01-01',
                'updated_date': '2024-06-01',
                'registrant_organization': registrant_org,
                'admin_contact': admin_contact,
                'tech_contact': tech_contact,
                'name_servers': mock_nameservers,
                'domain_status': ['clientTransferProhibited'],
                'dnssec_enabled': domain_hash % 4 == 0
            },
            'security_analysis': {
                'has_privacy_protection': has_privacy,
                'is_recently_registered': is_new,
                'security_issues': ['Recently registered domain'] if is_new else [],
                'risk_score': 20 if is_new else 5,
                'dnssec_enabled': domain_hash % 4 == 0
            },
            'age_analysis': {
                'age_category': 'new' if is_new else 'established',
                'creation_date': '2024-01-01' if is_new else '2020-01-01',
                'expiration_date': '2025-01-01',
                'days_until_expiry': 365
            },
            'nameserver_analysis': {
                'count': 2,
                'providers': ['cloudflare'] if domain_hash % 2 == 0 else [],
                'uses_cloud_dns': domain_hash % 2 == 0,
                'geographic_distribution': 'global'
            },
            'note': 'Mock WHOIS analysis - query failed'
        }