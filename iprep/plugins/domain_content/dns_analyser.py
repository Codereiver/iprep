"""
DNS analyser plugin.

This plugin analyses DNS records and infrastructure
information for domain names.
"""

import socket
from typing import Dict, Any, Optional, List
from ..base import DomainContentPlugin, PluginTrafficType


class DNSAnalyserPlugin(DomainContentPlugin):
    """Domain DNS analysis plugin."""
    
    def __init__(self):
        """Initialize the DNS analyser plugin."""
        super().__init__("DNS-Analyser", timeout=10, rate_limit_delay=1.0, 
                         traffic_type=PluginTrafficType.ACTIVE)
    
    def analyze_domain_content(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Analyse domain DNS records and infrastructure.
        
        Args:
            domain: The domain name to analyse
            
        Returns:
            DNS analysis data dictionary or None if not available
        """
        self._enforce_rate_limit()
        
        try:
            dns_records = self._get_dns_records(domain)
            infrastructure = self._analyze_infrastructure(dns_records)
            
            # Create title based on DNS lookup results
            title_parts = []
            
            # A records
            a_records = dns_records.get('A', [])
            if a_records:
                if len(a_records) == 1:
                    title_parts.append(f"A: {a_records[0]}")
                else:
                    title_parts.append(f"A: {a_records[0]} (+{len(a_records)-1} more)")
            
            # AAAA records
            aaaa_records = dns_records.get('AAAA', [])
            if aaaa_records:
                title_parts.append(f"AAAA: {aaaa_records[0]}")
            
            # MX records
            mx_records = dns_records.get('MX', [])
            if mx_records:
                title_parts.append(f"MX: {len(mx_records)} record{'s' if len(mx_records) > 1 else ''}")
            
            # Additional info
            subdomains = self._detect_common_subdomains(domain)
            if subdomains:
                title_parts.append(f"Subdomains: {len(subdomains)}")
            
            hosting_provider = self._identify_hosting_provider(dns_records)
            if hosting_provider != 'unknown':
                title_parts.append(f"Host: {hosting_provider}")
            
            title = "; ".join(title_parts) if title_parts else "DNS Resolution Available"
            
            return {
                'title': title,
                'dns_records': dns_records,
                'infrastructure_analysis': infrastructure,
                'domain_age_estimate': self._estimate_domain_age(domain),
                'subdomains_detected': subdomains,
                'mail_security': self._analyze_mail_security(dns_records),
                'cdn_usage': self._detect_cdn_usage(dns_records),
                'hosting_provider': hosting_provider
            }
            
        except Exception as e:
            self._handle_request_error(e, domain)
            return None
    
    def _get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """
        Retrieve various DNS records for the domain.
        
        Args:
            domain: The domain name
            
        Returns:
            Dictionary of DNS record types and their values
        """
        dns_records = {}
        
        # A records
        try:
            a_records = socket.getaddrinfo(domain, None, socket.AF_INET)
            dns_records['A'] = list(set([addr[4][0] for addr in a_records]))
        except socket.gaierror:
            dns_records['A'] = []
        
        # AAAA records (IPv6)
        try:
            aaaa_records = socket.getaddrinfo(domain, None, socket.AF_INET6)
            dns_records['AAAA'] = list(set([addr[4][0] for addr in aaaa_records]))
        except socket.gaierror:
            dns_records['AAAA'] = []
        
        # MX records (simplified - would need dnspython for full implementation)
        try:
            # This is a simplified approach; full implementation would use dnspython
            mx_domain = f"mail.{domain}"
            mx_records = socket.getaddrinfo(mx_domain, None, socket.AF_INET)
            dns_records['MX'] = [f"10 mail.{domain}"] if mx_records else []
        except socket.gaierror:
            dns_records['MX'] = []
        
        # CNAME (simplified check for www)
        try:
            www_records = socket.getaddrinfo(f"www.{domain}", None, socket.AF_INET)
            if www_records:
                dns_records['CNAME'] = [f"www.{domain}"]
            else:
                dns_records['CNAME'] = []
        except socket.gaierror:
            dns_records['CNAME'] = []
        
        return dns_records
    
    def _analyze_infrastructure(self, dns_records: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        Analyze DNS infrastructure characteristics.
        
        Args:
            dns_records: DNS records data
            
        Returns:
            Infrastructure analysis results
        """
        analysis = {
            'ip_count': len(dns_records.get('A', [])),
            'ipv6_enabled': len(dns_records.get('AAAA', [])) > 0,
            'multiple_a_records': len(dns_records.get('A', [])) > 1,
            'has_mail_records': len(dns_records.get('MX', [])) > 0,
            'has_www_subdomain': len(dns_records.get('CNAME', [])) > 0,
            'load_balancing': len(dns_records.get('A', [])) > 2
        }
        
        # Analyze IP ranges for hosting patterns
        a_records = dns_records.get('A', [])
        if a_records:
            analysis['ip_ranges'] = self._analyze_ip_ranges(a_records)
        
        return analysis
    
    def _analyze_ip_ranges(self, ip_addresses: List[str]) -> Dict[str, Any]:
        """
        Analyze IP address ranges and patterns.
        
        Args:
            ip_addresses: List of IP addresses
            
        Returns:
            IP range analysis
        """
        if not ip_addresses:
            return {}
        
        # Simple analysis of IP patterns
        octets = []
        for ip in ip_addresses:
            parts = ip.split('.')
            if len(parts) == 4:
                octets.append([int(p) for p in parts])
        
        if not octets:
            return {}
        
        # Check if IPs are in same subnet
        same_class_c = len(set((o[0], o[1], o[2]) for o in octets)) == 1
        same_class_b = len(set((o[0], o[1]) for o in octets)) == 1
        
        return {
            'same_class_c_subnet': same_class_c,
            'same_class_b_subnet': same_class_b,
            'ip_diversity': len(set(ip_addresses))
        }
    
    def _estimate_domain_age(self, domain: str) -> str:
        """
        Estimate domain age based on simple heuristics.
        
        Args:
            domain: The domain name
            
        Returns:
            Estimated age category
        """
        # This is a very simplified approach
        # Real implementation would query WHOIS data
        return 'unknown'
    
    def _detect_common_subdomains(self, domain: str) -> List[str]:
        """
        Detect common subdomains.
        
        Args:
            domain: The domain name
            
        Returns:
            List of detected subdomains
        """
        common_subdomains = ['www', 'mail', 'ftp', 'blog', 'api', 'admin', 'shop']
        detected = []
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{domain}"
                socket.getaddrinfo(full_domain, None)
                detected.append(subdomain)
            except socket.gaierror:
                continue
        
        return detected
    
    def _analyze_mail_security(self, dns_records: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        Analyze mail security configuration.
        
        Args:
            dns_records: DNS records data
            
        Returns:
            Mail security analysis
        """
        # Simplified mail security analysis
        has_mx = len(dns_records.get('MX', [])) > 0
        
        return {
            'has_mx_records': has_mx,
            'spf_detected': False,  # Would need TXT record parsing
            'dmarc_detected': False,  # Would need TXT record parsing
            'dkim_detected': False,  # Would need TXT record parsing
            'mail_provider_detected': 'unknown'
        }
    
    def _detect_cdn_usage(self, dns_records: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        Detect CDN usage patterns.
        
        Args:
            dns_records: DNS records data
            
        Returns:
            CDN detection results
        """
        # Simple CDN detection based on common patterns
        a_records = dns_records.get('A', [])
        
        # Check for common CDN IP ranges (simplified)
        cdn_indicators = {
            'cloudflare': False,
            'fastly': False,
            'cloudfront': False,
            'akamai': False
        }
        
        # This would be more sophisticated in a real implementation
        if any(ip.startswith('104.') for ip in a_records):
            cdn_indicators['cloudflare'] = True
        
        return {
            'cdn_detected': any(cdn_indicators.values()),
            'cdn_providers': [k for k, v in cdn_indicators.items() if v],
            'multiple_providers': sum(cdn_indicators.values()) > 1
        }
    
    def _identify_hosting_provider(self, dns_records: Dict[str, List[str]]) -> str:
        """
        Identify hosting provider based on DNS patterns.
        
        Args:
            dns_records: DNS records data
            
        Returns:
            Identified hosting provider or 'unknown'
        """
        a_records = dns_records.get('A', [])
        
        if not a_records:
            return 'unknown'
        
        # Simple hosting provider detection (would be more comprehensive in reality)
        first_ip = a_records[0]
        
        if first_ip.startswith('185.199.'):
            return 'github-pages'
        elif first_ip.startswith('151.101.'):
            return 'fastly'
        elif first_ip.startswith('104.'):
            return 'cloudflare'
        else:
            return 'unknown'
    
