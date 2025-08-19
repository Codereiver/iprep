# iprep - IP and Domain Reputation Analysis Tool

A comprehensive security analysis tool that performs IP geolocation, domain reputation checking, and network security analysis by querying multiple public data sources and performing direct security assessments.

## Features

- **Dual Analysis Modes**: Supports both IP addresses and domain names
- **Plugin-Based Architecture**: Modular design with 12+ specialized analysis plugins
- **Security-First Design**: Passive-only by default with explicit opt-in for active scanning
- **Traffic Classification**: Plugins are classified as passive (API queries) or active (direct target contact)
- **Comprehensive Coverage**: Geolocation, reputation, DNS, TLS/SSL, WHOIS, and content analysis
- **Security Hardening**: HTTPS enforcement, input validation, output sanitization, SSRF protection
- **Rate Limiting**: Built-in rate limiting to respect API limits and avoid overwhelming targets
- **Flexible Configuration**: Environment variable and command-line control over plugin behavior

## Installation

```bash
git clone <repository-url>
cd iprep
```

## Usage

### Command Line Interface

#### Basic Analysis (Passive-Only by Default)
```bash
# Analyze IP address (passive analysis only)
python -m iprep.agent 8.8.8.8

# Analyze domain name (passive analysis only)
python -m iprep.agent example.com
```

#### Active Analysis (Direct Target Contact)
```bash
# Enable active scanning for comprehensive analysis
python -m iprep.agent --allow-active example.com

# Use environment variable for global control
IPREP_ALLOW_ACTIVE_PLUGINS=true python -m iprep.agent example.com
```

#### Plugin Management
```bash
# List all available plugins and their types
python -m iprep.agent --list-plugins

# Show which plugins would contact targets directly
python -m iprep.agent --show-active
```

#### Debug Mode
```bash
# Enable basic debug output
python -m iprep.agent --debug example.com

# Enable detailed debug output
python -m iprep.agent --debug --debug-level detailed example.com

# Enable verbose debug output (full data)
python -m iprep.agent --debug --debug-level verbose example.com

# Use environment variables for debug mode
IPREP_DEBUG=true IPREP_DEBUG_LEVEL=detailed python -m iprep.agent example.com
```

### Python API

```python
from iprep.agent import IPRepAgent

# Create agent (passive-only by default)
agent = IPRepAgent()

# Analyze IP address
ip_results = agent.analyze_ip("8.8.8.8")

# Analyze domain name
domain_results = agent.analyze_domain("example.com")

# Analyze input (auto-detects IP vs domain)
results = agent.analyze_input("example.com")
```

## Available Plugins

The tool includes 12 specialized plugins organized by traffic type and analysis focus:

### Passive Plugins (Query APIs About Targets)

#### IP Geolocation & Reputation
- **IP-API** - Free IP geolocation service providing country, region, city, ISP, and ASN information
- **IPinfo** - IP geolocation and network details with comprehensive geographic and organizational data
- **AbuseIPDB** - Community-driven IP abuse database for identifying malicious IP addresses
- **GreyNoise** - Internet background noise detection to distinguish scanning traffic from targeted attacks
- **URLVoid** - Multi-engine IP reputation checker aggregating data from various security vendors

#### Domain Reputation  
- **PhishTank** - Community-driven phishing detection service for identifying malicious domains and URLs
- **URLVoid-Domain** - Domain reputation analysis using multiple security engines and threat feeds
- **VirusTotal-Domain** - Domain analysis using VirusTotal's comprehensive threat intelligence database

### Active Plugins (Directly Contact Targets)

#### Domain Content & Infrastructure Analysis
- **DNS-Analyser** - Comprehensive DNS record analysis including A, AAAA, MX, CNAME records, subdomain detection, and hosting provider identification
- **HTTP-Analyser** - Website content analysis including title extraction, technology detection, and security headers
- **TLS-Analyser** - SSL/TLS certificate analysis with CN/SAN field extraction, expiry tracking, cipher suites, and comprehensive certificate examination (bypasses validation to analyse any presented certificate)
- **WHOIS-Analyser** - Domain registration information including registrar, admin/tech contacts, creation dates, nameservers, and ownership details

## Architecture

The project follows a security-focused, modular plugin-based architecture:

### Core Components
- **Agent**: Main orchestrator that coordinates all analysis tasks and manages plugin filtering
- **Validator**: IP address and domain validation with security hardening
- **Aggregator**: Combines and correlates results from multiple data sources
- **Security Manager**: Handles input validation, output sanitization, and SSRF protection
- **Configuration System**: Manages API keys, timeouts, and plugin behavior securely

### Plugin Classification System
- **Passive Plugins**: Query third-party APIs and databases about targets (no direct target contact)
- **Active Plugins**: Directly contact targets to gather information (generates network traffic to target)
- **Traffic Type Control**: Users can control which plugin types are enabled for privacy and security

## Security Features

### Input Validation & SSRF Protection
- URL validation to prevent Server-Side Request Forgery attacks
- Input sanitization for IP addresses and domain names
- Content-type validation for HTTP responses
- Hostname verification for active connections

### Output Sanitization
- API key redaction from error messages and logs
- Text length limiting and content sanitization
- Safe error message formatting to prevent information disclosure

### Secure Configuration
- Environment variable-based API key management
- HTTPS-only endpoints enforcement for all external communications
- Request timeout bounds (1-30 seconds) to prevent resource exhaustion
- Plugin traffic type classification for controlled analysis

## Configuration

### API Keys (Optional)
Some plugins support API keys for enhanced functionality:

```bash
# GreyNoise (optional - free tier available)
export IPREP_GREYNOISE_API_KEY="your-api-key"

# AbuseIPDB (optional for higher rate limits)
export IPREP_ABUSEIPDB_API_KEY="your-api-key"

# PhishTank (optional for higher rate limits)
export IPREP_PHISHTANK_API_KEY="your-api-key"
```

### Plugin Control
```bash
# Disable active plugins globally (default: false - passive only)
export IPREP_ALLOW_ACTIVE_PLUGINS=false

# Enable active plugins globally
export IPREP_ALLOW_ACTIVE_PLUGINS=true

# Set custom request timeout (1-30 seconds)
export IPREP_REQUEST_TIMEOUT=15

# Enable debug mode for troubleshooting
export IPREP_DEBUG=true
export IPREP_DEBUG_LEVEL=detailed  # Options: basic, detailed, verbose
```

## Plugin Development

### Creating New Plugins

Choose the appropriate base class based on your plugin's purpose and traffic type:

```python
from iprep.plugins.base import ReputationPlugin, PluginTrafficType

class MyReputationPlugin(ReputationPlugin):
    def __init__(self):
        super().__init__("MyService", timeout=10, rate_limit_delay=1.0)
        # Specify traffic type: PASSIVE (API queries) or ACTIVE (target contact)
        self.traffic_type = PluginTrafficType.PASSIVE
    
    def get_reputation(self, ip_address):
        # Implement your reputation logic here
        return {
            'is_malicious': False,
            'threat_types': [],
            'confidence_score': 0.1,
            'last_seen': '2024-01-01'
        }
```

### Plugin Types
- **GeolocationPlugin**: For IP geolocation services (typically passive)
- **ReputationPlugin**: For IP reputation services (typically passive)  
- **DomainReputationPlugin**: For domain reputation services (typically passive)
- **DomainContentPlugin**: For domain content analysis (typically active)

### Security Guidelines
- Set appropriate traffic type (`PluginTrafficType.PASSIVE` or `PluginTrafficType.ACTIVE`)
- Use HTTPS-only endpoints for external API calls
- Implement proper error handling with the `_handle_request_error()` method
- Sanitize all output using the security utilities
- Include rate limiting with `_enforce_rate_limit()`

## Testing

### Running Tests
Run the comprehensive test suite with over 210 tests:

```bash
# Run all tests
python -m pytest tests/

# Run with verbose output
python -m pytest tests/ -v

# Run specific test categories
python -m pytest tests/unit/ -v           # Unit tests
python -m pytest tests/integration/ -v    # Integration tests
python -m pytest tests/security/ -v       # Security tests
python -m pytest tests/plugins/ -v        # Plugin tests
```

### Test Coverage
The test suite includes:
- Unit tests for all core components and plugins
- Integration tests for end-to-end workflows
- Security tests for input validation and SSRF protection
- Plugin classification and traffic type tests
- Mock API response handling and error scenarios

## Example Output

### Passive Analysis (Default)
```bash
$ python -m iprep.agent example.com
Analysis results for example.com (domain):
  ℹ️  Passive analysis: Used 8 passive plugin(s)

  Domain: example.com
  Reputation Analysis (3 sources):
    PhishTank: CLEAN []
    URLVoid-Domain: CLEAN []
    VirusTotal-Domain: CLEAN []
  Content Analysis (0 sources):
  Summary:
    Potentially Malicious: False
    Detections: 0/3
```

### Active Analysis (With --allow-active)
```bash
$ python -m iprep.agent --allow-active google.com
Analysis results for google.com (domain):
  ⚠️  Active scanning: 4 plugin(s) contacted the target directly
  ℹ️  Passive analysis: Used 8 passive plugin(s)

  Domain: google.com
  Reputation Analysis (3 sources):
    PhishTank: CLEAN []
    URLVoid-Domain: CLEAN []
    VirusTotal-Domain: CLEAN []
  Content Analysis (4 sources):
    DNS-Analyser: 'A: 142.250.117.102 (+5 more); AAAA: 2a00:1450:4009:c17::8b; MX: 1 record; Subdomains: 6' []
    HTTP-Analyser: '301 Moved' []
    TLS-Analyser: 'CN: *.google.com; SAN: *.google.com, *.appengine.google.com, *.bdn.dev, *.origin-test.bdn.dev, *.cloud.google.com, *.crowdsource.google.com, *.datacompute.google.com, *.google.ca, *.google.cl, *.google.co.in; Expires in 40 days' []
    WHOIS-Analyser: 'Registrar: +1.2086851750; Created: 1997-09-15' []
  Summary:
    Potentially Malicious: False
    Detections: 0/3
    Technologies:
```

## Recent Enhancements (2024)

### Enhanced Domain Content Analysis

The domain content analysis plugins have been significantly improved to provide detailed, actionable security intelligence:

#### TLS-Analyser Improvements
- **Certificate Details**: Displays actual CN (Common Name) and complete SAN (Subject Alternative Names) fields
- **Expiry Tracking**: Shows precise days until certificate expiration with clear warnings
- **Full Certificate Analysis**: No truncation of SAN lists - shows all Subject Alternative Names
- **Example Output**: `"CN: *.google.com; SAN: *.google.com, *.appengine.google.com, ...; Expires in 40 days"`

#### DNS-Analyser Improvements  
- **Comprehensive DNS Records**: Displays A, AAAA, and MX record information with IP addresses
- **Subdomain Discovery**: Detects and counts common subdomains (www, mail, api, admin, etc.)
- **Infrastructure Analysis**: Identifies hosting providers and CDN usage patterns
- **Example Output**: `"A: 142.250.117.102 (+5 more); AAAA: 2a00:1450:4009:c17::8b; MX: 1 record; Subdomains: 6"`

#### WHOIS-Analyser Improvements
- **Contact Information**: Extracts registrar, admin contacts, and tech contacts from WHOIS data
- **Registration Intelligence**: Shows registrant organization, creation dates, and ownership details
- **Privacy Detection**: Identifies when privacy protection services are in use
- **Example Output**: `"Registrar: GoDaddy; Org: Example Corp; Admin: admin@example.com; Created: 2020-01-01"`

#### Output Format Improvements
- **Rich Information Display**: All analyzers now provide meaningful data instead of generic "N/A" responses
- **No Title Truncation**: Removed artificial character limits to show complete information
- **Consistent Formatting**: Standardized output formats across all domain content plugins
- **Enhanced User Experience**: Clear, informative summaries that provide actionable security insights

These improvements transform the tool from showing basic connectivity status to providing comprehensive domain security intelligence including certificate details, DNS infrastructure, and registration information.

## Privacy and Ethics

### Passive vs Active Analysis
- **Passive analysis** (default): Only queries third-party APIs about targets - no direct contact with target infrastructure
- **Active analysis** (opt-in): Directly contacts targets for comprehensive analysis - generates network traffic to target

### Responsible Use
- Use passive-only analysis when privacy is a concern
- Only use active analysis on domains/IPs you own or have explicit permission to analyze
- Respect rate limits and avoid overwhelming target infrastructure
- Be aware that active analysis may be logged by target systems

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please:
1. Follow the existing code style and plugin architecture
2. Add comprehensive tests for new functionality
3. Update documentation for any new features
4. Ensure all security guidelines are followed for new plugins