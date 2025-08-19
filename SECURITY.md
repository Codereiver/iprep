# Security Features and Best Practices

This document outlines the security measures implemented in the iprep project to protect against common vulnerabilities and ensure secure operation.

## Security Features Implemented

### 1. Secure Configuration Management

**Location**: `iprep/config.py`

- **API Key Security**: API keys are loaded from environment variables only, never hardcoded
- **Key Validation**: API keys are validated for format and length before use
- **Secure Endpoints**: Only HTTPS endpoints are allowed for external requests
- **Timeout Bounds**: Request timeouts are bounded between 1-30 seconds to prevent DoS

**Environment Variables**:
- `IPREP_ABUSEIPDB_API_KEY` - AbuseIPDB API key
- `IPREP_VIRUSTOTAL_API_KEY` - VirusTotal API key  
- `IPREP_URLVOID_API_KEY` - URLVoid API key
- `IPREP_REQUEST_TIMEOUT` - Global request timeout (bounded 1-30s)

### 2. Input Validation and SSRF Protection

**Location**: `iprep/security.py`

- **URL Validation**: All URLs are validated before making requests
- **HTTPS Enforcement**: Only HTTPS schemes are allowed
- **Private IP Blocking**: Private/internal IP addresses are blocked to prevent SSRF
- **Port Filtering**: Dangerous ports (SSH, database ports, etc.) are blocked
- **Domain Validation**: Prevents domain confusion attacks

**Protected Against**:
- Server-Side Request Forgery (SSRF)
- Internal network scanning
- Protocol confusion attacks
- Port scanning via HTTP requests

### 3. Output Sanitization

**Location**: `iprep/security.py`

- **HTML Escaping**: All extracted content is HTML-escaped to prevent injection
- **Control Character Filtering**: Control characters are removed or hex-encoded
- **Length Limits**: Output is truncated to prevent memory exhaustion
- **Content Type Validation**: Only safe content types are processed

**Prevents**:
- Cross-site scripting (XSS) in logs
- Terminal escape sequence injection
- Log injection attacks
- Memory exhaustion via large content

### 4. Error Message Sanitization

**Location**: `iprep/security.py`

- **API Key Redaction**: API keys and tokens are automatically redacted from error messages
- **Path Sanitization**: Internal file paths are redacted
- **IP Address Filtering**: Internal IP addresses are filtered from error messages
- **Safe Logging**: Error messages are sanitized before logging

**Protects Against**:
- API key leakage in logs
- Information disclosure via error messages
- Internal network topology exposure

### 5. Secure Network Communications

**Applied Across All Plugins**:

- **HTTPS Only**: All external requests use HTTPS with certificate verification
- **Request Timeouts**: All requests have bounded timeouts
- **Rate Limiting**: Built-in rate limiting prevents abuse
- **User-Agent Control**: Consistent, identifiable user-agent strings
- **Redirect Protection**: Redirects are disabled to prevent attacks

### 6. Plugin Security

- **Dynamic Loading Protection**: Plugin loading is restricted to known paths
- **Error Isolation**: Plugin failures don't crash the main application
- **Resource Limits**: Memory and time limits prevent resource exhaustion
- **Sandboxing**: Plugins run with limited privileges

## Security Best Practices

### For Developers

1. **Never hardcode API keys or secrets in code**
2. **Always use environment variables for configuration**
3. **Validate all inputs before processing**
4. **Sanitize all outputs before displaying/logging**
5. **Use HTTPS for all external communications**
6. **Implement proper error handling without information disclosure**

### For Users

1. **Set API keys via environment variables**:
   ```bash
   export IPREP_ABUSEIPDB_API_KEY="your-secure-api-key"
   ```

2. **Use secure endpoints only** - the tool enforces HTTPS

3. **Monitor logs for security events** - errors are sanitized but still useful

4. **Keep timeouts reasonable** - default bounds prevent DoS

### For Deployment

1. **Environment Variable Security**:
   - Use secure secret management systems
   - Never log environment variables
   - Rotate API keys regularly

2. **Network Security**:
   - Deploy behind firewalls
   - Monitor outbound requests
   - Block internal network access if needed

3. **Monitoring**:
   - Monitor for failed requests (potential attacks)
   - Watch for unusual patterns
   - Log security events appropriately

## Threat Model

### Threats Mitigated

- **Server-Side Request Forgery (SSRF)**: Prevented via URL validation and private IP blocking
- **Information Disclosure**: Mitigated through error message sanitization
- **Injection Attacks**: Prevented via input validation and output sanitization
- **API Key Exposure**: Prevented through secure configuration management
- **Network Attacks**: Mitigated via HTTPS enforcement and timeout bounds

### Residual Risks

- **Dependency Vulnerabilities**: Keep dependencies updated
- **DNS Attacks**: DNS responses are trusted (by design for functionality)
- **Certificate Authority Compromise**: Standard PKI risks apply
- **Rate Limiting Bypass**: Distributed attacks may still succeed

## Security Testing

The project includes comprehensive security tests:

- **Configuration Security**: Tests secure API key handling
- **Input Validation**: Tests URL validation and SSRF protection  
- **Output Sanitization**: Tests injection prevention
- **Network Security**: Tests HTTPS enforcement
- **Error Handling**: Tests information disclosure prevention

Run security tests:
```bash
python -m pytest tests/security/ -v
```

## Incident Response

If you discover a security vulnerability:

1. **Do not publish the vulnerability publicly**
2. **Report via secure channels to project maintainers**
3. **Provide detailed reproduction steps**
4. **Allow time for assessment and remediation**

## Security Updates

This security documentation is updated with each release. Check the changelog for security-related changes and ensure you're running the latest version.

## Compliance Notes

This tool is designed for defensive security purposes and follows security best practices for:

- Input validation and sanitization
- Secure communications
- Error handling
- Configuration management
- Output sanitization

The tool does not store sensitive data persistently and operates with minimal privileges required for its function.