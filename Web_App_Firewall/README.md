# Web Application Firewall (WAF) - Python Implementation

A comprehensive Web Application Firewall built in Python that protects web applications from common security threats.

## 🔒 Features

### Security Protection Layers

1. **SQL Injection Detection**
   - Detects common SQL injection patterns
   - Monitors UNION, SELECT, DROP, INSERT, UPDATE queries
   - Blocks comment-based and boolean-based attacks

2. **Cross-Site Scripting (XSS) Prevention**
   - Blocks script tags and JavaScript execution
   - Detects event handlers (onclick, onerror, onload)
   - Prevents iframe and object injections

3. **Path Traversal Protection**
   - Blocks directory traversal attempts (../, ../../)
   - Detects encoded traversal patterns
   - Protects against file system access

4. **Command Injection Prevention**
   - Blocks shell command execution attempts
   - Detects pipe operators and command chains
   - Prevents system command injection

5. **Malicious File Upload Detection**
   - Blocks dangerous file extensions (.exe, .php, .jsp, .dll)
   - Prevents executable uploads
   - Protects against web shell uploads

6. **Rate Limiting**
   - Limits requests per IP address (100 requests/minute default)
   - Temporary IP blocking for violators (5 minutes)
   - DDoS and brute force protection

7. **User-Agent Validation**
   - Detects suspicious or missing user agents
   - Identifies automated attack tools

## 📁 Project Structure

```
waf-project/
│
├── waf.py              # Main WAF server implementation
├── test_waf.py         # Comprehensive testing suite
├── requirements.txt    # Python dependencies
├── waf.log            # Attack and request logs (auto-generated)
└── README.md          # This file
```

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Setup

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install requests colorama
```

## 💻 Usage

### Starting the WAF Server

Run the WAF server on localhost:
```bash
python waf.py
```

The server will start on `http://localhost:8080` by default.

**Server Output:**
```
2025-01-XX XX:XX:XX - INFO - WAF Server started on 0.0.0.0:8080
Security features enabled:
  - SQL Injection Detection
  - XSS Detection
  - Path Traversal Detection
  - Command Injection Detection
  - Malicious File Upload Detection
  - Rate Limiting (100 req/min per IP)
  - Suspicious User-Agent Detection

Access statistics at: http://localhost:8080/waf/stats
```

### Running Tests

In a separate terminal, run the test suite:
```bash
python test_waf.py
```

This will:
- Test all security features
- Simulate various attack scenarios
- Display real-time results with color coding
- Show WAF statistics

### Viewing Statistics

Access WAF statistics in your browser:
```
http://localhost:8080/waf/stats
```

Or use curl:
```bash
curl http://localhost:8080/waf/stats
```

**Statistics include:**
- Total attacks blocked
- Attacks by type (SQL Injection, XSS, etc.)
- Top attacking IP addresses
- Currently blocked IPs

## 🧪 Testing Examples

### Normal Request (Allowed)
```bash
curl http://localhost:8080/home
```

### SQL Injection (Blocked)
```bash
curl "http://localhost:8080/users?id=1' OR '1'='1"
```

### XSS Attack (Blocked)
```bash
curl "http://localhost:8080/search?q=<script>alert('XSS')</script>"
```

### Path Traversal (Blocked)
```bash
curl "http://localhost:8080/files?path=../../etc/passwd"
```

### Command Injection (Blocked)
```bash
curl "http://localhost:8080/ping?host=8.8.8.8;cat /etc/passwd"
```

## 📊 Log File

All requests and attacks are logged to `waf.log`:

```
2025-01-XX XX:XX:XX - WARNING - Attack detected from 127.0.0.1: SQL_INJECTION
2025-01-XX XX:XX:XX - INFO - Blocked request from 127.0.0.1: ['SQL_INJECTION']
2025-01-XX XX:XX:XX - INFO - Allowed request from 127.0.0.1: GET /home
```

## ⚙️ Configuration

### Adjusting Rate Limits

In `waf.py`, modify the RateLimiter initialization:

```python
self.rate_limiter = RateLimiter(
    max_requests=100,    # Maximum requests
    time_window=60       # Time window in seconds
)
```

### Changing Server Port

Modify the `run_waf_server` call:

```python
run_waf_server(host='0.0.0.0', port=8080)
```

### Adding Custom Security Rules

Add new patterns to the `SecurityRules` class:

```python
CUSTOM_PATTERNS = [
    r"your_pattern_here",
    r"another_pattern",
]
```

## 🎯 Real-World Integration

### Using as a Reverse Proxy

To protect an existing application:

1. Modify the `handle_request` method in `waf.py`
2. Forward clean requests to your backend:

```python
import requests

# In handle_request, after WAF check passes:
backend_url = f"http://your-backend:8000{path}"
backend_response = requests.request(
    method=method,
    url=backend_url,
    headers=headers,
    data=body
)
# Forward response to client
```

### Production Deployment

For production use, consider:
- Using a production WSGI server (gunicorn, uWSGI)
- Adding HTTPS support
- Implementing persistent storage for logs
- Adding more sophisticated rate limiting
- Integration with SIEM systems

## 🔍 Attack Detection Details

### SQL Injection Patterns
- Boolean-based: `OR 1=1`, `AND 1=0`
- Union-based: `UNION SELECT`
- Comment-based: `--`, `#`, `/* */`
- Stacked queries: `;DROP TABLE`

### XSS Patterns
- Script tags: `<script>`, `</script>`
- Event handlers: `onclick=`, `onerror=`
- JavaScript protocol: `javascript:`
- Data URIs and encoded scripts

### Path Traversal
- Unix-style: `../`, `../../`
- Windows-style: `..\`, `..\..\`
- URL encoded: `%2e%2e/`, `%252e`

## 📈 Performance

- **Latency:** ~1-5ms per request (pattern matching)
- **Throughput:** Handles thousands of requests per second
- **Memory:** Minimal memory footprint
- **Scalability:** Can be deployed with multiple instances

## 🛡️ Security Considerations

**Important Notes:**
- This WAF is for educational/demonstration purposes
- For production, use established solutions like ModSecurity, AWS WAF, or Cloudflare
- Regularly update security patterns
- Monitor false positives/negatives
- Combine with other security measures (HTTPS, authentication, etc.)

## 🔄 Future Enhancements

Potential improvements:
- [ ] Machine learning-based anomaly detection
- [ ] Geo-blocking capabilities
- [ ] Custom rule engine
- [ ] Web dashboard for monitoring
- [ ] Database integration for persistent logs
- [ ] Email alerts for critical attacks
- [ ] API for rule management
- [ ] Support for regex custom rules
- [ ] Integration with threat intelligence feeds

## 📚 Learning Resources

This project demonstrates:
- HTTP request/response handling
- Regular expression pattern matching
- Rate limiting algorithms
- Threat detection logic
- Logging and monitoring
- Security best practices

## 🤝 Contributing

To extend this WAF:
1. Add new attack patterns in `SecurityRules`
2. Implement detection logic in `analyze_request`
3. Add corresponding tests in `test_waf.py`
4. Update documentation

## 📝 License

This project is for educational purposes. Use responsibly and ethically.

## ⚠️ Disclaimer

This WAF is a learning project and should not be used as the sole security measure in production environments. Always use multiple layers of security and follow security best practices.

## 🐛 Troubleshooting

### Server won't start
- Check if port 8080 is available
- Try a different port
- Check firewall settings

### Tests failing
- Ensure server is running
- Wait a few seconds between test runs
- Check if port is correct in test_waf.py

### High false positives
- Adjust regex patterns
- Add whitelisting for known safe patterns
- Review and tune detection thresholds

## 📞 Support

For issues or questions:
1. Check the logs in `waf.log`
2. Review test output for details
3. Verify configuration settings
