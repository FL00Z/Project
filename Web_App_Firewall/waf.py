#!/usr/bin/env python3
"""
Web Application Firewall (WAF)
A comprehensive WAF implementation with multiple security layers
"""

import re
import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
import threading
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('waf.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class SecurityRules:
    """Security rules and patterns for detecting attacks"""
    
    # SQL Injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(\bunion\b.*\bselect\b)",
        r"(\bselect\b.*\bfrom\b)",
        r"(\binsert\b.*\binto\b)",
        r"(\bdelete\b.*\bfrom\b)",
        r"(\bdrop\b.*\btable\b)",
        r"(\bupdate\b.*\bset\b)",
        r"(--|\#|\/\*|\*\/)",
        r"(\bor\b.*=.*)",
        r"(\band\b.*=.*)",
        r"('.*\bor\b.*'.*=.*')",
        r"(1=1|1=0)",
        r"(\bexec(\s|\+)+(s|x)p\w+)",
    ]
    
    # XSS (Cross-Site Scripting) patterns
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"onclick\s*=",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
        r"<embed[^>]*>",
        r"eval\s*\(",
        r"expression\s*\(",
        r"vbscript:",
        r"onmouseover\s*=",
    ]
    
    # Path Traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.",
        r"%2e%2e",
        r"\.\.\\",
        r"%252e",
    ]
    
    # Command Injection patterns
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`$()]",
        r"\b(cat|ls|pwd|wget|curl|chmod|rm|mv|cp)\b",
        r"(>|<|>>)",
    ]
    
    # File Upload patterns (dangerous extensions)
    DANGEROUS_EXTENSIONS = [
        r"\.exe$",
        r"\.dll$",
        r"\.sh$",
        r"\.bat$",
        r"\.cmd$",
        r"\.php$",
        r"\.jsp$",
        r"\.asp$",
    ]


class RateLimiter:
    """Rate limiting to prevent DDoS and brute force attacks"""
    
    def __init__(self, max_requests=100, time_window=60):
        self.max_requests = max_requests
        self.time_window = time_window  # in seconds
        self.requests = defaultdict(list)
        self.blocked_ips = {}
        self.lock = threading.Lock()
    
    def is_allowed(self, ip_address):
        """Check if request from IP is allowed"""
        with self.lock:
            current_time = datetime.now()
            
            # Check if IP is temporarily blocked
            if ip_address in self.blocked_ips:
                if current_time < self.blocked_ips[ip_address]:
                    return False
                else:
                    del self.blocked_ips[ip_address]
            
            # Clean old requests
            cutoff_time = current_time - timedelta(seconds=self.time_window)
            self.requests[ip_address] = [
                req_time for req_time in self.requests[ip_address]
                if req_time > cutoff_time
            ]
            
            # Check rate limit
            if len(self.requests[ip_address]) >= self.max_requests:
                # Block IP for 5 minutes
                self.blocked_ips[ip_address] = current_time + timedelta(minutes=5)
                logger.warning(f"Rate limit exceeded for {ip_address}. Blocking for 5 minutes.")
                return False
            
            # Add current request
            self.requests[ip_address].append(current_time)
            return True


class WAFEngine:
    """Core WAF engine for analyzing and filtering requests"""
    
    def __init__(self):
        self.rate_limiter = RateLimiter(max_requests=100, time_window=60)
        self.rules = SecurityRules()
        self.attack_log = []
    
    def analyze_request(self, method, path, headers, body, client_ip):
        """Analyze HTTP request for security threats"""
        threats = []
        
        # Decode URL
        decoded_path = unquote(path)
        decoded_body = unquote(body) if body else ""
        
        # Check for SQL Injection
        for pattern in self.rules.SQL_INJECTION_PATTERNS:
            if re.search(pattern, decoded_path, re.IGNORECASE) or \
               re.search(pattern, decoded_body, re.IGNORECASE):
                threats.append("SQL_INJECTION")
                break
        
        # Check for XSS
        for pattern in self.rules.XSS_PATTERNS:
            if re.search(pattern, decoded_path, re.IGNORECASE) or \
               re.search(pattern, decoded_body, re.IGNORECASE):
                threats.append("XSS")
                break
        
        # Check for Path Traversal
        for pattern in self.rules.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, decoded_path, re.IGNORECASE):
                threats.append("PATH_TRAVERSAL")
                break
        
        # Check for Command Injection
        for pattern in self.rules.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, decoded_path, re.IGNORECASE) or \
               re.search(pattern, decoded_body, re.IGNORECASE):
                threats.append("COMMAND_INJECTION")
                break
        
        # Check for dangerous file uploads
        for pattern in self.rules.DANGEROUS_EXTENSIONS:
            if re.search(pattern, decoded_path, re.IGNORECASE):
                threats.append("MALICIOUS_FILE_UPLOAD")
                break
        
        # Check headers for suspicious patterns
        user_agent = headers.get('User-Agent', '')
        if not user_agent or len(user_agent) < 10:
            threats.append("SUSPICIOUS_USER_AGENT")
        
        # Log threats
        if threats:
            attack_info = {
                'timestamp': datetime.now().isoformat(),
                'client_ip': client_ip,
                'method': method,
                'path': path,
                'threats': threats,
                'body_preview': body[:100] if body else None
            }
            self.attack_log.append(attack_info)
            logger.warning(f"Attack detected from {client_ip}: {', '.join(threats)}")
        
        return threats
    
    def is_request_allowed(self, method, path, headers, body, client_ip):
        """Determine if request should be allowed"""
        # Check rate limiting
        if not self.rate_limiter.is_allowed(client_ip):
            logger.warning(f"Request blocked: Rate limit exceeded for {client_ip}")
            return False, ["RATE_LIMIT_EXCEEDED"]
        
        # Analyze for security threats
        threats = self.analyze_request(method, path, headers, body, client_ip)
        
        if threats:
            return False, threats
        
        return True, []
    
    def get_statistics(self):
        """Get WAF statistics"""
        total_attacks = len(self.attack_log)
        attacks_by_type = defaultdict(int)
        attacks_by_ip = defaultdict(int)
        
        for attack in self.attack_log:
            attacks_by_ip[attack['client_ip']] += 1
            for threat in attack['threats']:
                attacks_by_type[threat] += 1
        
        return {
            'total_attacks_blocked': total_attacks,
            'attacks_by_type': dict(attacks_by_type),
            'top_attacking_ips': sorted(
                attacks_by_ip.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
            'currently_blocked_ips': len(self.rate_limiter.blocked_ips)
        }


class WAFHandler(BaseHTTPRequestHandler):
    """HTTP request handler with WAF protection"""
    
    waf_engine = None  # Will be set by the server
    
    def do_GET(self):
        self.handle_request('GET')
    
    def do_POST(self):
        self.handle_request('POST')
    
    def do_PUT(self):
        self.handle_request('PUT')
    
    def do_DELETE(self):
        self.handle_request('DELETE')
    
    def handle_request(self, method):
        """Handle incoming HTTP request with WAF protection"""
        client_ip = self.client_address[0]
        path = self.path
        headers = dict(self.headers)
        
        # Read request body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""
        
        # Check with WAF
        allowed, threats = self.waf_engine.is_request_allowed(
            method, path, headers, body, client_ip
        )
        
        if not allowed:
            # Block the request
            self.send_response(403)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            response = {
                'error': 'Request blocked by WAF',
                'threats_detected': threats,
                'timestamp': datetime.now().isoformat()
            }
            self.wfile.write(json.dumps(response, indent=2).encode())
            logger.info(f"Blocked request from {client_ip}: {threats}")
            return
        
        # Request is clean - handle normally
        if path == '/waf/stats':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            stats = self.waf_engine.get_statistics()
            self.wfile.write(json.dumps(stats, indent=2).encode())
        else:
            # Forward to backend application (simulated)
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            response_html = f"""
            <html>
                <head><title>Protected Application</title></head>
                <body>
                    <h1>Request Allowed</h1>
                    <p>Your request passed WAF security checks.</p>
                    <p><strong>Method:</strong> {method}</p>
                    <p><strong>Path:</strong> {path}</p>
                    <p><strong>Client IP:</strong> {client_ip}</p>
                    <hr>
                    <p><a href="/waf/stats">View WAF Statistics</a></p>
                </body>
            </html>
            """
            self.wfile.write(response_html.encode())
        
        logger.info(f"Allowed request from {client_ip}: {method} {path}")
    
    def log_message(self, format, *args):
        """Override to use our logger"""
        logger.info("%s - - %s" % (self.client_address[0], format % args))


def run_waf_server(host='0.0.0.0', port=8080):
    """Run the WAF server"""
    waf_engine = WAFEngine()
    WAFHandler.waf_engine = waf_engine
    
    server = HTTPServer((host, port), WAFHandler)
    
    logger.info(f"WAF Server started on {host}:{port}")
    logger.info("Security features enabled:")
    logger.info("  - SQL Injection Detection")
    logger.info("  - XSS Detection")
    logger.info("  - Path Traversal Detection")
    logger.info("  - Command Injection Detection")
    logger.info("  - Malicious File Upload Detection")
    logger.info("  - Rate Limiting (100 req/min per IP)")
    logger.info("  - Suspicious User-Agent Detection")
    logger.info("\nAccess statistics at: http://localhost:8080/waf/stats")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("\nShutting down WAF server...")
        server.shutdown()


if __name__ == "__main__":
    run_waf_server()
