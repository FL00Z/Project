#!/usr/bin/env python3
"""
WAF Testing Script
Tests various attack scenarios against the WAF
"""

import requests
import time
import json
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

BASE_URL = "http://localhost:8080"


def print_test(test_name, passed):
    """Print test result"""
    if passed:
        print(f"{Fore.GREEN}✓ {test_name}")
    else:
        print(f"{Fore.RED}✗ {test_name}")


def test_normal_request():
    """Test a normal, safe request"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Testing Normal Request")
    print(f"{Fore.CYAN}{'='*60}")
    
    try:
        response = requests.get(f"{BASE_URL}/home")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text[:200]}...")
        print_test("Normal request allowed", response.status_code == 200)
        return response.status_code == 200
    except Exception as e:
        print(f"{Fore.RED}Error: {e}")
        return False


def test_sql_injection():
    """Test SQL injection detection"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Testing SQL Injection Detection")
    print(f"{Fore.CYAN}{'='*60}")
    
    sql_payloads = [
        "/users?id=1' OR '1'='1",
        "/search?q=admin'--",
        "/login?user=admin' UNION SELECT * FROM users--",
        "/products?category=electronics' DROP TABLE products--",
    ]
    
    blocked_count = 0
    for payload in sql_payloads:
        try:
            response = requests.get(f"{BASE_URL}{payload}")
            if response.status_code == 403:
                blocked_count += 1
                data = response.json()
                print(f"{Fore.YELLOW}Blocked: {payload}")
                print(f"  Threats: {data.get('threats_detected', [])}")
        except Exception as e:
            print(f"{Fore.RED}Error with {payload}: {e}")
    
    success = blocked_count == len(sql_payloads)
    print_test(f"SQL Injection blocked ({blocked_count}/{len(sql_payloads)})", success)
    return success


def test_xss_attack():
    """Test XSS detection"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Testing XSS Detection")
    print(f"{Fore.CYAN}{'='*60}")
    
    xss_payloads = [
        "/search?q=<script>alert('XSS')</script>",
        "/comment?text=<img src=x onerror=alert('XSS')>",
        "/profile?bio=<iframe src='evil.com'></iframe>",
        "/feedback?msg=javascript:alert('XSS')",
    ]
    
    blocked_count = 0
    for payload in xss_payloads:
        try:
            response = requests.get(f"{BASE_URL}{payload}")
            if response.status_code == 403:
                blocked_count += 1
                data = response.json()
                print(f"{Fore.YELLOW}Blocked: {payload}")
                print(f"  Threats: {data.get('threats_detected', [])}")
        except Exception as e:
            print(f"{Fore.RED}Error with {payload}: {e}")
    
    success = blocked_count == len(xss_payloads)
    print_test(f"XSS attacks blocked ({blocked_count}/{len(xss_payloads)})", success)
    return success


def test_path_traversal():
    """Test path traversal detection"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Testing Path Traversal Detection")
    print(f"{Fore.CYAN}{'='*60}")
    
    traversal_payloads = [
        "/files?path=../../etc/passwd",
        "/download?file=../../../windows/system32/config/sam",
        "/view?doc=....//....//etc/shadow",
    ]
    
    blocked_count = 0
    for payload in traversal_payloads:
        try:
            response = requests.get(f"{BASE_URL}{payload}")
            if response.status_code == 403:
                blocked_count += 1
                data = response.json()
                print(f"{Fore.YELLOW}Blocked: {payload}")
                print(f"  Threats: {data.get('threats_detected', [])}")
        except Exception as e:
            print(f"{Fore.RED}Error with {payload}: {e}")
    
    success = blocked_count == len(traversal_payloads)
    print_test(f"Path traversal blocked ({blocked_count}/{len(traversal_payloads)})", success)
    return success


def test_command_injection():
    """Test command injection detection"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Testing Command Injection Detection")
    print(f"{Fore.CYAN}{'='*60}")
    
    cmd_payloads = [
        "/ping?host=8.8.8.8;cat /etc/passwd",
        "/execute?cmd=ls|grep secret",
        "/system?action=backup && rm -rf /",
    ]
    
    blocked_count = 0
    for payload in cmd_payloads:
        try:
            response = requests.get(f"{BASE_URL}{payload}")
            if response.status_code == 403:
                blocked_count += 1
                data = response.json()
                print(f"{Fore.YELLOW}Blocked: {payload}")
                print(f"  Threats: {data.get('threats_detected', [])}")
        except Exception as e:
            print(f"{Fore.RED}Error with {payload}: {e}")
    
    success = blocked_count == len(cmd_payloads)
    print_test(f"Command injection blocked ({blocked_count}/{len(cmd_payloads)})", success)
    return success


def test_rate_limiting():
    """Test rate limiting"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Testing Rate Limiting (sending 105 requests)")
    print(f"{Fore.CYAN}{'='*60}")
    
    blocked = False
    for i in range(105):
        try:
            response = requests.get(f"{BASE_URL}/test")
            if response.status_code == 403:
                data = response.json()
                if 'RATE_LIMIT_EXCEEDED' in data.get('threats_detected', []):
                    print(f"{Fore.YELLOW}Rate limit triggered at request {i+1}")
                    blocked = True
                    break
        except Exception as e:
            print(f"{Fore.RED}Error: {e}")
            break
        
        if (i + 1) % 20 == 0:
            print(f"Sent {i+1} requests...")
    
    print_test("Rate limiting working", blocked)
    return blocked


def test_malicious_file_upload():
    """Test malicious file upload detection"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Testing Malicious File Upload Detection")
    print(f"{Fore.CYAN}{'='*60}")
    
    file_payloads = [
        "/upload?file=malware.exe",
        "/upload?file=shell.php",
        "/upload?file=backdoor.jsp",
    ]
    
    blocked_count = 0
    for payload in file_payloads:
        try:
            response = requests.get(f"{BASE_URL}{payload}")
            if response.status_code == 403:
                blocked_count += 1
                data = response.json()
                print(f"{Fore.YELLOW}Blocked: {payload}")
                print(f"  Threats: {data.get('threats_detected', [])}")
        except Exception as e:
            print(f"{Fore.RED}Error with {payload}: {e}")
    
    success = blocked_count == len(file_payloads)
    print_test(f"Malicious uploads blocked ({blocked_count}/{len(file_payloads)})", success)
    return success


def view_statistics():
    """View WAF statistics"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}WAF Statistics")
    print(f"{Fore.CYAN}{'='*60}")
    
    try:
        response = requests.get(f"{BASE_URL}/waf/stats")
        if response.status_code == 200:
            stats = response.json()
            print(json.dumps(stats, indent=2))
        else:
            print(f"{Fore.RED}Failed to get statistics")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}")


def run_all_tests():
    """Run all tests"""
    print(f"\n{Fore.MAGENTA}{'='*60}")
    print(f"{Fore.MAGENTA}WAF Testing Suite")
    print(f"{Fore.MAGENTA}{'='*60}")
    print(f"{Fore.YELLOW}Make sure the WAF server is running on {BASE_URL}")
    print(f"{Fore.YELLOW}Run: python waf.py")
    
    input("\nPress Enter to start tests...")
    
    results = []
    
    # Run tests
    results.append(("Normal Request", test_normal_request()))
    time.sleep(1)
    
    results.append(("SQL Injection Detection", test_sql_injection()))
    time.sleep(1)
    
    results.append(("XSS Detection", test_xss_attack()))
    time.sleep(1)
    
    results.append(("Path Traversal Detection", test_path_traversal()))
    time.sleep(1)
    
    results.append(("Command Injection Detection", test_command_injection()))
    time.sleep(1)
    
    results.append(("Malicious File Upload Detection", test_malicious_file_upload()))
    time.sleep(1)
    
    results.append(("Rate Limiting", test_rate_limiting()))
    time.sleep(2)
    
    # View statistics
    view_statistics()
    
    # Summary
    print(f"\n{Fore.MAGENTA}{'='*60}")
    print(f"{Fore.MAGENTA}Test Summary")
    print(f"{Fore.MAGENTA}{'='*60}")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = f"{Fore.GREEN}PASS" if result else f"{Fore.RED}FAIL"
        print(f"{test_name}: {status}")
    
    print(f"\n{Fore.CYAN}Total: {passed}/{total} tests passed")
    
    if passed == total:
        print(f"{Fore.GREEN}All tests passed! ✓")
    else:
        print(f"{Fore.YELLOW}Some tests failed. Check the WAF logs for details.")


if __name__ == "__main__":
    run_all_tests()
