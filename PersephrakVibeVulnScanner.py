#!/usr/bin/env python3
"""
PersephrakVibeVulnScanner.py

Defensive vulnerability scanner for vibe-coded websites.
Designed to help AI-assisted developers quickly find and patch common mistakes.

Usage:
    python3 PersephrakVibeVulnScanner.py www.example.com

IMPORTANT:
    Before running, set your AI API key in the API_KEY variable below.
    This scanner uses an AI backend to prioritize checks and interpret responses,
    making it faster and more accurate than purely rule-based scanners.

License: MIT
Author: Xer0TLabs x Persephrak Decentralized Syndicate
"""

import argparse
import json
import re
import sys
import time
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Any

try:
    import requests
except ImportError:
    print("Error: 'requests' library not found. Install it with: pip install requests")
    sys.exit(1)

try:
    # Optional: for better terminal output
    from colorama import init, Fore, Style
    init()
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False

# =============================================================================
# CONFIGURATION
# =============================================================================

# -----------------------------------------------------------------------------
# USER CONFIGURATION: SET YOUR AI API KEY HERE
# -----------------------------------------------------------------------------
# Replace with your actual API key from your AI provider (e.g., OpenAI, Anthropic, etc.)
# This key is used to accelerate scanning by letting AI prioritize and interpret checks.
# -----------------------------------------------------------------------------
API_KEY = "YOUR_AI_API_KEY_HERE"
# -----------------------------------------------------------------------------

# Example AI endpoint (adjust to your provider)
# For demonstration, this uses a generic structure. Modify as needed.
AI_API_URL = "https://api.openai.com/v1/chat/completions"
AI_MODEL = "gpt-4o-mini"  # or your preferred model

# Scanner settings
USER_AGENT = "PersephrakVibeVulnScanner/1.0 (Defensive Security Tool)"
TIMEOUT = 10  # seconds
MAX_PAGES_TO_SCAN = 20
MAX_LINKS_PER_PAGE = 50

# Severity levels
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def colorize(text: str, color: str) -> str:
    """Apply color to text if colorama is available."""
    if COLORS_AVAILABLE:
        color_map = {
            "red": Fore.RED,
            "green": Fore.GREEN,
            "yellow": Fore.YELLOW,
            "blue": Fore.BLUE,
            "magenta": Fore.MAGENTA,
            "cyan": Fore.CYAN,
            "white": Fore.WHITE,
            "reset": Style.RESET_ALL
        }
        return f"{color_map.get(color, '')}{text}{Style.RESET_ALL}"
    return text

def print_banner():
    """Print scanner banner."""
    banner = """
    =============================================================================
       Persephrak Vibe Vulnerability Scanner
       Defensive security tool for AI-assisted (vibe-coded) websites
    =============================================================================
    """
    print(colorize(banner, "cyan"))

def normalize_url(url: str) -> str:
    """Normalize URL to include scheme if missing."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")

def get_domain(url: str) -> str:
    """Extract domain from URL."""
    parsed = urlparse(url)
    return parsed.netloc

def is_same_domain(url: str, domain: str) -> bool:
    """Check if URL belongs to the same domain."""
    parsed = urlparse(url)
    return parsed.netloc == domain or parsed.netloc.endswith("." + domain)

def extract_links(html: str, base_url: str) -> List[str]:
    """Extract links from HTML content."""
    links = []
    # Simple regex-based link extraction (for demonstration)
    # In production, use BeautifulSoup or similar
    href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
    for match in href_pattern.finditer(html):
        link = match.group(1)
        if link.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        full_url = urljoin(base_url, link)
        links.append(full_url)
    return links[:MAX_LINKS_PER_PAGE]

def make_request(url: str, method: str = "GET", data: Optional[Dict] = None,
                 headers: Optional[Dict] = None) -> Optional[requests.Response]:
    """Make HTTP request with error handling."""
    try:
        req_headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/json,*/*"
        }
        if headers:
            req_headers.update(headers)
        
        if method.upper() == "GET":
            response = requests.get(url, headers=req_headers, timeout=TIMEOUT, allow_redirects=True)
        elif method.upper() == "POST":
            response = requests.post(url, json=data, headers=req_headers, timeout=TIMEOUT, allow_redirects=True)
        else:
            return None
        
        return response
    except requests.exceptions.RequestException as e:
        return None

# =============================================================================
# AI INTEGRATION
# =============================================================================

def query_ai(prompt: str) -> Optional[str]:
    """
    Query AI API for assistance.
    Returns AI response text or None on error.
    """
    if API_KEY == "YOUR_AI_API_KEY_HERE":
        print(colorize("[!] AI API key not configured. Running in basic mode.", "yellow"))
        return None
    
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": AI_MODEL,
        "messages": [
            {
                "role": "system",
                "content": "You are a security assistant helping analyze web application vulnerabilities. Focus on practical, actionable findings for defensive security."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "max_tokens": 1000,
        "temperature": 0.3
    }
    
    try:
        response = requests.post(AI_API_URL, json=payload, headers=headers, timeout=TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            return data.get("choices", [{}])[0].get("message", {}).get("content", "")
        else:
            print(colorize(f"[!] AI API error: {response.status_code}", "red"))
            return None
    except Exception as e:
        print(colorize(f"[!] AI query failed: {str(e)}", "red"))
        return None

def ai_prioritize_checks(findings: List[Dict]) -> List[Dict]:
    """
    Use AI to prioritize and enrich findings.
    Returns sorted/enhanced findings list.
    """
    if not findings:
        return findings
    
    # Prepare concise summary for AI
    summary = "Analyze these security findings and prioritize by severity and exploitability:\n\n"
    for i, finding in enumerate(findings[:20], 1):  # Limit to top 20 for AI context
        summary += f"{i}. [{finding['severity']}] {finding['name']}: {finding['description']}\n"
    
    summary += "\nReturn a JSON array with 'priority_order' (list of indices 1-based) and 'recommendations' (list of strings)."
    
    ai_response = query_ai(summary)
    
    if ai_response:
        try:
            # Try to parse JSON from AI response
            json_match = re.search(r'\[.*\]', ai_response, re.DOTALL)
            if json_match:
                ai_data = json.loads(json_match.group())
                if isinstance(ai_data, list) and len(ai_data) > 0:
                    # AI returned prioritized list
                    print(colorize("[*] AI prioritization applied.", "green"))
                    # Reorder findings based on AI priority (simplified)
                    return findings  # In full version, implement reordering logic
        except json.JSONDecodeError:
            pass
    
    return findings

def ai_generate_remediation(finding: Dict) -> str:
    """
    Use AI to generate specific remediation advice for a finding.
    """
    prompt = f"""
    Security Finding:
    - Name: {finding['name']}
    - Severity: {finding['severity']}
    - Description: {finding['description']}
    - URL: {finding.get('url', 'N/A')}
    
    Provide a concise, actionable remediation (2-3 sentences) for a developer using AI code generators.
    Focus on code-level fixes and configuration changes.
    """
    
    ai_response = query_ai(prompt)
    if ai_response:
        return ai_response.strip()
    return finding.get('remediation', 'Review and fix according to security best practices.')

# =============================================================================
# VULNERABILITY CHECKS
# =============================================================================

def check_secrets_in_response(html: str, url: str) -> List[Dict]:
    """Check for exposed secrets in HTML/JS responses."""
    findings = []
    
    # Patterns for common secrets
    secret_patterns = [
        (r'["\']api[_-]?key["\']\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "API Key"),
        (r'["\']secret["\']\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "Secret"),
        (r'["\']password["\']\s*[:=]\s*["\']([^"\']{4,})["\']', "Password"),
        (r'["\']token["\']\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', "Token"),
        (r'AWS[_A-Z0-9]*\s*[:=]\s*["\']?([A-Z0-9]{16,})["\']?', "AWS Credential"),
    ]
    
    for pattern, secret_type in secret_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        if matches:
            findings.append({
                "name": f"Potential {secret_type} Exposure",
                "severity": SEVERITY_CRITICAL,
                "url": url,
                "description": f"Found potential {secret_type} in client-side code. This could allow attackers to abuse your API or services.",
                "evidence": matches[0] if matches else None,
                "remediation": "Move all secrets to server-side environment variables. Never expose API keys, tokens, or passwords in frontend code."
            })
    
    return findings

def check_missing_security_headers(response: requests.Response, url: str) -> List[Dict]:
    """Check for missing security headers."""
    findings = []
    headers = response.headers
    
    required_headers = {
        "Strict-Transport-Security": (SEVERITY_MEDIUM, "HSTS header missing. Site may be vulnerable to protocol downgrade attacks."),
        "X-Content-Type-Options": (SEVERITY_LOW, "X-Content-Type-Options header missing. Browser may MIME-sniff responses."),
        "X-Frame-Options": (SEVERITY_LOW, "X-Frame-Options header missing. Site may be vulnerable to clickjacking."),
        "Content-Security-Policy": (SEVERITY_MEDIUM, "CSP header missing. Site may be more vulnerable to XSS attacks."),
        "X-XSS-Protection": (SEVERITY_INFO, "X-XSS-Protection header missing (deprecated but still useful for older browsers)."),
    }
    
    for header, (severity, description) in required_headers.items():
        if header not in headers:
            findings.append({
                "name": f"Missing Security Header: {header}",
                "severity": severity,
                "url": url,
                "description": description,
                "remediation": f"Add '{header}' header to all responses. Configure your web server or framework to include security headers."
            })
    
    return findings

def check_insecure_cookies(response: requests.Response, url: str) -> List[Dict]:
    """Check for insecure cookie configurations."""
    findings = []
    
    cookies = response.cookies
    for cookie in cookies:
        issues = []
        if not cookie.secure and urlparse(url).scheme == "https":
            issues.append("Secure flag missing")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("HttpOnly flag missing")
        if cookie.sameSite is None or cookie.sameSite.lower() == "none":
            issues.append("SameSite attribute missing or set to None")
        
        if issues:
            findings.append({
                "name": f"Insecure Cookie: {cookie.name}",
                "severity": SEVERITY_MEDIUM if "Secure" in str(issues) else SEVERITY_LOW,
                "url": url,
                "description": f"Cookie '{cookie.name}' has issues: {', '.join(issues)}. This could expose sessions to attacks.",
                "remediation": "Set Secure, HttpOnly, and SameSite=Strict (or Lax) flags on all session cookies."
            })
    
    return findings

def check_common_paths(base_url: str) -> List[Dict]:
    """Check for exposed common paths (admin, config, etc.)."""
    findings = []
    common_paths = [
        "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
        "/.env", "/.git", "/config.php", "/wp-config.php",
        "/backup", "/db", "/database", "/sql",
        "/api/admin", "/api/v1/admin", "/debug", "/test"
    ]
    
    for path in common_paths:
        url = urljoin(base_url, path)
        response = make_request(url)
        if response and response.status_code == 200:
            # Check if page contains sensitive info
            content = response.text.lower()
            if any(keyword in content for keyword in ["password", "secret", "key", "token", "config"]):
                findings.append({
                    "name": f"Exposed Sensitive Path: {path}",
                    "severity": SEVERITY_HIGH if ".env" in path or ".git" in path else SEVERITY_MEDIUM,
                    "url": url,
                    "description": f"Path '{path}' is accessible and may contain sensitive information.",
                    "remediation": "Restrict access to admin/config paths. Use authentication and proper access controls. Never expose .env or .git directories."
                })
    
    return findings

def check_idor_patterns(base_url: str, html: str) -> List[Dict]:
    """
    Check for potential IDOR patterns in URLs and forms.
    This is a heuristic check based on common vibe-coding mistakes.
    """
    findings = []
    
    # Look for numeric IDs in URLs or forms
    id_patterns = [
        r'user[_-]?id["\']?\s*[:=]?\s*["\']?(\d+)',
        r'account[_-]?id["\']?\s*[:=]?\s*["\']?(\d+)',
        r'profile[_-]?id["\']?\s*[:=]?\s*["\']?(\d+)',
        r'/user/(\d+)',
        r'/account/(\d+)',
        r'/profile/(\d+)',
    ]
    
    for pattern in id_patterns:
        if re.search(pattern, html, re.IGNORECASE):
            findings.append({
                "name": "Potential IDOR Pattern Detected",
                "severity": SEVERITY_MEDIUM,
                "url": base_url,
                "description": "Found patterns suggesting user/account IDs in URLs or forms. Verify that proper authorization checks are in place.",
                "remediation": "Implement server-side authorization checks for all resource access. Never trust client-provided IDs without verifying ownership."
            })
            break  # One finding is enough
    
    return findings

def check_form_security(html: str, url: str) -> List[Dict]:
    """Check for form security issues (CSRF, etc.)."""
    findings = []
    
    # Check for forms without CSRF tokens
    form_pattern = re.compile(r'<form[^>]*>', re.IGNORECASE)
    csrf_pattern = re.compile(r'csrf|_token|authenticity_token', re.IGNORECASE)
    
    forms = form_pattern.findall(html)
    for form in forms:
        if not csrf_pattern.search(form) and 'method="POST"' in form.upper():
            findings.append({
                "name": "Form Without CSRF Protection",
                "severity": SEVERITY_MEDIUM,
                "url": url,
                "description": "Found POST form without apparent CSRF token. This could allow CSRF attacks.",
                "remediation": "Add CSRF tokens to all state-changing forms. Use framework-built CSRF protection (e.g., Django CSRF, Laravel CSRF, etc.)."
            })
            break  # One finding is enough
    
    return findings

def check_error_disclosure(html: str, url: str) -> List[Dict]:
    """Check for error messages that disclose sensitive information."""
    findings = []
    
    error_patterns = [
        r'stack trace',
        r'exception.*line',
        r'error.*at.*line',
        r'sql.*syntax',
        r'undefined variable',
        r'fatal error',
    ]
    
    for pattern in error_patterns:
        if re.search(pattern, html, re.IGNORECASE):
            findings.append({
                "name": "Potential Error Disclosure",
                "severity": SEVERITY_MEDIUM,
                "url": url,
                "description": "Found detailed error messages that may disclose internal information (stack traces, SQL errors, etc.).",
                "remediation": "Disable debug mode in production. Show generic error messages to users. Log detailed errors server-side only."
            })
            break
    
    return findings

def check_ssl_tls(url: str) -> List[Dict]:
    """Check for basic SSL/TLS issues."""
    findings = []
    
    if not url.startswith("https://"):
        findings.append({
            "name": "Site Not Using HTTPS",
            "severity": SEVERITY_HIGH,
            "url": url,
            "description": "Site is accessible over HTTP. All traffic should be encrypted.",
            "remediation": "Enforce HTTPS for all traffic. Use HSTS header. Obtain SSL certificate (e.g., Let's Encrypt)."
        })
    
    return findings

# =============================================================================
# MAIN SCANNER
# =============================================================================

def scan_url(url: str) -> List[Dict]:
    """Perform comprehensive scan on a single URL."""
    findings = []
    
    print(colorize(f"[*] Scanning: {url}", "blue"))
    
    # Make initial request
    response = make_request(url)
    if not response:
        print(colorize(f"[!] Failed to fetch: {url}", "red"))
        return findings
    
    html = response.text
    
    # Run all checks
    findings.extend(check_secrets_in_response(html, url))
    findings.extend(check_missing_security_headers(response, url))
    findings.extend(check_insecure_cookies(response, url))
    findings.extend(check_form_security(html, url))
    findings.extend(check_error_disclosure(html, url))
    findings.extend(check_idor_patterns(url, html))
    
    # Check common paths (limited to avoid excessive requests)
    if len(findings) < 10:  # Only if we haven't found many issues yet
        findings.extend(check_common_paths(url))
    
    # SSL check
    findings.extend(check_ssl_tls(url))
    
    return findings

def scan_site(base_url: str) -> List[Dict]:
    """Scan entire site (limited pages)."""
    all_findings = []
    visited = set()
    to_visit = [base_url]
    domain = get_domain(base_url)
    
    print(colorize(f"[*] Starting site scan for: {domain}", "cyan"))
    
    while to_visit and len(visited) < MAX_PAGES_TO_SCAN:
        current_url = to_visit.pop(0)
        
        if current_url in visited:
            continue
        
        visited.add(current_url)
        
        # Scan current page
        findings = scan_url(current_url)
        all_findings.extend(findings)
        
        # Extract links for further scanning
        response = make_request(current_url)
        if response:
            links = extract_links(response.text, current_url)
            for link in links:
                if is_same_domain(link, domain) and link not in visited:
                    to_visit.append(link)
        
        # Rate limiting
        time.sleep(0.5)
    
    print(colorize(f"[*] Scanned {len(visited)} pages.", "green"))
    
    return all_findings

def print_report(findings: List[Dict], target: str):
    """Print formatted report."""
    print("\n" + "=" * 80)
    print(colorize("SCAN REPORT", "cyan"))
    print("=" * 80)
    print(f"Target: {target}")
    print(f"Total Findings: {len(findings)}")
    print()
    
    # Group by severity
    severity_order = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]
    
    for severity in severity_order:
        sev_findings = [f for f in findings if f['severity'] == severity]
        if sev_findings:
            print(colorize(f"\n[{severity}] - {len(sev_findings)} finding(s)", "yellow"))
            print("-" * 80)
            
            for i, finding in enumerate(sev_findings, 1):
                print(f"\n{i}. {finding['name']}")
                print(f"   URL: {finding['url']}")
                print(f"   Description: {finding['description']}")
                if finding.get('evidence'):
                    print(f"   Evidence: {finding['evidence']}")
                if finding.get('remediation'):
                    print(f"   Remediation: {finding['remediation']}")
    
    print("\n" + "=" * 80)
    print(colorize("END OF REPORT", "cyan"))
    print("=" * 80)

def save_report(findings: List[Dict], target: str, filename: str = "scan_report.json"):
    """Save findings to JSON file."""
    report = {
        "target": target,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "findings": findings,
        "summary": {
            "total": len(findings),
            "critical": len([f for f in findings if f['severity'] == SEVERITY_CRITICAL]),
            "high": len([f for f in findings if f['severity'] == SEVERITY_HIGH]),
            "medium": len([f for f in findings if f['severity'] == SEVERITY_MEDIUM]),
            "low": len([f for f in findings if f['severity'] == SEVERITY_LOW]),
            "info": len([f for f in findings if f['severity'] == SEVERITY_INFO])
        }
    }
    
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(colorize(f"[*] Report saved to: {filename}", "green"))

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Persephrak Vibe Vulnerability Scanner - Defensive security for AI-coded websites"
    )
    parser.add_argument(
        "target",
        help="Target URL (e.g., www.example.com or https://example.com)"
    )
    parser.add_argument(
        "--output",
        default="scan_report.json",
        help="Output JSON report filename (default: scan_report.json)"
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI assistance (run in basic mode)"
    )
    
    args = parser.parse_args()
    
    print_banner()
    
    # Normalize target URL
    target = normalize_url(args.target)
    domain = get_domain(target)
    
    print(colorize(f"[*] Target: {target}", "green"))
    print(colorize(f"[*] Domain: {domain}", "green"))
    
    if API_KEY == "YOUR_AI_API_KEY_HERE":
        print(colorize("[!] WARNING: AI API key not configured. Scanner will run in basic mode.", "yellow"))
        print(colorize("[!] Edit the script and set API_KEY variable for AI-assisted scanning.", "yellow"))
    
    # Perform scan
    print(colorize("\n[*] Starting scan...", "cyan"))
    start_time = time.time()
    
    findings = scan_site(target)
    
    elapsed = time.time() - start_time
    print(colorize(f"[*] Scan completed in {elapsed:.2f} seconds.", "green"))
    
    # AI prioritization (if enabled and API key set)
    if not args.no_ai and API_KEY != "YOUR_AI_API_KEY_HERE":
        print(colorize("\n[*] Requesting AI prioritization...", "blue"))
        findings = ai_prioritize_checks(findings)
        
        # Generate AI-powered remediation for top findings
        print(colorize("[*] Generating AI-powered remediation advice...", "blue"))
        for finding in findings[:10]:  # Top 10 findings
            ai_remediation = ai_generate_remediation(finding)
            if ai_remediation:
                finding['ai_remediation'] = ai_remediation
    
    # Print and save report
    print_report(findings, target)
    save_report(findings, target, args.output)
    
    print(colorize("\n[*] Scan complete. Review findings and patch vulnerabilities.", "green"))
    print(colorize("[*] Remember: This is a defensive tool. Use responsibly and only on systems you own or have permission to test.", "cyan"))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colorize("\n[!] Scan interrupted by user.", "yellow"))
        sys.exit(0)
    except Exception as e:
        print(colorize(f"\n[!] Unexpected error: {str(e)}", "red"))
        sys.exit(1)
