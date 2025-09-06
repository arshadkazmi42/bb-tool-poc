# Web Cache Poisoning Scanner

A focused CLI tool that detects **actual web cache poisoning vulnerabilities** using proper URL discovery and two-step testing methodology.

## 🎯 What It Does

- **Discovers real URLs** using Wayback Machine, robots.txt, sitemaps, HTML parsing, and common path testing
- **Tests for actual cache poisoning** using header injection and parameter pollution techniques
- **Uses cache busters** in every request to bypass caching
- **Implements two-step testing** (poisoned request → clean request → compare responses)
- **Prioritizes vulnerable URLs** (API endpoints, admin areas, user endpoints)

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Scan a single domain
python cache_poison_scanner.py -d example.com

# Scan multiple domains from file
python cache_poison_scanner.py -f domains.txt

# Custom output file
python cache_poison_scanner.py -d example.com -o my_report.txt

# Adjust rate limiting
python cache_poison_scanner.py -d example.com --rate-limit 2.0 --concurrent 3
```

## 📋 Usage

```bash
python cache_poison_scanner.py [OPTIONS]

Options:
  -d, --domain TEXT     Single domain to scan
  -f, --file TEXT       File containing list of domains
  -o, --output TEXT     Output report file (default: cache_poison_report.txt)
  --rate-limit FLOAT    Delay between requests in seconds (default: 1.0)
  --concurrent INTEGER  Maximum concurrent requests (default: 5)
  --verbose, -v         Enable verbose logging
  --help               Show this message and exit
```

## 🔍 Discovery Methods

1. **Wayback Machine** - Historical URL discovery
2. **robots.txt** - Sitemap and path discovery
3. **sitemap.xml** - Indexed URL extraction
4. **HTML parsing** - Link, form, and script discovery
5. **Common paths** - Testing known vulnerable endpoints

## 🎯 Testing Methodology

### Header Injection Testing
- `X-Forwarded-Host: evil.com`
- `X-Forwarded-Proto: http`
- `X-Original-URL: /admin`
- `X-Rewrite-URL: /admin`
- `X-Custom-IP-Authorization: 127.0.0.1`
- `X-Forwarded-Server: evil.com`
- `X-HTTP-Host-Override: evil.com`
- `Forwarded: for=evil.com;by=evil.com;host=evil.com`

### Parameter Pollution Testing
- `redirect=evil.com&redirect=legitimate.com`
- `url=evil.com&url=legitimate.com`
- `next=evil.com&next=legitimate.com`
- `target=evil.com&target=legitimate.com`
- `return=evil.com&return=legitimate.com`
- `link=evil.com&link=legitimate.com`
- `goto=evil.com&goto=legitimate.com`

## 📊 Sample Output

```
🎯 Starting cache poisoning scan for: example.com
🔍 Discovering URLs for: example.com
📜 Found 45 URLs from Wayback Machine
📊 Discovered 67 URLs
🎯 Testing 23 most vulnerable URLs
🎯 Testing: https://example.com/api/v1/
🎯 Testing: https://example.com/admin/
🎯 Testing: https://example.com/user/profile
🎯 Cache poisoning detected via content match: X-Forwarded-Host=evil.com
🎯 CACHE POISONING VULNERABILITY FOUND in example.com
✅ Cache poisoning scan completed!
```

## 📄 Report Format

```
================================================================================
WEB CACHE POISONING SCAN REPORT
================================================================================
Generated: 2025-01-27 10:30:15

🎯 CACHE POISONING VULNERABILITIES FOUND: 2
============================================================

VULNERABILITY 1:
  Type: header_injection_poisoning
  URL: https://example.com/api/v1/
  Severity: high
  Description: Cache poisoning via header injection: X-Forwarded-Host = evil.com
  Header: X-Forwarded-Host = evil.com

VULNERABILITY 2:
  Type: parameter_pollution_poisoning
  URL: https://example.com/redirect
  Severity: high
  Description: Cache poisoning via parameter pollution: redirect = evil.com
  Parameter: redirect = evil.com
```

## ⚠️ Security Notice

This tool is for **authorized security testing only**. Only use it on domains you own or have explicit permission to test. Unauthorized testing may be illegal.

## 📝 License

This project is for educational and authorized security testing purposes only.
