#!/usr/bin/env python3
"""
AI-Driven Open Redirect Scanner Tool
Professional pentesting tool for discovering open redirect vulnerabilities
"""

import sys
import json
import requests
import urllib.parse
import re
import os
from typing import List, Dict, Any, Optional
import argparse
from urllib.parse import urlparse, urljoin, parse_qs
import time

# OpenAI API configuration
OPENAI_BASE_URL = "https://api.openai.com/v1"

class OpenRedirectScanner:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or self._get_api_key()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.canary_domain = "https://canary.com"
    
    def _get_api_key(self) -> str:
        """
        Get OpenAI API key from multiple sources in order of preference:
        1. Environment variable OPENAI_API_KEY
        2. .env file
        3. User input prompt
        """
        # Try environment variable first
        api_key = os.getenv('OPENAI_API_KEY')
        if api_key:
            return api_key
        
        # Try .env file
        try:
            from dotenv import load_dotenv
            load_dotenv()
            api_key = os.getenv('OPENAI_API_KEY')
            if api_key:
                return api_key
        except ImportError:
            pass  # python-dotenv not installed
        
        # Try config file
        config_paths = [
            os.path.expanduser('~/.openai/config'),
            os.path.expanduser('~/.config/openai/config'),
            '.openai_config'
        ]
        
        for config_path in config_paths:
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r') as f:
                        for line in f:
                            if line.startswith('OPENAI_API_KEY='):
                                return line.split('=', 1)[1].strip().strip('"\'')
                except (IOError, OSError):
                    continue
        
        # Last resort: prompt user
        print("🔑 OpenAI API key not found in environment variables or config files.")
        print("You can set it by:")
        print("  1. export OPENAI_API_KEY='your-key-here'")
        print("  2. Create a .env file with OPENAI_API_KEY=your-key-here")
        print("  3. Create ~/.openai/config with OPENAI_API_KEY=your-key-here")
        print("  4. Enter it now (will not be saved):")
        
        api_key = input("OpenAI API Key: ").strip()
        if not api_key:
            raise ValueError("OpenAI API key is required")
        
        return api_key
        
    def discover_redirect_candidates(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Step 1: AI-powered discovery of potential redirect parameters
        """
        if not self.api_key:
            print("Error: OpenAI API key not provided.")
            return []
            
        try:
            # First, fetch the target page to analyze
            print(f"🔍 Analyzing target: {target_url}")
            response = self.session.get(target_url, timeout=10, allow_redirects=True)
            
            if response.status_code != 200:
                print(f"❌ Failed to fetch target: HTTP {response.status_code}")
                return []
                
            # Extract domain and paths for AI analysis
            parsed_url = urlparse(target_url)
            domain = parsed_url.netloc
            path = parsed_url.path
            
            # Prepare context for AI
            page_content = response.text[:5000]  # Limit content for token efficiency
            form_inputs = self._extract_form_inputs(page_content)
            url_params = parse_qs(parsed_url.query)
            
            # AI prompt for discovery
            prompt = f"""
You are a seasoned bug bounty hunter analyzing a web application for open redirect vulnerabilities.

Target Domain: {domain}
Current Path: {path}
URL Parameters: {list(url_params.keys())}
Form Inputs Found: {form_inputs}

Analyze this web application and identify potential redirect parameter candidates. Look for:
1. URL parameters that might control redirects
2. Form fields that could be used for redirects
3. Hidden parameters in forms
4. Common redirect patterns in the URL structure

Think like a professional pentester. Consider:
- Authentication flows (login redirects)
- Error handling (error redirects)
- Navigation systems (menu redirects)
- API endpoints that might redirect
- Any JavaScript that manipulates URLs

Return ONLY a JSON array of objects with this exact format:
[
  {{"path": "/login", "param_candidates": ["redirect", "next", "return_to"]}},
  {{"path": "/api/auth", "param_candidates": ["callback", "redirect_uri"]}}
]

If no candidates are found, return an empty array: []

Be thorough but precise. Only include parameters that have a realistic chance of being used for redirects.
"""

            # Call OpenAI API
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": "You are an expert security researcher specializing in web application vulnerabilities."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.3,
                "max_tokens": 1000
            }
            
            print("🤖 Querying AI for redirect parameter discovery...")
            ai_response = requests.post(
                f"{OPENAI_BASE_URL}/chat/completions",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if ai_response.status_code != 200:
                print(f"❌ AI API error: {ai_response.status_code}")
                return []
                
            ai_data = ai_response.json()
            ai_content = ai_data['choices'][0]['message']['content'].strip()
            
            # Extract JSON from AI response
            try:
                # Find JSON array in the response
                json_match = re.search(r'\[.*\]', ai_content, re.DOTALL)
                if json_match:
                    candidates = json.loads(json_match.group())
                    print(f"✅ AI discovered {len(candidates)} potential redirect paths")
                    return candidates
                else:
                    print("❌ No valid JSON found in AI response")
                    return []
                    
            except json.JSONDecodeError as e:
                print(f"❌ Failed to parse AI response as JSON: {e}")
                return []
                
        except Exception as e:
            print(f"❌ Error during AI discovery: {e}")
            return []
    
    def _extract_form_inputs(self, html_content: str) -> List[str]:
        """Extract form input names from HTML content"""
        input_pattern = r'<input[^>]+name=["\']([^"\']+)["\']'
        return list(set(re.findall(input_pattern, html_content, re.IGNORECASE)))
    
    def generate_payload_variants(self, param: str) -> List[str]:
        """
        Generate various payload variants for testing open redirects
        """
        variants = []
        
        # Base URL payloads
        variants.extend([
            f"{self.canary_domain}",
            f"//{self.canary_domain.replace('https://', '')}",
            f"\\{self.canary_domain}",
            f"/\\{self.canary_domain.replace('https://', '')}",
            f"\\{self.canary_domain.replace('https://', '')}",
            f"//{self.canary_domain.replace('https://', '')}/",
            f"https:{self.canary_domain}",
            f"http:{self.canary_domain}",
        ])
        
        # URL encoded variants
        for variant in variants[:4]:  # Only encode the main variants
            variants.append(urllib.parse.quote(variant, safe=''))
        
        # Double URL encoded
        for variant in variants[:2]:
            variants.append(urllib.parse.quote(urllib.parse.quote(variant, safe=''), safe=''))
        
        # Path traversal attempts
        variants.extend([
            f"/{self.canary_domain.replace('https://', '')}",
            f"./{self.canary_domain.replace('https://', '')}",
            f"../{self.canary_domain.replace('https://', '')}",
            f"..%2F{self.canary_domain.replace('https://', '')}",
        ])
        
        return list(set(variants))  # Remove duplicates
    
    def test_redirect_vulnerability(self, base_url: str, path: str, param: str, payload: str) -> Optional[Dict[str, Any]]:
        """
        Test a specific parameter with a payload for open redirect vulnerability
        """
        try:
            # Construct test URL
            test_url = urljoin(base_url, path)
            params = {param: payload}
            
            # Make request with redirects disabled to see the redirect response
            response = self.session.get(
                test_url, 
                params=params, 
                allow_redirects=False,
                timeout=10
            )
            
            # Check for redirect responses
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                
                # Check if the redirect goes to our canary domain
                if self.canary_domain.replace('https://', '') in location:
                    return {
                        "url_tested": response.url,
                        "vulnerable": True,
                        "evidence": f"Redirect to: {location}",
                        "cwe": 601,
                        "poc": f"Visit: {response.url}"
                    }
            
            # Check for JavaScript redirects in response body
            if response.status_code == 200:
                body = response.text.lower()
                if any(redirect_pattern in body for redirect_pattern in [
                    f'window.location.href = "{self.canary_domain}"',
                    f'window.location = "{self.canary_domain}"',
                    f'location.href = "{self.canary_domain}"',
                    f'location = "{self.canary_domain}"',
                    f'<meta http-equiv="refresh" content="0;url={self.canary_domain}">',
                    f'<script>window.location="{self.canary_domain}"</script>'
                ]):
                    return {
                        "url_tested": response.url,
                        "vulnerable": True,
                        "evidence": f"JavaScript redirect found in response body",
                        "cwe": 601,
                        "poc": f"Visit: {response.url}"
                    }
            
            return None
            
        except Exception as e:
            print(f"⚠️  Error testing {param}={payload}: {e}")
            return None
    
    def scan_target(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Main scanning function that orchestrates the two-step process
        """
        print(f"🚀 Starting Open Redirect scan for: {target_url}")
        print("=" * 60)
        
        # Step 1: AI Discovery
        candidates = self.discover_redirect_candidates(target_url)
        
        if not candidates:
            print("❌ No redirect parameter candidates found by AI")
            return []
        
        print(f"\n🎯 Testing {len(candidates)} discovered paths...")
        
        # Step 2: Local Testing
        vulnerabilities = []
        parsed_url = urlparse(target_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        for candidate in candidates:
            path = candidate.get('path', '/')
            param_candidates = candidate.get('param_candidates', [])
            
            print(f"\n🔍 Testing path: {path}")
            print(f"   Parameters: {', '.join(param_candidates)}")
            
            for param in param_candidates:
                print(f"   ⚡ Testing parameter: {param}")
                
                # Generate payload variants
                payloads = self.generate_payload_variants(param)
                
                for payload in payloads:
                    result = self.test_redirect_vulnerability(base_url, path, param, payload)
                    if result:
                        print(f"   ✅ VULNERABILITY FOUND!")
                        vulnerabilities.append(result)
                        break  # Found vulnerability for this param, move to next
                
                # Small delay to avoid overwhelming the server
                time.sleep(0.1)
        
        return vulnerabilities

def main():
    parser = argparse.ArgumentParser(description='AI-Driven Open Redirect Scanner')
    parser.add_argument('target_url', help='Target URL to scan for open redirects')
    parser.add_argument('--api-key', help='OpenAI API key (or set OPENAI_API_KEY env var)')
    
    args = parser.parse_args()
    
    # Validate target URL
    if not args.target_url.startswith(('http://', 'https://')):
        args.target_url = 'https://' + args.target_url
    
    # Initialize scanner
    scanner = OpenRedirectScanner(api_key=args.api_key)
    
    # Run scan
    vulnerabilities = scanner.scan_target(args.target_url)
    
    # Output results
    print("\n" + "=" * 60)
    print("📊 SCAN RESULTS")
    print("=" * 60)
    
    if vulnerabilities:
        print(f"🎯 Found {len(vulnerabilities)} open redirect vulnerabilities:")
        print(json.dumps(vulnerabilities, indent=2))
    else:
        print("✅ No open redirect vulnerabilities found")
        print("[]")

if __name__ == "__main__":
    main()
