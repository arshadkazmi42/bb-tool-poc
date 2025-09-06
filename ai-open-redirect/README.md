# AI-Driven Open Redirect Scanner

A professional pentesting tool that uses AI to discover and test open redirect vulnerabilities in web applications.

## Features

- **AI-Powered Discovery**: Uses OpenAI GPT-4 to intelligently discover potential redirect parameters
- **Comprehensive Testing**: Tests multiple payload variants including URL encoding and path tricks
- **Professional Output**: Returns structured JSON results suitable for bug bounty reports
- **No Hardcoding**: AI discovers parameters dynamically, no fallback to common parameter names
- **Token Efficient**: Two-step process optimizes AI usage

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set your OpenAI API key using one of these methods:

**Method 1: Environment Variable (Recommended)**
```bash
export OPENAI_API_KEY="your-api-key-here"
```

**Method 2: .env file**
```bash
cp env.example .env
# Edit .env and add your API key
```

**Method 3: Config file**
```bash
mkdir -p ~/.openai
echo "OPENAI_API_KEY=your-api-key-here" > ~/.openai/config
```

**Method 4: Command line**
The tool will prompt you for the API key if not found in the above methods.

## Usage

```bash
python3 open_redirect_poc.py <target_url>
```

### Examples

```bash
# Basic scan
python3 open_redirect_poc.py https://example.com

# With API key override
python3 open_redirect_poc.py https://example.com --api-key your-key

# Scan with http protocol
python3 open_redirect_poc.py http://example.com
```

## How It Works

### Step 1: AI Discovery
The tool analyzes the target website and uses AI to identify potential redirect parameters by:
- Examining URL structure and parameters
- Analyzing form inputs
- Looking for common redirect patterns
- Thinking like a seasoned bug bounty hunter

### Step 2: Local Testing
For each discovered parameter, the tool tests multiple payload variants:
- Plain URLs (`https://canary.com`)
- URL-encoded variants (`https%3A%2F%2Fcanary.com`)
- Protocol-relative URLs (`//canary.com`)
- Path-trick variations (`/\\canary.com`, `../canary.com`)
- Double URL encoding
- JavaScript redirect patterns

## Output Format

The tool returns JSON results with confirmed vulnerabilities:

```json
[
  {
    "url_tested": "https://example.com/login?redirect=https://canary.com",
    "vulnerable": true,
    "evidence": "Redirect to: https://canary.com",
    "cwe": 601,
    "poc": "Visit: https://example.com/login?redirect=https://canary.com"
  }
]
```

If no vulnerabilities are found, returns an empty array: `[]`

## Requirements

- Python 3.7+
- OpenAI API key (no hardcoding - multiple secure methods supported)
- Internet connection

## Security Features

- **No hardcoded API keys** - Multiple secure methods for API key management
- **Environment variable support** - Standard `OPENAI_API_KEY` environment variable
- **Config file support** - `~/.openai/config` or `.openai_config` files
- **Interactive prompts** - Secure input when no config found
- **Open source ready** - Safe for public repositories

## Security Note

This tool is designed for authorized security testing only. Always ensure you have permission to test the target application.
