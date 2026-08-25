# Persephrak Vibe Vulnerability Scanner

Defensive vulnerability scanner for AI-assisted (vibe-coded) websites.  
Designed to help developers who use AI code generators quickly find and patch common security mistakes before deployment.

---

## Disclaimer

This tool is for **defensive security and educational purposes only**.  
Only scan systems you **own** or have **explicit written permission** to test.  
The author is not responsible for any misuse or damage caused by this software.

---

## Features

- Scans for common vibe-coding security issues:
  - Exposed secrets in frontend code (API keys, tokens, passwords)
  - Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
  - Insecure cookie configurations
  - Potential IDOR patterns
  - Forms without CSRF protection
  - Error messages disclosing internal information
  - Exposed sensitive paths (/admin, /.env, /.git, etc.)
  - Basic HTTPS enforcement check
- AI-assisted analysis (optional):
  - Prioritizes findings by severity and exploitability
  - Generates developer-friendly remediation advice
- Outputs:
  - Colored terminal report
  - JSON report for CI/CD or further processing

---

## Requirements

- Python 3.8+
- `requests`
- `colorama` (optional, for colored output)

Install dependencies:

```bash
pip install requests colorama
```

---

## Setup

1. Clone or download this repository:

   ```bash
   git clone https://github.com/e4zyy/PersephrakVibeVulnScanner.git
   cd PersephrakVibeVulnScanner
   ```

2. Open `PersephrakVibeVulnScanner.py` and set your AI API key:

   ```python
   API_KEY = "YOUR_AI_API_KEY_HERE"  # Replace with your actual key
   ```

   Adjust the AI endpoint and model if needed:

   ```python
   AI_API_URL = "https://api.openai.com/v1/chat/completions"
   AI_MODEL = "gpt-4o-mini"
   ```

3. Make the script executable (optional):

   ```bash
   chmod +x PersephrakVibeVulnScanner.py
   ```

---

## Usage

Basic scan (single target):

```bash
python3 PersephrakVibeVulnScanner.py www.example.com
```

With custom output file:

```bash
python3 PersephrakVibeVulnScanner.py www.example.com --output report.json
```

Disable AI assistance (basic mode):

```bash
python3 PersephrakVibeVulnScanner.py www.example.com --no-ai
```

Help:

```bash
python3 PersephrakVibeVulnScanner.py --help
```

---

## How It Works

1. The scanner normalizes the target URL and extracts the domain.
2. It crawls up to a configurable number of pages on the same domain.
3. For each page, it runs a set of security checks:
   - Pattern-based detection (secrets, error messages, IDOR hints)
   - Header and cookie analysis
   - Common sensitive path enumeration
4. If an AI API key is configured:
   - Findings are sent to the AI for prioritization.
   - AI-generated remediation advice is attached to top findings.
5. Results are printed to the terminal and saved as a JSON report.

---

## Example Output

```text
================================================================================
SCAN REPORT
================================================================================
Target: https://www.example.com
Total Findings: 7

[CRITICAL] - 1 finding(s)
--------------------------------------------------------------------------------

1. Potential API Key Exposure
   URL: https://www.example.com
   Description: Found potential API Key in client-side code. This could allow attackers to abuse your API or services.
   Evidence: sk_live_...
   Remediation: Move all secrets to server-side environment variables. Never expose API keys, tokens, or passwords in frontend code.

[HIGH] - 1 finding(s)
--------------------------------------------------------------------------------

1. Site Not Using HTTPS
   URL: https://www.example.com
   Description: Site is accessible over HTTP. All traffic should be encrypted.
   Remediation: Enforce HTTPS for all traffic. Use HSTS header. Obtain SSL certificate (e.g., Let's Encrypt).

...

================================================================================
END OF REPORT
================================================================================
```

---

## Project Structure

- `PersephrakVibeVulnScanner.py` – Main scanner script
- `README.md` – This file
- `.gitignore` – Basic ignore rules for Python projects

---

## Extending the Scanner

You can extend the scanner by:

- Adding new check functions in the `VULNERABILITY CHECKS` section.
- Adjusting `MAX_PAGES_TO_SCAN` and `TIMEOUT` for deeper or faster scans.
- Integrating with CI/CD pipelines using the JSON report.
- Customizing AI prompts to match your stack (Next.js, Supabase, etc.).

---

## License

MIT License. See `LICENSE` file for details.

---

## Author

Xer0TLabs x Persephrak Decentralized Syndicate   
Defensive security tooling for AI-assisted development.

---

## Contributing

Contributions are welcome. Please:

1. Fork the repository.
2. Create a feature branch.
3. Submit a pull request with a clear description of changes.

---

## Acknowledgements

- OWASP Top 10
- AI-assisted development community
- Defensive security researchers and tooling authors
