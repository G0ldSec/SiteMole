# SiteMole

SiteMole is a Python-based web reconnaissance and security assessment tool built for penetration testers. It automates passive checks that are typically done manually during the information gathering and configuration review phase of a web application pentest.

## Features

SiteMole covers 20 modules mapped to common pentest findings (PT-WEB), grouped into five categories:

**Reconnaissance** -- extracting comments, links, images, metadata and checking Subresource Integrity.

**Security Headers and Cookies** -- full header presence check with deep CSP and X-XSS-Protection analysis, cookie flag validation (Secure, HttpOnly, SameSite), F5 BIG-IP persistence cookie decoding (standard, route-domain hex, vi-hex, encrypted detection), and version information disclosure.

**Configuration and Crypto** -- HTTP-to-HTTPS redirect and HSTS validation, SSL/TLS protocol and cipher suite check, certificate expiry/CN/SAN/chain verification, CORS misconfiguration testing, HTTP method enumeration, and JWT token analysis.

**Information Disclosure** -- internal (RFC1918) IP address leakage in headers and body, Host header injection, sensitive file exposure (.git, .env, .svn, web.config, backups), directory listing detection, default web server page detection, and autocomplete on sensitive form fields.

**GDPR and Privacy** -- Google Fonts and external font CDN detection (GDPR Art. 6, LG München I, Az. 3 O 17493/20).

## Installation

Clone the repository:

```
git clone https://github.com/G0ldSec/SiteMole.git
cd SiteMole
```

Install dependencies:

```
pip install -r requirements.txt
```

Requires Python 3.8 or newer. For the SSL/TLS protocol check, `openssl` should be available in your PATH (optional, the module skips it gracefully if missing).

## Usage

Run a single module against a target:

```
python sitemole.py -t https://example.com -m headers
```

Run all modules and save results to a file:

```
python sitemole.py -t https://example.com -m all -o report.txt
```

Scan a list of targets:

```
python sitemole.py -l targets.txt -m all -o report.txt
```

Authenticate with a session cookie and/or JWT token:

```
python sitemole.py -t https://app.example.com -c 'PHPSESSID=abc123' -m all
python sitemole.py -t https://api.example.com --token eyJhbGciOi... -m jwt
python sitemole.py -t https://app.example.com -c 'session=xyz; lang=en' --token eyJ... -m all
```

If no module is specified, SiteMole starts in interactive mode with a numbered menu.

## Available Modules

| Module | Description |
|---|---|
| comments | Extract HTML comments |
| sri | Check Subresource Integrity on external JS/CSS |
| links | Extract all href links from the page |
| images | Extract all image URLs (jpg, png, gif, svg) |
| metadata | Extract HTML meta tags, CMS and framework detection |
| headers | Full header analysis with CSP deep-dive and X-XSS-Protection check |
| cookies | Cookie flag check (Secure, HttpOnly, SameSite) and F5 BigIP decode |
| version | Version info disclosure (Server, X-Powered-By, X-AspNet-Version) |
| cleartext | HTTP-to-HTTPS redirect check, mixed content, HSTS validation |
| ssl | SSL/TLS protocol versions, cipher suite, certificate expiry/CN/SAN/chain |
| cors | CORS misconfiguration (wildcard, origin reflection, null origin) |
| methods | HTTP method enumeration via OPTIONS and direct TRACE check |
| jwt | JWT token analysis (alg:none, weak algorithms, missing exp/iat/iss) |
| ips | Internal RFC1918 IP addresses in headers and response body |
| hostinject | Host header injection (reflection in headers, body, redirects) |
| disclosure | Sensitive file exposure (.git, .env, .svn, web.config, backups) |
| dirlist | Directory listing on common paths (/icons/, /uploads/, /backup/) |
| defaults | Default web server pages (Apache, Nginx, IIS, Tomcat) |
| autocomplete | Missing autocomplete=off on password and login fields |
| fonts | Google Fonts and external font CDN check (GDPR) |
| all | Run ALL modules and save results to file |

## CLI Options

```
-t, --target      Single target URL (e.g., https://example.com)
-l, --list        File containing target URLs, one per line
-m, --module      Module to run (see table above)
-o, --output      Output file for 'all' module (default: results.txt)
-c, --cookie      Cookie string to send with requests
--token           Bearer / JWT token to send as Authorization header
```

## Target Lists

Create a text file with one URL per line. Lines starting with `#` are treated as comments and skipped.

```
# production
https://app.example.com
https://api.example.com

# staging
https://staging.example.com
```

## Output

Each module prints its findings directly to the terminal with color-coded severity:

- Red: confirmed issue or missing critical control
- Yellow: warning or informational finding worth reviewing
- Green: check passed, no issue detected

When running with `-m all`, results are additionally saved to a text file (default `results.txt`, override with `-o`).

Every module displays a banner with the target URL and resolved IP address before running its checks.

## Requirements

```
requests
termcolor
```

Python standard library modules used: argparse, base64, json, re, ssl, socket, struct, os, datetime, urllib.parse, subprocess.

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome. Feel free to open an issue or submit a pull request.

## Disclaimer

Use this tool for authorized security assessments only. Always obtain written permission before testing targets you do not own. The author takes no responsibility for any misuse or unauthorized use of SiteMole.
