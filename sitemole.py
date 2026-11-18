import argparse
import base64
import json
import re
import ssl
import socket
import struct
import requests
import subprocess
import os
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from termcolor import colored

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

def display_banner():
    banner = r"""
 ____  _ _       __  __       _      
/ ___|(_) |_ ___|  \/  | ___ | | ___ 
\___ \| | __/ _ \ |\/| |/ _ \| |/ _ \
 ___) | | ||  __/ |  | | (_) | |  __/
|____/|_|\__\___|_|  |_|\___/|_|\___|
                                    by ChiZu
                                    
https://github.com/G0ldSec
    """
    print(banner)

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def build_auth(cookie_str=None, token=None):
    """Build an auth dict consumed by all modules."""
    return {"cookie": cookie_str, "token": token}

def requests_kwargs(auth):
    """Return extra kwargs for requests.get() based on auth config."""
    kwargs = {"timeout": 10, "headers": {"User-Agent": UA}}
    if auth.get("cookie"):
        kwargs["headers"]["Cookie"] = auth["cookie"]
    if auth.get("token"):
        kwargs["headers"]["Authorization"] = f"Bearer {auth['token']}"
    return kwargs

def curl_auth_args(auth):
    """Return extra curl CLI args for cookie / token."""
    args = []
    if auth.get("cookie"):
        args += ["-H", f"Cookie: {auth['cookie']}"]
    if auth.get("token"):
        args += ["-H", f"Authorization: Bearer {auth['token']}"]
    return args

def print_auth_info(auth):
    """Show which auth options are active."""
    if auth.get("cookie"):
        # mask value after '=' for display
        masked = re.sub(r'=([^;]{4})[^;]*', r'=\1***', auth["cookie"])
        print(colored(f"[*] Cookie: {masked}", "yellow"))
    if auth.get("token"):
        print(colored(f"[*] Bearer token: {auth['token'][:12]}...", "yellow"))

# ---------------------------------------------------------------------------
# Target loading
# ---------------------------------------------------------------------------

def load_targets(target=None, list_file=None):
    """Load targets from a single URL or a file containing one URL per line."""
    targets = []
    if list_file:
        if not os.path.isfile(list_file):
            print(colored(f"❌ File not found: {list_file}", "red"))
            exit(1)
        with open(list_file, "r", encoding="utf-8") as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith("#"):
                    targets.append(url)
        if not targets:
            print(colored("❌ No URLs found in the list file.", "red"))
            exit(1)
        print(colored(f"[+] Loaded {len(targets)} target(s) from {list_file}", "green"))
    elif target:
        targets.append(target)
    return targets

# ---------------------------------------------------------------------------
# Modules
# ---------------------------------------------------------------------------

def extract_comments(target_url, auth):
    print(colored(f"\n[+] Running Comment Extractor on {target_url}", "cyan"))
    try:
        response = requests.get(target_url, **requests_kwargs(auth))
        comments = re.findall(r'<!--(.*?)-->', response.text)
        output = "\n".join(comments) if comments else "No HTML comments found."
        print(output)
        return output
    except Exception as e:
        msg = f"❌ Failed to fetch {target_url}: {e}"
        print(colored(msg, "red"))
        return msg

def sri_checker(target_url, auth):
    print(colored(f"\n[+] Running SRI Checker on {target_url}", "cyan"))
    domain = urlparse(target_url).netloc
    curl_command = [
        "curl", "-s", "-L",
        "--cookie", "cookies.txt",
        "--cookie-jar", "cookies.txt",
        "-A", UA,
        *curl_auth_args(auth),
        target_url
    ]
    result = subprocess.run(curl_command, capture_output=True, text=True, encoding='utf-8', errors='ignore')
    page_source = result.stdout
    resource_links = set(re.findall(r'https://[^"\'>]+(?:\.js|\.css)', page_source, re.IGNORECASE))
    if not resource_links:
        print("\n❌ No external JavaScript or CSS resources found.")
        return "No external JavaScript or CSS resources found."
    print("\n[+] Extracted JavaScript and CSS URLs:")
    for link in resource_links:
        print(link)
    sri_in_use, sri_not_in_use = [], []
    for resource_url in resource_links:
        resource_domain = urlparse(resource_url).netloc
        if resource_domain != domain:
            curl_check_command = ["curl", "-s", "-L", resource_url]
            try:
                resource_content = subprocess.run(curl_check_command, capture_output=True, text=True, encoding='utf-8', errors='ignore').stdout
                if resource_content and 'integrity="' in resource_content:
                    sri_in_use.append(resource_url)
                else:
                    sri_not_in_use.append(resource_url)
            except Exception as e:
                print(f"❌ Failed to fetch {resource_url}: {e}")
    output = ""
    if sri_in_use:
        output += "\n✅ Resources with SRI in use:\n" + "\n".join(sri_in_use)
    if sri_not_in_use:
        output += "\n❌ Resources without SRI:\n" + "\n".join(sri_not_in_use)
    print(output)
    return output

def extract_links(target_url, auth):
    print(colored(f"\n[+] Running Link Extractor on {target_url}", "cyan"))
    try:
        response = requests.get(target_url, **requests_kwargs(auth))
        links = re.findall(r'href=["\'](.*?)["\']', response.text)
        output = "\n".join(sorted(set(links))) if links else "No links found."
        print(output)
        return output
    except Exception as e:
        msg = f"❌ Failed to fetch {target_url}: {e}"
        print(colored(msg, "red"))
        return msg

def extract_images(target_url, auth):
    print(colored(f"\n[+] Running Image Scraper on {target_url}", "cyan"))
    try:
        response = requests.get(target_url, **requests_kwargs(auth))
        images = re.findall(r'src=["\'](.*?\.(jpg|jpeg|png|gif|svg))["\']', response.text)
        output = "\n".join(sorted(set(img[0] for img in images))) if images else "No images found."
        print(output)
        return output
    except Exception as e:
        msg = f"❌ Failed to fetch {target_url}: {e}"
        print(colored(msg, "red"))
        return msg

# ---------------------------------------------------------------------------
# BigIP cookie decoding
# ---------------------------------------------------------------------------

def decode_bigip_standard(encoded_ip_str, encoded_port_str):
    """Decode standard BIGipServer format: <decimal_ip>.<decimal_port>.0000
    IP is stored as a little-endian 32-bit integer.
    Port is stored as a big-endian 16-bit integer with swapped bytes."""
    try:
        ip_int = int(encoded_ip_str)
        # Pack as unsigned 32-bit little-endian, unpack as 4 bytes
        ip_bytes = struct.pack("<I", ip_int)
        ip = f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"

        port_int = int(encoded_port_str)
        # Pack as unsigned 16-bit big-endian, unpack as little-endian
        port_bytes = struct.pack(">H", port_int)
        port = struct.unpack("<H", port_bytes)[0]

        return ip, port
    except (ValueError, struct.error):
        return None, None


def decode_bigip_hex_rd(cookie_value):
    """Decode route-domain format:
    rd<rd>o00000000000000000000ffff<8_hex_ip>o<port_dec>"""
    m = re.match(
        r'rd(\d+)o00000000000000000000ffff([0-9a-f]{8})o(\d+)',
        cookie_value, re.IGNORECASE
    )
    if not m:
        return None, None, None
    rd = m.group(1)
    hex_ip = m.group(2)
    try:
        ip_bytes = bytes.fromhex(hex_ip)
        ip = f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"
        port = int(m.group(3))
        return ip, port, rd
    except (ValueError, IndexError):
        return None, None, None


def decode_bigip_vi(cookie_value):
    """Decode vi-hex format: vi<8_hex_ip>.<port_dec> (less common)."""
    m = re.match(r'vi([0-9a-f]{8})\.(\d+)', cookie_value, re.IGNORECASE)
    if not m:
        return None, None
    try:
        hex_ip = m.group(1)
        ip_bytes = bytes.fromhex(hex_ip)
        ip = f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"
        port = int(m.group(2))
        return ip, port
    except (ValueError, IndexError):
        return None, None


def decode_bigip_cookie(cookie_name, cookie_value):
    """Try all known BIGipServer encoding formats. Returns a result dict or None."""
    if not cookie_name.lower().startswith("bigipserver"):
        return None

    pool_name = cookie_name[len("BIGipServer"):]
    result = {"pool": pool_name, "raw": cookie_value}

    # Format 1: standard decimal  --  <ip_dec>.<port_dec>.0000
    m = re.match(r'^(\d+)\.(\d+)\.\d+$', cookie_value)
    if m:
        ip, port = decode_bigip_standard(m.group(1), m.group(2))
        if ip and port:
            result.update({"ip": ip, "port": port, "format": "standard"})
            return result

    # Format 2: route-domain hex
    ip, port, rd = decode_bigip_hex_rd(cookie_value)
    if ip:
        result.update({"ip": ip, "port": port, "route_domain": rd, "format": "route-domain"})
        return result

    # Format 3: vi-hex
    ip, port = decode_bigip_vi(cookie_value)
    if ip:
        result.update({"ip": ip, "port": port, "format": "vi-hex"})
        return result

    # Could not decode (likely encrypted)
    result["format"] = "encrypted/unknown"
    return result


# ---------------------------------------------------------------------------
# Cookie analysis (flags + BigIP)
# ---------------------------------------------------------------------------

def analyze_cookies(raw_headers_text, output):
    """Analyze Set-Cookie headers for security flags and BigIP information leakage."""
    # Collect all Set-Cookie lines (there can be many)
    set_cookie_lines = []
    for line in raw_headers_text.splitlines():
        if line.lower().startswith("set-cookie:"):
            set_cookie_lines.append(line.split(":", 1)[1].strip())

    if not set_cookie_lines:
        return

    output.append("")
    output.append(colored("=" * 60, "yellow"))
    output.append(colored("  Cookie Security Analysis", "yellow"))
    output.append(colored("=" * 60, "yellow"))

    bigip_found = False

    for sc in set_cookie_lines:
        # Parse name=value from the first segment
        parts = [p.strip() for p in sc.split(";")]
        if "=" not in parts[0]:
            continue
        cookie_name, cookie_value = parts[0].split("=", 1)
        flags_lower = [p.strip().lower() for p in parts[1:]]
        flags_str = "; ".join(parts[1:]) if len(parts) > 1 else "(none)"

        output.append("")
        output.append(colored(f"  Cookie: {cookie_name}", "white"))

        # --- Flag checks ---
        flag_issues = []
        has_secure = any(f == "secure" for f in flags_lower)
        has_httponly = any(f == "httponly" for f in flags_lower)
        has_samesite = any(f.startswith("samesite=") for f in flags_lower)
        samesite_val = ""
        for f in flags_lower:
            if f.startswith("samesite="):
                samesite_val = f.split("=", 1)[1]

        if not has_secure:
            flag_issues.append((
                "❌ Missing 'Secure' flag",
                "Cookie is transmitted over HTTP (unencrypted). A network attacker\n"
                "    can intercept it via MITM."
            ))
        if not has_httponly:
            flag_issues.append((
                "❌ Missing 'HttpOnly' flag",
                "Cookie is accessible via JavaScript (document.cookie). XSS can\n"
                "    steal this cookie directly."
            ))
        if not has_samesite:
            flag_issues.append((
                "⚠️  Missing 'SameSite' attribute",
                "Without SameSite the browser defaults to 'Lax' (modern browsers),\n"
                "    but older browsers treat it as 'None', allowing cross-site request\n"
                "    attachment. Explicit SameSite=Strict or Lax is recommended."
            ))
        elif samesite_val == "none" and not has_secure:
            flag_issues.append((
                "❌ SameSite=None WITHOUT Secure flag",
                "Modern browsers reject SameSite=None cookies that lack the Secure\n"
                "    flag entirely, but older browsers will send them cross-site over HTTP."
            ))

        if flag_issues:
            for title, detail in flag_issues:
                color = "red" if title.startswith("❌") else "yellow"
                output.append(colored(f"    {title}", color))
                for dl in detail.split("\n"):
                    output.append(colored(f"    {dl}", color))
        else:
            output.append(colored("    ✅ Secure, HttpOnly, SameSite all present.", "green"))

        # --- BigIP decoding ---
        bigip_result = decode_bigip_cookie(cookie_name, cookie_value)
        if bigip_result:
            bigip_found = True
            output.append("")
            output.append(colored("    🔓 F5 BIG-IP PERSISTENCE COOKIE DETECTED", "red"))
            output.append(colored(f"    Pool Name : {bigip_result['pool']}", "red"))
            output.append(colored(f"    Raw Value : {bigip_result['raw']}", "red"))
            output.append(colored(f"    Encoding  : {bigip_result['format']}", "red"))

            if bigip_result["format"] == "encrypted/unknown":
                output.append(colored(
                    "    Could not decode -- cookie appears to be encrypted.", "yellow"))
                output.append(colored(
                    "    (F5 supports cookie encryption since BIG-IP v11.5)", "yellow"))
            else:
                ip = bigip_result["ip"]
                port = bigip_result["port"]
                output.append(colored(f"    Backend IP: {ip}", "red"))
                output.append(colored(f"    Backend Port: {port}", "red"))
                if "route_domain" in bigip_result:
                    output.append(colored(f"    Route Domain: {bigip_result['route_domain']}", "red"))

                output.append("")
                output.append(colored(
                    "    ⚠️  INFORMATION DISCLOSURE: The unencrypted cookie exposes the", "red"))
                output.append(colored(
                    "    internal backend server IP and port. This reveals:", "red"))
                output.append(colored(
                    "    - Internal network topology / RFC1918 addressing", "red"))
                output.append(colored(
                    "    - Number and identity of backend servers (pool enumeration)", "red"))
                output.append(colored(
                    "    - An attacker can manipulate the cookie to target a specific", "red"))
                output.append(colored(
                    "      backend server, bypassing load balancing or pinning to a", "red"))
                output.append(colored(
                    "      known vulnerable node", "red"))
                output.append("")
                output.append(colored(
                    "    Recommendation: Enable BIG-IP cookie encryption on the", "cyan"))
                output.append(colored(
                    "    virtual server's HTTP profile (Cookie Encryption = Required).", "cyan"))
                output.append(colored(
                    "    Alternatively, switch to server-side persistence (source-addr,", "cyan"))
                output.append(colored(
                    "    SSL session ID, or universal persistence with iRules).", "cyan"))
                output.append(colored(
                    "    Ref: https://my.f5.com/manage/s/article/K14784", "cyan"))

    if not bigip_found:
        # Quick check if any cookie name hints at a load balancer
        all_names = [sc.split("=", 1)[0].strip() for sc in set_cookie_lines if "=" in sc]
        lb_patterns = ["AWSALB", "AWSELB", "JSESSIONID", "ROUTEID", "SERVERID",
                       "HAProxy", "X-Varnish", "incap_ses_", "visid_incap_"]
        for name in all_names:
            for pat in lb_patterns:
                if pat.lower() in name.lower():
                    output.append("")
                    output.append(colored(
                        f"  ℹ️  Load-balancer cookie detected: {name} (pattern: {pat})", "yellow"))

    output.append("")
    output.append(colored("  Ref: https://owasp.org/www-project-web-security-testing-guide/latest/"
                          "4-Web_Application_Security_Testing/06-Session_Management_Testing/"
                          "02-Testing_for_Cookies_Attributes", "cyan"))
    output.append(colored("=" * 60, "yellow"))
    output.append("")


def analyze_xss_protection(headers, output):
    """Analyze X-XSS-Protection header in detail."""
    MDN_LINK = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
    xss_val = headers.get("x-xss-protection", "").strip()

    if not xss_val:
        # Header not present at all -- that's fine, no analysis needed
        return

    output.append("")
    output.append(colored("=" * 60, "red"))
    output.append(colored("  X-XSS-Protection Analysis", "red"))
    output.append(colored("=" * 60, "red"))
    output.append(colored(f"  Value: {xss_val}", "red"))
    output.append("")
    output.append(colored(
        "  ❌ DEPRECATED - This header should be REMOVED entirely.", "red"))
    output.append(colored(
        "  The XSS Auditor/filter that this header controlled has been", "red"))
    output.append(colored(
        "  removed from all modern browsers (Chrome 78+, Edge, Safari).", "red"))
    output.append(colored(
        "  Firefox never implemented it.", "red"))
    output.append("")

    # Parse the value
    parts = [p.strip().lower() for p in xss_val.split(";")]
    mode_value = parts[0] if parts else ""

    if mode_value == "1" and "mode=block" not in parts:
        # 1 without mode=block -- the worst case
        output.append(colored(
            "  ⚠️  DANGEROUS: Value '1' WITHOUT mode=block is set.", "red"))
        output.append(colored(
            "  In legacy browsers with an active XSS Auditor, this mode", "red"))
        output.append(colored(
            "  sanitizes the page by selectively removing scripts that look", "red"))
        output.append(colored(
            "  like a reflected XSS payload. Attackers can abuse this to", "red"))
        output.append(colored(
            "  selectively DISABLE legitimate inline scripts on the page by", "red"))
        output.append(colored(
            "  injecting partial payloads that trigger the filter.", "red"))
        output.append(colored(
            "  This turns the XSS protection into an XSS attack vector.", "red"))
    elif mode_value == "1" and "mode=block" in parts:
        output.append(colored(
            "  ⚠️  Value '1; mode=block' is set.", "yellow"))
        output.append(colored(
            "  In legacy browsers this blocked the entire page when the", "yellow"))
        output.append(colored(
            "  auditor detected a potential XSS payload. While safer than", "yellow"))
        output.append(colored(
            "  '1' alone, it was still vulnerable to side-channel attacks", "yellow"))
        output.append(colored(
            "  that allowed cross-site information leaks by measuring", "yellow"))
        output.append(colored(
            "  whether a page loaded or was blocked.", "yellow"))
    elif mode_value == "0":
        output.append(colored(
            "  Value '0' explicitly disables the filter. This is the least", "yellow"))
        output.append(colored(
            "  harmful setting, but the header is still unnecessary since", "yellow"))
        output.append(colored(
            "  no current browser has an XSS auditor to disable.", "yellow"))

    output.append("")
    output.append(colored(
        "  Recommendation: Remove the header entirely and use a strong", "cyan"))
    output.append(colored(
        "  Content-Security-Policy instead to mitigate XSS.", "cyan"))
    output.append(colored(f"  Reference: {MDN_LINK}", "cyan"))
    output.append(colored("=" * 60, "red"))
    output.append("")


def analyze_csp(headers, output):
    """Deep-analyze Content-Security-Policy for misconfigurations."""
    csp = headers.get("content-security-policy", "")

    output.append("")
    output.append(colored("=" * 60, "magenta"))
    output.append(colored("  Content-Security-Policy Analysis", "magenta"))
    output.append(colored("=" * 60, "magenta"))

    if not csp:
        output.append(colored(
            "  ❌ No CSP header present.", "red"))
        output.append(colored(
            "  Without CSP the browser has no restrictions on where scripts,", "red"))
        output.append(colored(
            "  styles, images, frames and other resources can be loaded from.", "red"))
        output.append(colored(
            "  This is the single most effective header to mitigate XSS,", "red"))
        output.append(colored(
            "  clickjacking, and data injection attacks.", "red"))
        output.append(colored(
            "  Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP", "cyan"))
        output.append(colored("=" * 60, "magenta"))
        output.append("")
        return

    output.append(colored(f"  Policy: {csp}", "white"))
    output.append("")

    # Parse directives into a dict
    directives = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = " ".join(tokens[1:]) if len(tokens) > 1 else ""

    findings = []

    # --- Check for dangerous source values in script-related directives ---
    script_directives = ["script-src", "default-src", "script-src-elem", "script-src-attr"]
    all_script_sources = ""
    for d in script_directives:
        if d in directives:
            all_script_sources += " " + directives[d]

    if "'unsafe-inline'" in all_script_sources:
        findings.append((
            "❌ 'unsafe-inline' in script source",
            "Allows inline <script> blocks and event handlers (onclick, onerror, ...).\n"
            "  This completely negates CSP's XSS protection because an attacker who\n"
            "  achieves HTML injection can execute arbitrary JavaScript inline.",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#unsafe_inline_script"
        ))

    if "'unsafe-eval'" in all_script_sources:
        findings.append((
            "❌ 'unsafe-eval' in script source",
            "Allows eval(), Function(), setTimeout('string'), and setInterval('string').\n"
            "  Attackers can exploit this if they control any string that reaches these\n"
            "  functions, turning a data injection into code execution.",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#unsafe_eval"
        ))

    if "data:" in all_script_sources:
        findings.append((
            "❌ 'data:' in script source",
            "Allows loading scripts from data: URIs, e.g.:\n"
            "  <script src=\"data:text/javascript,alert(document.cookie)\"></script>\n"
            "  Any HTML injection can load and execute arbitrary JavaScript this way.",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src"
        ))

    # Check for wildcard * in script sources
    script_src_val = directives.get("script-src", directives.get("default-src", ""))
    if re.search(r'(?<!\.)(\*)', script_src_val):
        # bare * (not *.example.com)
        findings.append((
            "❌ Wildcard '*' in script source",
            "Allows scripts to be loaded from ANY origin. An attacker can host\n"
            "  malicious JavaScript on any domain and load it into the page.\n"
            "  This effectively disables CSP script protection.",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src"
        ))

    if "http:" in all_script_sources:
        findings.append((
            "⚠️  'http:' scheme in script source",
            "Allows loading scripts over unencrypted HTTP. A network attacker\n"
            "  (MITM) can intercept and replace the script with malicious code.",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src"
        ))

    # --- Check for missing critical directives ---
    if "default-src" not in directives:
        findings.append((
            "⚠️  Missing 'default-src' directive",
            "Without default-src, any resource type that does not have its own\n"
            "  directive falls back to no restriction at all. Always set default-src\n"
            "  as a catch-all, typically to 'self' or 'none'.",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src"
        ))

    if "script-src" not in directives and "default-src" not in directives:
        findings.append((
            "❌ No 'script-src' and no 'default-src'",
            "Scripts can be loaded from anywhere. CSP provides no XSS mitigation\n"
            "  without at least one of these directives.",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src"
        ))

    if "object-src" not in directives:
        obj_fallback = directives.get("default-src", "")
        if "'none'" not in obj_fallback:
            findings.append((
                "⚠️  Missing 'object-src' directive",
                "Without object-src (or default-src 'none'), <object>, <embed> and\n"
                "  <applet> elements can load plugins from any origin. Even though\n"
                "  Flash is dead, PDF and other plugin types can still be abused.\n"
                "  Set object-src 'none' unless you explicitly need plugins.",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/object-src"
            ))

    if "base-uri" not in directives:
        findings.append((
            "⚠️  Missing 'base-uri' directive",
            "Without base-uri, an attacker who achieves HTML injection can insert\n"
            "  a <base> tag to change the base URL of the page. All relative URLs\n"
            "  (scripts, forms, links) would then resolve to the attacker's domain.\n"
            "  Set base-uri 'self' or 'none'.",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/base-uri"
        ))

    if "form-action" not in directives:
        findings.append((
            "⚠️  Missing 'form-action' directive",
            "Without form-action, forms on the page can submit data to any origin.\n"
            "  An attacker with HTML injection can create a form that exfiltrates\n"
            "  sensitive data (tokens, credentials) to an external server.\n"
            "  Note: form-action does NOT fall back to default-src.",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/form-action"
        ))

    if "frame-ancestors" not in directives:
        findings.append((
            "⚠️  Missing 'frame-ancestors' directive",
            "Without frame-ancestors, the page can be embedded in <iframe> on any\n"
            "  origin, enabling clickjacking attacks. frame-ancestors replaces the\n"
            "  older X-Frame-Options header and is the recommended mechanism.\n"
            "  Note: frame-ancestors does NOT fall back to default-src.",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors"
        ))
    elif "frame-ancestors" in directives:
        fa_val = directives["frame-ancestors"]
        if "*" in fa_val.split():
            findings.append((
                "❌ frame-ancestors set to '*'",
                "Any origin can embed this page in an iframe, rendering the\n"
                "  directive useless against clickjacking.",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors"
            ))

    # --- Check style-src for unsafe-inline ---
    style_sources = ""
    for d in ["style-src", "default-src", "style-src-elem", "style-src-attr"]:
        if d in directives:
            style_sources += " " + directives[d]
    if "'unsafe-inline'" in style_sources:
        findings.append((
            "⚠️  'unsafe-inline' in style source",
            "Allows inline <style> blocks and style attributes. While lower risk\n"
            "  than unsafe-inline in script-src, it can still enable data\n"
            "  exfiltration via CSS injection (e.g. reading CSRF tokens with\n"
            "  attribute selectors sending data via background-image URLs).",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/style-src"
        ))

    # --- Print findings ---
    if findings:
        for title, detail, ref in findings:
            color = "red" if title.startswith("❌") else "yellow"
            output.append(colored(f"  {title}", color))
            for line in detail.split("\n"):
                output.append(colored(f"  {line}", color))
            output.append(colored(f"  Ref: {ref}", "cyan"))
            output.append("")
    else:
        output.append(colored("  ✅ No obvious CSP misconfigurations detected.", "green"))
        output.append("")

    output.append(colored("=" * 60, "magenta"))
    output.append("")


def analyze_headers(target_url, auth):
    print(colored(f"\n[+] Running HTTP Header Analysis on {target_url}", "cyan"))
    try:
        curl_command = [
            "curl", "-s", "-D", "-", "-o", "/dev/null",
            "-A", UA,
            "-L",
            *curl_auth_args(auth),
            target_url
        ]
        result = subprocess.run(curl_command, capture_output=True, text=True)
        raw_headers = result.stdout
        boxed_output = f"\n{'-'*70}\n| FULL HTTP REQUEST/RESPONSE (incl. redirects)\n{'-'*70}\n{raw_headers}\n{'-'*70}\n"
        print(colored(boxed_output, "cyan"))
        if not raw_headers:
            raise Exception("No headers received.")
    except Exception as e:
        print(colored(f"❌ Failed to fetch headers: {e}", "red"))
        return f"Failed to fetch headers: {e}"

    headers = {}
    for line in raw_headers.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            headers[key.strip().lower()] = value.strip()

    output = []

    # --- Security header presence check ---
    output.append(colored("\n--- Security Header Presence ---", "white"))
    critical_headers = {
        "strict-transport-security": None,
        "x-frame-options": "🔶 Superseded by CSP frame-ancestors",
        "x-content-type-options": None,
        "content-security-policy": None,
        "referrer-policy": None,
        "permissions-policy": None,
        "cache-control": None,
        "x-permitted-cross-domain-policies": None,
        "cross-origin-embedder-policy": None,
        "cross-origin-opener-policy": None,
        "cross-origin-resource-policy": None,
        "feature-policy": "🔶 Superseded by Permissions-Policy"
    }
    for header, note in critical_headers.items():
        header_present = header in headers
        line = f"{header}: {headers.get(header, '')}"
        if header == "feature-policy":
            if "permissions-policy" in headers:
                continue
            elif header_present:
                output.append(colored(f"{line}  [🔶 Deprecated! Use Permissions-Policy instead]", "yellow"))
            else:
                output.append(colored("⚠️ Feature-Policy is missing (use Permissions-Policy)", "yellow"))
            continue
        if header_present:
            if note:
                output.append(colored(f"{line}  [{note}]", "yellow"))
            else:
                output.append(colored(line, "green"))
        else:
            color = "yellow" if note else "red"
            icon = "⚠️" if note else "❌"
            output.append(colored(f"{icon} {header} is missing!", color))

    # --- Cookie analysis (flags + BigIP) ---
    analyze_cookies(raw_headers, output)

    # --- X-XSS-Protection deep analysis ---
    analyze_xss_protection(headers, output)

    # --- CSP deep analysis ---
    analyze_csp(headers, output)

    print("\n".join(output))
    return "\n".join(output)


def check_cookies(target_url, auth):
    """Standalone cookie analysis module -- fetches headers and runs cookie checks."""
    print(colored(f"\n[+] Running Cookie Analysis on {target_url}", "cyan"))
    try:
        curl_command = [
            "curl", "-s", "-D", "-", "-o", "/dev/null",
            "-A", UA, "-L",
            *curl_auth_args(auth),
            target_url
        ]
        result = subprocess.run(curl_command, capture_output=True, text=True)
        raw_headers = result.stdout
        if not raw_headers:
            msg = "No headers received."
            print(colored(f"❌ {msg}", "red"))
            return msg
    except Exception as e:
        msg = f"Failed to fetch headers: {e}"
        print(colored(f"❌ {msg}", "red"))
        return msg

    output = []
    analyze_cookies(raw_headers, output)
    if not output or all(not line.strip() for line in output):
        output.append(colored("No Set-Cookie headers found in the response.", "yellow"))
    result_str = "\n".join(output)
    print(result_str)
    return result_str

# ---------------------------------------------------------------------------
# PT-WEB-33: Version Information Disclosure
# ---------------------------------------------------------------------------

def check_version_info(target_url, auth):
    """Parse Server, X-Powered-By, X-AspNet-Version, X-Generator and similar
    headers that leak software versions."""
    print(colored(f"\n[+] Running Version Info Disclosure Check on {target_url}", "cyan"))
    try:
        curl_cmd = [
            "curl", "-s", "-D", "-", "-o", "/dev/null", "-A", UA, "-L",
            *curl_auth_args(auth), target_url
        ]
        result = subprocess.run(curl_cmd, capture_output=True, text=True)
        raw = result.stdout
        if not raw:
            raise Exception("No headers received.")
    except Exception as e:
        msg = f"❌ Failed to fetch headers: {e}"
        print(colored(msg, "red"))
        return msg

    version_headers = [
        "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
        "x-generator", "x-drupal-cache", "x-varnish", "x-litespeed-cache",
        "x-turbo-charged-by", "x-redirect-by", "x-cms", "x-content-powered-by",
        "x-runtime", "x-owa-version",
    ]
    output = []
    found = False
    for line in raw.splitlines():
        if ": " not in line:
            continue
        hdr, val = line.split(": ", 1)
        hdr_low = hdr.strip().lower()
        if hdr_low in version_headers:
            found = True
            output.append(colored(f"  ❌ {hdr.strip()}: {val.strip()}", "red"))

    if found:
        output.insert(0, colored("  Version / technology information found in HTTP headers:", "red"))
        output.append("")
        output.append(colored(
            "  ⚠️  Exposed version strings help attackers identify known CVEs", "yellow"))
        output.append(colored(
            "  for the exact software version in use. Remove or genericize these", "yellow"))
        output.append(colored(
            "  headers in the web server / reverse proxy configuration.", "yellow"))
    else:
        output.append(colored("  ✅ No version-disclosing headers found.", "green"))

    result_str = "\n".join(output)
    print(result_str)
    return result_str


# ---------------------------------------------------------------------------
# PT-WEB-37: Unsafe CORS Configuration
# ---------------------------------------------------------------------------

API_PROBE_PATHS = [
    "/graphql", "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1", "/v1", "/v2",
    "/oauth/token", "/auth", "/login",
    "/ws", "/websocket", "/hub", "/signalr",
]


def _cors_test_url(url, evil_origins, auth):
    """Test a single URL against all evil origins. Returns list of finding strings."""
    findings = []
    for origin in evil_origins:
        try:
            kw = requests_kwargs(auth)
            kw["headers"]["Origin"] = origin
            kw["allow_redirects"] = True
            resp = requests.get(url, **kw)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if not acao:
                continue

            if acao == "*":
                findings.append(colored(
                    f"  ❌ ACAO is wildcard '*' on {url}", "red"))
                findings.append(colored(
                    f"     Origin sent: {origin}", "red"))
                findings.append(colored(
                    "     Any website can read responses from this endpoint.", "red"))
                if acac.lower() == "true":
                    findings.append(colored(
                        "     AND Access-Control-Allow-Credentials: true!", "red"))
                    findings.append(colored(
                        "     Browsers ignore credentials with wildcard ACAO, but this", "red"))
                    findings.append(colored(
                        "     misconfiguration signals a broken CORS implementation.", "red"))
                findings.append("")

            elif acao.lower() == origin.lower():
                findings.append(colored(
                    f"  ❌ ACAO reflects attacker origin on {url}", "red"))
                findings.append(colored(
                    f"     Origin sent: {origin}  |  ACAO returned: {acao}", "red"))
                if acac.lower() == "true":
                    findings.append(colored(
                        "     AND Access-Control-Allow-Credentials: true!", "red"))
                    findings.append(colored(
                        "     An attacker's page can read authenticated responses from", "red"))
                    findings.append(colored(
                        "     this endpoint, stealing sensitive user data cross-site.", "red"))
                else:
                    findings.append(colored(
                        "     Origin reflection without credentials is lower risk but", "yellow"))
                    findings.append(colored(
                        "     still allows unauthenticated data to be read cross-origin.", "yellow"))
                findings.append("")

            elif acao.lower() == "null" and origin == "null":
                findings.append(colored(
                    f"  ❌ ACAO reflects 'null' origin on {url}", "red"))
                findings.append(colored(
                    f"     ACAO: {acao}  |  Credentials: {acac}", "red"))
                findings.append(colored(
                    "     Sandboxed iframes and data: URIs send Origin: null.", "red"))
                findings.append(colored(
                    "     An attacker can use a sandboxed iframe to match this.", "red"))
                if acac.lower() == "true":
                    findings.append(colored(
                        "     WITH Access-Control-Allow-Credentials: true!", "red"))
                    findings.append(colored(
                        "     This allows an attacker to read authenticated responses", "red"))
                    findings.append(colored(
                        "     from a sandboxed context, exfiltrating user data.", "red"))
                findings.append("")

        except Exception:
            continue

    return findings


def check_cors(target_url, auth):
    """Send requests with crafted Origin headers to test CORS policy.
    Tests the target URL itself plus common API endpoint paths."""
    print(colored(f"\n[+] Running CORS Configuration Check on {target_url}", "cyan"))
    output = []
    parsed = urlparse(target_url)
    evil_origins = [
        "https://evil.com",
        f"https://{parsed.netloc}.evil.com",   # subdomain trick
        f"https://evil-{parsed.netloc}",       # prefix trick
        "null",                                 # null origin
    ]

    # Build list of URLs to test: the target itself + common API paths on the same host
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    urls_to_test = [target_url]
    for path in API_PROBE_PATHS:
        probe_url = base_url + path
        if probe_url != target_url:
            urls_to_test.append(probe_url)

    tested = 0
    for url in urls_to_test:
        findings = _cors_test_url(url, evil_origins, auth)
        if findings:
            output.extend(findings)
        tested += 1

    if not output:
        output.append(colored(
            f"  ✅ No unsafe CORS configuration detected ({tested} endpoints probed).", "green"))
    else:
        output.append(colored(
            f"  Tested {tested} endpoints on {parsed.netloc}", "white"))
        output.append(colored(
            "  Ref: https://portswigger.net/web-security/cors", "cyan"))

    result_str = "\n".join(output)
    print(result_str)
    return result_str


# ---------------------------------------------------------------------------
# PT-WEB-53: Unsafe HTTP Methods
# ---------------------------------------------------------------------------

def check_http_methods(target_url, auth):
    """Send OPTIONS request and check for dangerous allowed methods."""
    print(colored(f"\n[+] Running HTTP Methods Check on {target_url}", "cyan"))
    output = []
    dangerous = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "PROPFIND",
                 "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}
    try:
        kw = requests_kwargs(auth)
        resp = requests.options(target_url, **kw)
        allow = resp.headers.get("Allow", "")
        if not allow:
            # Try Access-Control-Allow-Methods (CORS preflight)
            allow = resp.headers.get("Access-Control-Allow-Methods", "")
        if not allow:
            output.append(colored(
                "  ℹ️  No Allow or Access-Control-Allow-Methods header returned.", "yellow"))
            output.append(colored(
                "  The server may not respond to OPTIONS requests.", "yellow"))
        else:
            methods = {m.strip().upper() for m in allow.split(",")}
            output.append(colored(f"  Allowed methods: {', '.join(sorted(methods))}", "white"))
            found_dangerous = methods & dangerous
            if found_dangerous:
                output.append(colored(
                    f"  ❌ Potentially dangerous methods enabled: {', '.join(sorted(found_dangerous))}", "red"))
                if "TRACE" in found_dangerous:
                    output.append(colored(
                        "     TRACE can enable Cross-Site Tracing (XST) attacks to steal", "red"))
                    output.append(colored(
                        "     cookies marked HttpOnly via JavaScript.", "red"))
                if "PUT" in found_dangerous or "DELETE" in found_dangerous:
                    output.append(colored(
                        "     PUT/DELETE may allow unauthorized file upload or deletion", "red"))
                    output.append(colored(
                        "     on misconfigured WebDAV or REST endpoints.", "red"))
            else:
                output.append(colored(
                    "  ✅ No dangerous HTTP methods detected.", "green"))

        # Also try TRACE directly
        try:
            trace_resp = requests.request("TRACE", target_url, **requests_kwargs(auth))
            if trace_resp.status_code == 200 and "TRACE" in trace_resp.text.upper():
                output.append(colored(
                    "  ❌ TRACE method is active! Server echoes the request.", "red"))
        except Exception:
            pass

    except Exception as e:
        output.append(colored(f"  ❌ Error: {e}", "red"))

    result_str = "\n".join(output)
    print(result_str)
    return result_str


# ---------------------------------------------------------------------------
# PT-WEB-59: Internal IP Address Disclosure
# ---------------------------------------------------------------------------

RFC1918_PATTERNS = [
    r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    r'\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b',
    r'\b192\.168\.\d{1,3}\.\d{1,3}\b',
]
RFC1918_RE = re.compile("|".join(RFC1918_PATTERNS))

def check_internal_ips(target_url, auth):
    """Search for RFC1918 internal IP addresses in headers and body."""
    print(colored(f"\n[+] Running Internal IP Disclosure Check on {target_url}", "cyan"))
    output = []
    try:
        kw = requests_kwargs(auth)
        kw["allow_redirects"] = True
        resp = requests.get(target_url, **kw)

        # Check headers
        header_ips = set()
        for hdr, val in resp.headers.items():
            for ip in RFC1918_RE.findall(val):
                header_ips.add((hdr, ip))

        # Check body
        body_ips = set(RFC1918_RE.findall(resp.text))
        # Exclude IPs that are part of the target's own network context (like CSP)
        # but still report them -- they're info disclosure either way

        if header_ips:
            output.append(colored("  ❌ Internal IPs found in HTTP headers:", "red"))
            for hdr, ip in sorted(header_ips):
                output.append(colored(f"     {hdr}: {ip}", "red"))

        if body_ips:
            output.append(colored(
                f"  ❌ Internal IPs found in response body: {', '.join(sorted(body_ips))}", "red"))

        if header_ips or body_ips:
            output.append("")
            output.append(colored(
                "  ⚠️  Internal IP addresses reveal network topology to an attacker.", "yellow"))
            output.append(colored(
                "  Check reverse proxy config, error pages, and application output.", "yellow"))
        else:
            output.append(colored("  ✅ No internal IP addresses found.", "green"))

    except Exception as e:
        output.append(colored(f"  ❌ Error: {e}", "red"))

    result_str = "\n".join(output)
    print(result_str)
    return result_str


# ---------------------------------------------------------------------------
# PT-WEB-69: Autocomplete on Sensitive Fields
# ---------------------------------------------------------------------------

def check_autocomplete(target_url, auth):
    """Check for missing autocomplete=off on password and login fields."""
    print(colored(f"\n[+] Running Autocomplete Check on {target_url}", "cyan"))
    output = []
    try:
        kw = requests_kwargs(auth)
        kw["allow_redirects"] = True
        resp = requests.get(target_url, **kw)
        html = resp.text

        # Find all input fields
        inputs = re.findall(r'<input[^>]*>', html, re.IGNORECASE)
        sensitive_types = ["password", "email", "tel", "credit-card"]
        sensitive_names = ["pass", "pwd", "user", "login", "email", "card",
                          "cvv", "cvc", "ssn", "account", "secret", "token"]

        issues = []
        for inp in inputs:
            inp_lower = inp.lower()
            # Check type
            type_match = re.search(r'type=["\']?(\w+)', inp_lower)
            name_match = re.search(r'name=["\']?([^"\'>\s]+)', inp_lower)
            id_match = re.search(r'id=["\']?([^"\'>\s]+)', inp_lower)

            field_type = type_match.group(1) if type_match else ""
            field_name = name_match.group(1) if name_match else ""
            field_id = id_match.group(1) if id_match else ""
            field_label = field_name or field_id or field_type

            is_sensitive = False
            if field_type in sensitive_types:
                is_sensitive = True
            for sn in sensitive_names:
                if sn in field_name.lower() or sn in field_id.lower():
                    is_sensitive = True
                    break

            if is_sensitive:
                has_autocomplete_off = "autocomplete" in inp_lower and (
                    'autocomplete="off"' in inp_lower or
                    "autocomplete='off'" in inp_lower or
                    "autocomplete=off" in inp_lower or
                    'autocomplete="new-password"' in inp_lower
                )
                if not has_autocomplete_off:
                    issues.append(field_label)

        # Also check <form> level
        forms = re.findall(r'<form[^>]*>', html, re.IGNORECASE)
        form_has_autocomplete_off = False
        for form in forms:
            if 'autocomplete="off"' in form.lower() or "autocomplete='off'" in form.lower():
                form_has_autocomplete_off = True

        if issues and not form_has_autocomplete_off:
            output.append(colored(
                "  ❌ Sensitive fields without autocomplete=\"off\":", "red"))
            for f in issues:
                output.append(colored(f"     - {f}", "red"))
            output.append("")
            output.append(colored(
                "  Browsers may cache entered values (passwords, emails) in the", "yellow"))
            output.append(colored(
                "  autocomplete dropdown. On shared computers this exposes credentials.", "yellow"))
            output.append(colored(
                "  Set autocomplete=\"off\" or autocomplete=\"new-password\" on sensitive fields.", "yellow"))
        elif not inputs:
            output.append(colored("  ℹ️  No input fields found on this page.", "yellow"))
        else:
            output.append(colored("  ✅ Sensitive fields have autocomplete disabled.", "green"))

    except Exception as e:
        output.append(colored(f"  ❌ Error: {e}", "red"))

    result_str = "\n".join(output)
    print(result_str)
    return result_str


# ---------------------------------------------------------------------------
# PT-WEB-71: HTML Metadata Extraction
# ---------------------------------------------------------------------------

def check_metadata(target_url, auth):
    """Extract HTML meta tags that reveal CMS, author, generator info."""
    print(colored(f"\n[+] Running Metadata Extraction on {target_url}", "cyan"))
    output = []
    try:
        kw = requests_kwargs(auth)
        kw["allow_redirects"] = True
        resp = requests.get(target_url, **kw)
        html = resp.text

        # Extract meta tags
        metas = re.findall(r'<meta\s+[^>]*>', html, re.IGNORECASE)
        interesting_names = ["generator", "author", "cms", "framework",
                            "powered-by", "application-name", "version",
                            "copyright", "description", "keywords"]
        findings = []
        for meta in metas:
            meta_lower = meta.lower()
            name_match = re.search(r'(?:name|property)=["\']?([^"\'>\s]+)', meta_lower)
            content_match = re.search(r'content=["\']([^"\']*)', meta, re.IGNORECASE)
            if name_match and content_match:
                name = name_match.group(1).lower()
                content = content_match.group(1)
                for iname in interesting_names:
                    if iname in name:
                        findings.append((name, content))
                        break

        # Check for common CMS indicators in HTML
        cms_indicators = {
            "WordPress": [r'wp-content/', r'wp-includes/', r'wp-json'],
            "Joomla": [r'/components/com_', r'Joomla!'],
            "Drupal": [r'Drupal\.settings', r'/sites/default/files/'],
            "Typo3": [r'typo3conf/', r'typo3temp/'],
            "Shopify": [r'cdn\.shopify\.com'],
            "Magento": [r'/skin/frontend/', r'Mage\.Cookies'],
        }
        detected_cms = []
        for cms, patterns in cms_indicators.items():
            for pat in patterns:
                if re.search(pat, html, re.IGNORECASE):
                    detected_cms.append(cms)
                    break

        if findings:
            output.append(colored("  ❌ Metadata with technology information:", "red"))
            for name, content in findings:
                output.append(colored(f"     {name}: {content}", "red"))

        if detected_cms:
            output.append(colored(
                f"  ❌ CMS/Framework detected in HTML: {', '.join(detected_cms)}", "red"))

        if findings or detected_cms:
            output.append("")
            output.append(colored(
                "  ⚠️  Exposed CMS/version metadata helps attackers fingerprint the", "yellow"))
            output.append(colored(
                "  technology stack and find version-specific vulnerabilities.", "yellow"))
        else:
            output.append(colored(
                "  ✅ No revealing metadata or CMS indicators found.", "green"))

    except Exception as e:
        output.append(colored(f"  ❌ Error: {e}", "red"))

    result_str = "\n".join(output)
    print(result_str)
    return result_str


# ---------------------------------------------------------------------------
# PT-WEB-32: Cleartext Transmission / Missing HTTPS Redirect
# ---------------------------------------------------------------------------

def check_cleartext(target_url, auth):
    """Check HTTP→HTTPS redirect and mixed content references."""
    print(colored(f"\n[+] Running Cleartext Transmission Check on {target_url}", "cyan"))
    output = []
    parsed = urlparse(target_url)
    hostname = parsed.netloc

    # Test 1: Does HTTP redirect to HTTPS?
    http_url = f"http://{hostname}{parsed.path or '/'}"
    try:
        resp = requests.get(http_url, allow_redirects=False,
                           timeout=10, headers={"User-Agent": UA})
        if resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get("Location", "")
            if location.startswith("https://"):
                if resp.status_code == 301:
                    output.append(colored(
                        f"  ✅ HTTP redirects to HTTPS (301 Permanent)", "green"))
                else:
                    output.append(colored(
                        f"  ⚠️  HTTP redirects to HTTPS but uses {resp.status_code} (not 301)", "yellow"))
                    output.append(colored(
                        "     Use 301 for permanent redirect so browsers cache it.", "yellow"))
            else:
                output.append(colored(
                    f"  ❌ HTTP redirects but NOT to HTTPS: {location}", "red"))
        elif resp.status_code == 200:
            output.append(colored(
                "  ❌ HTTP returns 200 without redirecting to HTTPS!", "red"))
            output.append(colored(
                "     Content is served over unencrypted HTTP.", "red"))
        else:
            output.append(colored(
                f"  ℹ️  HTTP returns status {resp.status_code}", "yellow"))
    except requests.exceptions.ConnectionError:
        output.append(colored(
            "  ℹ️  HTTP port not reachable (may be intentionally closed).", "yellow"))
    except Exception as e:
        output.append(colored(f"  ℹ️  HTTP check error: {e}", "yellow"))

    # Test 2: Check for mixed content in HTTPS page
    if parsed.scheme == "https" or target_url.startswith("https"):
        try:
            kw = requests_kwargs(auth)
            kw["allow_redirects"] = True
            resp = requests.get(target_url, **kw)
            # Find http:// references in src/href (excluding protocol-relative)
            mixed = re.findall(
                r'(?:src|href|action)=["\']http://[^"\']+["\']',
                resp.text, re.IGNORECASE
            )
            if mixed:
                output.append(colored(
                    f"  ❌ Mixed content: {len(mixed)} HTTP resource(s) on HTTPS page:", "red"))
                for m in mixed[:10]:
                    output.append(colored(f"     {m}", "red"))
                if len(mixed) > 10:
                    output.append(colored(
                        f"     ... and {len(mixed)-10} more", "red"))
            else:
                output.append(colored(
                    "  ✅ No mixed content (HTTP resources on HTTPS page) found.", "green"))
        except Exception as e:
            output.append(colored(f"  ℹ️  Mixed content check error: {e}", "yellow"))

    # Test 3: Check HSTS
    try:
        kw = requests_kwargs(auth)
        resp = requests.get(target_url, **kw)
        hsts = resp.headers.get("Strict-Transport-Security", "")
        if hsts:
            output.append(colored(f"  ✅ HSTS header present: {hsts}", "green"))
            if "includesubdomains" not in hsts.lower():
                output.append(colored(
                    "     ⚠️  Consider adding includeSubDomains", "yellow"))
            if "preload" not in hsts.lower():
                output.append(colored(
                    "     ℹ️  Consider adding preload for HSTS preload list", "yellow"))
        else:
            output.append(colored(
                "  ❌ No HSTS header — browsers won't enforce HTTPS on future visits.", "red"))
    except Exception:
        pass

    result_str = "\n".join(output)
    print(result_str)
    return result_str


# ---------------------------------------------------------------------------
# PT-WEB-35/36: SSL/TLS Configuration & Certificate Check
# ---------------------------------------------------------------------------

def check_ssl_tls(target_url, auth):
    """Check SSL/TLS protocol versions, cipher suites, and certificate issues."""
    print(colored(f"\n[+] Running SSL/TLS & Certificate Check on {target_url}", "cyan"))
    output = []
    parsed = urlparse(target_url)
    hostname = parsed.netloc.split(":")[0]
    port = parsed.port or 443

    # --- Certificate check via Python ssl ---
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()

                output.append(colored(f"  Protocol: {protocol}", "white"))
                output.append(colored(f"  Cipher: {cipher[0]} ({cipher[2]} bits)", "white"))

                # Expiry
                not_after = cert.get("notAfter", "")
                if not_after:
                    # Format: 'Dec 31 23:59:59 2025 GMT'
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    exp = exp.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (exp - now).days
                    if days_left < 0:
                        output.append(colored(
                            f"  ❌ Certificate EXPIRED {abs(days_left)} days ago!", "red"))
                    elif days_left < 30:
                        output.append(colored(
                            f"  ⚠️  Certificate expires in {days_left} days ({not_after})", "yellow"))
                    else:
                        output.append(colored(
                            f"  ✅ Certificate valid for {days_left} more days ({not_after})", "green"))

                # Subject / SAN
                subject = dict(x[0] for x in cert.get("subject", ()))
                cn = subject.get("commonName", "")
                san_list = []
                for san_type, san_val in cert.get("subjectAltName", ()):
                    san_list.append(san_val)

                output.append(colored(f"  CN: {cn}", "white"))
                if san_list:
                    output.append(colored(f"  SANs: {', '.join(san_list[:10])}", "white"))

                # CN/SAN mismatch
                all_names = [cn] + san_list
                hostname_matches = False
                for name in all_names:
                    if name == hostname:
                        hostname_matches = True
                    elif name.startswith("*.") and hostname.endswith(name[1:]):
                        hostname_matches = True
                if not hostname_matches:
                    output.append(colored(
                        f"  ❌ Hostname '{hostname}' does not match CN/SANs!", "red"))

                # Issuer
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                issuer_cn = issuer.get("commonName", "")
                issuer_org = issuer.get("organizationName", "")
                output.append(colored(f"  Issuer: {issuer_cn} ({issuer_org})", "white"))

                # Self-signed check
                if subject == issuer or issuer_cn == cn:
                    output.append(colored(
                        "  ❌ Certificate appears to be self-signed!", "red"))

    except ssl.SSLCertVerificationError as e:
        output.append(colored(f"  ❌ Certificate verification failed: {e}", "red"))
    except ssl.SSLError as e:
        output.append(colored(f"  ❌ SSL error: {e}", "red"))
    except Exception as e:
        output.append(colored(f"  ❌ Connection error: {e}", "red"))

    # --- Check for deprecated protocols via openssl ---
    deprecated = ["ssl3", "tls1", "tls1_1"]
    deprecated_labels = {"ssl3": "SSLv3", "tls1": "TLSv1.0", "tls1_1": "TLSv1.1"}
    for proto in deprecated:
        try:
            cmd = [
                "openssl", "s_client", f"-{proto}",
                "-connect", f"{hostname}:{port}",
                "-servername", hostname,
            ]
            proc = subprocess.run(
                cmd, input="", capture_output=True, text=True, timeout=10
            )
            combined = proc.stdout + proc.stderr
            if "CONNECTED" in combined and "error" not in combined.lower():
                output.append(colored(
                    f"  ❌ Deprecated protocol {deprecated_labels[proto]} is supported!", "red"))
            # If openssl itself errors, the protocol is not supported -- good
        except FileNotFoundError:
            output.append(colored("  ℹ️  openssl not found, skipping protocol checks", "yellow"))
            break
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

    result_str = "\n".join(output)
    print(result_str)
    return result_str


# ---------------------------------------------------------------------------
# PT-WEB-38: JWT Configuration Check
# ---------------------------------------------------------------------------

def check_jwt(target_url, auth):
    """Analyze JWT token (from --token) for misconfigurations."""
    print(colored(f"\n[+] Running JWT Configuration Check", "cyan"))
    output = []

    token = auth.get("token", "")
    if not token:
        output.append(colored(
            "  ℹ️  No --token provided, skipping JWT analysis.", "yellow"))
        output.append(colored(
            "  Use --token <JWT> to analyze a JWT.", "yellow"))
        result_str = "\n".join(output)
        print(result_str)
        return result_str

    parts = token.split(".")
    if len(parts) < 2:
        output.append(colored("  ❌ Token does not look like a JWT (expected 3 dot-separated parts).", "red"))
        result_str = "\n".join(output)
        print(result_str)
        return result_str

    # Decode header
    try:
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        output.append(colored(f"  JWT Header: {json.dumps(header, indent=2)}", "white"))
    except Exception:
        output.append(colored("  ❌ Failed to decode JWT header.", "red"))
        result_str = "\n".join(output)
        print(result_str)
        return result_str

    # Decode payload
    try:
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        # Redact sensitive fields for display
        display_payload = {k: v for k, v in payload.items()}
        output.append(colored(f"  JWT Payload: {json.dumps(display_payload, indent=2)}", "white"))
    except Exception:
        output.append(colored("  ❌ Failed to decode JWT payload.", "red"))
        payload = {}

    output.append("")

    # Check algorithm
    alg = header.get("alg", "").upper()
    if alg == "NONE":
        output.append(colored(
            "  ❌ CRITICAL: Algorithm is 'none' — JWT signature is not verified!", "red"))
        output.append(colored(
            "     An attacker can forge any token by setting alg:none and removing", "red"))
        output.append(colored(
            "     the signature. This is a critical authentication bypass.", "red"))
    elif alg in ("HS256", "HS384", "HS512"):
        output.append(colored(
            f"  ⚠️  Symmetric algorithm ({alg}) — the server uses a shared secret.", "yellow"))
        output.append(colored(
            "     If the secret is weak, it can be brute-forced (e.g., jwt_tool, hashcat).", "yellow"))
        output.append(colored(
            "     Consider RSA/ECDSA (RS256/ES256) for better key management.", "yellow"))
    elif alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EDDSA"):
        output.append(colored(f"  ✅ Asymmetric algorithm ({alg})", "green"))
    else:
        output.append(colored(f"  ⚠️  Uncommon algorithm: {alg}", "yellow"))

    # Check for missing exp
    if "exp" not in payload:
        output.append(colored(
            "  ❌ Missing 'exp' (expiration) claim — token never expires!", "red"))
        output.append(colored(
            "     Stolen tokens remain valid indefinitely.", "red"))
    else:
        try:
            exp_time = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
            now = datetime.now(timezone.utc)
            if exp_time < now:
                output.append(colored(
                    f"  ⚠️  Token is expired (exp: {exp_time.isoformat()})", "yellow"))
            else:
                delta = exp_time - now
                output.append(colored(
                    f"  ✅ Token expires in {delta.days}d {delta.seconds//3600}h (exp: {exp_time.isoformat()})", "green"))
                if delta.days > 30:
                    output.append(colored(
                        "     ⚠️  Very long expiration — consider shorter token lifetime.", "yellow"))
        except Exception:
            pass

    # Check for missing iat
    if "iat" not in payload:
        output.append(colored(
            "  ⚠️  Missing 'iat' (issued at) claim — cannot determine token age.", "yellow"))

    # Check for missing sub/iss
    if "iss" not in payload:
        output.append(colored(
            "  ⚠️  Missing 'iss' (issuer) claim.", "yellow"))
    if "sub" not in payload:
        output.append(colored(
            "  ⚠️  Missing 'sub' (subject) claim.", "yellow"))

    # Check header for kid/jku/jwk
    if "jku" in header:
        output.append(colored(
            f"  ⚠️  'jku' header present: {header['jku']}", "yellow"))
        output.append(colored(
            "     If the server fetches keys from this URL, an attacker may be able", "yellow"))
        output.append(colored(
            "     to supply their own public key via SSRF or DNS rebinding.", "yellow"))
    if "jwk" in header:
        output.append(colored(
            "  ⚠️  Embedded 'jwk' in header — the server may trust attacker-supplied keys.", "yellow"))

    output.append("")
    output.append(colored(
        "  Ref: https://portswigger.net/web-security/jwt", "cyan"))

    result_str = "\n".join(output)
    print(result_str)
    return result_str


# ---------------------------------------------------------------------------
# PT-WEB-48: Directory Listing
# ---------------------------------------------------------------------------

def check_dir_listing(target_url, auth):
    """Probe common directories for directory listing."""
    print(colored(f"\n[+] Running Directory Listing Check on {target_url}", "cyan"))
    output = []
    test_paths = [
        "/icons/", "/images/", "/img/", "/css/", "/js/", "/assets/",
        "/uploads/", "/media/", "/static/", "/backup/", "/tmp/",
        "/files/", "/docs/", "/data/", "/logs/",
    ]

    listings_found = []
    try:
        for path in test_paths:
            url = urljoin(target_url, path)
            kw = requests_kwargs(auth)
            kw["allow_redirects"] = True
            try:
                resp = requests.get(url, **kw)
                if resp.status_code == 200:
                    lower_body = resp.text.lower()
                    if ("index of" in lower_body or
                        "<title>directory listing" in lower_body or
                        'class="icon"' in lower_body and "parent directory" in lower_body):
                        listings_found.append(url)
            except Exception:
                continue

    except Exception as e:
        output.append(colored(f"  ❌ Error: {e}", "red"))

    if listings_found:
        output.append(colored("  ❌ Directory listing enabled:", "red"))
        for url in listings_found:
            output.append(colored(f"     {url}", "red"))
        output.append("")
        output.append(colored(
            "  ⚠️  Directory listing exposes file names, backup files, and internal", "yellow"))
        output.append(colored(
            "  structure. Disable it in the web server configuration.", "yellow"))
    else:
        output.append(colored(
            "  ✅ No directory listings found on common paths.", "green"))

    result_str = "\n".join(output)
    print(result_str)
    return result_str


# ---------------------------------------------------------------------------
# PT-WEB-68: Default Web Pages
# ---------------------------------------------------------------------------

DEFAULT_SIGNATURES = {
    "Apache": [
        "Apache2 Debian Default Page",
        "Apache2 Ubuntu Default Page",
        "It works!",
        "Apache HTTP Server Test Page",
    ],
    "Nginx": [
        "Welcome to nginx!",
        "If you see this page, the nginx web server is successfully installed",
    ],
    "IIS": [
        "IIS Windows Server",
        "Internet Information Services",
        "Microsoft Internet Information Services",
    ],
    "Tomcat": [
        "Apache Tomcat",
        "If you're seeing this, you've successfully installed Tomcat",
    ],
    "Node.js/Express": [
        "Express",
        "Cannot GET /",
    ],
    "Laravel": [
        "Laravel",
    ],
}

def check_default_pages(target_url, auth):
    """Check if the site shows a default web server page."""
    print(colored(f"\n[+] Running Default Page Detection on {target_url}", "cyan"))
    output = []
    try:
        kw = requests_kwargs(auth)
        kw["allow_redirects"] = True
        resp = requests.get(target_url, **kw)
        body = resp.text
        title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip() if title_match else ""

        detected = []
        for server, signatures in DEFAULT_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in body.lower() or sig.lower() in title.lower():
                    detected.append((server, sig))
                    break

        if detected:
            for server, sig in detected:
                output.append(colored(
                    f"  ❌ Default {server} page detected (matched: '{sig}')", "red"))
            output.append("")
            output.append(colored(
                "  ⚠️  Default pages reveal the web server type and confirm default", "yellow"))
            output.append(colored(
                "  configuration. Replace with a custom page or return 404.", "yellow"))
        else:
            output.append(colored(
                "  ✅ No default web server pages detected.", "green"))

    except Exception as e:
        output.append(colored(f"  ❌ Error: {e}", "red"))

    result_str = "\n".join(output)
    print(result_str)
    return result_str


# ---------------------------------------------------------------------------
# PT-WEB-70: Host Header Injection
# ---------------------------------------------------------------------------

def check_host_injection(target_url, auth):
    """Send modified Host header and check for reflection."""
    print(colored(f"\n[+] Running Host Header Injection Check on {target_url}", "cyan"))
    output = []
    parsed = urlparse(target_url)
    evil_host = "evil.sitemole-test.com"

    try:
        # Test 1: Replace Host header
        kw = requests_kwargs(auth)
        kw["headers"]["Host"] = evil_host
        kw["allow_redirects"] = False
        resp = requests.get(target_url, **kw)

        # Check if evil host is reflected in response headers or body
        reflected_in_headers = False
        reflected_in_body = False

        for hdr, val in resp.headers.items():
            if evil_host in val.lower():
                reflected_in_headers = True
                output.append(colored(
                    f"  ❌ Evil Host reflected in header: {hdr}: {val}", "red"))

        if evil_host in resp.text.lower():
            reflected_in_body = True
            output.append(colored(
                "  ❌ Evil Host reflected in response body!", "red"))

        location = resp.headers.get("Location", "")
        if evil_host in location.lower():
            output.append(colored(
                f"  ❌ Evil Host reflected in redirect Location: {location}", "red"))

        # Test 2: X-Forwarded-Host
        kw2 = requests_kwargs(auth)
        kw2["headers"]["X-Forwarded-Host"] = evil_host
        kw2["allow_redirects"] = False
        resp2 = requests.get(target_url, **kw2)

        for hdr, val in resp2.headers.items():
            if evil_host in val.lower():
                output.append(colored(
                    f"  ❌ X-Forwarded-Host reflected in header: {hdr}: {val}", "red"))

        if evil_host in resp2.text.lower():
            output.append(colored(
                "  ❌ X-Forwarded-Host reflected in response body!", "red"))

        if reflected_in_headers or reflected_in_body:
            output.append("")
            output.append(colored(
                "  ⚠️  Host header injection can lead to:", "yellow"))
            output.append(colored(
                "  - Password reset poisoning (reset links with attacker domain)", "yellow"))
            output.append(colored(
                "  - Cache poisoning (serving attacker content from cache)", "yellow"))
            output.append(colored(
                "  - SSRF via routing manipulation", "yellow"))
            output.append(colored(
                "  Ref: https://portswigger.net/web-security/host-header", "cyan"))
        elif not output:
            output.append(colored(
                "  ✅ No Host header injection detected.", "green"))

    except Exception as e:
        output.append(colored(f"  ❌ Error: {e}", "red"))

    result_str = "\n".join(output)
    print(result_str)
    return result_str


# ---------------------------------------------------------------------------
# PT-WEB-76: Source Code / Sensitive File Disclosure
# ---------------------------------------------------------------------------

SENSITIVE_PATHS = [
    ("/.git/HEAD", "Git repository", "ref: refs/"),
    ("/.git/config", "Git config", "[core]"),
    ("/.env", "Environment file", None),  # any 200 is a finding
    ("/.svn/entries", "SVN metadata", None),
    ("/web.config", "IIS web.config", "<configuration"),
    ("/WEB-INF/web.xml", "Java WEB-INF", "<web-app"),
    ("/.htaccess", "Apache .htaccess", None),
    ("/.htpasswd", "Apache .htpasswd", None),
    ("/crossdomain.xml", "Flash crossdomain", "<cross-domain-policy"),
    ("/phpinfo.php", "PHP info page", "phpinfo()"),
    ("/info.php", "PHP info page", "phpinfo()"),
    ("/server-status", "Apache server-status", "Apache Server Status"),
    ("/server-info", "Apache server-info", "Apache Server Information"),
    ("/.DS_Store", "macOS DS_Store", None),
    ("/robots.txt", "Robots.txt", None),
    ("/sitemap.xml", "Sitemap", None),
]

BACKUP_EXTENSIONS = [".bak", ".old", ".orig", ".save", ".swp", "~", ".copy", ".tmp"]

def check_source_disclosure(target_url, auth):
    """Check for exposed sensitive files and source code."""
    print(colored(f"\n[+] Running Source Code / Sensitive File Disclosure Check on {target_url}", "cyan"))
    output = []
    findings = []

    for path, description, signature in SENSITIVE_PATHS:
        url = urljoin(target_url, path)
        try:
            kw = requests_kwargs(auth)
            kw["allow_redirects"] = False
            resp = requests.get(url, **kw)
            if resp.status_code == 200:
                body = resp.text[:2000]
                # Avoid false positives: custom 404 pages
                if "404" in body.lower() and "not found" in body.lower():
                    continue
                if signature:
                    if signature.lower() in body.lower():
                        findings.append((path, description))
                else:
                    # For files like .env, any 200 with content is suspicious
                    if len(body.strip()) > 0:
                        findings.append((path, description))
        except Exception:
            continue

    # Check for backup files of common pages
    base_pages = ["/index.php", "/index.html", "/config.php",
                  "/wp-config.php", "/configuration.php", "/settings.py"]
    for page in base_pages:
        for ext in BACKUP_EXTENSIONS[:3]:  # Limit checks
            bak_url = urljoin(target_url, page + ext)
            try:
                kw = requests_kwargs(auth)
                kw["allow_redirects"] = False
                resp = requests.get(bak_url, **kw)
                if resp.status_code == 200 and len(resp.text.strip()) > 10:
                    if "404" not in resp.text.lower()[:500]:
                        findings.append((page + ext, f"Backup of {page}"))
            except Exception:
                continue

    if findings:
        output.append(colored("  ❌ Sensitive / source files accessible:", "red"))
        for path, desc in findings:
            output.append(colored(f"     {path}  ({desc})", "red"))
        output.append("")
        output.append(colored(
            "  ⚠️  Exposed source files, configs and backups can reveal:", "yellow"))
        output.append(colored(
            "  - Database credentials, API keys, secrets (.env, config files)", "yellow"))
        output.append(colored(
            "  - Full source code allowing code review for vulns (.git)", "yellow"))
        output.append(colored(
            "  - Internal paths and server architecture", "yellow"))
        output.append(colored(
            "  Block access to these paths in the web server config.", "yellow"))
    else:
        output.append(colored(
            "  ✅ No exposed sensitive files found on common paths.", "green"))

    result_str = "\n".join(output)
    print(result_str)
    return result_str


# ---------------------------------------------------------------------------
# GDPR: Google Fonts / External Font Check
# ---------------------------------------------------------------------------

EXTERNAL_FONT_DOMAINS = [
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "use.typekit.net",
    "fast.fonts.net",
    "cloud.typography.com",
    "use.fontawesome.com",       # FA from CDN can also transfer IPs
    "kit.fontawesome.com",
]

def check_google_fonts(target_url, auth):
    """Check if Google Fonts or other external font services are loaded
    directly from third-party servers, which transfers the visitor's IP
    address to that third party without consent (GDPR violation per
    LG München, Az. 3 O 17493/20)."""
    print(colored(f"\n[+] Running GDPR Google Fonts / External Font Check on {target_url}", "cyan"))
    output = []

    try:
        # Fetch page HTML
        kw = requests_kwargs(auth)
        kw["allow_redirects"] = True
        resp = requests.get(target_url, **kw)
        html = resp.text

        findings = []

        # 1) Check <link> tags for external font stylesheets
        link_tags = re.findall(r'<link[^>]*>', html, re.IGNORECASE)
        for tag in link_tags:
            href_match = re.search(r'href=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            if not href_match:
                continue
            href = href_match.group(1)
            for domain in EXTERNAL_FONT_DOMAINS:
                if domain in href.lower():
                    findings.append(("link", domain, href))

        # 2) Check @import and @font-face in inline <style> blocks
        style_blocks = re.findall(r'<style[^>]*>(.*?)</style>', html, re.IGNORECASE | re.DOTALL)
        for block in style_blocks:
            for domain in EXTERNAL_FONT_DOMAINS:
                urls_in_css = re.findall(r'url\(["\']?([^"\')\s]+)["\']?\)', block)
                imports = re.findall(r'@import\s+["\']([^"\']+)["\']', block)
                for url in urls_in_css + imports:
                    if domain in url.lower():
                        findings.append(("css-inline", domain, url))

        # 3) Check for JS-based font loading (e.g., WebFont.load, google fonts API)
        script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL)
        for block in script_blocks:
            for domain in EXTERNAL_FONT_DOMAINS:
                if domain in block.lower():
                    findings.append(("javascript", domain, f"(referenced in inline script)"))

        # 4) Check external script src for font loaders
        script_srcs = re.findall(r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE)
        for src in script_srcs:
            for domain in EXTERNAL_FONT_DOMAINS:
                if domain in src.lower():
                    findings.append(("script-src", domain, src))

        # Deduplicate
        findings = list(set(findings))

        if findings:
            # Separate Google Fonts from other providers
            google_findings = [f for f in findings if "google" in f[1] or "gstatic" in f[1]]
            other_findings = [f for f in findings if f not in google_findings]

            if google_findings:
                output.append(colored(
                    "  ❌ GOOGLE FONTS loaded from external Google servers!", "red"))
                output.append("")
                for ftype, domain, url in google_findings:
                    truncated = url if len(url) < 120 else url[:117] + "..."
                    output.append(colored(f"     [{ftype}] {domain}", "red"))
                    output.append(colored(f"       {truncated}", "red"))
                output.append("")
                output.append(colored(
                    "  ⚠️  GDPR VIOLATION: Loading Google Fonts from fonts.googleapis.com", "yellow"))
                output.append(colored(
                    "  or fonts.gstatic.com transfers the visitor's IP address to Google", "yellow"))
                output.append(colored(
                    "  (a US company) without prior consent. The Munich Regional Court", "yellow"))
                output.append(colored(
                    "  ruled this a violation of GDPR Art. 6(1) and awarded damages", "yellow"))
                output.append(colored(
                    "  (LG München I, Az. 3 O 17493/20, Jan 2022).", "yellow"))
                output.append("")
                output.append(colored(
                    "  Recommendation: Self-host the font files on your own server.", "cyan"))
                output.append(colored(
                    "  Download fonts via https://gwfh.mranftl.com/fonts or the", "cyan"))
                output.append(colored(
                    "  google-webfonts-helper, then serve them from your domain.", "cyan"))
                output.append(colored(
                    "  Replace the <link href=\"fonts.googleapis.com/...\"> with a", "cyan"))
                output.append(colored(
                    "  local @font-face declaration in your CSS.", "cyan"))
                output.append(colored(
                    "  Ref: https://rewis.io/urteile/urt/lhm-20-01-2022-3-o-1749320/", "cyan"))

            if other_findings:
                output.append("")
                output.append(colored(
                    "  ⚠️  Other external font services detected:", "yellow"))
                for ftype, domain, url in other_findings:
                    truncated = url if len(url) < 120 else url[:117] + "..."
                    output.append(colored(f"     [{ftype}] {domain}", "yellow"))
                    output.append(colored(f"       {truncated}", "yellow"))
                output.append("")
                output.append(colored(
                    "  Any external font CDN transfers the visitor's IP address to a", "yellow"))
                output.append(colored(
                    "  third party. Under GDPR this requires a legal basis (consent or", "yellow"))
                output.append(colored(
                    "  legitimate interest). Self-hosting is the safest option.", "yellow"))
        else:
            output.append(colored(
                "  ✅ No external Google Fonts or third-party font CDN references found.", "green"))

    except Exception as e:
        output.append(colored(f"  ❌ Error: {e}", "red"))

    result_str = "\n".join(output)
    print(result_str)
    return result_str


# ---------------------------------------------------------------------------
# Module dispatch
# ---------------------------------------------------------------------------

MODULE_MAP = {
    "comments": extract_comments,
    "sri": sri_checker,
    "links": extract_links,
    "images": extract_images,
    "headers": analyze_headers,
    "cookies": check_cookies,
    "version": check_version_info,
    "cors": check_cors,
    "methods": check_http_methods,
    "ips": check_internal_ips,
    "autocomplete": check_autocomplete,
    "metadata": check_metadata,
    "cleartext": check_cleartext,
    "ssl": check_ssl_tls,
    "jwt": check_jwt,
    "dirlist": check_dir_listing,
    "defaults": check_default_pages,
    "hostinject": check_host_injection,
    "disclosure": check_source_disclosure,
    "fonts": check_google_fonts,
}

def resolve_target(target_url):
    """Resolve hostname to IP for display."""
    try:
        hostname = urlparse(target_url).netloc.split(":")[0]
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception:
        return "unresolved"


def print_module_banner(module_label, target_url, resolved_ip):
    """Print a consistent banner before each module run."""
    print(colored(f"\n{'='*70}", "cyan"))
    print(colored(f"  Module : {module_label}", "cyan"))
    print(colored(f"  Target : {target_url}", "cyan"))
    print(colored(f"  IP     : {resolved_ip}", "cyan"))
    print(colored(f"{'='*70}", "cyan"))


def run_module(module_name, targets, auth):
    """Run a single module against all targets."""
    func = MODULE_MAP.get(module_name)
    if not func:
        return []
    results = []
    for url in targets:
        resolved_ip = resolve_target(url)
        print_module_banner(module_name, url, resolved_ip)
        results.append(f"\n{'='*70}\n TARGET: {url} ({resolved_ip})\n{'='*70}")
        results.append(func(url, auth))
    return results

def run_all_modules(targets, auth, output_file="results.txt"):
    """Run every module against all targets and save to file."""
    print(f"\n[+] Running all modules against {len(targets)} target(s), saving to {output_file}")
    all_modules_ordered = [
        ("Cleartext / HTTPS Redirect", check_cleartext),
        ("SSL/TLS & Certificate", check_ssl_tls),
        ("Header Analysis", analyze_headers),
        ("Cookie Analysis", check_cookies),
        ("Version Info Disclosure", check_version_info),
        ("CORS Configuration", check_cors),
        ("HTTP Methods", check_http_methods),
        ("Internal IP Disclosure", check_internal_ips),
        ("Host Header Injection", check_host_injection),
        ("JWT Configuration", check_jwt),
        ("Metadata Extraction", check_metadata),
        ("Default Pages", check_default_pages),
        ("Autocomplete Check", check_autocomplete),
        ("Directory Listing", check_dir_listing),
        ("Source Code / Sensitive Files", check_source_disclosure),
        ("GDPR Google Fonts / External Fonts", check_google_fonts),
        ("Comments Extractor", extract_comments),
        ("SRI Checker", sri_checker),
        ("Link Extractor", extract_links),
        ("Image Scraper", extract_images),
    ]
    results = []
    for url in targets:
        resolved_ip = resolve_target(url)
        results.append(f"\n{'#'*70}\n# TARGET: {url} ({resolved_ip})\n{'#'*70}")
        for label, func in all_modules_ordered:
            print_module_banner(label, url, resolved_ip)
            results.append(f"\n===== {label} =====")
            results.append(func(url, auth))

    file_path = os.path.join(os.getcwd(), output_file)
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(str(r) for r in results))
        print(colored(f"[+] Results saved to {file_path}", "green"))
    except Exception as e:
        print(colored(f"❌ Failed to write results to file: {e}", "red"))

# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

def select_module():
    while True:
        print("\n🤔 Select a module:\n")
        print(colored("--- Reconnaissance ---", "cyan"))
        print(" 1) Comments Extractor")
        print(" 2) SRI Checker")
        print(" 3) Link Extractor")
        print(" 4) Image Scraper")
        print(" 5) Metadata Extraction (CMS, generator, author)")
        print(colored("--- Security Headers & Cookies ---", "cyan"))
        print(" 6) Header Analysis (presence + CSP + X-XSS-Protection)")
        print(" 7) Cookie Analysis (Flags + BigIP Decode)")
        print(" 8) Version Info Disclosure (Server, X-Powered-By, ...)")
        print(colored("--- Configuration & Crypto ---", "cyan"))
        print("10) Cleartext / HTTPS Redirect + HSTS")
        print("11) SSL/TLS & Certificate Check")
        print("12) CORS Configuration")
        print("13) HTTP Methods (OPTIONS + TRACE)")
        print("14) JWT Configuration (requires --token)")
        print(colored("--- Information Disclosure ---", "cyan"))
        print("15) Internal IP Address Disclosure")
        print("16) Host Header Injection")
        print("17) Source Code / Sensitive File Disclosure")
        print("18) Directory Listing")
        print("19) Default Web Pages")
        print("20) Autocomplete on Sensitive Fields")
        print(colored("--- GDPR / Privacy ---", "cyan"))
        print("21) Google Fonts / External Font CDN (GDPR)")
        print(colored("--- Batch ---", "cyan"))
        print("99) Run All Modules and Save to File")
        print(" 0) Exit")
        choice = input("\nChoose a module: ").strip()
        modules = {
            "1": "comments", "2": "sri", "3": "links", "4": "images",
            "5": "metadata", "6": "headers", "7": "cookies", "8": "version",
            "10": "cleartext", "11": "ssl", "12": "cors", "13": "methods",
            "14": "jwt", "15": "ips", "16": "hostinject",
            "17": "disclosure", "18": "dirlist", "19": "defaults",
            "20": "autocomplete",
            "21": "fonts",
            "99": "all", "0": "exit"
        }
        selected = modules.get(choice, None)
        if selected:
            return selected
        else:
            print("❌ Invalid choice! Please try again.")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SiteMole - Web Reconnaissance Tool",
        epilog="""\
Available modules (-m):

  Reconnaissance:
    comments      Extract HTML comments (<!-- ... -->)
    sri           Check Subresource Integrity on external JS/CSS
    links         Extract all href links from the page
    images        Extract all image URLs (jpg, png, gif, svg)
    metadata      Extract HTML meta tags (generator, author, CMS detection)

  Security Headers & Cookies:
    headers       Full header analysis (presence check + CSP deep-dive + X-XSS-Protection)
    cookies       Cookie flag check (Secure, HttpOnly, SameSite) + F5 BigIP decode
    version       Version info disclosure (Server, X-Powered-By, X-AspNet-Version, ...)

  Configuration & Crypto:
    cleartext     HTTP-to-HTTPS redirect check, mixed content, HSTS validation
    ssl           SSL/TLS protocol versions, cipher suite, certificate expiry/CN/SAN/chain
    cors          CORS misconfiguration (wildcard, origin reflection, null origin)
    methods       HTTP method enumeration via OPTIONS + direct TRACE check
    jwt           JWT token analysis (alg:none, weak algos, missing exp/iat/iss)

  Information Disclosure:
    ips           Internal (RFC1918) IP addresses in headers and response body
    hostinject    Host header injection (reflection in headers, body, redirects)
    disclosure    Sensitive file exposure (.git, .env, .svn, web.config, backups, ...)
    dirlist       Directory listing on common paths (/icons/, /uploads/, /backup/, ...)
    defaults      Default web server pages (Apache, Nginx, IIS, Tomcat)
    autocomplete  Missing autocomplete=off on password / login fields

  GDPR / Privacy:
    fonts         Google Fonts & external font CDN check (GDPR Art. 6, LG München)

  Batch:
    all           Run ALL modules and save results to file (-o)

Examples:
  python sitemole.py -t https://example.com -m headers
  python sitemole.py -l targets.txt -m all -o report.txt
  python sitemole.py -t https://app.example.com -c 'PHPSESSID=abc123def' -m all
  python sitemole.py -t https://api.example.com --token eyJhbGciOi... -m jwt
  python sitemole.py -t https://target.com -m cookies       # BigIP decode + cookie flags
  python sitemole.py -t https://target.com -m ssl           # SSL/TLS + cert check
  python sitemole.py -t https://target.com -m cors          # CORS misconfiguration
  python sitemole.py -t https://target.com -m disclosure    # .git, .env, backups
  python sitemole.py -t https://target.com -m version       # Server/X-Powered-By leaks
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-t", "--target", help="Single target URL (e.g., https://example.com)")
    parser.add_argument("-l", "--list", dest="list_file", help="File containing target URLs, one per line")
    all_modules = list(MODULE_MAP.keys()) + ["all"]
    parser.add_argument("-m", "--module", choices=all_modules,
                        help="Module to run")
    parser.add_argument("-o", "--output", default="results.txt",
                        help="Output file for 'all' module (default: results.txt)")
    parser.add_argument("-c", "--cookie",
                        help="Cookie string to send with requests (e.g., 'PHPSESSID=abc123' or 'name=val; name2=val2')")
    parser.add_argument("--token",
                        help="Bearer / JWT token to send as Authorization header")
    args = parser.parse_args()

    display_banner()

    if args.target and args.list_file:
        print(colored("❌ Use either -t (single target) or -l (list file), not both.", "red"))
        exit(1)

    # Build auth config
    auth = build_auth(cookie_str=args.cookie, token=args.token)

    # Load targets
    targets = load_targets(target=args.target, list_file=args.list_file)

    # If no targets yet (interactive mode), ask for input
    if not targets:
        print("Provide a target:")
        print("  1) Single URL")
        print("  2) File with URL list")
        choice = input("Choice (1/2): ").strip()
        if choice == "2":
            list_file = input("Enter path to URL list file: ").strip()
            targets = load_targets(list_file=list_file)
        else:
            url = input("Enter target URL: ").strip()
            targets = [url]

    print(colored(f"\n[*] {len(targets)} target(s) loaded.", "cyan"))
    for i, t in enumerate(targets, 1):
        print(f"    {i}. {t}")
    print_auth_info(auth)

    # CLI mode with module specified
    if args.module:
        if args.module == "all":
            run_all_modules(targets, auth, output_file=args.output)
        else:
            run_module(args.module, targets, auth)
        print("\nExiting SiteMole. Goodbye!\n")
        exit(0)

    # Interactive mode
    while True:
        selected = select_module()
        if selected == "exit":
            print("Exiting SiteMole. Goodbye!")
            break
        if selected == "all":
            run_all_modules(targets, auth, output_file=args.output)
        else:
            run_module(selected, targets, auth)
        print("\nReturning to menu...\n")

if __name__ == "__main__":
    main()
