import requests
import re
from urllib.parse import quote
import html
from tqdm import tqdm
import sys

# Define XSS patterns to look for in responses
XSS_PATTERNS = [
    '<script>',
    '</script>',
    'javascript:',
    'eval(',
    'alert(',
    'document.cookie',
    'document.write(',
    'onload=',
    'onerror=',
    'src=',
    'data:text/html'
]


# Define encoding functions
def url_encode(payload):
    return quote(payload)


def html_encode(payload):
    return html.escape(payload)


def double_encode(payload):
    return quote(quote(payload))


def unicode_encode(payload):
    return ''.join(f'\\u{ord(c):04x}' for c in payload)


# Function to load payloads from a file
def load_payloads(file_path):
    try:
        with open(file_path, 'r') as file:
            payloads = file.read().splitlines()
        return payloads
    except IOError as e:
        print(f"Error loading payloads: {e}")
        return []


# Function to send HTTP request with a payload and optional cookies
def send_request(url, param, payload, cookies=None):
    try:
        if cookies:
            cookie_header = "; ".join(f"{key}={value}" for key, value in cookies.items())
            headers = {'Cookie': cookie_header}
        else:
            headers = {}

        full_url = f"{url}?{param}={payload}"
        response = requests.get(full_url, headers=headers)
        return response
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return None


# Function to check if payload is reflected in response
def is_payload_reflected(response, payload):
    if response is None:
        return False
    return any(pattern in response.text for pattern in XSS_PATTERNS)


# Function to detect WAF
def detect_waf(response):
    if response is None:
        return None

    status_code = response.status_code
    headers = response.headers
    body = response.text.lower()

    if status_code in [403, 406, 429]:
        return "Generic WAF"

    if any(header_name.lower().find("waf") != -1 for header_name in headers) or \
            any(header_value.lower().find("waf") != -1 for header_value in headers.values()):
        return "Generic WAF"

    if any(header_name.lower().find("x-sucuri-id") != -1 for header_name in headers) or \
            any(header_value.lower().find("sucuri") != -1 for header_value in headers.values()):
        return "Sucuri WAF"

    if any(header_name.lower().find("x-cdn") != -1 and "imperva" in header_value.lower() for header_name, header_value
           in headers.items()):
        return "Imperva Incapsula WAF"

    if any(header_name.lower().find("x-cdn") != -1 and "cloudflare" in header_value.lower() for
           header_name, header_value in headers.items()):
        return "Cloudflare WAF"

    if any(header_name.lower().find("server") != -1 and "cloudflare" in header_value.lower() for
           header_name, header_value in headers.items()):
        return "Cloudflare WAF"

    if any(header_name.lower().find("x-distil") != -1 for header_name in headers) or \
            any(header_value.lower().find("distil") != -1 for header_value in headers.values()):
        return "Distil WAF"

    if any(header_name.lower().find("x-akamai") != -1 for header_name in headers) or \
            any(header_value.lower().find("akamai") != -1 for header_value in headers.values()):
        return "Akamai WAF"

    if any(header_name.lower().find("x-barracuda") != -1 for header_name in headers) or \
            any(header_value.lower().find("barracuda") != -1 for header_value in headers.values()):
        return "Barracuda WAF"

    if any(header_name.lower().find("x-citrix") != -1 for header_name in headers) or \
            any(header_value.lower().find("citrix") != -1 for header_value in headers.values()):
        return "Citrix WAF"

    if any(header_name.lower().find("x-f5") != -1 for header_name in headers) or \
            any(header_value.lower().find("f5") != -1 for header_value in headers.values()):
        return "F5 BIG-IP WAF"

    if any(header_name.lower().find("x-dosarrest") != -1 for header_name in headers) or \
            any(header_value.lower().find("dosarrest") != -1 for header_value in headers.values()):
        return "DOSarrest WAF"

    if "access denied" in body or "blocked by waf" in body or "request rejected" in body:
        return "Generic WAF"

    if "firewall" in body:
        if "modsecurity" in body:
            return "ModSecurity WAF"
        if "application firewall" in body:
            return "Generic WAF"

    if "forbidden" in body or "security incident" in body:
        return "Generic WAF"

    if "cloudflare" in body:
        return "Cloudflare WAF"

    if "sucuri" in body:
        return "Sucuri WAF"

    if "imperva" in body:
        return "Imperva Incapsula WAF"

    if "akamai" in body:
        return "Akamai WAF"

    if "radware" in body:
        return "Radware WAF"

    if "denylist" in body or "blacklist" in body:
        return "Generic WAF"

    if "attack detected" in body:
        return "Generic WAF"

    return None


# Function to determine allowed and disallowed characters
def determine_allowed_characters(url, params, cookies):
    allowed_chars = set()
    disallowed_chars = set()
    all_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ")

    print("Determining allowed and disallowed characters...")
    for char in tqdm(all_chars, desc="Checking Characters"):
        payload = char
        for param in params:
            response = send_request(url, param, payload, cookies)
            if response is None:
                continue

            if is_payload_reflected(response, payload):
                allowed_chars.add(char)
            else:
                disallowed_chars.add(char)

    return allowed_chars, disallowed_chars


# Function to test encoding methods for disallowed characters
def test_encoding_for_disallowed_chars(url, params, disallowed_chars, cookies):
    encoding_methods = {
        'URL Encoding': url_encode,
        'HTML Encoding': html_encode,
        'Double Encoding': double_encode,
        'Unicode Encoding': unicode_encode
    }

    print("Testing encoding methods for disallowed characters...")
    for char in tqdm(disallowed_chars, desc="Encoding Characters"):
        for method_name, encoding_function in encoding_methods.items():
            encoded_char = encoding_function(char)
            payload = encoded_char
            for param in params:
                response = send_request(url, param, payload, cookies)
                if response is None:
                    continue

                if is_payload_reflected(response, payload):
                    print(f"Disallowed character '{char}' (encoded with {method_name}) was reflected in the response.")
                    break


# Function to adaptively test XSS payloads
def test_xss_adaptive(url, params, cookies):
    # Load payloads from file
    payloads = load_payloads('payloads.txt')

    # Determine allowed and disallowed characters
    allowed_chars, disallowed_chars = determine_allowed_characters(url, params, cookies)

    print(f"Allowed Characters: {allowed_chars}")
    print(f"Disallowed Characters: {disallowed_chars}")

    # Test encoding methods for disallowed characters
    test_encoding_for_disallowed_chars(url, params, disallowed_chars, cookies)

    issues = []
    observed_payloads = set()

    print("Testing XSS payloads...")
    for payload in tqdm(payloads, desc="Testing Payloads"):
        for param in params:
            response = send_request(url, param, payload, cookies)
            if response is None:
                continue

            if is_payload_reflected(response, payload):
                issues.append({
                    'url': url,
                    'payload': payload,
                    'issue': "Potential XSS found with payload: " + payload
                })
                observed_payloads.add(payload)
                break

        if not issues:
            waf_type = detect_waf(response)
            if waf_type:
                for payload in tqdm(payloads, desc="Testing WAF Bypass Payloads"):
                    response = send_request(url, param, payload, cookies)
                    if response is None:
                        continue

                    if is_payload_reflected(response, payload):
                        issues.append({
                            'url': url,
                            'payload': payload,
                            'issue': f"Potential XSS found with WAF bypass payload: {payload} (WAF: {waf_type})"
                        })
                        observed_payloads.add(payload)
                        break

    if not issues:
        issues.append({
            'url': url,
            'issue': "No XSS vulnerabilities detected, check manually.",
            'detail': f"Tested payloads: {payloads}"
        })

    return issues, observed_payloads


# Function to print ASCII art
def print_ascii_art():
    ascii_art = """
     _       _             _  __  ______ ____  
    / \   __| | __ _ _ __ | |_\ \/ / ___/ ___| 
   / _ \ / _` |/ _` | '_ \| __|\  /\___ \___ \ 
  / ___ \ (_| | (_| | |_) | |_ /  \ ___) |__) |
 /_/   \_\__,_|\__,_| .__/ \__/_/\_\____/____/ 
                    |_|                        
    """
    print(ascii_art)


def main():
    print_ascii_art()

    # User input
    target_url = input("Enter the target URL (including scheme, e.g., http://example.com): ")
    params = input("Enter the parameters to test (comma-separated): ").split(',')
    cookies_input = input("Enter cookies (key=value format, comma-separated, leave empty if none): ")
    cookies = None
    if cookies_input.strip():
        cookies = dict(cookie.split('=') for cookie in cookies_input.split(','))

    # Run the XSS testing
    issues, observed_payloads = test_xss_adaptive(target_url, params, cookies)

    # Print results
    for issue in issues:
        print(f"URL: {issue.get('url')}")
        print(f"Issue: {issue.get('issue')}")
        if 'detail' in issue:
            print(f"Detail: {issue.get('detail')}")
        print()

    print(f"Observed Payloads: {observed_payloads}")


if __name__ == "__main__":
    main()
