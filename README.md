# Citrix Bleed 2 PoC Scanner (CVE-2025-5777)

This script is a Proof-of-Concept (PoC) scanner for the hypothetical vulnerability "Citrix Bleed 2" (CVE-2025-5777). It is designed to detect potential memory leaks from Citrix ADC devices by sending oversized requests and analyzing the responses for sensitive information.

## Features

- **Multiple Test Methods**: Supports `oversized-headers`, `oversized-body`, and `randomized` testing methods.
- **Differential Analysis**: Compares test responses against a baseline to identify leaked data.
- **High-Confidence Token Extraction**: Uses regex and entropy analysis to find potential tokens (e.g., session cookies, JWTs).
- **Multiple Export Formats**: Can export findings to JSON, CSV, or raw text files.
- **Configurable**: Allows setting the number of requests, delay, and other options.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/citrix-bleed-2-scanner.git
    cd citrix-bleed-2-scanner
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: You will need to create a `requirements.txt` file containing `requests`)*

## Usage

```bash
python citrix_bleed_2_scanner.py --target <TARGET_URL> [OPTIONS]
```

### Examples

-   **Basic scan:**
    ```bash
    python citrix_bleed_2_scanner.py --target https://192.168.1.100
    ```

-   **Loop with a delay:**
    ```bash
    python citrix_bleed_2_scanner.py --target https://192.168.1.100 --loop 10 --delay 5
    ```

-   **Use a specific test method and export to JSON:**
    ```bash
    python citrix_bleed_2_scanner.py --target https://192.168.1.100 --test-method oversized-body --json-out results.json
    ```

### Options

| Option              | Description                                                              | Default      |
| ------------------- | ------------------------------------------------------------------------ | ------------ |
| `--target`          | Target URL (e.g., `https://192.168.1.100`)                               | **Required** |
| `--loop`            | Number of requests to send                                               | `1`          |
| `--delay`           | Delay between requests in seconds                                        | `2.0`        |
| `--test-method`     | The testing method to use (`randomized`, `oversized-headers`, `oversized-body`) | `randomized` |
| `--json-out`        | Export found tokens to a JSON file                                       | `None`       |
| `--csv-out`         | Export found tokens to a CSV file                                        | `None`       |
| `--raw-out`         | Export raw response content to a file                                    | `None`       |
| `--no-insecure`     | Enable TLS certificate verification                                      | `disabled`   |


## Legal Disclaimer

This script is provided for educational and authorized security testing purposes only. By using this script, you agree that you will only use it on systems for which you have explicit, written permission to test. The author and contributors are not responsible for any misuse or damage caused by this script. Unauthorized scanning of systems is illegal and strictly prohibited.
