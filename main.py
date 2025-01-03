#!/usr/bin/env python3
"""
vscan-common-file-scanner
A lightweight command-line tool for scanning common configuration, backup, and log files
on a target web server by sending HTTP HEAD requests.

Usage Examples:
    python main.py -u https://example.com -w paths.txt
    python main.py --url https://example.com --wordlist common_files.txt --verbose
"""

import argparse
import logging
import sys
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

__version__ = "1.0.0"

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.Namespace: Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="A lightweight tool to scan for common configuration, backup, and log files on a target web server."
    )
    parser.add_argument(
        '-u', '--url',
        required=True,
        help='Target URL (e.g., https://example.com)'
    )
    parser.add_argument(
        '-w', '--wordlist',
        default='common_paths.txt',
        help='Path to the wordlist file containing directories and file names to scan. Default is common_paths.txt'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file to save the scan results.'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=5,
        help='Timeout for HTTP requests in seconds. Default is 5 seconds.'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging.'
    )
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {__version__}',
        help='Show program version.'
    )
    return parser.parse_args()

def setup_logging(verbose=False):
    """
    Configures the logging settings.

    Args:
        verbose (bool): If True, set logging level to DEBUG. Otherwise, INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='[%(levelname)s] %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

def load_wordlist(wordlist_path):
    """
    Loads the wordlist from the specified file.

    Args:
        wordlist_path (str): Path to the wordlist file.

    Returns:
        list: A list of paths to scan.
    """
    try:
        with open(wordlist_path, 'r') as file:
            paths = [line.strip() for line in file if line.strip()]
            logging.debug(f"Loaded {len(paths)} paths from {wordlist_path}")
            return paths
    except FileNotFoundError:
        logging.error(f"Wordlist file not found: {wordlist_path}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading wordlist file: {e}")
        sys.exit(1)

def send_head_request(url, timeout):
    """
    Sends an HTTP HEAD request to the specified URL.

    Args:
        url (str): The URL to send the HEAD request to.
        timeout (int): Timeout for the request in seconds.

    Returns:
        requests.Response or None: The response object if successful, None otherwise.
    """
    try:
        response = requests.head(url, timeout=timeout, allow_redirects=True)
        logging.debug(f"HEAD {url} - Status Code: {response.status_code}")
        return response
    except requests.RequestException as e:
        logging.warning(f"Request failed for {url}: {e}")
        return None

def scan_target(target_url, paths, timeout):
    """
    Scans the target URL for the existence of specified paths by sending HEAD requests.

    Args:
        target_url (str): The base URL of the target web server.
        paths (list): A list of paths to scan.
        timeout (int): Timeout for HTTP requests in seconds.

    Returns:
        list: A list of tuples containing the path and status code for existing paths.
    """
    existing_paths = []
    for path in paths:
        full_url = urljoin(target_url, path)
        response = send_head_request(full_url, timeout)
        if response and response.status_code == 200:
            logging.info(f"Found: {full_url} (Status: {response.status_code})")
            existing_paths.append((full_url, response.status_code))
        elif response:
            logging.debug(f"Not found: {full_url} (Status: {response.status_code})")
    return existing_paths

def save_results(results, output_file):
    """
    Saves the scan results to the specified output file.

    Args:
        results (list): List of tuples containing the path and status code.
        output_file (str): Path to the output file.
    """
    try:
        with open(output_file, 'w') as file:
            for url, status in results:
                file.write(f"{url} - Status: {status}\n")
        logging.info(f"Results saved to {output_file}")
    except Exception as e:
        logging.error(f"Failed to save results to {output_file}: {e}")

def main():
    """
    The main function that orchestrates the scanning process.
    """
    args = setup_argparse()
    setup_logging(args.verbose)

    logging.debug("Starting vscan-common-file-scanner")
    logging.debug(f"Target URL: {args.url}")
    logging.debug(f"Wordlist: {args.wordlist}")
    logging.debug(f"Timeout: {args.timeout}s")
    logging.debug(f"Output File: {args.output}")

    paths = load_wordlist(args.wordlist)
    results = scan_target(args.url, paths, args.timeout)

    if args.output:
        save_results(results, args.output)
    else:
        print("\nScan Results:")
        for url, status in results:
            print(f"{url} - Status: {status}")

    logging.debug("Scan completed.")

if __name__ == "__main__":
    main()