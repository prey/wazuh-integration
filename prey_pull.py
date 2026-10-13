#!/usr/bin/env python3
"""Prey SIEM poller for Wazuh's `wodle command`.

Prints one OCSF event per line on stdout, which Wazuh ingests as JSON.
Configuration comes from environment variables:
  PREY_API_KEY      Developers API key (read-only is enough). Required.
  PREY_ENDPOINT     Pull endpoint. Defaults to the production URL.
  PREY_CURSOR_FILE  Where the last delivered cursor is kept.
  PREY_HOST_HEADER  Optional Host header override, only for local testing.
"""
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request

ENDPOINT = os.environ.get("PREY_ENDPOINT", "https://api.preyproject.com/v1/siem/events")
# integrations/ is a volume in wazuh-docker, so the cursor survives a container recreate.
CURSOR_FILE = os.environ.get("PREY_CURSOR_FILE", "/var/ossec/integrations/prey_cursor")
PAGE_SIZE = 500
MAX_PAGES = 20
CA_BUNDLES = (
    "/etc/pki/tls/certs/ca-bundle.crt",  # RHEL, Amazon Linux, wazuh-docker
    "/etc/ssl/certs/ca-certificates.crt",  # Debian, Ubuntu
    "/etc/ssl/ca-bundle.pem",  # SUSE
)


def read_cursor():
    try:
        with open(CURSOR_FILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""


def write_cursor(cursor):
    # Write-then-rename so a crash never leaves a half-written cursor.
    tmp = CURSOR_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write(cursor)
    os.replace(tmp, CURSOR_FILE)


def ssl_context():
    # Wazuh's bundled Python ships without CA certificates, so fall back to the system bundle.
    paths = ssl.get_default_verify_paths()
    if not (paths.cafile or paths.capath):
        for bundle in CA_BUNDLES:
            if os.path.exists(bundle):
                return ssl.create_default_context(cafile=bundle)
    return ssl.create_default_context()


def fetch(api_key, cursor):
    query = urllib.parse.urlencode({"after": cursor, "limit": PAGE_SIZE})
    request = urllib.request.Request(f"{ENDPOINT}?{query}", headers={"apikey": api_key})
    if os.environ.get("PREY_HOST_HEADER"):
        request.add_header("Host", os.environ["PREY_HOST_HEADER"])
    with urllib.request.urlopen(request, timeout=30, context=ssl_context()) as response:
        return json.load(response)


def main():
    api_key = os.environ.get("PREY_API_KEY")
    if not api_key:
        print("PREY_API_KEY is not set", file=sys.stderr)
        return 1

    cursor = read_cursor()
    for _ in range(MAX_PAGES):
        page = fetch(api_key, cursor)
        for event in page["events"]:
            print(json.dumps(event, separators=(",", ":")))
        sys.stdout.flush()
        # Only advance after the page is printed: a crash re-sends a page rather than losing it.
        cursor = page["next_cursor"]
        write_cursor(cursor)
        if not page["has_more"]:
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
