# DNS RRSIG Checker

A small Flask web app that looks up the RRSIG (DNSSEC signature) records for
a domain and displays their algorithm and signature length. Every lookup is
also appended to a CSV log, and the page shows the 25 most recent logged
lookups.

## What it does

You enter a domain name and pick a DNS record type (A, AAAA, MX, NS, SOA,
TXT, DNSKEY, DS, or CAA). The app queries DNS with the DNSSEC OK (DO) bit
set and reads back any RRSIG records covering that record type. Since a
zone can be signed by more than one key (e.g. during a key rollover, or
when multiple algorithms are used), the results are shown as a table that
may have more than one row — one row per RRSIG found.

For each RRSIG, the table shows:

- **Type Covered** — the record type the signature covers
- **Algorithm** — the DNSSEC algorithm number and name (e.g. `13 (ECDSAP256SHA256)`)
- **Signature Length (bytes)** — length of the raw signature
- **Key Tag** — the key tag identifying the signing key
- **Signer** — the name that signed the RRset
- **Inception / Expiration** — the signature's validity window, in UTC

Below the results, a second table lists the 25 most recent lookups logged
across all past queries (domain, algorithm number/name, and signature
length), most recent first.

## Requirements

- Python 3.9+
- [Flask](https://pypi.org/project/Flask/)
- [dnspython](https://pypi.org/project/dnspython/)

## Setup

```bash
git clone https://github.com/danyork/dns-rrsig-checker.git
cd dns-rrsig-checker
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

## Usage

Start the app:

```bash
./venv/bin/python app.py
```

Then open [http://127.0.0.1:5000/](http://127.0.0.1:5000/) in a browser,
enter a domain (e.g. `cloudflare.com`), choose a record type, and click
**Look up**.

If the domain isn't DNSSEC-signed, or the chosen record type doesn't exist
for it, the app reports that instead of a table.

## Logging

Every successful lookup appends a row per RRSIG found to `rrsig_log.csv` in
the project directory, with these columns:

- `domain`
- `algorithm_number`
- `algorithm_name`
- `signature_length`

This file is created automatically on first use and is excluded from git
via `.gitignore`, since it's runtime data rather than source code.

## Notes

- DNS queries are sent directly to `1.1.1.1` and `8.8.8.8`, since these
  reliably honor the DNSSEC OK (DO) bit and return RRSIG records. Your
  system's configured resolver is not used.
- This app does not validate DNSSEC signatures — it only reports what
  RRSIG records exist and their basic properties.
