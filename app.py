from datetime import datetime, timezone

import dns.dnssec
import dns.flags
import dns.rdatatype
import dns.resolver
from flask import Flask, render_template, request

app = Flask(__name__)

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "SOA", "TXT", "DNSKEY", "DS", "CAA"]

# Public resolvers that reliably set the DO bit and return RRSIG records.
NAMESERVERS = ["1.1.1.1", "8.8.8.8"]


def get_resolver():
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = NAMESERVERS
    # Set the DNSSEC OK (DO) bit so RRSIG records are included in the response.
    resolver.use_edns(0, dns.flags.DO, 1232)
    return resolver


def format_epoch(value):
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def lookup_rrsigs(domain, rdtype):
    resolver = get_resolver()
    answer = resolver.resolve(domain, rdtype, raise_on_no_answer=False)

    rrsigs = []
    for rrset in answer.response.answer:
        if rrset.rdtype == dns.rdatatype.RRSIG:
            for rr in rrset:
                rrsigs.append(
                    {
                        "type_covered": dns.rdatatype.to_text(rr.type_covered),
                        "algorithm_number": int(rr.algorithm),
                        "algorithm_name": dns.dnssec.algorithm_to_text(rr.algorithm),
                        "signature_length": len(rr.signature),
                        "key_tag": rr.key_tag,
                        "signer": str(rr.signer),
                        "expiration": format_epoch(rr.expiration),
                        "inception": format_epoch(rr.inception),
                    }
                )
    return rrsigs


@app.route("/", methods=["GET", "POST"])
def index():
    domain = ""
    rdtype = "A"
    rrsigs = None
    error = None

    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        rdtype = request.form.get("rdtype", "A").strip().upper()

        if not domain:
            error = "Please enter a domain name."
        else:
            try:
                rrsigs = lookup_rrsigs(domain, rdtype)
                if not rrsigs:
                    error = (
                        f"No RRSIG records found for {domain} ({rdtype}). "
                        "The domain may not be DNSSEC-signed, or that record type doesn't exist."
                    )
            except dns.resolver.NXDOMAIN:
                error = f"{domain} does not exist (NXDOMAIN)."
            except dns.resolver.NoNameservers:
                error = "No nameservers could answer the query."
            except dns.exception.Timeout:
                error = "The DNS query timed out."
            except Exception as exc:  # noqa: BLE001
                error = f"Lookup failed: {exc}"

    return render_template(
        "index.html",
        domain=domain,
        rdtype=rdtype,
        record_types=RECORD_TYPES,
        rrsigs=rrsigs,
        error=error,
    )


if __name__ == "__main__":
    app.run(debug=True)
