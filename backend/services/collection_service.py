import json
from pathlib import Path

from backend.validation.domain_validator import validate_domain

from backend.collectors.dns_collector import get_dns_records
from backend.collectors.subdomain_collector import get_subdomains
from backend.collectors.amass_collector import get_amass_subdomains
from backend.collectors.certificate_collector import get_certificates
from backend.collectors.ip_metadata_collector import get_all_ip_metadata
from backend.collectors.virus_total_collector import collect_virustotal_domain


def collect_domain_osint(domain):

    # =========================================================
    # 1. DOMAIN INPUT & VALIDATION
    # =========================================================

    print("[*] Validating domain...")

    valid, result = validate_domain(domain)

    if not valid:
        raise ValueError(result)

    domain = result

    print(f"[+] Domain validated: {domain}")

    # =========================================================
    # 2. INITIALIZE RESULTS
    # =========================================================

    results = {
        "domain": domain,
        "dns_records": {},
        "ips": [],
        "ip_metadata": [],
        "subdomains": [],
        "certificates": [],
        "virustotal": {}
    }

    # =========================================================
    # 3. DNS COLLECTION
    # =========================================================

    print("\n[*] Collecting DNS records...")

    results["dns_records"] = get_dns_records(domain)

    # =========================================================
    # 4. IP EXTRACTION
    # =========================================================

    results["ips"] = (
        results["dns_records"].get("A", [])
        + results["dns_records"].get("AAAA", [])
    )

    # Remove duplicate IP addresses while preserving order
    results["ips"] = list(
        dict.fromkeys(results["ips"])
    )

    print(
        f"[+] IP addresses found: {len(results['ips'])}"
    )

    # =========================================================
    # 5. IP METADATA COLLECTION
    # =========================================================

    print("\n[*] Collecting IP metadata...")

    results["ip_metadata"] = get_all_ip_metadata(
        results["ips"]
    )

    # =========================================================
    # 6. SUBDOMAIN COLLECTION
    # =========================================================

    print("\n[*] Collecting subdomains...")

    # ---------------------------------------------------------
    # Subfinder
    # ---------------------------------------------------------

    print("[*] Running Subfinder...")

    subfinder_subdomains = get_subdomains(domain)

    print(
        f"[+] Subfinder found: "
        f"{len(subfinder_subdomains)}"
    )

    # ---------------------------------------------------------
    # Amass
    # ---------------------------------------------------------

    print("[*] Running Amass...")

    amass_subdomains = get_amass_subdomains(domain)

    print(
        f"[+] Amass found: "
        f"{len(amass_subdomains)}"
    )

    # =========================================================
    # 7. COMBINE & PRESERVE SUBDOMAIN SOURCES
    # =========================================================

    subdomain_sources = {}

    # ---------------------------------------------------------
    # Subfinder results
    # ---------------------------------------------------------

    for subdomain in subfinder_subdomains:

        if not isinstance(subdomain, str):
            continue

        subdomain = subdomain.strip()

        if not subdomain:
            continue

        if subdomain not in subdomain_sources:
            subdomain_sources[subdomain] = []

        if "Subfinder" not in subdomain_sources[subdomain]:
            subdomain_sources[subdomain].append("Subfinder")

    # ---------------------------------------------------------
    # Amass results
    # ---------------------------------------------------------

    for subdomain in amass_subdomains:

        if not isinstance(subdomain, str):
            continue

        subdomain = subdomain.strip()

        if not subdomain:
            continue

        if subdomain not in subdomain_sources:
            subdomain_sources[subdomain] = []

        if "Amass" not in subdomain_sources[subdomain]:
            subdomain_sources[subdomain].append("Amass")

    # =========================================================
    # FINAL SOURCE-AWARE SUBDOMAIN LIST
    # =========================================================

    results["subdomains"] = [
        {
            "subdomain": subdomain,
            "sources": sources
        }
        for subdomain, sources
        in sorted(subdomain_sources.items())
    ]

    # =========================================================
    # CORRELATION STATISTICS
    # =========================================================

    common_subdomains = [
        subdomain
        for subdomain, sources
        in subdomain_sources.items()
        if len(sources) > 1
    ]

    print(
        f"[+] Unique subdomains found: "
        f"{len(results['subdomains'])}"
    )

    print(
        f"[+] Subdomains found by both sources: "
        f"{len(common_subdomains)}"
    )

    # =========================================================
    # 8. CERTIFICATE COLLECTION
    # =========================================================

    print("\n[*] Collecting certificates...")

    results["certificates"] = get_certificates(domain)

    print(
        f"[+] Certificates found: "
        f"{len(results['certificates'])}"
    )

    # =========================================================
    # 9. VIRUSTOTAL COLLECTION
    # =========================================================

    print("\n[*] Collecting VirusTotal intelligence...")

    results["virustotal"] = collect_virustotal_domain(
        domain
    )

    print("[+] VirusTotal lookup complete.")

    # =========================================================
    # 10. RETURN RESULTS
    # =========================================================

    return results


# =============================================================
# STANDALONE EXECUTION
# =============================================================

if __name__ == "__main__":

    domain = input(
        "Enter domain: "
    ).strip()

    print(
        "\n[*] Starting OSINT collection...\n"
    )

    try:

        results = collect_domain_osint(
            domain
        )

        # =====================================================
        # SAVE RAW DATA
        # =====================================================

        output_directory = Path(
            "data/raw"
        )

        output_directory.mkdir(
            parents=True,
            exist_ok=True
        )

        output_file = (
            output_directory
            / f"{results['domain']}.json"
        )

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                results,
                file,
                indent=4,
                ensure_ascii=False
            )

        print(
            "\n[+] Collection complete."
        )

        print(
            f"[+] Results saved to: "
            f"{output_file}"
        )

    except ValueError as error:

        print(
            f"\n[!] Domain validation failed: "
            f"{error}"
        )

    except Exception as error:

        print(
            f"\n[!] Collection error: "
            f"{error}"
        )