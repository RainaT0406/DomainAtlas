import json
from pathlib import Path

from backend.validation.domain_validator import validate_domain

from backend.collectors.dns_collector import get_dns_records
from backend.collectors.subdomain_collector import get_subdomains
from backend.collectors.certificate_collector import get_certificates
from backend.collectors.ip_metadata_collector import get_all_ip_metadata


def collect_domain_osint(domain):

    # ---------------------------------------------------------
    # 1. DOMAIN INPUT & VALIDATION
    # ---------------------------------------------------------

    print("[*] Validating domain...")

    valid, result = validate_domain(domain)

    if not valid:
        raise ValueError(result)

    domain = result

    print(f"[+] Domain validated: {domain}")

    # ---------------------------------------------------------
    # 2. INITIALIZE RESULTS
    # ---------------------------------------------------------

    results = {
        "domain": domain,
        "dns_records": {},
        "ips": [],
        "ip_metadata": [],
        "subdomains": [],
        "certificates": []
    }

    # ---------------------------------------------------------
    # 3. DNS COLLECTION
    # ---------------------------------------------------------

    print("\n[*] Collecting DNS records...")

    results["dns_records"] = get_dns_records(domain)

    # ---------------------------------------------------------
    # 4. IP EXTRACTION
    # ---------------------------------------------------------

    results["ips"] = (
        results["dns_records"].get("A", [])
        + results["dns_records"].get("AAAA", [])
    )

    print(f"[+] IP addresses found: {len(results['ips'])}")

    # ---------------------------------------------------------
    # 5. IP METADATA COLLECTION
    # ---------------------------------------------------------

    print("\n[*] Collecting IP metadata...")

    results["ip_metadata"] = get_all_ip_metadata(results["ips"])

    # ---------------------------------------------------------
    # 6. SUBDOMAIN COLLECTION
    # ---------------------------------------------------------

    print("\n[*] Collecting subdomains...")

    results["subdomains"] = get_subdomains(domain)

    print(f"[+] Subdomains found: {len(results['subdomains'])}")

    # ---------------------------------------------------------
    # 7. CERTIFICATE COLLECTION
    # ---------------------------------------------------------

    print("\n[*] Collecting certificates...")

    results["certificates"] = get_certificates(domain)

    print(f"[+] Certificates found: {len(results['certificates'])}")

    return results


if __name__ == "__main__":

    domain = input("Enter domain: ").strip()

    print("\n[*] Starting OSINT collection...\n")

    try:

        results = collect_domain_osint(domain)

        output_directory = Path("data/raw")
        output_directory.mkdir(parents=True, exist_ok=True)

        output_file = output_directory / f"{results['domain']}.json"

        with open(output_file, "w", encoding="utf-8") as file:
            json.dump(
                results,
                file,
                indent=4,
                ensure_ascii=False
            )

        print("\n[+] Collection complete.")
        print(f"[+] Results saved to: {output_file}")

    except ValueError as error:

        print(f"\n[!] Domain validation failed: {error}")

    except Exception as error:

        print(f"\n[!] Collection error: {error}")