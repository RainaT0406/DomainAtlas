import json
import subprocess
from pathlib import Path

from backend.validation.domain_validator import validate_domain

from backend.collectors.dns_collector import get_dns_records
from backend.collectors.subdomain_collector import get_subdomains
from backend.collectors.amass_collector import get_amass_subdomains
from backend.collectors.certificate_collector import get_certificates
from backend.collectors.ip_metadata_collector import get_all_ip_metadata
from backend.collectors.virus_total_collector import collect_virustotal_domain


# Global variable to track subprocesses for cancellation
_active_processes = []


def cancel_active_processes():
    """Terminate all active subprocesses."""
    global _active_processes
    for proc in _active_processes:
        try:
            if proc and proc.poll() is None:  # Still running
                print(f"[*] Terminating process {proc.pid}")
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except Exception as e:
            print(f"[!] Error terminating process: {e}")
    _active_processes = []


def collect_domain_osint(domain, progress_callback=None, is_cancelled=None):
    """
    Collect OSINT data for a domain.

    Parameters
    ----------
    domain : str
        Target domain.
    progress_callback : callable, optional
        Function to call with progress updates.
        Receives dict with step, label, message, status, progress.
    is_cancelled : callable, optional
        Function that returns True if the scan should be cancelled.
    """

    def update_progress(step, label, message, status, progress):
        """Send progress update if callback provided."""
        if progress_callback:
            progress_callback({
                "step": step,
                "label": label,
                "message": message,
                "status": status,
                "progress": progress,
            })
        
        print(f"[{progress:3d}%] [{status:9s}] {label}: {message}")

    def check_cancelled():
        """Check if the scan has been cancelled."""
        if is_cancelled and is_cancelled():
            print("\n[!] Scan cancelled by user during collection.")
            # Terminate any running subprocesses
            cancel_active_processes()
            return True
        return False

    # =========================================================
    # 1. DOMAIN INPUT & VALIDATION
    # =========================================================

    print("[*] Validating domain...")

    valid, result = validate_domain(domain)

    if not valid:
        raise ValueError(result)

    domain = result

    print(f"[+] Domain validated: {domain}")

    # Check if cancelled after validation
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

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

    update_progress(
        "dns",
        "DNS Resolution",
        "Querying DNS records...",
        "running",
        20
    )

    results["dns_records"] = get_dns_records(domain)

    # Check if cancelled after DNS
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    update_progress(
        "dns",
        "DNS Resolution",
        "DNS records resolved",
        "completed",
        30
    )

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

    update_progress(
        "ip_metadata",
        "IP Metadata",
        "Looking up ASN and organization...",
        "running",
        32
    )

    results["ip_metadata"] = get_all_ip_metadata(
        results["ips"]
    )

    # Check if cancelled after IP metadata
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    update_progress(
        "ip_metadata",
        "IP Metadata",
        "IP metadata collected",
        "completed",
        35
    )

    # =========================================================
    # 6. SUBDOMAIN COLLECTION
    # =========================================================

    print("\n[*] Collecting subdomains...")

    # ---------------------------------------------------------
    # Subfinder
    # ---------------------------------------------------------

    # Check before Subfinder
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    print("[*] Running Subfinder...")

    update_progress(
        "subfinder",
        "Subdomain Discovery",
        "Running Subfinder...",
        "running",
        38
    )

    subfinder_subdomains = get_subdomains(domain, is_cancelled=is_cancelled)

    # Check if cancelled after Subfinder
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    print(
        f"[+] Subfinder found: "
        f"{len(subfinder_subdomains)}"
    )

    update_progress(
        "subfinder",
        "Subdomain Discovery",
        f"Subfinder found {len(subfinder_subdomains)} subdomains",
        "completed",
        45
    )

    # ---------------------------------------------------------
    # Amass
    # ---------------------------------------------------------

    # Check before Amass
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    print("[*] Running Amass...")

    update_progress(
        "amass",
        "Subdomain Discovery",
        "Running AMASS...",
        "running",
        48
    )

    amass_subdomains = get_amass_subdomains(domain, is_cancelled=is_cancelled)

    # Check if cancelled after Amass
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    print(
        f"[+] Amass found: "
        f"{len(amass_subdomains)}"
    )

    update_progress(
        "amass",
        "Subdomain Discovery",
        f"AMASS found {len(amass_subdomains)} subdomains",
        "completed",
        55
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

    update_progress(
        "certificates",
        "Certificate Intelligence",
        "Querying Certificate Transparency...",
        "running",
        60
    )

    results["certificates"] = get_certificates(domain)

    # Check if cancelled after certificates
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    print(
        f"[+] Certificates found: "
        f"{len(results['certificates'])}"
    )

    update_progress(
        "certificates",
        "Certificate Intelligence",
        f"Found {len(results['certificates'])} certificates",
        "completed",
        65
    )

    # =========================================================
    # 9. VIRUSTOTAL COLLECTION (ENHANCED)
    # =========================================================

    print("\n[*] Collecting comprehensive VirusTotal intelligence...")

    update_progress(
        "virustotal",
        "VirusTotal Intelligence",
        "Querying VirusTotal API for detailed analysis...",
        "running",
        68
    )

    try:
        # Use enhanced collector (already using the new function)
        vt_data = collect_virustotal_domain(domain)
        results["virustotal"] = vt_data
        
        # Check if cancelled after VirusTotal
        if check_cancelled():
            return {"success": False, "message": "Scan cancelled"}
        
        # Show detailed summary
        print("[+] VirusTotal analysis complete.")
        if vt_data:
            print(f"    Risk Score: {vt_data.get('risk_score', 'N/A')}/100")
            print(f"    Malicious Vendors: {vt_data.get('security_summary', {}).get('malicious', 0)}")
            print(f"    Suspicious Vendors: {vt_data.get('security_summary', {}).get('suspicious', 0)}")
            print(f"    Total Vendors: {vt_data.get('security_summary', {}).get('total_vendors', 0)}")
            
            # Show risk factors if any
            risk_factors = vt_data.get('risk_factors', [])
            if risk_factors:
                print("    Risk Factors:")
                for factor in risk_factors[:3]:
                    print(f"      - {factor['description']}")
        else:
            print("[!] No VirusTotal data returned.")
        
        update_progress(
            "virustotal",
            "VirusTotal Intelligence",
            f"Risk Score: {vt_data.get('risk_score', 'N/A')}/100 | {vt_data.get('security_summary', {}).get('malicious', 0)} malicious vendors",
            "completed",
            70
        )
        
    except Exception as e:
        print(f"[!] VirusTotal collection error: {e}")
        results["virustotal"] = {"error": str(e)}
        update_progress(
            "virustotal",
            "VirusTotal Intelligence",
            f"Error: {str(e)[:50]}...",
            "failed",
            70
        )

    # =========================================================
    # 10. RETURN RESULTS
    # =========================================================

    # Final cancellation check before returning
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

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