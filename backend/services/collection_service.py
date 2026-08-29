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
    Collect OSINT data for a domain with real-time progress tracking.
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
        
        # Fix: Convert progress to int for display with %d format
        print(f"[{int(progress):3d}%] [{status:9s}] {label}: {message}")

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

    # Track progress for each major step
    step_progress = {
        "dns": 0,
        "ip_metadata": 0,
        "subfinder": 0,
        "amass": 0,
        "certificates": 0,
        "virustotal": 0
    }
    
    def calculate_overall_progress():
        """Calculate overall progress based on completed steps."""
        weights = {
            "dns": 15,        # 0-15%
            "ip_metadata": 10, # 15-25%
            "subfinder": 20,   # 25-45%
            "amass": 20,       # 45-65%
            "certificates": 10, # 65-75%
            "virustotal": 15   # 75-90%
        }
        
        total = 0
        for step, value in step_progress.items():
            weight = weights.get(step, 10)
            if value >= 100:
                total += weight
            else:
                total += (value / 100) * weight
        
        # Cap at 90% (remaining 10% for normalization and final steps)
        return min(90, total)

    # =========================================================
    # 3. DNS COLLECTION
    # =========================================================

    print("\n[*] Collecting DNS records...")

    update_progress(
        "dns",
        "DNS Resolution",
        "Querying DNS records...",
        "running",
        5
    )

    results["dns_records"] = get_dns_records(domain)
    step_progress["dns"] = 100

    # Check if cancelled after DNS
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    overall = calculate_overall_progress()
    update_progress(
        "dns",
        "DNS Resolution",
        "DNS records resolved",
        "completed",
        overall
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
        calculate_overall_progress()
    )

    results["ip_metadata"] = get_all_ip_metadata(
        results["ips"]
    )
    step_progress["ip_metadata"] = 100

    # Check if cancelled after IP metadata
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    overall = calculate_overall_progress()
    update_progress(
        "ip_metadata",
        "IP Metadata",
        "IP metadata collected",
        "completed",
        overall
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
        calculate_overall_progress()
    )

    subfinder_subdomains = get_subdomains(domain, is_cancelled=is_cancelled)
    step_progress["subfinder"] = 100

    # Check if cancelled after Subfinder
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    print(
        f"[+] Subfinder found: "
        f"{len(subfinder_subdomains)}"
    )

    overall = calculate_overall_progress()
    update_progress(
        "subfinder",
        "Subdomain Discovery",
        f"Subfinder found {len(subfinder_subdomains)} subdomains",
        "completed",
        overall
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
        calculate_overall_progress()
    )

    amass_subdomains = get_amass_subdomains(domain, is_cancelled=is_cancelled)
    step_progress["amass"] = 100

    # Check if cancelled after Amass
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    print(
        f"[+] Amass found: "
        f"{len(amass_subdomains)}"
    )

    overall = calculate_overall_progress()
    update_progress(
        "amass",
        "Subdomain Discovery",
        f"AMASS found {len(amass_subdomains)} subdomains",
        "completed",
        overall
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
        calculate_overall_progress()
    )

    results["certificates"] = get_certificates(domain)
    step_progress["certificates"] = 100

    # Check if cancelled after certificates
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    print(
        f"[+] Certificates found: "
        f"{len(results['certificates'])}"
    )

    overall = calculate_overall_progress()
    update_progress(
        "certificates",
        "Certificate Intelligence",
        f"Found {len(results['certificates'])} certificates",
        "completed",
        overall
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
        calculate_overall_progress()
    )

    try:
        # Use enhanced collector
        vt_data = collect_virustotal_domain(domain)
        results["virustotal"] = vt_data
        step_progress["virustotal"] = 100
        
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
        
        overall = calculate_overall_progress()
        update_progress(
            "virustotal",
            "VirusTotal Intelligence",
            f"Risk Score: {vt_data.get('risk_score', 'N/A')}/100 | {vt_data.get('security_summary', {}).get('malicious', 0)} malicious vendors",
            "completed",
            overall
        )
        
    except Exception as e:
        print(f"[!] VirusTotal collection error: {e}")
        results["virustotal"] = {"error": str(e)}
        overall = calculate_overall_progress()
        update_progress(
            "virustotal",
            "VirusTotal Intelligence",
            f"Error: {str(e)[:50]}...",
            "failed",
            overall
        )

    # =========================================================
    # 10. RETURN RESULTS
    # =========================================================

    # Final cancellation check before returning
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    # Update to 90% (remaining 10% handled by pipeline_service)
    overall = calculate_overall_progress()
    update_progress(
        "collection_summary",
        "OSINT Collection",
        f"Collection complete: {len(results['subdomains'])} subdomains",
        "completed",
        overall
    )

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