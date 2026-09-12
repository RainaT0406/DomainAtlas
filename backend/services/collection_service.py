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
from backend.collectors.port_scanner_collector import collect_port_scan_data


# ============================================================
# GLOBAL PROCESS TRACKING
# ============================================================

_active_processes = []


# ============================================================
# CANCEL ACTIVE SUBPROCESSES
# ============================================================

def cancel_active_processes():
    """
    Terminate all active subprocesses.

    Used when the user cancels an OSINT scan.
    """

    global _active_processes

    for proc in _active_processes:

        try:

            if proc and proc.poll() is None:

                print(
                    f"[*] Terminating process {proc.pid}"
                )

                proc.terminate()

                try:

                    proc.wait(timeout=2)

                except subprocess.TimeoutExpired:

                    proc.kill()

        except Exception as e:

            print(
                f"[!] Error terminating process: {e}"
            )

    _active_processes = []


# ============================================================
# MAIN COLLECTION FUNCTION
# ============================================================

def collect_domain_osint(
    domain,
    progress_callback=None,
    is_cancelled=None
):
    """
    Collect OSINT data for a domain with real-time
    progress tracking.

    Collection modules:

        1. Domain validation
        2. DNS records
        3. IP extraction
        4. IP metadata
        5. TCP port scanning
        6. Subfinder
        7. AMASS
        8. Subdomain correlation
        9. Certificate intelligence
        10. VirusTotal intelligence

    Port scanning includes:

        - TCP open-port detection
        - Service identification
        - Banner grabbing
    """

    # ========================================================
    # PROGRESS HELPER
    # ========================================================

    def update_progress(
        step,
        label,
        message,
        status,
        progress
    ):
        """
        Send progress update to the frontend/backend.
        """

        if progress_callback:

            try:

                progress_callback({
                    "step": step,
                    "label": label,
                    "message": message,
                    "status": status,
                    "progress": int(progress)
                })

            except Exception as e:

                print(
                    f"[!] Progress callback error: {e}"
                )

        print(
            f"[{int(progress):3d}%] "
            f"[{status:9s}] "
            f"{label}: "
            f"{message}"
        )


    # ========================================================
    # CANCELLATION HELPER
    # ========================================================

    def check_cancelled():
        """
        Check whether the current scan has been cancelled.
        """

        if is_cancelled:

            try:

                if is_cancelled():

                    print(
                        "\n[!] Scan cancelled by user "
                        "during collection."
                    )

                    cancel_active_processes()

                    return True

            except Exception as e:

                print(
                    f"[!] Cancellation check error: {e}"
                )

        return False


    # ========================================================
    # 1. DOMAIN INPUT & VALIDATION
    # ========================================================

    print(
        "\n[*] Validating domain..."
    )

    valid, result = validate_domain(
        domain
    )

    if not valid:

        raise ValueError(
            result
        )

    domain = result

    print(
        f"[+] Domain validated: {domain}"
    )

    if check_cancelled():

        return {
            "success": False,
            "message": "Scan cancelled"
        }


    # ========================================================
    # 2. INITIALIZE RESULTS
    # ========================================================

    results = {

        "domain": domain,

        "dns_records": {},

        "ips": [],

        "ip_metadata": [],

        "subdomains": [],

        "certificates": [],

        "virustotal": {},

        "port_scan": {}
    }


    # ========================================================
    # STEP PROGRESS
    # ========================================================

    step_progress = {

        "dns": 0,

        "ip_metadata": 0,

        "subfinder": 0,

        "amass": 0,

        "certificates": 0,

        "virustotal": 0,

        "port_scan": 0
    }


    # ========================================================
    # PROGRESS WEIGHTS
    # ========================================================

    weights = {

        "dns": 12,

        "ip_metadata": 8,

        "subfinder": 18,

        "amass": 18,

        "certificates": 8,

        "virustotal": 12,

        "port_scan": 14
    }


    def calculate_overall_progress():
        """
        Calculate weighted collection progress.

        Collection occupies approximately 0-90%.
        """

        total = 0.0

        for step, value in step_progress.items():

            weight = weights.get(
                step,
                0
            )

            total += (
                value / 100
            ) * weight

        return min(
            90,
            int(total)
        )


    # ========================================================
    # 3. DNS COLLECTION
    # ========================================================

    print(
        "\n[*] Collecting DNS records..."
    )

    update_progress(
        "dns",
        "DNS Resolution",
        "Querying DNS records...",
        "running",
        5
    )

    try:

        results["dns_records"] = (
            get_dns_records(domain)
        )

        step_progress["dns"] = 100

    except Exception as e:

        print(
            f"[!] DNS collection error: {e}"
        )

        results["dns_records"] = {}

        step_progress["dns"] = 100

    if check_cancelled():

        return {
            "success": False,
            "message": "Scan cancelled"
        }

    update_progress(
        "dns",
        "DNS Resolution",
        "DNS records resolved",
        "completed",
        calculate_overall_progress()
    )


    # ========================================================
    # 4. IP EXTRACTION
    # ========================================================

    results["ips"] = (

        results["dns_records"].get(
            "A",
            []
        )

        +

        results["dns_records"].get(
            "AAAA",
            []
        )
    )

    # Remove duplicates
    results["ips"] = list(
        dict.fromkeys(
            results["ips"]
        )
    )

    print(
        f"[+] IP addresses found: "
        f"{len(results['ips'])}"
    )

    for ip in results["ips"]:

        print(
            f"    - {ip}"
        )


    # ========================================================
    # 5. IP METADATA COLLECTION
    # ========================================================

    print(
        "\n[*] Collecting IP metadata..."
    )

    update_progress(
        "ip_metadata",
        "IP Metadata",
        "Looking up ASN and organization...",
        "running",
        calculate_overall_progress()
    )

    try:

        results["ip_metadata"] = (
            get_all_ip_metadata(
                results["ips"]
            )
        )

    except Exception as e:

        print(
            f"[!] IP metadata error: {e}"
        )

        results["ip_metadata"] = []

    step_progress["ip_metadata"] = 100

    if check_cancelled():

        return {
            "success": False,
            "message": "Scan cancelled"
        }

    update_progress(
        "ip_metadata",
        "IP Metadata",
        "IP metadata collected",
        "completed",
        calculate_overall_progress()
    )


    # ========================================================
    # 6. PORT SCANNING
    # ========================================================

    print(
        "\n" + "=" * 60
    )

    print(
        "PORT SCANNING"
    )

    print(
        "=" * 60
    )


    # --------------------------------------------------------
    # Port scanner currently uses AF_INET.
    #
    # Therefore only scan IPv4 addresses.
    # --------------------------------------------------------

    ipv4_addresses = []

    for ip in results["ips"]:

        if not isinstance(
            ip,
            str
        ):
            continue

        ip = ip.strip()

        if not ip:
            continue

        # Simple IPv4 validation
        parts = ip.split(".")

        if len(parts) != 4:
            continue

        try:

            if all(
                0 <= int(part) <= 255
                for part in parts
            ):

                ipv4_addresses.append(ip)

        except ValueError:

            continue

    # Deduplicate
    ipv4_addresses = list(
        dict.fromkeys(
            ipv4_addresses
        )
    )


    if ipv4_addresses:

        print(
            f"[*] Performing port scans on "
            f"{len(ipv4_addresses)} IPv4 address(es)..."
        )

        update_progress(
            "port_scan",
            "Port Scanning",
            (
                f"Scanning "
                f"{len(ipv4_addresses)} IPv4 address(es)..."
            ),
            "running",
            calculate_overall_progress()
        )


        # ----------------------------------------------------
        # Port scan progress callback
        # ----------------------------------------------------

        def port_scan_progress(
            update
        ):

            total = update.get(
                "total",
                0
            )

            current = update.get(
                "current",
                0
            )

            ip = update.get(
                "ip",
                ""
            )

            open_ports = update.get(
                "open_ports",
                0
            )


            if total > 0:

                # Convert IP progress into
                # the 14% port-scan stage.
                stage_progress = min(
                    100,
                    int(
                        (
                            current
                            /
                            total
                        )
                        * 100
                    )
                )

                step_progress[
                    "port_scan"
                ] = stage_progress


            overall = (
                calculate_overall_progress()
            )


            print(
                f"[Port Scan] "
                f"{ip} → "
                f"{open_ports} open port(s)"
            )


            if progress_callback:

                try:

                    progress_callback({

                        "step":
                            "port_scan_detail",

                        "label":
                            "Port Scanning",

                        "message":
                            (
                                f"Scanning {ip}... "
                                f"Found "
                                f"{open_ports} "
                                f"open port(s)"
                            ),

                        "status":
                            "running",

                        "progress":
                            overall
                    })

                except Exception as e:

                    print(
                        "[!] Port scan "
                        f"progress callback error: {e}"
                    )


        # ----------------------------------------------------
        # Execute port scan
        # ----------------------------------------------------

        try:

            port_scan_results = (
                collect_port_scan_data(

                    ips=ipv4_addresses,

                    timeout=1.0,

                    # IMPORTANT:
                    # This matches the corrected
                    # port scanner collector.
                    enable_banner_grabbing=True,

                    cancellation_callback=(
                        is_cancelled
                    ),

                    progress_callback=(
                        port_scan_progress
                    )
                )
            )


            # ------------------------------------------------
            # Store result
            # ------------------------------------------------

            results["port_scan"] = (
                port_scan_results.get(
                    "port_scan",
                    {}
                )
            )

            step_progress[
                "port_scan"
            ] = 100


            # ------------------------------------------------
            # Summary
            # ------------------------------------------------

            open_ports_total = (
                results["port_scan"].get(
                    "open_ports_total",
                    0
                )
            )

            scanned_ips = (
                results["port_scan"].get(
                    "scanned_ips",
                    0
                )
            )


            print(
                "\n[+] Port scan complete:"
            )

            print(
                f"    IPv4 IPs scanned: "
                f"{scanned_ips}"
            )

            print(
                f"    Open ports found: "
                f"{open_ports_total}"
            )


            # ------------------------------------------------
            # Display individual services
            # ------------------------------------------------

            for ip_result in (
                results["port_scan"].get(
                    "results",
                    []
                )
            ):

                ip = ip_result.get(
                    "ip",
                    "unknown"
                )

                open_count = (
                    ip_result.get(
                        "open_count",
                        0
                    )
                )

                print(
                    f"\n    IP: {ip}"
                )

                print(
                    f"    Open ports: "
                    f"{open_count}"
                )


                for port in (
                    ip_result.get(
                        "open_ports",
                        []
                    )
                ):

                    port_number = port.get(
                        "port"
                    )

                    service = port.get(
                        "service",
                        "unknown"
                    )

                    banner = port.get(
                        "banner"
                    )


                    print(
                        f"      "
                        f"{port_number}/tcp "
                        f"→ {service}"
                    )


                    if banner:

                        display_banner = (
                            banner[:120]
                        )

                        if len(banner) > 120:

                            display_banner += "..."

                        print(
                            f"        "
                            f"Banner: "
                            f"{display_banner}"
                        )


        except Exception as e:

            print(
                "\n[!] Port scan error:"
            )

            print(
                f"    {e}"
            )


            # ------------------------------------------------
            # Do NOT destroy the entire OSINT scan
            # because port scanning failed.
            # ------------------------------------------------

            results["port_scan"] = {

                "error":
                    str(e),

                "scanned_ips":
                    len(ipv4_addresses),

                "open_ports_total":
                    0,

                "results":
                    []
            }


            step_progress[
                "port_scan"
            ] = 100


        if check_cancelled():

            return {
                "success": False,
                "message": "Scan cancelled"
            }


        # ----------------------------------------------------
        # Port scan completed
        # ----------------------------------------------------

        update_progress(

            "port_scan",

            "Port Scanning",

            (
                f"Found "
                f"{results['port_scan'].get('open_ports_total', 0)} "
                f"open ports"
            ),

            "completed",

            calculate_overall_progress()
        )


    else:

        print(
            "\n[!] No IPv4 addresses available "
            "for port scanning."
        )


        results["port_scan"] = {

            "scanned_ips": 0,

            "open_ports_total": 0,

            "results": []
        }


        step_progress[
            "port_scan"
        ] = 100


        update_progress(

            "port_scan",

            "Port Scanning",

            "No IPv4 addresses available",

            "completed",

            calculate_overall_progress()
        )


    # ========================================================
    # 7. SUBDOMAIN COLLECTION
    # ========================================================

    print(
        "\n" + "=" * 60
    )

    print(
        "SUBDOMAIN DISCOVERY"
    )

    print(
        "=" * 60
    )


    # --------------------------------------------------------
    # Subfinder
    # --------------------------------------------------------

    if check_cancelled():

        return {
            "success": False,
            "message": "Scan cancelled"
        }


    print(
        "[*] Running Subfinder..."
    )

    update_progress(

        "subfinder",

        "Subdomain Discovery",

        "Running Subfinder...",

        "running",

        calculate_overall_progress()
    )


    try:

        subfinder_subdomains = (
            get_subdomains(
                domain,
                is_cancelled=is_cancelled
            )
        )

    except Exception as e:

        print(
            f"[!] Subfinder error: {e}"
        )

        subfinder_subdomains = []


    step_progress[
        "subfinder"
    ] = 100


    if check_cancelled():

        return {
            "success": False,
            "message": "Scan cancelled"
        }


    print(
        f"[+] Subfinder found: "
        f"{len(subfinder_subdomains)}"
    )


    update_progress(

        "subfinder",

        "Subdomain Discovery",

        (
            f"Subfinder found "
            f"{len(subfinder_subdomains)} "
            f"subdomains"
        ),

        "completed",

        calculate_overall_progress()
    )


    # --------------------------------------------------------
    # AMASS
    # --------------------------------------------------------

    if check_cancelled():

        return {
            "success": False,
            "message": "Scan cancelled"
        }


    print(
        "[*] Running Amass..."
    )


    update_progress(

        "amass",

        "Subdomain Discovery",

        "Running AMASS...",

        "running",

        calculate_overall_progress()
    )


    try:

        amass_subdomains = (
            get_amass_subdomains(
                domain,
                is_cancelled=is_cancelled
            )
        )

    except Exception as e:

        print(
            f"[!] AMASS error: {e}"
        )

        amass_subdomains = []


    step_progress[
        "amass"
    ] = 100


    if check_cancelled():

        return {
            "success": False,
            "message": "Scan cancelled"
        }


    print(
        f"[+] Amass found: "
        f"{len(amass_subdomains)}"
    )


    update_progress(

        "amass",

        "Subdomain Discovery",

        (
            f"AMASS found "
            f"{len(amass_subdomains)} "
            f"subdomains"
        ),

        "completed",

        calculate_overall_progress()
    )


    # ========================================================
    # 8. COMBINE SUBDOMAINS
    # ========================================================

    subdomain_sources = {}


    # --------------------------------------------------------
    # Subfinder results
    # --------------------------------------------------------

    for subdomain in (
        subfinder_subdomains
    ):

        if not isinstance(
            subdomain,
            str
        ):
            continue


        subdomain = (
            subdomain.strip()
        )


        if not subdomain:
            continue


        if subdomain not in subdomain_sources:

            subdomain_sources[
                subdomain
            ] = []


        if (
            "Subfinder"
            not in
            subdomain_sources[
                subdomain
            ]
        ):

            subdomain_sources[
                subdomain
            ].append(
                "Subfinder"
            )


    # --------------------------------------------------------
    # Amass results
    # --------------------------------------------------------

    for subdomain in (
        amass_subdomains
    ):

        if not isinstance(
            subdomain,
            str
        ):
            continue


        subdomain = (
            subdomain.strip()
        )


        if not subdomain:
            continue


        if subdomain not in subdomain_sources:

            subdomain_sources[
                subdomain
            ] = []


        if (
            "Amass"
            not in
            subdomain_sources[
                subdomain
            ]
        ):

            subdomain_sources[
                subdomain
            ].append(
                "Amass"
            )


    # --------------------------------------------------------
    # Final merged subdomains
    # --------------------------------------------------------

    results["subdomains"] = [

        {
            "subdomain":
                subdomain,

            "sources":
                sources
        }

        for subdomain, sources
        in sorted(
            subdomain_sources.items()
        )
    ]


    # --------------------------------------------------------
    # Common subdomains
    # --------------------------------------------------------

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


    # ========================================================
    # 9. CERTIFICATE COLLECTION
    # ========================================================

    print(
        "\n[*] Collecting certificates..."
    )


    update_progress(

        "certificates",

        "Certificate Intelligence",

        "Querying Certificate Transparency...",

        "running",

        calculate_overall_progress()
    )


    try:

        results["certificates"] = (
            get_certificates(
                domain
            )
        )

    except Exception as e:

        print(
            f"[!] Certificate collection error: {e}"
        )

        results["certificates"] = []


    step_progress[
        "certificates"
    ] = 100


    if check_cancelled():

        return {
            "success": False,
            "message": "Scan cancelled"
        }


    print(
        f"[+] Certificates found: "
        f"{len(results['certificates'])}"
    )


    update_progress(

        "certificates",

        "Certificate Intelligence",

        (
            f"Found "
            f"{len(results['certificates'])} "
            f"certificates"
        ),

        "completed",

        calculate_overall_progress()
    )


    # ========================================================
    # 10. VIRUSTOTAL COLLECTION
    # ========================================================

    print(
        "\n[*] Collecting comprehensive "
        "VirusTotal intelligence..."
    )


    update_progress(

        "virustotal",

        "VirusTotal Intelligence",

        "Querying VirusTotal API for detailed analysis...",

        "running",

        calculate_overall_progress()
    )


    try:

        vt_data = (
            collect_virustotal_domain(
                domain
            )
        )


        results[
            "virustotal"
        ] = vt_data


        step_progress[
            "virustotal"
        ] = 100


        if check_cancelled():

            return {
                "success": False,
                "message": "Scan cancelled"
            }


        print(
            "[+] VirusTotal analysis complete."
        )


        if vt_data:

            print(
                f"    Risk Score: "
                f"{vt_data.get('risk_score', 'N/A')}/100"
            )


            print(
                f"    Malicious Vendors: "
                f"{vt_data.get('security_summary', {}).get('malicious', 0)}"
            )


            print(
                f"    Suspicious Vendors: "
                f"{vt_data.get('security_summary', {}).get('suspicious', 0)}"
            )


            print(
                f"    Total Vendors: "
                f"{vt_data.get('security_summary', {}).get('total_vendors', 0)}"
            )


            risk_factors = (
                vt_data.get(
                    "risk_factors",
                    []
                )
            )


            if risk_factors:

                print(
                    "    Risk Factors:"
                )


                for factor in (
                    risk_factors[:3]
                ):

                    print(
                        f"      - "
                        f"{factor.get('description', '')}"
                    )


        else:

            print(
                "[!] No VirusTotal data returned."
            )


        update_progress(

            "virustotal",

            "VirusTotal Intelligence",

            (
                f"Risk Score: "
                f"{vt_data.get('risk_score', 'N/A')}/100 | "
                f"{vt_data.get('security_summary', {}).get('malicious', 0)} "
                f"malicious vendors"
            ),

            "completed",

            calculate_overall_progress()
        )


    except Exception as e:

        print(
            f"[!] VirusTotal collection error: {e}"
        )


        results[
            "virustotal"
        ] = {

            "error":
                str(e)
        }


        step_progress[
            "virustotal"
        ] = 100


        update_progress(

            "virustotal",

            "VirusTotal Intelligence",

            (
                f"Error: "
                f"{str(e)[:80]}..."
            ),

            "failed",

            calculate_overall_progress()
        )


    # ========================================================
    # 11. FINAL CANCELLATION CHECK
    # ========================================================

    if check_cancelled():

        return {
            "success": False,
            "message": "Scan cancelled"
        }


    # ========================================================
    # 12. COLLECTION SUMMARY
    # ========================================================

    overall = (
        calculate_overall_progress()
    )


    update_progress(

        "collection_summary",

        "OSINT Collection",

        (
            f"Collection complete: "
            f"{len(results['subdomains'])} "
            f"subdomains, "
            f"{results['port_scan'].get('open_ports_total', 0)} "
            f"open ports"
        ),

        "completed",

        overall
    )


    print(
        "\n" + "=" * 60
    )

    print(
        "OSINT COLLECTION COMPLETE"
    )

    print(
        "=" * 60
    )


    # ========================================================
    # FINAL RESULT
    # ========================================================

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

        results = (
            collect_domain_osint(
                domain
            )
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
            /
            f"{results['domain']}.json"
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


        # =====================================================
        # PORT SCAN SUMMARY
        # =====================================================

        if results.get(
            "port_scan"
        ):

            port_scan = (
                results[
                    "port_scan"
                ]
            )


            print(
                "\n[+] Port Scan Summary:"
            )


            print(
                f"    IPs scanned: "
                f"{port_scan.get('scanned_ips', 0)}"
            )


            print(
                f"    Open ports: "
                f"{port_scan.get('open_ports_total', 0)}"
            )


            # -------------------------------------------------
            # Individual IP results
            # -------------------------------------------------

            for ip_result in (
                port_scan.get(
                    "results",
                    []
                )
            ):

                print(
                    f"\n    IP: "
                    f"{ip_result.get('ip', 'unknown')} "
                    f"("
                    f"{ip_result.get('open_count', 0)} "
                    f"open ports)"
                )


                for port in (
                    ip_result.get(
                        "open_ports",
                        []
                    )
                ):

                    print(
                        f"      Port "
                        f"{port.get('port')}/tcp: "
                        f"{port.get('service', 'unknown')}"
                    )


                    if port.get(
                        "banner"
                    ):

                        banner = (
                            port["banner"]
                        )


                        if len(banner) > 80:

                            banner = (
                                banner[:80]
                                + "..."
                            )


                        print(
                            f"        Banner: "
                            f"{banner}"
                        )


    except ValueError as error:

        print(
            "\n[!] Domain validation failed: "
            f"{error}"
        )


    except KeyboardInterrupt:

        print(
            "\n[!] Collection interrupted by user."
        )


    except Exception as error:

        print(
            "\n[!] Collection error: "
            f"{error}"
        )