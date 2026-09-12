from datetime import datetime, timezone

from backend.services.collection_service import collect_domain_osint
from backend.normalizers.entity_normalizer import normalize_data
from backend.graph.neo4j_loader import load_normalized_data_object
from backend.analysis.graph_analyzer import get_domain_analysis
from backend.analysis.ai_reporter import generate_ai_report


# ============================================================
# COMPLETE OSINT PIPELINE
# ============================================================

def run_osint_pipeline(
    domain,
    password,
    progress_callback=None,
    scan_id=None,
    is_cancelled=None
):
    """
    Execute the complete Domain-Centric OSINT pipeline.

    Pipeline:

        Domain Input
             ↓
        Domain Validation
             ↓
        OSINT Collection
             ↓
        Entity Normalization
             ↓
        Neo4j Graph Loading
             ↓
        Graph Analysis
             ↓
        AI-Assisted Reporting

    OSINT Collection includes:
        - DNS
        - Subfinder
        - Amass
        - IP resolution
        - ASN / organization
        - Certificates
        - VirusTotal
        - TCP port scanning
        - Service/banner detection
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
        """Send progress update if callback is available."""

        update = {
            "step": step,
            "label": label,
            "message": message,
            "status": status,
            "progress": progress,
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat()
        }

        if progress_callback:
            try:
                progress_callback(update)
            except Exception as error:
                print(
                    f"[!] Progress callback error: {error}"
                )

        print(
            f"[{progress:3d}%] "
            f"[{status:9s}] "
            f"{label}: {message}"
        )

    # ========================================================
    # CANCELLATION HELPER
    # ========================================================

    def check_cancelled():
        """Check whether the current scan was cancelled."""

        if is_cancelled:

            try:
                if is_cancelled():
                    print(
                        "\n[!] Scan cancelled by user."
                    )
                    return True

            except Exception as error:
                print(
                    f"[!] Cancellation check error: {error}"
                )

        return False

    # ========================================================
    # 0. INITIALIZATION
    # ========================================================

    print("\n" + "=" * 60)
    print("DOMAIN-CENTRIC OSINT PIPELINE")
    print("=" * 60)

    if scan_id:
        print(f"[*] Scan ID: {scan_id}")

    if check_cancelled():
        return {
            "success": False,
            "message": "Scan cancelled"
        }

    update_progress(
        "init",
        "Initialization",
        "Pipeline started",
        "completed",
        5
    )

    # ========================================================
    # 1. OSINT COLLECTION
    # ========================================================

    print("\n" + "=" * 60)
    print("STEP 1 - OSINT COLLECTION")
    print("=" * 60)

    if check_cancelled():
        return {
            "success": False,
            "message": "Scan cancelled"
        }

    update_progress(
        "collection",
        "OSINT Collection",
        "Starting OSINT collection...",
        "running",
        10
    )

    try:

        raw_data = collect_domain_osint(
            domain,
            progress_callback=progress_callback,
            is_cancelled=is_cancelled
        )

    except Exception as error:

        update_progress(
            "collection",
            "OSINT Collection",
            f"Collection failed: {error}",
            "failed",
            70
        )

        raise

    if check_cancelled():
        return {
            "success": False,
            "message": "Scan cancelled"
        }

    # ========================================================
    # COLLECTION SUMMARY
    # ========================================================

    subdomain_count = len(
        raw_data.get("subdomains", [])
    )

    ip_addresses = raw_data.get(
        "ip_addresses",
        []
    )

    ip_count = len(ip_addresses)

    # --------------------------------------------------------
    # VirusTotal summary
    # --------------------------------------------------------

    vt_data = raw_data.get(
        "virustotal",
        {}
    )

    if vt_data and not vt_data.get("error"):

        vt_risk = vt_data.get(
            "risk_score",
            "N/A"
        )

        vt_malicious = vt_data.get(
            "security_summary",
            {}
        ).get(
            "malicious",
            0
        )

        print(
            f"[+] VirusTotal Risk Score: "
            f"{vt_risk}/100"
        )

        print(
            f"[+] VirusTotal Malicious "
            f"Detections: {vt_malicious}"
        )

    # --------------------------------------------------------
    # Port Scan summary
    # --------------------------------------------------------

    port_scan_data = raw_data.get(
        "port_scan",
        {}
    )

    if port_scan_data:

        if port_scan_data.get("error"):

            print(
                "[!] Port Scan Error: "
                f"{port_scan_data['error']}"
            )

        else:

            open_ports_total = port_scan_data.get(
                "open_ports_total",
                0
            )

            scanned_ips = port_scan_data.get(
                "scanned_ips",
                0
            )

            print(
                f"[+] Port Scan: "
                f"{open_ports_total} open "
                f"ports found on "
                f"{scanned_ips} IPs"
            )

            # Show detected services
            for ip_result in port_scan_data.get(
                "results",
                []
            ):

                ip = ip_result.get(
                    "ip",
                    "unknown"
                )

                for port in ip_result.get(
                    "open_ports",
                    []
                ):

                    print(
                        f"    {ip}:"
                        f"{port.get('port')}/tcp"
                        f" → "
                        f"{port.get('service', 'unknown')}"
                    )

    else:

        print(
            "[!] No port scan data returned."
        )

    # --------------------------------------------------------
    # Collection completed
    # --------------------------------------------------------

    update_progress(
        "collection_summary",
        "OSINT Collection",
        (
            f"Collected "
            f"{subdomain_count} subdomains, "
            f"{ip_count} IP addresses"
        ),
        "completed",
        70
    )

    print(
        "\n[+] OSINT collection completed."
    )

    # ========================================================
    # 2. ENTITY NORMALIZATION
    # ========================================================

    print("\n" + "=" * 60)
    print("STEP 2 - ENTITY NORMALIZATION")
    print("=" * 60)

    if check_cancelled():
        return {
            "success": False,
            "message": "Scan cancelled"
        }

    update_progress(
        "normalization",
        "Entity Normalization",
        "Normalizing entities...",
        "running",
        75
    )

    try:

        normalized_data = normalize_data(
            raw_data
        )

    except Exception as error:

        update_progress(
            "normalization",
            "Entity Normalization",
            f"Normalization failed: {error}",
            "failed",
            80
        )

        raise

    if check_cancelled():
        return {
            "success": False,
            "message": "Scan cancelled"
        }

    entity_count = len(
        normalized_data.get(
            "entities",
            []
        )
    )

    relationship_count = len(
        normalized_data.get(
            "relationships",
            []
        )
    )

    print(
        f"[+] Entities generated: "
        f"{entity_count}"
    )

    print(
        f"[+] Relationships generated: "
        f"{relationship_count}"
    )

    update_progress(
        "normalization",
        "Entity Normalization",
        (
            f"{entity_count} entities, "
            f"{relationship_count} relationships"
        ),
        "completed",
        80
    )

    # ========================================================
    # 3. NEO4J GRAPH LOADING
    # ========================================================

    print("\n" + "=" * 60)
    print("STEP 3 - NEO4J GRAPH LOADING")
    print("=" * 60)

    if check_cancelled():
        return {
            "success": False,
            "message": "Scan cancelled"
        }

    update_progress(
        "graph_loading",
        "Knowledge Graph",
        "Loading into Neo4j...",
        "running",
        85
    )

    try:

        load_normalized_data_object(
            normalized_data,
            password
        )

    except Exception as error:

        update_progress(
            "graph_loading",
            "Knowledge Graph",
            f"Neo4j loading failed: {error}",
            "failed",
            85
        )

        raise

    if check_cancelled():
        return {
            "success": False,
            "message": "Scan cancelled"
        }

    print(
        "[+] Neo4j graph loading completed."
    )

    update_progress(
        "graph_loading",
        "Knowledge Graph",
        "Graph updated",
        "completed",
        90
    )

    # ========================================================
    # 4. GRAPH ANALYSIS
    # ========================================================

    print("\n" + "=" * 60)
    print("STEP 4 - GRAPH ANALYSIS")
    print("=" * 60)

    if check_cancelled():
        return {
            "success": False,
            "message": "Scan cancelled"
        }

    update_progress(
        "graph_analysis",
        "Graph Analysis",
        "Analyzing knowledge graph...",
        "running",
        92
    )

    try:

        graph_analysis = get_domain_analysis(
            domain,
            password
        )

    except Exception as error:

        update_progress(
            "graph_analysis",
            "Graph Analysis",
            f"Graph analysis failed: {error}",
            "failed",
            92
        )

        raise

    if check_cancelled():
        return {
            "success": False,
            "message": "Scan cancelled"
        }

    if graph_analysis is None:

        raise RuntimeError(
            f"Domain '{domain}' was not found "
            "in Neo4j after graph loading."
        )

    print(
        "[+] Graph analysis completed."
    )

    update_progress(
        "graph_analysis",
        "Graph Analysis",
        "Analysis complete",
        "completed",
        95
    )

    # ========================================================
    # 5. AI-ASSISTED REPORTING
    # ========================================================

    print("\n" + "=" * 60)
    print("STEP 5 - AI-ASSISTED REPORTING")
    print("=" * 60)

    if check_cancelled():
        return {
            "success": False,
            "message": "Scan cancelled"
        }

    update_progress(
        "ai_report",
        "AI Intelligence Report",
        "Generating AI assessment...",
        "running",
        97
    )

    try:

        ai_report = generate_ai_report(
            graph_analysis
        )

    except Exception as error:

        update_progress(
            "ai_report",
            "AI Intelligence Report",
            f"Report generation failed: {error}",
            "failed",
            97
        )

        raise

    if check_cancelled():
        return {
            "success": False,
            "message": "Scan cancelled"
        }

    print(
        "[+] AI-assisted report generated."
    )

    update_progress(
        "ai_report",
        "AI Intelligence Report",
        "Report generated",
        "completed",
        100
    )

    # ========================================================
    # 6. FINAL PIPELINE RESULT
    # ========================================================

    if check_cancelled():
        return {
            "success": False,
            "message": "Scan cancelled"
        }

    update_progress(
        "complete",
        "Analysis Complete",
        f"Intelligence report for {domain} is ready",
        "completed",
        100
    )

    return {
        "success": True,
        "domain": domain,

        # Complete collected intelligence
        "raw_data": raw_data,

        # Normalized graph data
        "normalized_data": normalized_data,

        # Graph analysis
        "graph_analysis": graph_analysis,

        # AI report
        "ai_report": ai_report,

        # Convenient direct access for API/frontend
        "port_scan": raw_data.get(
            "port_scan",
            {}
        )
    }


# ============================================================
# COMMAND-LINE TEST
# ============================================================

if __name__ == "__main__":

    domain = input(
        "Enter domain: "
    ).strip()

    password = input(
        "Enter Neo4j password: "
    )

    print("\n")

    print("=" * 60)
    print("DOMAIN-CENTRIC OSINT PIPELINE")
    print("=" * 60)

    try:

        result = run_osint_pipeline(
            domain,
            password
        )

        # ====================================================
        # PIPELINE COMPLETE
        # ====================================================

        print("\n" + "=" * 60)
        print("PIPELINE COMPLETED SUCCESSFULLY")
        print("=" * 60)

        analysis = result["graph_analysis"]

        # ====================================================
        # BASIC SUMMARY
        # ====================================================

        print("\nDomain:")

        print(
            f"  {analysis['domain']}"
        )

        # ====================================================
        # STATISTICS
        # ====================================================

        print("\nStatistics:")

        for key, value in analysis[
            "statistics"
        ].items():

            print(
                f"  {key}: {value}"
            )

        # ====================================================
        # RELATIONSHIP SUMMARY
        # ====================================================

        print("\nRelationship Summary:")

        for key, value in analysis[
            "relationships"
        ].items():

            print(
                f"  {key}: {value}"
            )

        # ====================================================
        # IP VERSION SUMMARY
        # ====================================================

        print("\nIP Version Summary:")

        print(
            f"  IPv4: "
            f"{analysis['ip_version_summary']['ipv4']}"
        )

        print(
            f"  IPv6: "
            f"{analysis['ip_version_summary']['ipv6']}"
        )

        print(
            f"  Unknown: "
            f"{analysis['ip_version_summary']['unknown']}"
        )

        # ====================================================
        # SUBDOMAIN PATTERN SUMMARY
        # ====================================================

        print(
            "\nSubdomain Pattern Analysis:"
        )

        patterns = analysis[
            "subdomain_patterns"
        ]

        print(
            f"  Numeric-leading: "
            f"{patterns['numeric_leading']}"
        )

        print(
            f"  Contains hyphen: "
            f"{patterns['contains_hyphen']}"
        )

        print(
            f"  Multi-level: "
            f"{patterns['multi_level']}"
        )

        print(
            "\n  Common prefixes:"
        )

        for item in patterns[
            "common_prefixes"
        ]:

            print(
                f"    - {item['prefix']}: "
                f"{item['count']}"
            )

        # ====================================================
        # VIRUSTOTAL SUMMARY
        # ====================================================

        print(
            "\nVirusTotal Intelligence:"
        )

        virustotal = analysis.get(
            "virustotal",
            {}
        )

        if virustotal and not virustotal.get(
            "error"
        ):

            print(
                f"  Risk Score: "
                f"{virustotal.get('risk_score', 'N/A')}/100"
            )

            print(
                f"  Reputation: "
                f"{virustotal.get('reputation', 'N/A')}"
            )

            security_summary = virustotal.get(
                "security_summary",
                {}
            )

            print(
                f"  Malicious: "
                f"{security_summary.get('malicious', 0)}"
            )

            print(
                f"  Suspicious: "
                f"{security_summary.get('suspicious', 0)}"
            )

            print(
                f"  Harmless: "
                f"{security_summary.get('harmless', 0)}"
            )

            print(
                f"  Undetected: "
                f"{security_summary.get('undetected', 0)}"
            )

            print(
                f"  Total Vendors: "
                f"{security_summary.get('total_vendors', 0)}"
            )

            registrar = virustotal.get(
                "registrar",
                "N/A"
            )

            if registrar:
                print(
                    f"  Registrar: {registrar}"
                )

        elif virustotal and virustotal.get(
            "error"
        ):

            print(
                f"  Error: "
                f"{virustotal['error']}"
            )

        else:

            print(
                "  No VirusTotal intelligence found."
            )

        # ====================================================
        # PORT SCAN RESULTS
        # ====================================================

        print(
            "\nPort Scan Results:"
        )

        port_scan = result.get(
            "port_scan",
            {}
        )

        if port_scan and not port_scan.get(
            "error"
        ):

            print(
                f"  IPs Scanned: "
                f"{port_scan.get('scanned_ips', 0)}"
            )

            print(
                f"  Open Ports Total: "
                f"{port_scan.get('open_ports_total', 0)}"
            )

            if port_scan.get("results"):

                print(
                    "\n  Open Ports by IP:"
                )

                for ip_result in port_scan[
                    "results"
                ][:5]:

                    print(
                        f"    {ip_result['ip']}: "
                        f"{ip_result['open_count']} "
                        f"open ports"
                    )

                    for port in ip_result[
                        "open_ports"
                    ][:5]:

                        print(
                            f"      - "
                            f"{port['port']}/tcp "
                            f"→ "
                            f"{port.get('service', 'unknown')}"
                        )

                        if port.get("banner"):

                            banner = port[
                                "banner"
                            ]

                            if len(banner) > 100:
                                banner = (
                                    banner[:100]
                                    + "..."
                                )

                            print(
                                f"        Banner: "
                                f"{banner}"
                            )

                    if ip_result[
                        "open_count"
                    ] > 5:

                        print(
                            f"      ... and "
                            f"{ip_result['open_count'] - 5} "
                            f"more ports"
                        )

                if len(
                    port_scan["results"]
                ) > 5:

                    print(
                        f"  ... and "
                        f"{len(port_scan['results']) - 5} "
                        f"more IPs"
                    )

            else:

                print(
                    "  No open ports found."
                )

        else:

            print(
                "  No port scan data available."
            )

        # ====================================================
        # GRAPH-DERIVED OBSERVATIONS
        # ====================================================

        print(
            "\nGraph-Derived Observations:"
        )

        for observation in analysis[
            "observations"
        ]:

            print(
                f"  - {observation}"
            )

        # ====================================================
        # INFRASTRUCTURE SUMMARY
        # ====================================================

        print(
            "\nInfrastructure:"
        )

        infrastructure = analysis[
            "infrastructure"
        ]

        print(
            f"\n  Subdomains: "
            f"{len(infrastructure['subdomains'])}"
        )

        print(
            "\n  First 20 subdomains:"
        )

        for subdomain in infrastructure[
            "subdomains"
        ][:20]:

            print(
                f"    - {subdomain}"
            )

        print(
            "\n  IP Addresses:"
        )

        for ip in infrastructure[
            "ip_addresses"
        ]:

            print(
                f"    - {ip}"
            )

        print(
            "\n  ASNs:"
        )

        for asn in infrastructure[
            "asns"
        ]:

            print(
                f"    - {asn}"
            )

        print(
            "\n  Organizations:"
        )

        for organization in infrastructure[
            "organizations"
        ]:

            print(
                f"    - {organization}"
            )

        print(
            "\n  Certificates:"
        )

        for certificate in infrastructure[
            "certificates"
        ]:

            print(
                f"    - {certificate}"
            )

        # ====================================================
        # AI REPORT
        # ====================================================

        print("\n" + "=" * 60)
        print("AI-ASSISTED INTELLIGENCE REPORT")
        print("=" * 60)

        print(
            result["ai_report"]
        )

        print("\n" + "=" * 60)
        print("END OF PIPELINE")
        print("=" * 60)

    except ValueError as error:

        print(
            f"\n[!] Validation error: {error}"
        )

    except KeyboardInterrupt:

        print(
            "\n[!] Pipeline interrupted by user."
        )

    except Exception as error:

        print(
            f"\n[!] Pipeline error: {error}"
        )