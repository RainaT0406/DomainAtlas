from backend.services.collection_service import collect_domain_osint
from backend.normalizers.entity_normalizer import normalize_data
from backend.graph.neo4j_loader import load_normalized_data_object
from backend.analysis.graph_analyzer import get_domain_analysis
from backend.analysis.ai_reporter import generate_ai_report
from datetime import datetime


# ============================================================
# COMPLETE OSINT PIPELINE
# ============================================================

def run_osint_pipeline(domain, password, progress_callback=None, scan_id=None, is_cancelled=None):
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

    Parameters
    ----------
    domain : str
        Target domain supplied by the analyst.

    password : str
        Neo4j database password.

    progress_callback : callable, optional
        Function to call with progress updates.
        Receives dict with:
        - step: str (unique step identifier)
        - label: str (human-readable step name)
        - message: str (current action)
        - status: str ('running', 'completed', 'failed')
        - progress: int (0-100)

    scan_id : str, optional
        Unique identifier for the scan.

    is_cancelled : callable, optional
        Function that returns True if the scan should be cancelled.

    Returns
    -------
    dict
        Complete pipeline result containing:

        - domain
        - raw_data
        - normalized_data
        - graph_analysis
        - ai_report
    """

    def update_progress(step, label, message, status, progress):
        """Send progress update if callback provided."""
        update = {
            "step": step,
            "label": label,
            "message": message,
            "status": status,
            "progress": progress,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if progress_callback:
            progress_callback(update)
        
        print(f"[{progress:3d}%] [{status:9s}] {label}: {message}")

    def check_cancelled():
        """Check if the scan has been cancelled."""
        if is_cancelled and is_cancelled():
            print("\n[!] Scan cancelled by user.")
            return True
        return False

    # ============================================================
    # 0. INITIALIZATION
    # ============================================================

    print("\n" + "=" * 60)
    print("DOMAIN-CENTRIC OSINT PIPELINE")
    print("=" * 60)

    if scan_id:
        print(f"[*] Scan ID: {scan_id}")

    # Check if cancelled
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    update_progress(
        "init",
        "Initialization",
        "Pipeline started",
        "completed",
        5
    )

    # ============================================================
    # 1. OSINT COLLECTION
    # ============================================================

    print("\n" + "=" * 60)
    print("STEP 1 - OSINT COLLECTION")
    print("=" * 60)

    # Check if cancelled
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    # OSINT Collection (with progress from collection_service)
    raw_data = collect_domain_osint(
        domain,
        progress_callback=progress_callback,
        is_cancelled=is_cancelled  # Pass cancellation check to collection_service
    )

    # Check if cancelled after collection
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    subdomain_count = len(
        raw_data.get("subdomains", [])
    )

    # Show VirusTotal summary
    vt_data = raw_data.get("virustotal", {})
    if vt_data and not vt_data.get("error"):
        vt_risk = vt_data.get("risk_score", "N/A")
        vt_malicious = vt_data.get("security_summary", {}).get("malicious", 0)
        print(f"[+] VirusTotal Risk Score: {vt_risk}/100")
        print(f"[+] VirusTotal Malicious Detections: {vt_malicious}")

    update_progress(
        "collection_summary",
        "OSINT Collection",
        f"Collected {subdomain_count} subdomains",
        "completed",
        70
    )

    print("\n[+] OSINT collection completed.")

    # ============================================================
    # 2. ENTITY NORMALIZATION
    # ============================================================

    print("\n" + "=" * 60)
    print("STEP 2 - ENTITY NORMALIZATION")
    print("=" * 60)

    # Check if cancelled
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    update_progress(
        "normalization",
        "Entity Normalization",
        "Normalizing entities...",
        "running",
        75
    )

    normalized_data = normalize_data(raw_data)

    # Check if cancelled after normalization
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    entity_count = len(
        normalized_data.get("entities", [])
    )

    relationship_count = len(
        normalized_data.get("relationships", [])
    )

    print(
        f"[+] Entities generated: {entity_count}"
    )

    print(
        f"[+] Relationships generated: {relationship_count}"
    )

    update_progress(
        "normalization",
        "Entity Normalization",
        f"{entity_count} entities, {relationship_count} relationships",
        "completed",
        80
    )

    # ============================================================
    # 3. NEO4J GRAPH LOADING
    # ============================================================

    print("\n" + "=" * 60)
    print("STEP 3 - NEO4J GRAPH LOADING")
    print("=" * 60)

    # Check if cancelled
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    update_progress(
        "graph_loading",
        "Knowledge Graph",
        "Loading into Neo4j...",
        "running",
        85
    )

    load_normalized_data_object(
        normalized_data,
        password
    )

    # Check if cancelled after graph loading
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    print("[+] Neo4j graph loading completed.")

    update_progress(
        "graph_loading",
        "Knowledge Graph",
        "Graph updated",
        "completed",
        90
    )

    # ============================================================
    # 4. GRAPH ANALYSIS
    # ============================================================

    print("\n" + "=" * 60)
    print("STEP 4 - GRAPH ANALYSIS")
    print("=" * 60)

    # Check if cancelled
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    update_progress(
        "graph_analysis",
        "Graph Analysis",
        "Analyzing knowledge graph...",
        "running",
        92
    )

    graph_analysis = get_domain_analysis(
        domain,
        password
    )

    # Check if cancelled after graph analysis
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    if graph_analysis is None:
        raise RuntimeError(
            f"Domain '{domain}' was not found in Neo4j "
            "after graph loading."
        )

    print("[+] Graph analysis completed.")

    update_progress(
        "graph_analysis",
        "Graph Analysis",
        "Analysis complete",
        "completed",
        95
    )

    # ============================================================
    # 5. AI-ASSISTED REPORTING
    # ============================================================

    print("\n" + "=" * 60)
    print("STEP 5 - AI-ASSISTED REPORTING")
    print("=" * 60)

    # Check if cancelled
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    update_progress(
        "ai_report",
        "AI Intelligence Report",
        "Generating AI assessment...",
        "running",
        97
    )

    ai_report = generate_ai_report(
        graph_analysis
    )

    # Check if cancelled after AI report
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    print("[+] AI-assisted report generated.")

    update_progress(
        "ai_report",
        "AI Intelligence Report",
        "Report generated",
        "completed",
        100
    )

    # ============================================================
    # 6. FINAL PIPELINE RESULT
    # ============================================================

    # Final cancellation check
    if check_cancelled():
        return {"success": False, "message": "Scan cancelled"}

    update_progress(
        "complete",
        "Analysis Complete",
        f"Intelligence report for {domain} is ready",
        "completed",
        100
    )

    return {
        "domain": domain,
        "raw_data": raw_data,
        "normalized_data": normalized_data,
        "graph_analysis": graph_analysis,
        "ai_report": ai_report
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

        # ========================================================
        # PIPELINE COMPLETE
        # ========================================================

        print("\n" + "=" * 60)
        print("PIPELINE COMPLETED SUCCESSFULLY")
        print("=" * 60)

        # ========================================================
        # BASIC SUMMARY
        # ========================================================

        analysis = result["graph_analysis"]

        print("\nDomain:")

        print(
            f"  {analysis['domain']}"
        )

        # ========================================================
        # STATISTICS
        # ========================================================

        print("\nStatistics:")

        for key, value in analysis[
            "statistics"
        ].items():

            print(
                f"  {key}: {value}"
            )

        # ========================================================
        # RELATIONSHIP SUMMARY
        # ========================================================

        print("\nRelationship Summary:")

        for key, value in analysis[
            "relationships"
        ].items():

            print(
                f"  {key}: {value}"
            )

        # ========================================================
        # IP VERSION SUMMARY
        # ========================================================

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

        # ========================================================
        # SUBDOMAIN PATTERN SUMMARY
        # ========================================================

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

        print("\n  Common prefixes:")

        for item in patterns[
            "common_prefixes"
        ]:

            print(
                f"    - {item['prefix']}: "
                f"{item['count']}"
            )

        # ========================================================
        # VIRUSTOTAL SUMMARY (ENHANCED)
        # ========================================================

        print(
            "\nVirusTotal Intelligence:"
        )

        virustotal = analysis.get(
            "virustotal",
            {}
        )

        if virustotal and not virustotal.get("error"):

            print(
                f"  Risk Score: "
                f"{virustotal.get('risk_score', 'N/A')}/100"
            )
            
            print(
                f"  Reputation: "
                f"{virustotal.get('reputation', 'N/A')}"
            )

            security_summary = virustotal.get("security_summary", {})
            print(f"  Malicious: {security_summary.get('malicious', 0)}")
            print(f"  Suspicious: {security_summary.get('suspicious', 0)}")
            print(f"  Harmless: {security_summary.get('harmless', 0)}")
            print(f"  Undetected: {security_summary.get('undetected', 0)}")
            print(f"  Total Vendors: {security_summary.get('total_vendors', 0)}")

            registrar = virustotal.get('registrar', 'N/A')
            if registrar:
                print(f"  Registrar: {registrar}")

            # Show risk factors
            risk_factors = virustotal.get('risk_factors', [])
            if risk_factors:
                print("\n  Risk Factors:")
                for factor in risk_factors:
                    print(f"    - [{factor['severity'].upper()}] {factor['description']}")
                    for detail in factor.get('details', [])[:2]:
                        print(f"      • {detail}")

            # Show vendor breakdown
            vendor_breakdown = virustotal.get('vendor_breakdown', [])
            malicious_vendors = [v for v in vendor_breakdown if v['status'] == 'malicious']
            if malicious_vendors:
                print("\n  Malicious Vendors:")
                for vendor in malicious_vendors[:5]:
                    print(f"    - {vendor['vendor']}: {vendor['result']}")

        elif virustotal and virustotal.get("error"):
            print(f"  Error: {virustotal['error']}")

        else:

            print(
                "  No VirusTotal intelligence found."
            )

        # ========================================================
        # GRAPH-DERIVED OBSERVATIONS
        # ========================================================

        print(
            "\nGraph-Derived Observations:"
        )

        for observation in analysis[
            "observations"
        ]:

            print(
                f"  - {observation}"
            )

        # ========================================================
        # INFRASTRUCTURE SUMMARY
        # ========================================================

        print("\nInfrastructure:")

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

        print("\n  IP Addresses:")

        for ip in infrastructure[
            "ip_addresses"
        ]:

            print(
                f"    - {ip}"
            )

        print("\n  ASNs:")

        for asn in infrastructure[
            "asns"
        ]:

            print(
                f"    - {asn}"
            )

        print("\n  Organizations:")

        for organization in infrastructure[
            "organizations"
        ]:

            print(
                f"    - {organization}"
            )

        print("\n  Certificates:")

        for certificate in infrastructure[
            "certificates"
        ]:

            print(
                f"    - {certificate}"
            )

        # ========================================================
        # AI REPORT
        # ========================================================

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

    except Exception as error:

        print(
            f"\n[!] Pipeline error: {error}"
        )