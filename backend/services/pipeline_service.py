from backend.services.collection_service import collect_domain_osint
from backend.normalizers.entity_normalizer import normalize_data
from backend.graph.neo4j_loader import load_normalized_data_object
from backend.analysis.graph_analyzer import get_domain_analysis
from backend.analysis.ai_reporter import generate_ai_report


# ============================================================
# COMPLETE OSINT PIPELINE
# ============================================================

def run_osint_pipeline(domain, password):
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

    # ============================================================
    # 1. OSINT COLLECTION
    # ============================================================

    print("\n" + "=" * 60)
    print("STEP 1 - OSINT COLLECTION")
    print("=" * 60)

    raw_data = collect_domain_osint(domain)

    print("\n[+] OSINT collection completed.")

    # ============================================================
    # 2. ENTITY NORMALIZATION
    # ============================================================

    print("\n" + "=" * 60)
    print("STEP 2 - ENTITY NORMALIZATION")
    print("=" * 60)

    normalized_data = normalize_data(raw_data)

    print(
        f"[+] Entities generated: "
        f"{len(normalized_data.get('entities', []))}"
    )

    print(
        f"[+] Relationships generated: "
        f"{len(normalized_data.get('relationships', []))}"
    )

    # ============================================================
    # 3. NEO4J GRAPH LOADING
    # ============================================================

    print("\n" + "=" * 60)
    print("STEP 3 - NEO4J GRAPH LOADING")
    print("=" * 60)

    load_normalized_data_object(
        normalized_data,
        password
    )

    print("[+] Neo4j graph loading completed.")

    # ============================================================
    # 4. GRAPH ANALYSIS
    # ============================================================

    print("\n" + "=" * 60)
    print("STEP 4 - GRAPH ANALYSIS")
    print("=" * 60)

    graph_analysis = get_domain_analysis(
        domain,
        password
    )

    if graph_analysis is None:
        raise RuntimeError(
            f"Domain '{domain}' was not found in Neo4j "
            "after graph loading."
        )

    print("[+] Graph analysis completed.")

    # ============================================================
    # 5. AI-ASSISTED REPORTING
    # ============================================================

    print("\n" + "=" * 60)
    print("STEP 5 - AI-ASSISTED REPORTING")
    print("=" * 60)

    ai_report = generate_ai_report(
        graph_analysis
    )

    print("[+] AI-assisted report generated.")

    # ============================================================
    # 6. FINAL PIPELINE RESULT
    # ============================================================

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
        # VIRUSTOTAL SUMMARY
        # ========================================================

        print(
            "\nVirusTotal Intelligence:"
        )

        virustotal = analysis.get(
            "virustotal",
            {}
        )

        if virustotal:

            print(
                f"  Reputation: "
                f"{virustotal.get('reputation')}"
            )

            print(
                f"  Malicious: "
                f"{virustotal.get('malicious')}"
            )

            print(
                f"  Suspicious: "
                f"{virustotal.get('suspicious')}"
            )

            print(
                f"  Harmless: "
                f"{virustotal.get('harmless')}"
            )

            print(
                f"  Undetected: "
                f"{virustotal.get('undetected')}"
            )

            print(
                f"  Timeout: "
                f"{virustotal.get('timeout')}"
            )

            print(
                f"  Registrar: "
                f"{virustotal.get('registrar')}"
            )

            print(
                f"  Source: "
                f"{virustotal.get('source')}"
            )

            print(
                f"  Method: "
                f"{virustotal.get('method')}"
            )

            print(
                f"  Recorded At: "
                f"{virustotal.get('recorded_at')}"
            )

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