from collections import Counter
from ipaddress import ip_address
import json

from neo4j import GraphDatabase


# ============================================================
# NEO4J CONFIGURATION
# ============================================================

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USERNAME = "neo4j"


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe_json_load(value, default):
    """
    Safely convert a JSON string stored in Neo4j back into
    a Python object.

    Neo4j stores structured VirusTotal fields such as
    categories, popularity ranks, and DNS records as
    JSON strings.
    """

    if value is None:
        return default

    if isinstance(value, (dict, list)):
        return value

    try:
        return json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def classify_ip_version(ip):
    """
    Determine whether an IP address is IPv4 or IPv6.
    """

    try:
        parsed_ip = ip_address(ip)

        if parsed_ip.version == 4:
            return "IPv4"

        if parsed_ip.version == 6:
            return "IPv6"

    except ValueError:
        pass

    return "Unknown"


# ============================================================
# GRAPH DATA FOR CYTOSCAPE
# ============================================================

def get_domain_graph(domain, password):
    """
    Retrieve the actual Neo4j nodes and relationships associated
    with a target domain.

    Returns a Cytoscape-compatible structure:

    {
        "nodes": [...],
        "edges": [...]
    }
    """

    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(NEO4J_USERNAME, password)
    )

    try:
        with driver.session(database="neo4j") as session:

            result = session.run(
                """
                MATCH (d:Domain {value: $domain})
                OPTIONAL MATCH path = (d)-[*1..2]-(related)

                WITH d, collect(path) AS paths

                UNWIND paths AS path
                UNWIND nodes(path) AS node

                WITH d,
                     collect(DISTINCT node) AS nodes,
                     paths

                UNWIND paths AS path
                UNWIND relationships(path) AS rel

                RETURN
                    nodes,
                    collect(DISTINCT rel) AS relationships
                """,
                domain=domain
            )

            record = result.single()

            if not record:
                return {
                    "nodes": [],
                    "edges": []
                }

            nodes = []
            edges = []

            # ==================================================
            # NODES
            # ==================================================

            for node in record["nodes"]:

                labels = list(node.labels)

                if not labels:
                    continue

                node_type = labels[0]
                node_id = str(node.element_id)
                value = node.get("value", node_id)

                nodes.append(
                    {
                        "data": {
                            "id": node_id,
                            "label": str(value),
                            "type": node_type
                        }
                    }
                )

            # ==================================================
            # EDGES
            # ==================================================

            for relationship in record["relationships"]:

                edges.append(
                    {
                        "data": {
                            "id": str(relationship.element_id),
                            "source": str(
                                relationship.start_node.element_id
                            ),
                            "target": str(
                                relationship.end_node.element_id
                            ),
                            "label": relationship.type
                        }
                    }
                )

            return {
                "nodes": nodes,
                "edges": edges
            }

    finally:
        driver.close()


# ============================================================
# DOMAIN GRAPH ANALYSIS
# ============================================================

def get_domain_analysis(domain, password):
    """
    Analyze the Neo4j graph associated with a target domain.

    The analysis includes:

        - Domain information
        - VirusTotal intelligence
        - Subdomains
        - IP addresses
        - ASNs
        - Organizations
        - Certificates
        - Relationship counts
        - IPv4 / IPv6 distribution
        - Subdomain patterns
        - Graph-derived observations

    Returns a structured dictionary suitable for:

        - FastAPI
        - Dashboard
        - AI-assisted reporting
        - JSON output
    """

    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(NEO4J_USERNAME, password)
    )

    try:
        with driver.session(database="neo4j") as session:

            # ==================================================
            # 1. BASIC DOMAIN INFORMATION
            # ==================================================

            result = session.run(
                """
                MATCH (d:Domain {value: $domain})
                RETURN d.value AS domain
                """,
                domain=domain
            )

            record = result.single()

            if not record:
                return None

            # ==================================================
            # 2. VIRUSTOTAL INTELLIGENCE
            # ==================================================

            result = session.run(
                """
                MATCH (d:Domain {value: $domain})

                RETURN
                    d.vt_source AS source,
                    d.vt_method AS method,
                    d.vt_recorded_at AS recorded_at,
                    d.vt_reputation AS reputation,
                    d.vt_malicious AS malicious,
                    d.vt_suspicious AS suspicious,
                    d.vt_harmless AS harmless,
                    d.vt_undetected AS undetected,
                    d.vt_timeout AS timeout,
                    d.vt_registrar AS registrar,
                    d.vt_creation_date AS creation_date,
                    d.vt_last_modification_date AS last_modification_date,
                    d.vt_categories AS categories,
                    d.vt_popularity_ranks AS popularity_ranks,
                    d.vt_dns_records AS dns_records
                """,
                domain=domain
            )

            vt_record = result.single()

            virustotal = {}

            if vt_record:

                vt_fields = [
                    "source",
                    "method",
                    "recorded_at",
                    "reputation",
                    "malicious",
                    "suspicious",
                    "harmless",
                    "undetected",
                    "timeout",
                    "registrar",
                    "creation_date",
                    "last_modification_date",
                    "categories",
                    "popularity_ranks",
                    "dns_records"
                ]

                has_vt_data = any(
                    vt_record[field] is not None
                    for field in vt_fields
                )

                if has_vt_data:

                    virustotal = {
                        "source": vt_record["source"],
                        "method": vt_record["method"],
                        "recorded_at": vt_record["recorded_at"],
                        "reputation": vt_record["reputation"],
                        "malicious": vt_record["malicious"],
                        "suspicious": vt_record["suspicious"],
                        "harmless": vt_record["harmless"],
                        "undetected": vt_record["undetected"],
                        "timeout": vt_record["timeout"],
                        "registrar": vt_record["registrar"],
                        "creation_date": vt_record[
                            "creation_date"
                        ],
                        "last_modification_date": vt_record[
                            "last_modification_date"
                        ],
                        "categories": safe_json_load(
                            vt_record["categories"],
                            {}
                        ),
                        "popularity_ranks": safe_json_load(
                            vt_record["popularity_ranks"],
                            {}
                        ),
                        "dns_records": safe_json_load(
                            vt_record["dns_records"],
                            []
                        )
                    }

            # ==================================================
            # 3. SUBDOMAINS
            # ==================================================

            result = session.run(
                """
                MATCH (d:Domain {value: $domain})
                      -[:HAS_SUBDOMAIN]->
                      (s:Subdomain)

                RETURN DISTINCT s.value AS subdomain
                ORDER BY subdomain
                """,
                domain=domain
            )

            subdomains = [
                record["subdomain"]
                for record in result
                if record["subdomain"]
            ]

            # ==================================================
            # 4. IP ADDRESSES
            # ==================================================

            result = session.run(
                """
                MATCH (d:Domain {value: $domain})
                      -[:RESOLVES_TO]->
                      (ip:IPAddress)

                RETURN DISTINCT ip.value AS ip
                ORDER BY ip
                """,
                domain=domain
            )

            ip_addresses = [
                record["ip"]
                for record in result
                if record["ip"]
            ]

            # ==================================================
            # 5. ASNs
            # ==================================================

            result = session.run(
                """
                MATCH (d:Domain {value: $domain})
                      -[:RESOLVES_TO]->
                      (ip:IPAddress)
                      -[:BELONGS_TO_ASN]->
                      (asn:ASN)

                RETURN DISTINCT asn.value AS asn
                ORDER BY asn
                """,
                domain=domain
            )

            asns = [
                record["asn"]
                for record in result
                if record["asn"]
            ]

            # ==================================================
            # 6. ORGANIZATIONS
            # ==================================================

            result = session.run(
                """
                MATCH (d:Domain {value: $domain})
                      -[:RESOLVES_TO]->
                      (ip:IPAddress)
                      -[:ASSOCIATED_WITH]->
                      (org:Organization)

                RETURN DISTINCT org.value AS organization
                ORDER BY organization
                """,
                domain=domain
            )

            organizations = [
                record["organization"]
                for record in result
                if record["organization"]
            ]

            # ==================================================
            # 7. CERTIFICATES
            # ==================================================

            result = session.run(
                """
                MATCH (d:Domain {value: $domain})
                      -[:HAS_CERTIFICATE]->
                      (cert:Certificate)

                RETURN DISTINCT cert.value AS certificate
                ORDER BY certificate
                """,
                domain=domain
            )

            certificates = [
                record["certificate"]
                for record in result
                if record["certificate"]
            ]

            # ==================================================
            # 8. RELATIONSHIP COUNTS
            # ==================================================

            relationship_counts = {}

            relationship_queries = {

                "HAS_SUBDOMAIN": """
                    MATCH (d:Domain {value: $domain})
                          -[r:HAS_SUBDOMAIN]->
                          (:Subdomain)

                    RETURN count(r) AS count
                """,

                "RESOLVES_TO": """
                    MATCH (d:Domain {value: $domain})
                          -[r:RESOLVES_TO]->
                          (:IPAddress)

                    RETURN count(r) AS count
                """,

                "BELONGS_TO_ASN": """
                    MATCH (d:Domain {value: $domain})
                          -[:RESOLVES_TO]->
                          (ip:IPAddress)
                          -[r:BELONGS_TO_ASN]->
                          (:ASN)

                    RETURN count(r) AS count
                """,

                "ASSOCIATED_WITH": """
                    MATCH (d:Domain {value: $domain})
                          -[:RESOLVES_TO]->
                          (ip:IPAddress)
                          -[r:ASSOCIATED_WITH]->
                          (:Organization)

                    RETURN count(r) AS count
                """,

                "HAS_CERTIFICATE": """
                    MATCH (d:Domain {value: $domain})
                          -[r:HAS_CERTIFICATE]->
                          (:Certificate)

                    RETURN count(r) AS count
                """
            }

            for relationship_type, query in relationship_queries.items():

                result = session.run(
                    query,
                    domain=domain
                )

                relationship_record = result.single()

                relationship_counts[relationship_type] = (
                    relationship_record["count"]
                    if relationship_record
                    else 0
                )

            # ==================================================
            # 9. IP VERSION ANALYSIS
            # ==================================================

            ipv4_count = 0
            ipv6_count = 0
            unknown_ip_count = 0

            for ip in ip_addresses:

                version = classify_ip_version(ip)

                if version == "IPv4":
                    ipv4_count += 1

                elif version == "IPv6":
                    ipv6_count += 1

                else:
                    unknown_ip_count += 1

            ip_version_summary = {
                "ipv4": ipv4_count,
                "ipv6": ipv6_count,
                "unknown": unknown_ip_count
            }

            # ==================================================
            # 10. SUBDOMAIN PATTERN ANALYSIS
            # ==================================================

            numeric_leading_count = 0
            hyphen_count = 0
            multi_level_count = 0

            prefix_counter = Counter()

            normalized_domain = (
                domain.lower().rstrip(".")
            )

            for subdomain in subdomains:

                normalized_subdomain = (
                    subdomain.lower().rstrip(".")
                )

                # ----------------------------------------------
                # Remove root domain
                # ----------------------------------------------

                relative_name = normalized_subdomain

                suffix = "." + normalized_domain

                if normalized_subdomain.endswith(suffix):

                    relative_name = normalized_subdomain[
                        :-len(suffix)
                    ]

                # ----------------------------------------------
                # Numeric-leading hostname
                # ----------------------------------------------

                if (
                    relative_name
                    and relative_name[0].isdigit()
                ):
                    numeric_leading_count += 1

                # ----------------------------------------------
                # Hyphen-containing hostname
                # ----------------------------------------------

                if "-" in relative_name:
                    hyphen_count += 1

                # ----------------------------------------------
                # Multiple labels
                # ----------------------------------------------

                if "." in relative_name:
                    multi_level_count += 1

                # ----------------------------------------------
                # First label / prefix
                # ----------------------------------------------

                first_label = relative_name.split(".")[0]

                if first_label:
                    prefix_counter[first_label] += 1

            common_prefixes = [
                {
                    "prefix": prefix,
                    "count": count
                }
                for prefix, count
                in prefix_counter.most_common(10)
            ]

            subdomain_patterns = {
                "numeric_leading": numeric_leading_count,
                "contains_hyphen": hyphen_count,
                "multi_level": multi_level_count,
                "common_prefixes": common_prefixes
            }

            # ==================================================
            # 11. GRAPH-DERIVED OBSERVATIONS
            # ==================================================

            observations = []

            # --------------------------------------------------
            # Subdomain scale
            # --------------------------------------------------

            if len(subdomains) > 1000:

                observations.append(
                    f"The graph contains a large subdomain "
                    f"dataset with {len(subdomains):,} "
                    f"observed subdomains."
                )

            elif len(subdomains) > 0:

                observations.append(
                    f"The graph contains "
                    f"{len(subdomains):,} observed subdomains."
                )

            else:

                observations.append(
                    "No subdomains were observed in the graph."
                )

            # --------------------------------------------------
            # IP infrastructure
            # --------------------------------------------------

            if len(ip_addresses) > 1:

                observations.append(
                    f"The domain resolves to multiple IP "
                    f"addresses ({len(ip_addresses)} observed)."
                )

            elif len(ip_addresses) == 1:

                observations.append(
                    "The domain resolves to one observed "
                    "IP address."
                )

            else:

                observations.append(
                    "No IP addresses were observed for the domain."
                )

            # --------------------------------------------------
            # IPv4 / IPv6
            # --------------------------------------------------

            if ipv4_count > 0 and ipv6_count > 0:

                observations.append(
                    f"Both IPv4 ({ipv4_count}) and IPv6 "
                    f"({ipv6_count}) addresses are present."
                )

            elif ipv4_count > 0:

                observations.append(
                    f"Only IPv4 infrastructure was observed "
                    f"({ipv4_count} addresses)."
                )

            elif ipv6_count > 0:

                observations.append(
                    f"Only IPv6 infrastructure was observed "
                    f"({ipv6_count} addresses)."
                )

            # --------------------------------------------------
            # ASN correlation
            # --------------------------------------------------

            if len(asns) == 1:

                observations.append(
                    f"All observed IP infrastructure maps to "
                    f"a single ASN: {asns[0]}."
                )

            elif len(asns) > 1:

                observations.append(
                    f"The observed IP infrastructure maps to "
                    f"{len(asns)} different ASNs."
                )

            # --------------------------------------------------
            # Organization correlation
            # --------------------------------------------------

            if len(organizations) == 1:

                observations.append(
                    f"The observed IP infrastructure is "
                    f"associated with one organization: "
                    f"{organizations[0]}."
                )

            elif len(organizations) > 1:

                observations.append(
                    f"The observed IP infrastructure is "
                    f"associated with {len(organizations)} "
                    f"organizations."
                )

            # --------------------------------------------------
            # Certificates
            # --------------------------------------------------

            if len(certificates) > 1:

                observations.append(
                    f"The graph contains {len(certificates)} "
                    f"certificates associated with the domain."
                )

            elif len(certificates) == 1:

                observations.append(
                    "One certificate is associated with "
                    "the domain."
                )

            # --------------------------------------------------
            # Subdomain patterns
            # --------------------------------------------------

            if numeric_leading_count > 0:

                observations.append(
                    f"{numeric_leading_count:,} observed "
                    f"subdomains begin with a numeric character."
                )

            if hyphen_count > 0:

                observations.append(
                    f"{hyphen_count:,} observed subdomains "
                    f"contain a hyphen."
                )

            if multi_level_count > 0:

                observations.append(
                    f"{multi_level_count:,} observed subdomains "
                    f"contain multiple labels."
                )

            # ==================================================
            # 12. VIRUSTOTAL OBSERVATIONS
            # ==================================================

            if virustotal:

                malicious = virustotal.get("malicious")
                suspicious = virustotal.get("suspicious")
                harmless = virustotal.get("harmless")
                undetected = virustotal.get("undetected")
                reputation = virustotal.get("reputation")
                registrar = virustotal.get("registrar")

                # ----------------------------------------------
                # Detection results
                # ----------------------------------------------

                if malicious is not None:

                    observations.append(
                        f"VirusTotal reports {malicious} "
                        f"malicious detections for the domain."
                    )

                if suspicious is not None:

                    observations.append(
                        f"VirusTotal reports {suspicious} "
                        f"suspicious detections for the domain."
                    )

                if harmless is not None:

                    observations.append(
                        f"VirusTotal reports {harmless} "
                        f"harmless detections for the domain."
                    )

                if undetected is not None:

                    observations.append(
                        f"VirusTotal reports {undetected} "
                        f"undetected security engine results."
                    )

                # ----------------------------------------------
                # Reputation
                # ----------------------------------------------

                if reputation is not None:

                    observations.append(
                        f"VirusTotal reputation score is "
                        f"{reputation}."
                    )

                # ----------------------------------------------
                # Registrar
                # ----------------------------------------------

                if registrar:

                    observations.append(
                        f"The domain registrar reported by "
                        f"VirusTotal is {registrar}."
                    )

            # ==================================================
            # 13. RETURN STRUCTURED ANALYSIS
            # ==================================================

            return {
                "domain": record["domain"],

                "statistics": {
                    "subdomains": len(subdomains),
                    "ip_addresses": len(ip_addresses),
                    "asns": len(asns),
                    "organizations": len(organizations),
                    "certificates": len(certificates)
                },

                "relationships": relationship_counts,

                "ip_version_summary": ip_version_summary,

                "subdomain_patterns": subdomain_patterns,

                "infrastructure": {
                    "subdomains": subdomains,
                    "ip_addresses": ip_addresses,
                    "asns": asns,
                    "organizations": organizations,
                    "certificates": certificates
                },

                "virustotal": virustotal,

                "observations": observations
            }

    finally:
        driver.close()


# ============================================================
# COMMAND-LINE EXECUTION
# ============================================================

if __name__ == "__main__":

    domain = input(
        "Enter domain: "
    ).strip()

    password = input(
        "Enter Neo4j password: "
    )

    print("\n[*] Analyzing graph...")

    try:

        analysis = get_domain_analysis(
            domain,
            password
        )

        # ======================================================
        # DOMAIN NOT FOUND
        # ======================================================

        if analysis is None:

            print(
                f"[!] Domain not found in Neo4j: {domain}"
            )

        else:

            print(
                "\n[+] Graph analysis complete."
            )

            # ==================================================
            # DOMAIN
            # ==================================================

            print("\nDomain:")

            print(
                f"  {analysis['domain']}"
            )

            # ==================================================
            # STATISTICS
            # ==================================================

            print("\nStatistics:")

            for key, value in analysis[
                "statistics"
            ].items():

                print(
                    f"  {key}: {value}"
                )

            # ==================================================
            # RELATIONSHIPS
            # ==================================================

            print("\nRelationship Summary:")

            for key, value in analysis[
                "relationships"
            ].items():

                print(
                    f"  {key}: {value}"
                )

            # ==================================================
            # IP VERSION
            # ==================================================

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

            # ==================================================
            # SUBDOMAIN PATTERNS
            # ==================================================

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

            # ==================================================
            # VIRUSTOTAL
            # ==================================================

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

            # ==================================================
            # OBSERVATIONS
            # ==================================================

            print(
                "\nGraph-Derived Observations:"
            )

            for observation in analysis[
                "observations"
            ]:

                print(
                    f"  - {observation}"
                )

            # ==================================================
            # INFRASTRUCTURE
            # ==================================================

            print("\nInfrastructure:")

            print(
                f"\n  Subdomains: "
                f"{len(analysis['infrastructure']['subdomains'])}"
            )

            print(
                "\n  First 20 subdomains:"
            )

            for subdomain in analysis[
                "infrastructure"
            ]["subdomains"][:20]:

                print(
                    f"    - {subdomain}"
                )

            print("\n  IP Addresses:")

            for ip in analysis[
                "infrastructure"
            ]["ip_addresses"]:

                print(
                    f"    - {ip}"
                )

            print("\n  ASNs:")

            for asn in analysis[
                "infrastructure"
            ]["asns"]:

                print(
                    f"    - {asn}"
                )

            print("\n  Organizations:")

            for organization in analysis[
                "infrastructure"
            ]["organizations"]:

                print(
                    f"    - {organization}"
                )

            print("\n  Certificates:")

            for certificate in analysis[
                "infrastructure"
            ]["certificates"]:

                print(
                    f"    - {certificate}"
                )

    except Exception as error:

        print(
            f"[!] Graph analysis error: {error}"
        )