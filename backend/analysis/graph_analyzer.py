from collections import Counter
from neo4j import GraphDatabase


NEO4J_URI = "bolt://localhost:7687"
NEO4J_USERNAME = "neo4j"


def get_domain_analysis(domain, password):

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
            # 2. SUBDOMAINS
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
            ]

            # ==================================================
            # 3. IP ADDRESSES
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
            ]

            # ==================================================
            # 4. ASNs
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
            ]

            # ==================================================
            # 5. ORGANIZATIONS
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
            ]

            # ==================================================
            # 6. CERTIFICATES
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
            ]

            # ==================================================
            # 7. RELATIONSHIP COUNTS
            # ==================================================

            relationship_types = [
                "HAS_SUBDOMAIN",
                "RESOLVES_TO",
                "BELONGS_TO_ASN",
                "ASSOCIATED_WITH",
                "HAS_CERTIFICATE"
            ]

            relationship_counts = {}

            for relationship_type in relationship_types:

                result = session.run(
                    f"""
                    MATCH (a)-[r:{relationship_type}]->(b)
                    WHERE
                        (a:Domain AND a.value = $domain)
                        OR
                        (
                            a:IPAddress
                            AND EXISTS {{
                                MATCH (d:Domain {{value: $domain}})
                                      -[:RESOLVES_TO]->
                                      (a)
                            }}
                        )
                    RETURN count(r) AS count
                    """,
                    domain=domain
                )

                record_count = result.single()

                relationship_counts[relationship_type] = (
                    record_count["count"]
                    if record_count
                    else 0
                )

            # ==================================================
            # 8. IP VERSION ANALYSIS
            # ==================================================

            ipv4_count = 0
            ipv6_count = 0

            for ip in ip_addresses:

                if ":" in ip:
                    ipv6_count += 1
                else:
                    ipv4_count += 1

            ip_version_summary = {
                "ipv4": ipv4_count,
                "ipv6": ipv6_count
            }

            # ==================================================
            # 9. SUBDOMAIN PATTERN ANALYSIS
            # ==================================================

            numeric_leading_count = 0
            hyphen_count = 0
            multi_level_count = 0

            prefix_counter = Counter()

            for subdomain in subdomains:

                # Remove the root domain
                relative_name = subdomain

                suffix = "." + domain

                if subdomain.endswith(suffix):

                    relative_name = subdomain[:-len(suffix)]

                # Numeric-leading hostname
                if relative_name and relative_name[0].isdigit():
                    numeric_leading_count += 1

                # Hyphen-containing hostname
                if "-" in relative_name:
                    hyphen_count += 1

                # Multiple labels before root domain
                if "." in relative_name:
                    multi_level_count += 1

                # First label / prefix
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
            # 10. GRAPH-DERIVED OBSERVATIONS
            # ==================================================

            observations = []

            # Subdomain scale
            if len(subdomains) > 1000:

                observations.append(
                    f"The graph contains a large subdomain dataset "
                    f"with {len(subdomains):,} observed subdomains."
                )

            elif len(subdomains) > 0:

                observations.append(
                    f"The graph contains "
                    f"{len(subdomains):,} observed subdomains."
                )

            # IP infrastructure
            if len(ip_addresses) > 1:

                observations.append(
                    f"The domain resolves to multiple IP addresses "
                    f"({len(ip_addresses)} observed)."
                )

            elif len(ip_addresses) == 1:

                observations.append(
                    "The domain resolves to one observed IP address."
                )

            # IPv4 / IPv6
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

            # ASN correlation
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

            # Organization correlation
            if len(organizations) == 1:

                observations.append(
                    f"The observed IP infrastructure is associated "
                    f"with one organization: {organizations[0]}."
                )

            elif len(organizations) > 1:

                observations.append(
                    f"The observed IP infrastructure is associated "
                    f"with {len(organizations)} organizations."
                )

            # Certificates
            if len(certificates) > 1:

                observations.append(
                    f"The graph contains {len(certificates)} certificates "
                    f"associated with the domain."
                )

            elif len(certificates) == 1:

                observations.append(
                    "One certificate is associated with the domain."
                )

            # Subdomain patterns
            if numeric_leading_count > 0:

                observations.append(
                    f"{numeric_leading_count:,} observed subdomains "
                    f"begin with a numeric character."
                )

            if hyphen_count > 0:

                observations.append(
                    f"{hyphen_count:,} observed subdomains contain "
                    f"a hyphen."
                )

            if multi_level_count > 0:

                observations.append(
                    f"{multi_level_count:,} observed subdomains "
                    f"contain multiple labels."
                )

            # ==================================================
            # 11. RETURN STRUCTURED ANALYSIS
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

                "observations": observations
            }

    finally:

        driver.close()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    domain = input("Enter domain: ").strip()

    password = input("Enter Neo4j password: ")

    print("\n[*] Analyzing graph...")

    try:

        analysis = get_domain_analysis(
            domain,
            password
        )

        if analysis is None:

            print(
                f"[!] Domain not found in Neo4j: {domain}"
            )

        else:

            print("\n[+] Graph analysis complete.")

            # ------------------------------------------------
            # DOMAIN
            # ------------------------------------------------

            print("\nDomain:")
            print(f"  {analysis['domain']}")

            # ------------------------------------------------
            # STATISTICS
            # ------------------------------------------------

            print("\nStatistics:")

            for key, value in analysis["statistics"].items():

                print(
                    f"  {key}: {value}"
                )

            # ------------------------------------------------
            # RELATIONSHIPS
            # ------------------------------------------------

            print("\nRelationship Summary:")

            for key, value in analysis["relationships"].items():

                print(
                    f"  {key}: {value}"
                )

            # ------------------------------------------------
            # IP VERSION
            # ------------------------------------------------

            print("\nIP Version Summary:")

            print(
                f"  IPv4: "
                f"{analysis['ip_version_summary']['ipv4']}"
            )

            print(
                f"  IPv6: "
                f"{analysis['ip_version_summary']['ipv6']}"
            )

            # ------------------------------------------------
            # SUBDOMAIN PATTERNS
            # ------------------------------------------------

            print("\nSubdomain Pattern Analysis:")

            patterns = analysis["subdomain_patterns"]

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

            for item in patterns["common_prefixes"]:

                print(
                    f"    - {item['prefix']}: "
                    f"{item['count']}"
                )

            # ------------------------------------------------
            # OBSERVATIONS
            # ------------------------------------------------

            print("\nGraph-Derived Observations:")

            for observation in analysis["observations"]:

                print(
                    f"  - {observation}"
                )

            # ------------------------------------------------
            # INFRASTRUCTURE
            # ------------------------------------------------

            print("\nInfrastructure:")

            print(
                f"\n  Subdomains: "
                f"{len(analysis['infrastructure']['subdomains'])}"
            )

            print("\n  First 20 subdomains:")

            for subdomain in analysis["infrastructure"]["subdomains"][:20]:

                print(
                    f"    - {subdomain}"
                )

            print("\n  IP Addresses:")

            for ip in analysis["infrastructure"]["ip_addresses"]:

                print(
                    f"    - {ip}"
                )

            print("\n  ASNs:")

            for asn in analysis["infrastructure"]["asns"]:

                print(
                    f"    - {asn}"
                )

            print("\n  Organizations:")

            for organization in analysis["infrastructure"]["organizations"]:

                print(
                    f"    - {organization}"
                )

            print("\n  Certificates:")

            for certificate in analysis["infrastructure"]["certificates"]:

                print(
                    f"    - {certificate}"
                )

    except Exception as error:

        print(
            f"[!] Graph analysis error: {error}"
        )