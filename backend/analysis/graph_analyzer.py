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

    Some VirusTotal fields are stored as JSON strings.
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
        parsed_ip = ip_address(str(ip))

        if parsed_ip.version == 4:
            return "IPv4"

        if parsed_ip.version == 6:
            return "IPv6"

    except (ValueError, TypeError):
        pass

    return "Unknown"


def normalize_port(port):
    """
    Normalize a Neo4j port value.

    Neo4j may return ports as integers or strings.
    The analyzer uses strings consistently internally.
    """
    if port is None:
        return None

    value = str(port).strip()

    if not value:
        return None

    return value


def port_sort_key(port):
    """
    Sort numeric ports numerically while keeping non-numeric
    values valid.
    """
    try:
        return (0, int(port))
    except (TypeError, ValueError):
        return (1, str(port))


def unique_preserve_order(values):
    """
    Remove duplicates while preserving original order.
    """
    seen = set()
    result = []

    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)

    return result


# ============================================================
# PORT ANALYSIS HELPERS
# ============================================================

# These are conventional port/service associations.
# They are NOT treated as proof that a service is running.
COMMON_PORT_SERVICES = {
    "20": "FTP-data",
    "21": "FTP",
    "22": "SSH",
    "23": "Telnet",
    "25": "SMTP",
    "53": "DNS",
    "80": "HTTP",
    "110": "POP3",
    "111": "RPCBind",
    "135": "MS-RPC",
    "139": "NetBIOS",
    "143": "IMAP",
    "443": "HTTPS",
    "445": "SMB",
    "465": "SMTPS",
    "587": "SMTP submission",
    "993": "IMAPS",
    "995": "POP3S",
    "1433": "Microsoft SQL Server",
    "1521": "Oracle Database",
    "2049": "NFS",
    "2375": "Docker API",
    "2376": "Docker API TLS",
    "3000": "Common web application port",
    "3306": "MySQL",
    "3389": "RDP",
    "5432": "PostgreSQL",
    "5601": "Kibana",
    "5900": "VNC",
    "6379": "Redis",
    "6443": "Kubernetes API",
    "8080": "HTTP alternate",
    "8443": "HTTPS alternate",
    "9200": "Elasticsearch",
    "27017": "MongoDB",
}


def analyze_port_distribution(open_ports_by_ip):
    """
    Produce deterministic statistics about observed open ports.

    No security conclusion is made here.
    """

    all_ports = []

    for ports in open_ports_by_ip.values():
        for port in ports:
            normalized = normalize_port(port)

            if normalized is not None:
                all_ports.append(normalized)

    counter = Counter(all_ports)

    unique_ports = sorted(
        counter.keys(),
        key=port_sort_key
    )

    most_common = [
        {
            "port": port,
            "count": count,
            "conventional_service": COMMON_PORT_SERVICES.get(port)
        }
        for port, count in counter.most_common(10)
    ]

    conventional_services = []

    for port in unique_ports:
        service = COMMON_PORT_SERVICES.get(port)

        if service:
            conventional_services.append(
                {
                    "port": port,
                    "service": service,
                    "observed_on_ips": counter[port]
                }
            )

    ports_per_ip = {}

    for ip, ports in open_ports_by_ip.items():
        ports_per_ip[ip] = len(
            unique_preserve_order(
                normalize_port(port)
                for port in ports
                if normalize_port(port) is not None
            )
        )

    return {
        "unique_port_count": len(unique_ports),
        "unique_ports": unique_ports,
        "most_common_ports": most_common,
        "conventional_services": conventional_services,
        "ports_per_ip": ports_per_ip,
        "max_ports_on_single_ip": (
            max(ports_per_ip.values())
            if ports_per_ip
            else 0
        ),
        "average_ports_per_exposed_ip": (
            round(
                sum(ports_per_ip.values()) / len(ports_per_ip),
                2
            )
            if ports_per_ip
            else 0
        )
    }


# ============================================================
# SUBDOMAIN ANALYSIS
# ============================================================

def analyze_subdomain_structure(subdomains, domain):
    """
    Analyze naming and structural characteristics of observed
    subdomains.

    These are lexical observations only.
    """

    numeric_leading_count = 0
    hyphen_count = 0
    multi_level_count = 0

    environment_count = 0
    service_count = 0
    wildcard_count = 0

    environment_patterns = []
    service_patterns = []
    wildcard_patterns = []
    numeric_patterns = []

    prefix_counter = Counter()

    normalized_domain = str(domain).lower().rstrip(".")

    environment_regex = (
        r"(^|[.-])(dev|development|test|testing|stage|staging|"
        r"prod|production|qa|uat)([.-]|$)"
    )

    service_regex = (
        r"(^|[.-])(api|app|web|cdn|static|media|assets|auth|"
        r"login|mail|smtp|pop|imap|ftp|ssh|mysql|postgres|"
        r"redis|mongo|elastic)([.-]|$)"
    )

    import re

    for subdomain in subdomains:

        if not subdomain:
            continue

        normalized = str(subdomain).lower().rstrip(".")

        suffix = "." + normalized_domain

        if normalized.endswith(suffix):
            relative_name = normalized[:-len(suffix)]
        else:
            relative_name = normalized

        if not relative_name:
            continue

        if relative_name[0].isdigit():
            numeric_leading_count += 1
            numeric_patterns.append(subdomain)

        if "-" in relative_name:
            hyphen_count += 1

        if "." in relative_name:
            multi_level_count += 1

        first_label = relative_name.split(".")[0]

        if first_label:
            prefix_counter[first_label] += 1

        if re.search(environment_regex, relative_name):
            environment_count += 1
            environment_patterns.append(subdomain)

        if re.search(service_regex, relative_name):
            service_count += 1
            service_patterns.append(subdomain)

        if relative_name.startswith("*."):
            wildcard_count += 1
            wildcard_patterns.append(subdomain)

    total = len(subdomains)

    return {
        "numeric_leading": numeric_leading_count,
        "contains_hyphen": hyphen_count,
        "multi_level": multi_level_count,

        "environment_related": environment_count,
        "service_related": service_count,
        "wildcard": wildcard_count,

        "numeric_leading_percentage": (
            round((numeric_leading_count / total) * 100, 2)
            if total else 0
        ),

        "hyphen_percentage": (
            round((hyphen_count / total) * 100, 2)
            if total else 0
        ),

        "multi_level_percentage": (
            round((multi_level_count / total) * 100, 2)
            if total else 0
        ),

        "environment_patterns": environment_patterns[:100],
        "service_patterns": service_patterns[:100],
        "wildcard_patterns": wildcard_patterns[:100],
        "numeric_patterns": numeric_patterns[:100],

        "common_prefixes": [
            {
                "prefix": prefix,
                "count": count
            }
            for prefix, count
            in prefix_counter.most_common(10)
        ]
    }


# ============================================================
# INFRASTRUCTURE METRICS
# ============================================================

def calculate_infrastructure_metrics(
    subdomains,
    ip_addresses,
    asns,
    organizations,
    certificates,
    open_ports_by_ip
):
    """
    Calculate deterministic infrastructure metrics.

    These metrics describe the collected dataset. They do not
    determine security, maliciousness, ownership, or compromise.
    """

    subdomain_count = len(subdomains)
    ip_count = len(ip_addresses)
    asn_count = len(asns)
    organization_count = len(organizations)
    certificate_count = len(certificates)

    total_open_ports = sum(
        len(ports)
        for ports in open_ports_by_ip.values()
    )

    exposed_ip_count = len(open_ports_by_ip)

    metrics = {
        "subdomain_count": subdomain_count,
        "ip_count": ip_count,
        "asn_count": asn_count,
        "organization_count": organization_count,
        "certificate_count": certificate_count,

        "total_open_ports": total_open_ports,
        "ips_with_open_ports": exposed_ip_count,

        "subdomains_per_ip": (
            round(subdomain_count / ip_count, 2)
            if ip_count else 0
        ),

        "ips_per_subdomain": (
            round(ip_count / subdomain_count, 4)
            if subdomain_count else 0
        ),

        "certificates_per_domain": certificate_count,

        "asn_concentration": (
            round(1 / asn_count, 4)
            if asn_count == 1
            else None
        ),

        "port_exposure_percentage": (
            round(
                (exposed_ip_count / ip_count) * 100,
                2
            )
            if ip_count else 0
        )
    }

    return metrics


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

    The domain node is always preserved when it exists.
    """

    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(NEO4J_USERNAME, password)
    )

    try:
        with driver.session(database="neo4j") as session:

            # ------------------------------------------------
            # Retrieve domain + related nodes
            # ------------------------------------------------

            result = session.run(
                """
                MATCH (d:Domain {value: $domain})

                OPTIONAL MATCH path = (d)-[*1..2]-(related)

                WITH d,
                     collect(DISTINCT d) +
                     collect(DISTINCT related) AS raw_nodes,
                     collect(path) AS paths

                UNWIND raw_nodes AS node

                WITH
                    collect(DISTINCT node) AS nodes,
                    paths

                RETURN nodes,
                       paths
                """,
                domain=domain
            )

            record = result.single()

            if not record:
                return {
                    "nodes": [],
                    "edges": []
                }

            # ------------------------------------------------
            # NODES
            # ------------------------------------------------

            nodes = []
            node_ids = set()

            for node in record["nodes"]:

                if node is None:
                    continue

                labels = list(node.labels)

                if not labels:
                    continue

                node_type = labels[0]
                node_id = str(node.element_id)

                value = node.get("value", node_id)

                node_data = {
                    "id": node_id,
                    "label": str(value),
                    "type": node_type
                }

                # Port-specific properties
                if node_type == "Port":

                    port_value = normalize_port(
                        node.get("value")
                    )

                    if port_value:
                        node_data["label"] = port_value

                    service = node.get("service")

                    if service:
                        node_data["service"] = str(service)

                    banner = node.get("banner")

                    if banner:
                        node_data["banner"] = str(banner)[:200]

                # ServiceBanner properties
                if node_type == "ServiceBanner":

                    node_data["label"] = str(value)

                nodes.append({
                    "data": node_data
                })

                node_ids.add(node_id)

            # ------------------------------------------------
            # EDGES
            # ------------------------------------------------

            edges = []
            edge_ids = set()

            for path in record["paths"]:

                if path is None:
                    continue

                for relationship in path.relationships:

                    edge_id = str(relationship.element_id)

                    if edge_id in edge_ids:
                        continue

                    start_id = str(
                        relationship.start_node.element_id
                    )

                    target_id = str(
                        relationship.end_node.element_id
                    )

                    # Only include relationships whose endpoints
                    # are actually present in the node set.
                    if (
                        start_id not in node_ids
                        or target_id not in node_ids
                    ):
                        continue

                    edges.append(
                        {
                            "data": {
                                "id": edge_id,
                                "source": start_id,
                                "target": target_id,
                                "label": relationship.type
                            }
                        }
                    )

                    edge_ids.add(edge_id)

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

    The function performs deterministic analysis of collected
    graph data. It does not perform external lookups.

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

            domain_value = record["domain"]

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
                    d.vt_last_modification_date
                        AS last_modification_date,
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
                        "creation_date":
                            vt_record["creation_date"],
                        "last_modification_date":
                            vt_record[
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
            # 5. PORT SCAN RESULTS
            # ==================================================

            open_ports_by_ip = {}
            port_banners = {}

            # IMPORTANT:
            # Only ports connected to this domain's observed IPs
            # are retrieved.

            if ip_addresses:

                result = session.run(
                    """
                    MATCH (d:Domain {value: $domain})
                          -[:RESOLVES_TO]->
                          (ip:IPAddress)
                          -[:HAS_OPEN_PORT]->
                          (p:Port)

                    RETURN DISTINCT
                        ip.value AS ip,
                        p.value AS port

                    ORDER BY ip, port
                    """,
                    domain=domain
                )

                for record in result:

                    ip = record["ip"]
                    port = normalize_port(
                        record["port"]
                    )

                    if not ip or port is None:
                        continue

                    open_ports_by_ip.setdefault(
                        ip,
                        []
                    ).append(port)

                # Remove duplicates and sort ports.
                for ip, ports in open_ports_by_ip.items():

                    open_ports_by_ip[ip] = sorted(
                        unique_preserve_order(ports),
                        key=port_sort_key
                    )

                # ----------------------------------------------
                # Domain-scoped banners
                # ----------------------------------------------

                try:

                    result = session.run(
                        """
                        MATCH (d:Domain {value: $domain})
                              -[:RESOLVES_TO]->
                              (ip:IPAddress)
                              -[:HAS_OPEN_PORT]->
                              (p:Port)
                              -[:HAS_BANNER]->
                              (b:ServiceBanner)

                        RETURN DISTINCT
                            ip.value AS ip,
                            p.value AS port,
                            b.value AS banner
                        """,
                        domain=domain
                    )

                    for record in result:

                        ip = record["ip"]
                        port = normalize_port(
                            record["port"]
                        )
                        banner = record["banner"]

                        if (
                            not ip
                            or port is None
                            or banner is None
                        ):
                            continue

                        port_banners.setdefault(
                            ip,
                            {}
                        ).setdefault(
                            port,
                            []
                        ).append(
                            str(banner)
                        )

                except Exception:
                    # Banner data is supplementary.
                    # A missing banner must not break the
                    # main port analysis.
                    port_banners = {}

            port_distribution = analyze_port_distribution(
                open_ports_by_ip
            )

            port_scan_results = {
                "ip_count": len(open_ports_by_ip),

                "total_open_ports": sum(
                    len(ports)
                    for ports in open_ports_by_ip.values()
                ),

                "open_ports_by_ip":
                    open_ports_by_ip,

                "port_banners":
                    port_banners,

                "unique_port_count":
                    port_distribution[
                        "unique_port_count"
                    ],

                "unique_ports":
                    port_distribution[
                        "unique_ports"
                    ],

                "most_common_ports":
                    port_distribution[
                        "most_common_ports"
                    ],

                "conventional_services":
                    port_distribution[
                        "conventional_services"
                    ],

                "ports_per_ip":
                    port_distribution[
                        "ports_per_ip"
                    ],

                "max_ports_on_single_ip":
                    port_distribution[
                        "max_ports_on_single_ip"
                    ],

                "average_ports_per_exposed_ip":
                    port_distribution[
                        "average_ports_per_exposed_ip"
                    ]
            }

            # ==================================================
            # 6. ASNs
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
            # 7. ORGANIZATIONS
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
            # 8. CERTIFICATES
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
            # 9. RELATIONSHIP COUNTS
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
                """,

                "HAS_OPEN_PORT": """
                    MATCH (d:Domain {value: $domain})
                          -[:RESOLVES_TO]->
                          (ip:IPAddress)
                          -[r:HAS_OPEN_PORT]->
                          (:Port)

                    RETURN count(r) AS count
                """
            }

            for relationship_type, query in (
                relationship_queries.items()
            ):

                result = session.run(
                    query,
                    domain=domain
                )

                relationship_record = result.single()

                relationship_counts[
                    relationship_type
                ] = (
                    relationship_record["count"]
                    if relationship_record
                    else 0
                )

            # ==================================================
            # 10. IP VERSION ANALYSIS
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
            # 11. SUBDOMAIN PATTERN ANALYSIS
            # ==================================================

            subdomain_patterns = analyze_subdomain_structure(
                subdomains,
                domain_value
            )

            # ==================================================
            # 12. INFRASTRUCTURE METRICS
            # ==================================================

            infrastructure_metrics = (
                calculate_infrastructure_metrics(
                    subdomains,
                    ip_addresses,
                    asns,
                    organizations,
                    certificates,
                    open_ports_by_ip
                )
            )

            # ==================================================
            # 13. GRAPH-DERIVED OBSERVATIONS
            # ==================================================

            observations = []

            subdomain_count = len(subdomains)
            ip_count = len(ip_addresses)
            asn_count = len(asns)
            organization_count = len(organizations)
            certificate_count = len(certificates)

            # --------------------------------------------------
            # Subdomains
            # --------------------------------------------------

            if subdomain_count > 1000:

                observations.append(
                    f"The graph contains a large observed "
                    f"subdomain dataset with "
                    f"{subdomain_count:,} subdomains."
                )

            elif subdomain_count > 0:

                observations.append(
                    f"The graph contains "
                    f"{subdomain_count:,} observed subdomains."
                )

            else:

                observations.append(
                    "No subdomains were observed in the graph."
                )

            # --------------------------------------------------
            # IP addresses
            # --------------------------------------------------

            if ip_count > 1:

                observations.append(
                    f"The domain resolves to "
                    f"{ip_count} observed IP addresses."
                )

            elif ip_count == 1:

                observations.append(
                    "The domain resolves to one observed "
                    "IP address."
                )

            else:

                observations.append(
                    "No IP addresses were observed for the domain."
                )

            # --------------------------------------------------
            # IP version
            # --------------------------------------------------

            if ipv4_count > 0 and ipv6_count > 0:

                observations.append(
                    f"Both IPv4 ({ipv4_count}) and IPv6 "
                    f"({ipv6_count}) addresses are present "
                    f"in the observed IP dataset."
                )

            elif ipv4_count > 0:

                observations.append(
                    f"Only IPv4 addresses were observed "
                    f"({ipv4_count})."
                )

            elif ipv6_count > 0:

                observations.append(
                    f"Only IPv6 addresses were observed "
                    f"({ipv6_count})."
                )

            # --------------------------------------------------
            # Subdomain/IP concentration
            # --------------------------------------------------

            if subdomain_count > 0 and ip_count > 0:

                observations.append(
                    f"The observed dataset contains "
                    f"{infrastructure_metrics['subdomains_per_ip']:.2f} "
                    f"subdomains per observed IP address."
                )

            # --------------------------------------------------
            # ASN relationships
            # --------------------------------------------------

            if asn_count == 1:

                observations.append(
                    f"{relationship_counts['BELONGS_TO_ASN']} "
                    f"observed IP-to-ASN relationships map to "
                    f"one observed ASN: {asns[0]}."
                )

            elif asn_count > 1:

                observations.append(
                    f"The observed IP infrastructure maps to "
                    f"{asn_count} distinct ASNs."
                )

            # --------------------------------------------------
            # Organization relationships
            # --------------------------------------------------

            if organization_count == 1:

                observations.append(
                    f"{relationship_counts['ASSOCIATED_WITH']} "
                    f"observed IP-to-organization relationships "
                    f"are associated with one observed "
                    f"organization: {organizations[0]}."
                )

            elif organization_count > 1:

                observations.append(
                    f"The observed IP infrastructure has "
                    f"relationships with "
                    f"{organization_count} distinct "
                    f"organizations."
                )

            # --------------------------------------------------
            # Certificates
            # --------------------------------------------------

            if certificate_count > 1:

                observations.append(
                    f"The graph contains "
                    f"{certificate_count} certificates associated "
                    f"with the domain."
                )

            elif certificate_count == 1:

                observations.append(
                    "One certificate is associated with "
                    "the domain."
                )

            # --------------------------------------------------
            # Port scan
            # --------------------------------------------------

            total_open_ports = (
                port_scan_results[
                    "total_open_ports"
                ]
            )

            exposed_ip_count = (
                port_scan_results[
                    "ip_count"
                ]
            )

            if total_open_ports > 0:

                observations.append(
                    f"Port scanning identified "
                    f"{total_open_ports} open-port observations "
                    f"across {exposed_ip_count} IP addresses."
                )

                unique_port_count = (
                    port_scan_results[
                        "unique_port_count"
                    ]
                )

                observations.append(
                    f"{unique_port_count} distinct port numbers "
                    f"were observed."
                )

                most_common_ports = (
                    port_scan_results[
                        "most_common_ports"
                    ]
                )

                if most_common_ports:

                    common_ports_text = ", ".join(
                        f"{item['port']} "
                        f"({item['count']}x)"
                        for item in most_common_ports[:3]
                    )

                    observations.append(
                        f"The most frequently observed open "
                        f"ports were: {common_ports_text}."
                    )

            # --------------------------------------------------
            # Subdomain naming patterns
            # --------------------------------------------------

            numeric_count = (
                subdomain_patterns[
                    "numeric_leading"
                ]
            )

            if numeric_count > 0:

                observations.append(
                    f"{numeric_count:,} observed subdomains "
                    f"begin with a numeric character."
                )

            hyphen_count = (
                subdomain_patterns[
                    "contains_hyphen"
                ]
            )

            if hyphen_count > 0:

                observations.append(
                    f"{hyphen_count:,} observed subdomains "
                    f"contain a hyphen."
                )

            multi_level_count = (
                subdomain_patterns[
                    "multi_level"
                ]
            )

            if multi_level_count > 0:

                observations.append(
                    f"{multi_level_count:,} observed subdomains "
                    f"contain multiple labels below the target "
                    f"domain."
                )

            environment_count = (
                subdomain_patterns[
                    "environment_related"
                ]
            )

            if environment_count > 0:

                observations.append(
                    f"{environment_count:,} observed subdomains "
                    f"match predefined environment-related "
                    f"naming patterns."
                )

            service_count = (
                subdomain_patterns[
                    "service_related"
                ]
            )

            if service_count > 0:

                observations.append(
                    f"{service_count:,} observed subdomains "
                    f"match predefined service-related "
                    f"naming patterns."
                )

            # --------------------------------------------------
            # VirusTotal
            # --------------------------------------------------

            if virustotal:

                malicious = virustotal.get(
                    "malicious"
                )

                suspicious = virustotal.get(
                    "suspicious"
                )

                harmless = virustotal.get(
                    "harmless"
                )

                undetected = virustotal.get(
                    "undetected"
                )

                reputation = virustotal.get(
                    "reputation"
                )

                registrar = virustotal.get(
                    "registrar"
                )

                if malicious is not None:

                    observations.append(
                        f"VirusTotal reports "
                        f"{malicious} malicious detections "
                        f"for the domain."
                    )

                if suspicious is not None:

                    observations.append(
                        f"VirusTotal reports "
                        f"{suspicious} suspicious detections "
                        f"for the domain."
                    )

                if harmless is not None:

                    observations.append(
                        f"VirusTotal reports "
                        f"{harmless} harmless detections "
                        f"for the domain."
                    )

                if undetected is not None:

                    observations.append(
                        f"VirusTotal reports "
                        f"{undetected} undetected results "
                        f"for the domain."
                    )

                if reputation is not None:

                    observations.append(
                        f"VirusTotal reports a reputation "
                        f"score of {reputation}."
                    )

                if registrar:

                    observations.append(
                        f"VirusTotal reports the domain "
                        f"registrar as {registrar}."
                    )

            # ==================================================
            # 14. RETURN STRUCTURED ANALYSIS
            # ==================================================

            return {

                "domain": domain_value,

                "statistics": {
                    "subdomains": len(subdomains),
                    "ip_addresses": len(ip_addresses),
                    "asns": len(asns),
                    "organizations": len(organizations),
                    "certificates": len(certificates),
                    "open_ports":
                        port_scan_results[
                            "total_open_ports"
                        ]
                },

                "relationships":
                    relationship_counts,

                "ip_version_summary":
                    ip_version_summary,

                "subdomain_patterns":
                    subdomain_patterns,

                "infrastructure_metrics":
                    infrastructure_metrics,

                "port_scan":
                    port_scan_results,

                "infrastructure": {

                    "subdomains":
                        subdomains,

                    "ip_addresses":
                        ip_addresses,

                    "asns":
                        asns,

                    "organizations":
                        organizations,

                    "certificates":
                        certificates,

                    "open_ports":
                        open_ports_by_ip
                },

                "virustotal":
                    virustotal,

                "observations":
                    observations
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

        if analysis is None:

            print(
                f"[!] Domain not found in Neo4j: {domain}"
            )

        else:

            print(
                "\n[+] Graph analysis complete."
            )

            # ------------------------------------------------
            # Domain
            # ------------------------------------------------

            print("\nDomain:")
            print(
                f"  {analysis['domain']}"
            )

            # ------------------------------------------------
            # Statistics
            # ------------------------------------------------

            print("\nStatistics:")

            for key, value in (
                analysis["statistics"].items()
            ):

                print(
                    f"  {key}: {value}"
                )

            # ------------------------------------------------
            # Relationships
            # ------------------------------------------------

            print("\nRelationship Summary:")

            for key, value in (
                analysis["relationships"].items()
            ):

                print(
                    f"  {key}: {value}"
                )

            # ------------------------------------------------
            # IP Version
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

            print(
                f"  Unknown: "
                f"{analysis['ip_version_summary']['unknown']}"
            )

            # ------------------------------------------------
            # Port Scan
            # ------------------------------------------------

            print("\nPort Scan Results:")

            port_scan = analysis.get(
                "port_scan",
                {}
            )

            print(
                f"  IPs with open ports: "
                f"{port_scan.get('ip_count', 0)}"
            )

            print(
                f"  Total open ports: "
                f"{port_scan.get('total_open_ports', 0)}"
            )

            print(
                f"  Unique ports: "
                f"{port_scan.get('unique_port_count', 0)}"
            )

            unique_ports = port_scan.get(
                "unique_ports",
                []
            )

            if unique_ports:

                print(
                    "  Port numbers: "
                    + ", ".join(unique_ports)
                )

            most_common_ports = port_scan.get(
                "most_common_ports",
                []
            )

            if most_common_ports:

                print("\n  Most Common Ports:")

                for item in most_common_ports:

                    service = item.get(
                        "conventional_service"
                    )

                    service_text = (
                        f" ({service})"
                        if service
                        else ""
                    )

                    print(
                        f"    - "
                        f"{item['port']}: "
                        f"{item['count']} occurrence(s)"
                        f"{service_text}"
                    )

            open_ports = port_scan.get(
                "open_ports_by_ip",
                {}
            )

            if open_ports:

                print("\n  Open Ports by IP:")

                for ip, ports in list(
                    open_ports.items()
                )[:10]:

                    print(
                        f"    {ip}: "
                        f"{', '.join(ports)}"
                    )

                if len(open_ports) > 10:

                    print(
                        f"    ... and "
                        f"{len(open_ports) - 10} "
                        f"more IPs"
                    )

            # ------------------------------------------------
            # Subdomain Pattern Analysis
            # ------------------------------------------------

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
                f"  Environment-related: "
                f"{patterns['environment_related']}"
            )

            print(
                f"  Service-related: "
                f"{patterns['service_related']}"
            )

            print(
                f"  Wildcard: "
                f"{patterns['wildcard']}"
            )

            print("\n  Common prefixes:")

            for item in patterns[
                "common_prefixes"
            ]:

                print(
                    f"    - {item['prefix']}: "
                    f"{item['count']}"
                )

            # ------------------------------------------------
            # Infrastructure Metrics
            # ------------------------------------------------

            print(
                "\nInfrastructure Metrics:"
            )

            metrics = analysis.get(
                "infrastructure_metrics",
                {}
            )

            print(
                f"  Subdomains per IP: "
                f"{metrics.get('subdomains_per_ip', 0)}"
            )

            print(
                f"  IPs with open ports: "
                f"{metrics.get('ips_with_open_ports', 0)}"
            )

            print(
                f"  Port exposure percentage: "
                f"{metrics.get('port_exposure_percentage', 0)}%"
            )

            # ------------------------------------------------
            # VirusTotal
            # ------------------------------------------------

            print(
                "\nVirusTotal Intelligence:"
            )

            virustotal = analysis.get(
                "virustotal",
                {}
            )

            if virustotal:

                for field in [
                    "reputation",
                    "malicious",
                    "suspicious",
                    "harmless",
                    "undetected",
                    "timeout",
                    "registrar",
                    "source",
                    "method",
                    "recorded_at"
                ]:

                    print(
                        f"  {field}: "
                        f"{virustotal.get(field)}"
                    )

            else:

                print(
                    "  No VirusTotal intelligence found."
                )

            # ------------------------------------------------
            # Observations
            # ------------------------------------------------

            print(
                "\nGraph-Derived Observations:"
            )

            for observation in analysis[
                "observations"
            ]:

                print(
                    f"  - {observation}"
                )

            # ------------------------------------------------
            # Infrastructure
            # ------------------------------------------------

            print("\nInfrastructure:")

            infrastructure = analysis[
                "infrastructure"
            ]

            print(
                f"  Subdomains: "
                f"{len(infrastructure['subdomains'])}"
            )

            print("\n  First 20 subdomains:")

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

    except Exception as error:

        print(
            f"[!] Graph analysis error: {error}"
        )