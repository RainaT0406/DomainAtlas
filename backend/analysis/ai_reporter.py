"""
AI-Assisted Intelligence Reporting for DomainAtlas

The LLM is used only to interpret deterministic observations
already collected by the DomainAtlas pipeline.

Design principles:
- No external lookups
- No invented facts
- No unsupported security conclusions
- Deterministic metrics are calculated before the LLM call
- Port-scan results are consumed directly from the collector format
- VirusTotal observations remain explicitly attributed to VirusTotal
"""

import re
from collections import Counter
from typing import Any, Dict, List, Optional

import ollama

from backend.analysis.graph_analyzer import get_domain_analysis


# ============================================================
# GENERIC HELPERS
# ============================================================

def safe_list(value: Any) -> List[Any]:
    """Return a list regardless of whether input is None/singleton/list."""

    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, tuple):
        return list(value)

    if isinstance(value, set):
        return list(value)

    return [value]


def unique_values(values: List[Any]) -> List[Any]:
    """Preserve order while removing duplicates."""

    result = []
    seen = set()

    for value in values:
        key = str(value)

        if key not in seen:
            seen.add(key)
            result.append(value)

    return result


def format_list(values: List[Any], limit: Optional[int] = None) -> str:
    """Format a list safely for the LLM prompt."""

    values = safe_list(values)

    if not values:
        return "None observed."

    if limit is not None:
        displayed = values[:limit]
    else:
        displayed = values

    lines = [f"- {str(value)}" for value in displayed]

    if limit is not None and len(values) > limit:
        lines.append(
            f"- ... {len(values) - limit} additional item(s) not shown"
        )

    return "\n".join(lines)


# ============================================================
# SUBDOMAIN ANALYSIS
# ============================================================

def analyze_subdomains(
    subdomains: List[str],
    domain: str
) -> Dict[str, Any]:
    """
    Identify lexical patterns in observed subdomains.

    These are observations based solely on names.
    They do not establish the purpose or status of a system.
    """

    environment_patterns = []
    service_patterns = []
    wildcard_patterns = []
    numeric_patterns = []

    environment_regex = re.compile(
        r"(?:^|[-.])(dev|development|test|testing|stage|staging|"
        r"prod|production|qa|uat)(?:[-.]|$)",
        re.IGNORECASE
    )

    service_regex = re.compile(
        r"(?:^|[-.])(api|app|web|cdn|static|media|assets|auth|"
        r"login|mail|smtp|pop|imap|ftp|ssh|mysql|postgres|redis|"
        r"mongo|elastic)(?:[-.]|$)",
        re.IGNORECASE
    )

    numeric_regex = re.compile(
        r"(?:\d+-\d+|\d+\.\d+|[-.]\d+[-.]?)"
    )

    for original in safe_list(subdomains):

        subdomain = str(original).strip()
        clean = subdomain.lower().rstrip(".")

        suffix = "." + domain.lower().rstrip(".")

        if clean.endswith(suffix):
            clean = clean[:-len(suffix)]

        if re.search(r"^\*\.", clean):
            wildcard_patterns.append(subdomain)

        if environment_regex.search(clean):
            environment_patterns.append(subdomain)

        if service_regex.search(clean):
            service_patterns.append(subdomain)

        if numeric_regex.search(clean):
            numeric_patterns.append(subdomain)

    return {
        "environment_patterns": unique_values(environment_patterns),
        "service_patterns": unique_values(service_patterns),
        "wildcard_patterns": unique_values(wildcard_patterns),
        "numeric_patterns": unique_values(numeric_patterns),
    }


# ============================================================
# DNS / INFRASTRUCTURE ANALYSIS
# ============================================================

def analyze_dns_structure(
    subdomains: List[str],
    ip_addresses: List[str]
) -> Dict[str, Any]:
    """
    Calculate simple deterministic relationships between
    observed subdomain and IP counts.

    These metrics describe the collected dataset only.
    """

    unique_subdomains = unique_values(subdomains)
    unique_ips = unique_values(ip_addresses)

    subdomain_count = len(unique_subdomains)
    ip_count = len(unique_ips)

    if ip_count:
        subdomains_per_ip = subdomain_count / ip_count
    else:
        subdomains_per_ip = 0

    if subdomain_count:
        ips_per_subdomain = ip_count / subdomain_count
    else:
        ips_per_subdomain = 0

    return {
        "unique_subdomain_count": subdomain_count,
        "unique_ip_count": ip_count,
        "subdomains_per_ip": round(subdomains_per_ip, 2),
        "ips_per_subdomain": round(ips_per_subdomain, 4),
    }


# ============================================================
# IP VERSION ANALYSIS
# ============================================================

def analyze_ip_versions(
    ip_version_summary: Dict[str, Any]
) -> Dict[str, Any]:

    ipv4 = int(ip_version_summary.get("ipv4", 0) or 0)
    ipv6 = int(ip_version_summary.get("ipv6", 0) or 0)
    unknown = int(ip_version_summary.get("unknown", 0) or 0)

    total = ipv4 + ipv6 + unknown

    if total:
        ipv4_percentage = round((ipv4 / total) * 100, 1)
        ipv6_percentage = round((ipv6 / total) * 100, 1)
    else:
        ipv4_percentage = 0
        ipv6_percentage = 0

    return {
        "ipv4": ipv4,
        "ipv6": ipv6,
        "unknown": unknown,
        "total": total,
        "ipv4_percentage": ipv4_percentage,
        "ipv6_percentage": ipv6_percentage,
    }


# ============================================================
# PORT-SCAN NORMALIZATION
# ============================================================

def normalize_port_scan(
    analysis: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Normalize DomainAtlas port-scan output.

    Expected collector structure:

    {
        "port_scan": {
            "scanned_ips": ...,
            "open_ports_total": ...,
            "results": [
                {
                    "ip": "...",
                    "scan_time": ...,
                    "open_count": ...,
                    "open_ports": [
                        {
                            "port": 443,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "HTTPS",
                            "banner": "...",
                            "banner_available": True
                        }
                    ]
                }
            ]
        }
    }

    The function also tolerates older dictionary-style data.
    """

    infrastructure = analysis.get("infrastructure", {})

    if not isinstance(infrastructure, dict):
        infrastructure = {}

    # --------------------------------------------------------
    # Find port scan container
    # --------------------------------------------------------

    port_scan = infrastructure.get("port_scan")

    if not isinstance(port_scan, dict):
        port_scan = analysis.get("port_scan", {})

    if not isinstance(port_scan, dict):
        port_scan = {}

    # --------------------------------------------------------
    # New collector format
    # --------------------------------------------------------

    results = port_scan.get("results", [])

    if isinstance(results, list):

        normalized_results = []

        for result in results:

            if not isinstance(result, dict):
                continue

            ip = str(result.get("ip", "")).strip()

            if not ip:
                continue

            raw_ports = result.get("open_ports", [])

            if not isinstance(raw_ports, list):
                raw_ports = []

            ports = []

            for item in raw_ports:

                if not isinstance(item, dict):
                    continue

                port = item.get("port")

                if port is None:
                    continue

                ports.append({
                    "port": port,
                    "protocol": item.get("protocol", "tcp"),
                    "state": item.get("state", "open"),
                    "service": item.get("service", "unknown"),
                    "banner": item.get("banner"),
                    "banner_available": bool(
                        item.get("banner_available", False)
                    )
                })

            normalized_results.append({
                "ip": ip,
                "scan_time": result.get("scan_time"),
                "open_count": len(ports),
                "open_ports": ports
            })

        return build_port_statistics(
            normalized_results,
            scanned_ips=port_scan.get("scanned_ips"),
            reported_total=port_scan.get("open_ports_total")
        )

    # --------------------------------------------------------
    # Older dictionary format
    # --------------------------------------------------------

    old_format = infrastructure.get("open_ports")

    if isinstance(old_format, dict):

        normalized_results = []

        for ip, ports in old_format.items():

            normalized_ports = []

            for port in safe_list(ports):

                if isinstance(port, dict):

                    normalized_ports.append({
                        "port": port.get("port"),
                        "protocol": port.get("protocol", "tcp"),
                        "state": port.get("state", "open"),
                        "service": port.get("service", "unknown"),
                        "banner": port.get("banner"),
                        "banner_available": bool(
                            port.get("banner_available", False)
                        )
                    })

                else:

                    try:
                        port_number = int(port)
                    except (TypeError, ValueError):
                        continue

                    normalized_ports.append({
                        "port": port_number,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "unknown",
                        "banner": None,
                        "banner_available": False
                    })

            normalized_results.append({
                "ip": str(ip),
                "scan_time": None,
                "open_count": len(normalized_ports),
                "open_ports": normalized_ports
            })

        return build_port_statistics(
            normalized_results,
            scanned_ips=len(normalized_results)
        )

    # --------------------------------------------------------
    # No port scan data
    # --------------------------------------------------------

    return {
        "available": False,
        "scanned_ips": 0,
        "ips_with_open_ports": 0,
        "total_open_ports": 0,
        "unique_open_ports": [],
        "port_frequency": {},
        "service_frequency": {},
        "protocol_frequency": {},
        "banner_count": 0,
        "results": []
    }


# ============================================================
# PORT STATISTICS
# ============================================================

def build_port_statistics(
    results: List[Dict[str, Any]],
    scanned_ips: Optional[int] = None,
    reported_total: Optional[int] = None
) -> Dict[str, Any]:

    port_counter = Counter()
    service_counter = Counter()
    protocol_counter = Counter()

    total_open_ports = 0
    banner_count = 0

    for result in results:

        for item in result.get("open_ports", []):

            port = item.get("port")

            if port is not None:
                port_counter[str(port)] += 1

            service = item.get("service")

            if service:
                service_counter[str(service)] += 1

            protocol = item.get("protocol")

            if protocol:
                protocol_counter[str(protocol)] += 1

            total_open_ports += 1

            if item.get("banner_available"):
                banner_count += 1

    # Prefer actual parsed result count.
    # Do not blindly trust a separately reported count.
    if total_open_ports == 0 and reported_total:
        total_open_ports = int(reported_total)

    ips_with_open_ports = len([
        result for result in results
        if result.get("open_count", 0) > 0
    ])

    return {
        "available": True,
        "scanned_ips": (
            int(scanned_ips)
            if scanned_ips is not None
            else len(results)
        ),
        "ips_with_open_ports": ips_with_open_ports,
        "total_open_ports": total_open_ports,
        "unique_open_ports": sorted(
            port_counter.keys(),
            key=lambda x: int(x) if x.isdigit() else x
        ),
        "port_frequency": dict(port_counter),
        "service_frequency": dict(service_counter),
        "protocol_frequency": dict(protocol_counter),
        "banner_count": banner_count,
        "results": results
    }


# ============================================================
# PORT ANALYSIS
# ============================================================

def analyze_port_scan(
    port_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Produce evidence-based observations from port scan data.

    No security classification is performed.
    """

    if not port_data.get("available"):
        return {
            "available": False,
            "observations": []
        }

    observations = []

    scanned_ips = port_data.get("scanned_ips", 0)
    ips_with_open_ports = port_data.get("ips_with_open_ports", 0)
    total_open_ports = port_data.get("total_open_ports", 0)

    port_frequency = port_data.get("port_frequency", {})
    service_frequency = port_data.get("service_frequency", {})

    # --------------------------------------------------------
    # Coverage
    # --------------------------------------------------------

    if scanned_ips > 0:

        coverage = round(
            (ips_with_open_ports / scanned_ips) * 100,
            1
        )

        observations.append(
            f"{ips_with_open_ports} of {scanned_ips} scanned IP "
            f"addresses had at least one detected open TCP port "
            f"({coverage}%)."
        )

    # --------------------------------------------------------
    # Port distribution
    # --------------------------------------------------------

    if total_open_ports:

        observations.append(
            f"{total_open_ports} open TCP port observations were "
            f"recorded across the scanned IP addresses."
        )

    # --------------------------------------------------------
    # Common ports
    # --------------------------------------------------------

    common_ports = Counter(port_frequency).most_common(5)

    if common_ports:

        formatted = ", ".join(
            f"{port} ({count} occurrence"
            f"{'s' if count != 1 else ''})"
            for port, count in common_ports
        )

        observations.append(
            f"The most frequently observed open ports were: "
            f"{formatted}."
        )

    # --------------------------------------------------------
    # Services
    # --------------------------------------------------------

    common_services = Counter(service_frequency).most_common(5)

    if common_services:

        formatted = ", ".join(
            f"{service} ({count})"
            for service, count in common_services
        )

        observations.append(
            f"The most frequently identified services were: "
            f"{formatted}."
        )

    # --------------------------------------------------------
    # Banner coverage
    # --------------------------------------------------------

    banner_count = port_data.get("banner_count", 0)

    if total_open_ports:

        banner_percentage = round(
            (banner_count / total_open_ports) * 100,
            1
        )

        observations.append(
            f"Service banners were obtained for {banner_count} "
            f"of {total_open_ports} open-port observations "
            f"({banner_percentage}%)."
        )

    return {
        "available": True,
        "observations": observations
    }


# ============================================================
# RELATIONSHIP ANALYSIS
# ============================================================

def analyze_relationships(
    relationships: Dict[str, Any]
) -> List[str]:

    observations = []

    if not isinstance(relationships, dict):
        return observations

    for relationship, count in relationships.items():

        try:
            numeric_count = int(count)
        except (TypeError, ValueError):
            continue

        if numeric_count > 0:

            observations.append(
                f"{relationship}: {numeric_count} observed relationship(s)."
            )

    return observations


# ============================================================
# DATASET-LEVEL ANALYSIS
# ============================================================

def build_deterministic_analysis(
    analysis: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Build an evidence-based analytical layer before the LLM call.

    This is important for DomainAtlas because the LLM should not
    invent analytical facts.
    """

    domain = str(analysis.get("domain", ""))

    statistics = analysis.get("statistics", {})
    infrastructure = analysis.get("infrastructure", {})

    if not isinstance(statistics, dict):
        statistics = {}

    if not isinstance(infrastructure, dict):
        infrastructure = {}

    subdomains = safe_list(
        infrastructure.get("subdomains", [])
    )

    ip_addresses = safe_list(
        infrastructure.get("ip_addresses", [])
    )

    asns = safe_list(
        infrastructure.get("asns", [])
    )

    organizations = safe_list(
        infrastructure.get("organizations", [])
    )

    certificates = safe_list(
        infrastructure.get("certificates", [])
    )

    ip_version_summary = analysis.get(
        "ip_version_summary",
        {}
    )

    if not isinstance(ip_version_summary, dict):
        ip_version_summary = {}

    dns_structure = analyze_dns_structure(
        subdomains,
        ip_addresses
    )

    ip_versions = analyze_ip_versions(
        ip_version_summary
    )

    subdomain_patterns = analyze_subdomains(
        subdomains,
        domain
    )

    port_data = normalize_port_scan(
        analysis
    )

    port_analysis = analyze_port_scan(
        port_data
    )

    # --------------------------------------------------------
    # Concentration observations
    # --------------------------------------------------------

    observations = []

    if (
        dns_structure["unique_subdomain_count"] > 0
        and dns_structure["unique_ip_count"] > 0
    ):
        observations.append(
            f"The collected dataset contains approximately "
            f"{dns_structure['subdomains_per_ip']} observed "
            f"subdomains per unique IP address."
        )

    if len(asns) == 1 and len(ip_addresses) > 1:
        observations.append(
            "All observed IP addresses are associated with "
            "one observed ASN in the supplied graph data."
        )

    if len(organizations) == 1 and len(ip_addresses) > 1:
        observations.append(
            "All observed IP infrastructure is associated with "
            "one observed organization in the supplied graph data."
        )

    if ip_versions["ipv4"] > 0 and ip_versions["ipv6"] == 0:
        observations.append(
            "Only IPv4 addresses were observed in the supplied "
            "IP-version data."
        )

    elif ip_versions["ipv6"] > 0 and ip_versions["ipv4"] == 0:
        observations.append(
            "Only IPv6 addresses were observed in the supplied "
            "IP-version data."
        )

    if (
        subdomain_patterns["environment_patterns"]
        and subdomain_patterns["service_patterns"]
    ):
        observations.append(
            "Both environment-related and service-related "
            "subdomain naming patterns were observed."
        )

    observations.extend(
        port_analysis.get("observations", [])
    )

    return {
        "domain": domain,
        "statistics": statistics,
        "relationships": analysis.get("relationships", {}),
        "subdomains": subdomains,
        "ip_addresses": ip_addresses,
        "asns": asns,
        "organizations": organizations,
        "certificates": certificates,
        "ip_versions": ip_versions,
        "dns_structure": dns_structure,
        "subdomain_patterns": subdomain_patterns,
        "port_data": port_data,
        "port_analysis": port_analysis,
        "observations": observations
    }


# ============================================================
# VIRUSTOTAL FORMATTER
# ============================================================

def format_virustotal(
    virustotal: Any
) -> str:

    if not isinstance(virustotal, dict) or not virustotal:
        return "No VirusTotal intelligence was supplied."

    fields = [
        ("Source", "source"),
        ("Method", "method"),
        ("Recorded At", "recorded_at"),
        ("Reputation", "reputation"),
        ("Malicious detections", "malicious"),
        ("Suspicious detections", "suspicious"),
        ("Harmless detections", "harmless"),
        ("Undetected results", "undetected"),
        ("Timeout results", "timeout"),
        ("Registrar", "registrar"),
        ("Creation Date", "creation_date"),
        ("Last Modification Date", "last_modification_date"),
        ("Categories", "categories"),
        ("Popularity Ranks", "popularity_ranks"),
        ("DNS Records", "dns_records"),
    ]

    lines = []

    for label, key in fields:

        value = virustotal.get(key)

        if value is not None:
            lines.append(
                f"{label}: {value}"
            )

    return "\n".join(lines) if lines else "No VirusTotal fields were supplied."


# ============================================================
# PORT SCAN PROMPT FORMATTER
# ============================================================

def format_port_scan(
    port_data: Dict[str, Any]
) -> str:

    if not port_data.get("available"):
        return "No port-scan data was supplied."

    lines = [
        f"Scanned IPs: {port_data.get('scanned_ips', 0)}",
        f"IPs with open ports: {port_data.get('ips_with_open_ports', 0)}",
        f"Total open TCP ports: {port_data.get('total_open_ports', 0)}",
        f"Unique open ports: "
        f"{', '.join(port_data.get('unique_open_ports', [])) or 'None'}",
        f"Banner observations: {port_data.get('banner_count', 0)}",
        "",
        "Port frequency:"
    ]

    for port, count in sorted(
        port_data.get("port_frequency", {}).items(),
        key=lambda item: (
            int(item[0]) if str(item[0]).isdigit() else 999999
        )
    ):
        lines.append(
            f"- TCP/{port}: {count}"
        )

    lines.append("")
    lines.append("Service frequency:")

    for service, count in sorted(
        port_data.get("service_frequency", {}).items(),
        key=lambda item: (-item[1], item[0])
    ):
        lines.append(
            f"- {service}: {count}"
        )

    lines.append("")
    lines.append("Open ports by IP:")

    for result in port_data.get("results", []):

        ip = result.get("ip", "unknown")

        ports = result.get("open_ports", [])

        if not ports:
            continue

        port_descriptions = []

        for item in ports:

            port = item.get("port")
            service = item.get("service", "unknown")

            description = f"TCP/{port} ({service})"

            if item.get("banner_available"):
                description += " [banner available]"

            port_descriptions.append(description)

        lines.append(
            f"- {ip}: {', '.join(port_descriptions)}"
        )

    return "\n".join(lines)


# ============================================================
# AI REPORT GENERATOR
# ============================================================

def generate_ai_report(
    analysis: Dict[str, Any]
) -> str:
    """
    Generate an evidence-grounded intelligence report.

    The deterministic layer performs calculations first.
    Ollama then converts those observations into readable
    analytical prose.
    """

    if not isinstance(analysis, dict):
        raise ValueError(
            "Analysis data must be provided as a dictionary."
        )

    for field in [
        "domain",
        "statistics",
        "infrastructure"
    ]:

        if field not in analysis:

            raise ValueError(
                f"Required analysis field missing: {field}"
            )

    # ========================================================
    # DETERMINISTIC ANALYSIS
    # ========================================================

    data = build_deterministic_analysis(
        analysis
    )

    domain = data["domain"]
    statistics = data["statistics"]
    relationships = data["relationships"]

    subdomains = data["subdomains"]
    ip_addresses = data["ip_addresses"]
    asns = data["asns"]
    organizations = data["organizations"]
    certificates = data["certificates"]

    ip_versions = data["ip_versions"]
    dns_structure = data["dns_structure"]
    patterns = data["subdomain_patterns"]

    port_data = data["port_data"]

    graph_observations = analysis.get(
        "observations",
        []
    )

    if not isinstance(graph_observations, list):
        graph_observations = []

    all_observations = unique_values(
        data["observations"] + graph_observations
    )

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    relationship_lines = analyze_relationships(
        relationships
    )

    relationships_text = (
        "\n".join(
            f"- {item}"
            for item in relationship_lines
        )
        if relationship_lines
        else "No relationship counts were supplied."
    )

    # ========================================================
    # VIRUSTOTAL
    # ========================================================

    virustotal = analysis.get(
        "virustotal",
        {}
    )

    virustotal_text = format_virustotal(
        virustotal
    )

    # ========================================================
    # OBSERVATIONS
    # ========================================================

    observations_text = (
        "\n".join(
            f"- {item}"
            for item in all_observations
        )
        if all_observations
        else "No deterministic observations were supplied."
    )

    # ========================================================
    # PORT SCAN
    # ========================================================

    port_scan_text = format_port_scan(
        port_data
    )

    # ========================================================
    # SYSTEM PROMPT
    # ========================================================

    system_prompt = """
You are the AI-assisted intelligence reporting component
of DomainAtlas.

Your job is to perform LIMITED analytical interpretation of
the supplied OSINT dataset.

You are NOT an external researcher.

You MUST NOT:
- perform external lookups
- use internet knowledge
- invent facts
- invent entities
- invent relationships
- invent vulnerabilities
- infer ownership
- infer compromise
- classify a domain as malicious or benign
- claim that infrastructure is secure or insecure
- claim that an organization owns the domain
- treat a port being open as proof of a vulnerability
- treat a certificate as proof of legitimacy or security
- treat VirusTotal results as an independent verdict

However, you SHOULD perform legitimate analytical reasoning
from the supplied evidence.

Examples of ALLOWED analysis:

1. If many observed subdomains exist relative to the number
   of observed IP addresses, state that the collected dataset
   shows multiple subdomains per observed IP on average.

2. If multiple IP addresses map to one observed ASN, state that
   the observed IP infrastructure is concentrated in one ASN.

3. If multiple open ports occur repeatedly across several IPs,
   state that those ports recur across the scanned infrastructure.

4. If different service names occur in the port-scan results,
   state which services were observed and how frequently.

5. If environment-related names and service-related names both
   occur among subdomains, state that both naming patterns are
   present.

6. If banners were obtained for only some open ports, state
   that service identification from banners was partial.

7. If IPv4 is observed while IPv6 is absent, state exactly that.
   Do not infer a security implication from it.

Analytical statements MUST be traceable to supplied values
or simple calculations from those values.

Do not turn correlation into causation.

Do not turn association into ownership.

Do not turn observation into classification.

Preserve graph relationship direction.

For example:

Domain -> RESOLVES_TO -> IPAddress
IPAddress -> BELONGS_TO_ASN -> ASN

should be described as:

"The domain resolves to the observed IP addresses, and those
IP addresses map to the observed ASN."

Never say:

"The domain belongs to the ASN."

Similarly:

IPAddress -> ASSOCIATED_WITH -> Organization

must be described as an association with the observed IP
infrastructure, not as domain ownership.

VirusTotal observations must explicitly be attributed to
VirusTotal.

Port-scan observations must be described as observations from
the DomainAtlas TCP scan. An open port indicates that the TCP
connection test succeeded during the scan; it does not by itself
establish a vulnerability, compromise, or security weakness.

Use precise language such as:
- observed
- detected
- recorded
- associated
- mapped
- recurring
- concentrated
- distributed
- represented in the collected dataset
- indicates, when the statement follows directly from the data

Avoid unsupported language such as:
- secure
- insecure
- malicious
- benign
- suspicious
- compromised
- vulnerable
- dangerous
- trusted
- legitimate
- robust
- high-risk
- low-risk

Return exactly the requested six sections followed by one
limitation sentence.

Do not create additional headings.
"""

    # ========================================================
    # USER PROMPT
    # ========================================================

    prompt = f"""
Generate an analytical OSINT intelligence report for:

DOMAIN
{domain}

============================================================
GRAPH STATISTICS
============================================================

Observed subdomains:
{statistics.get("subdomains", len(subdomains))}

Observed IP addresses:
{statistics.get("ip_addresses", len(ip_addresses))}

Observed ASNs:
{statistics.get("asns", len(asns))}

Observed organizations:
{statistics.get("organizations", len(organizations))}

Observed certificates:
{statistics.get("certificates", len(certificates))}

Observed open ports:
{statistics.get("open_ports", port_data.get("total_open_ports", 0))}

============================================================
IP VERSION DISTRIBUTION
============================================================

IPv4:
{ip_versions["ipv4"]}

IPv6:
{ip_versions["ipv6"]}

Unknown:
{ip_versions["unknown"]}

IPv4 percentage:
{ip_versions["ipv4_percentage"]}%

IPv6 percentage:
{ip_versions["ipv6_percentage"]}%

============================================================
DNS / INFRASTRUCTURE METRICS
============================================================

Unique observed subdomains:
{dns_structure["unique_subdomain_count"]}

Unique observed IP addresses:
{dns_structure["unique_ip_count"]}

Observed subdomains per IP:
{dns_structure["subdomains_per_ip"]}

Observed IPs per subdomain:
{dns_structure["ips_per_subdomain"]}

These are descriptive ratios calculated from the supplied
dataset. Do not treat them as security scores.

============================================================
SUBDOMAIN NAMING PATTERNS
============================================================

Environment-related names:
{len(patterns["environment_patterns"])}

Service-related names:
{len(patterns["service_patterns"])}

Wildcard patterns:
{len(patterns["wildcard_patterns"])}

Numeric patterns:
{len(patterns["numeric_patterns"])}

Examples of environment-related names:
{format_list(patterns["environment_patterns"], 10)}

Examples of service-related names:
{format_list(patterns["service_patterns"], 10)}

============================================================
GRAPH RELATIONSHIPS
============================================================

{relationships_text}

============================================================
DETERMINISTIC OBSERVATIONS
============================================================

{observations_text}

============================================================
PORT SCAN RESULTS
============================================================

{port_scan_text}

IMPORTANT:

These port results come from the DomainAtlas TCP port scanner.

An open port means that the scanner successfully established
a TCP connection to that port during the scan.

Do not claim that an open port is vulnerable, insecure,
malicious, compromised, or dangerous.

Service names are based on the scanner's configured port
mapping and, where available, banner-based identification.

Banner-based identification is observational and may be absent
for some open ports.

============================================================
OBSERVED IP ADDRESSES
============================================================

{format_list(ip_addresses)}

============================================================
OBSERVED ASNs
============================================================

{format_list(asns)}

============================================================
OBSERVED ORGANIZATIONS
============================================================

{format_list(organizations)}

============================================================
OBSERVED CERTIFICATES
============================================================

{format_list(certificates, 20)}

============================================================
OBSERVED SUBDOMAINS
============================================================

Only the first 20 observed subdomains are provided.

Do not reproduce a complete subdomain list.

{format_list(subdomains, 20)}

============================================================
VIRUSTOTAL INTELLIGENCE
============================================================

{virustotal_text}

============================================================
REPORT FORMAT
============================================================

Produce exactly these six sections.

1. Domain Infrastructure

Discuss:
- the observed domain
- observed subdomain count
- observed IP count
- IPv4/IPv6 distribution
- the subdomain-to-IP relationship
- directly supported infrastructure structure
- relevant deterministic observations

Do not merely repeat the numbers.

Where appropriate, explain what the ratios mean descriptively.

Example of acceptable analysis:

"The dataset contains substantially more observed subdomains
than unique IP addresses, resulting in an average of X observed
subdomains per IP. This indicates that multiple observed
subdomains are represented by the same limited set of IP
addresses in the collected dataset."

Do not claim why this occurs unless the data explicitly shows it.

------------------------------------------------------------

2. Network Relationships

Explain:
- Domain -> IP relationships
- IP -> ASN relationships
- IP -> Organization relationships where applicable

Preserve graph direction.

Explain concentration or distribution only where supported
by the counts.

Do not imply ownership.

------------------------------------------------------------

3. Organizational Associations

Describe:
- observed organizations
- number of observed organizations
- their association with observed IP infrastructure

If one organization is associated with multiple observed IPs,
that can be stated.

Explicitly distinguish IP-organization association from domain
ownership.

------------------------------------------------------------

4. Certificate Observations

Describe:
- number of certificates
- observable certificate identifiers or names when supplied
- relationships to the domain

Do not infer security, trust, legitimacy, or ownership from
certificate presence.

------------------------------------------------------------

5. Infrastructure Patterns

This section should contain the strongest analytical part
of the report.

Discuss only patterns supported by the data, including:

- subdomain naming patterns
- environment-related names
- service-related names
- numeric naming patterns
- wildcard observations
- subdomain/IP ratios
- ASN concentration
- organization concentration
- IPv4/IPv6 distribution
- certificate count
- TCP port distribution
- recurring open ports
- recurring services
- banner coverage
- VirusTotal observations, explicitly attributed to VirusTotal
- registrar information when supplied

For port scanning, analyze patterns such as:

"The scan identified TCP/443 on N IP addresses, making it the
most frequently observed open port."

or:

"Open ports were observed across X of Y scanned IP addresses."

or:

"Banner information was available for X of Y open-port
observations, so service identification was available for only
part of the observed ports."

Do NOT say that these observations establish a vulnerability
or security weakness.

For VirusTotal:

Always write things such as:

"VirusTotal recorded X malicious detections..."

Do NOT convert this into:

"The domain is malicious."

------------------------------------------------------------

6. Key Takeaways

Provide 3-5 concise analytical findings.

Each finding must be directly supported by the supplied data.

Prefer findings that combine multiple observations.

For example:

"The collected dataset contains X subdomains across Y observed
IP addresses, resulting in approximately Z subdomains per IP."

"The observed IP infrastructure maps to one ASN in the supplied
graph data."

"The TCP scan found X open ports across Y IP addresses, with
TCP/443 being the most frequently observed."

Do not introduce information that has not already appeared.

============================================================
LIMITATION
============================================================

After the six sections, provide exactly one short paragraph
without a heading.

State that the report reflects only the collected DomainAtlas
OSINT and TCP scan data and does not independently establish
domain ownership, maliciousness, benignness, compromise,
vulnerability, or overall security posture.

============================================================
FINAL RULE
============================================================

Return ONLY:

1. Domain Infrastructure
2. Network Relationships
3. Organizational Associations
4. Certificate Observations
5. Infrastructure Patterns
6. Key Takeaways

followed by the single limitation paragraph.

No other headings.
No external research.
No invented facts.
No unsupported conclusions.
"""

    # ========================================================
    # OLLAMA
    # ========================================================

    response = ollama.chat(
        model="llama3.2:3b",
        messages=[
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        options={
            "temperature": 0
        }
    )

    report = (
        response
        .get("message", {})
        .get("content", "")
    )

    if not report:
        raise RuntimeError(
            "Ollama returned an empty report."
        )

    report = report.strip()

    # ========================================================
    # POST-GENERATION VALIDATION
    # ========================================================

    forbidden_phrases = [
        "robust",
        "secure",
        "trusted",
        "trustworthy",
        "legitimate",
        "compromised",
        "dangerous",
        "safe",
        "resilient",
        "vulnerable",
        "high-risk",
        "low-risk"
    ]

    report_lower = report.lower()

    detected_forbidden = [
        phrase
        for phrase in forbidden_phrases
        if phrase in report_lower
    ]

    if detected_forbidden:

        raise RuntimeError(
            "AI report contained unsupported terminology: "
            + ", ".join(detected_forbidden)
        )

    # --------------------------------------------------------
    # Required headings
    # --------------------------------------------------------

    required_headings = [
        "Domain Infrastructure",
        "Network Relationships",
        "Organizational Associations",
        "Certificate Observations",
        "Infrastructure Patterns",
        "Key Takeaways"
    ]

    missing_headings = [
        heading
        for heading in required_headings
        if heading.lower() not in report_lower
    ]

    if missing_headings:

        raise RuntimeError(
            "AI report missing required sections: "
            + ", ".join(missing_headings)
        )

    # --------------------------------------------------------
    # Basic hallucination protection
    # --------------------------------------------------------

    # These are particularly important because the model can
    # otherwise turn port observations into security claims.

    forbidden_security_claims = [
        "open port is vulnerable",
        "open ports are vulnerable",
        "port is vulnerable",
        "port indicates a vulnerability",
        "open port represents a vulnerability",
        "domain is malicious",
        "domain is benign",
        "domain is compromised",
        "infrastructure is compromised",
        "security vulnerability"
    ]

    detected_claims = [
        phrase
        for phrase in forbidden_security_claims
        if phrase in report_lower
    ]

    if detected_claims:

        raise RuntimeError(
            "AI report contained unsupported security claims: "
            + ", ".join(detected_claims)
        )

    return report


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

    print(
        "\n[*] Analyzing DomainAtlas graph..."
    )

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
                "[+] Graph analysis complete."
            )

            print(
                "\n[*] Generating AI-assisted "
                "intelligence report...\n"
            )

            report = generate_ai_report(
                analysis
            )

            print(
                "[+] AI analysis complete.\n"
            )

            print("=" * 70)
            print(
                "AI-ASSISTED INTELLIGENCE REPORT"
            )
            print("=" * 70)

            print(report)

            print("=" * 70)

    except Exception as error:

        print(
            f"[!] AI analysis error: {error}"
        )