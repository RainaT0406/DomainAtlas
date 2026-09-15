"""
graph_analyzer.py

DomainAtlas - Domain-Centric OSINT Graph Analyzer

This module:
    - Finds the target Domain node in Neo4j.
    - Performs target-scoped graph analysis.
    - Extracts infrastructure information.
    - Analyzes IP versions.
    - Analyzes subdomain naming patterns.
    - Analyzes TCP ports and service banners.
    - Extracts VirusTotal intelligence.
    - Generates deterministic observations.
    - Generates Cytoscape-compatible graph data.

Public functions:
    get_domain_graph(domain, password)
    get_domain_analysis(domain, password)
"""

import ipaddress
import json
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from neo4j import GraphDatabase


# ============================================================
# NEO4J CONFIGURATION
# ============================================================

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USERNAME = "neo4j"


# ============================================================
# GENERAL HELPERS
# ============================================================

def safe_json_load(value: Any, fallback: Any = None) -> Any:
    """
    Safely parse JSON.

    If value is already a Python object, return it unchanged.
    """
    if value is None:
        return fallback

    if isinstance(value, (dict, list, tuple, int, float, bool)):
        return value

    if isinstance(value, str):
        text = value.strip()

        if not text:
            return fallback

        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError, ValueError):
            return fallback

    return fallback


def _json_safe(value: Any) -> Any:
    """
    Convert Neo4j/Python values into JSON-safe values.
    """
    if value is None:
        return None

    if isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, dict):
        return {
            str(key): _json_safe(val)
            for key, val in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [
            _json_safe(item)
            for item in value
        ]

    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            pass

    return str(value)


def _node_properties(node: Any) -> Dict[str, Any]:
    """
    Safely return Neo4j node properties.
    """
    if node is None:
        return {}

    try:
        return dict(node)
    except Exception:
        return {}


def _relationship_properties(
    relationship: Any,
) -> Dict[str, Any]:
    """
    Safely return Neo4j relationship properties.
    """
    if relationship is None:
        return {}

    try:
        return dict(relationship)
    except Exception:
        return {}


def _first_value(
    properties: Dict[str, Any],
    keys: List[str],
    default: Any = None,
) -> Any:
    """
    Return the first non-empty property matching the supplied keys.
    """
    for key in keys:
        if key not in properties:
            continue

        value = properties.get(key)

        if value is None:
            continue

        if isinstance(value, str) and not value.strip():
            continue

        return value

    return default


def _string_value(
    properties: Dict[str, Any],
    keys: List[str],
    default: str = "",
) -> str:
    """
    Safely extract a property as a string.
    """
    value = _first_value(
        properties,
        keys,
        default,
    )

    if value is None:
        return default

    return str(value).strip()


def _integer_value(
    properties: Dict[str, Any],
    keys: List[str],
    default: int = 0,
) -> int:
    """
    Safely extract an integer.
    """
    value = _first_value(
        properties,
        keys,
        default,
    )

    if value is None:
        return default

    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


# ============================================================
# NORMALIZATION
# ============================================================

def _normalize_domain(value: Any) -> str:
    """
    Normalize a domain/FQDN.
    """
    if value is None:
        return ""

    text = str(value).strip().lower()

    text = re.sub(
        r"^[a-z][a-z0-9+.-]*://",
        "",
        text,
    )

    text = text.split("/", 1)[0]
    text = text.split("?", 1)[0]
    text = text.split("#", 1)[0]

    return text.rstrip(".")


def _normalize_ip(value: Any) -> str:
    """
    Normalize an IP address.
    """
    if value is None:
        return ""

    text = str(value).strip()

    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]

    return text


def _classify_ip_version(value: Any) -> str:
    """
    Return:
        ipv4
        ipv6
        unknown
    """
    value = _normalize_ip(value)

    if not value:
        return "unknown"

    try:
        address = ipaddress.ip_address(value)

        if address.version == 4:
            return "ipv4"

        if address.version == 6:
            return "ipv6"

    except ValueError:
        pass

    return "unknown"


def _normalize_port(value: Any) -> Optional[int]:
    """
    Normalize different port representations.

    Examples:
        80
        "80"
        "80/tcp"
        "tcp/80"
        "port 80"
    """
    if value is None:
        return None

    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value if 0 <= value <= 65535 else None

    if isinstance(value, float):
        number = int(value)

        if 0 <= number <= 65535:
            return number

        return None

    text = str(value).strip().lower()

    if not text:
        return None

    match = re.search(
        r"(?:tcp|udp)[\s:/-]*(\d{1,5})",
        text,
    )

    if match:
        number = int(match.group(1))

        if 0 <= number <= 65535:
            return number

    match = re.search(
        r"(\d{1,5})[\s:/-]*(?:tcp|udp)",
        text,
    )

    if match:
        number = int(match.group(1))

        if 0 <= number <= 65535:
            return number

    match = re.search(
        r"\b(\d{1,5})\b",
        text,
    )

    if match:
        number = int(match.group(1))

        if 0 <= number <= 65535:
            return number

    return None


def _port_display(
    properties: Dict[str, Any],
    port_number: Optional[int],
) -> str:
    """
    Return a readable port representation.
    """
    protocol = _string_value(
        properties,
        [
            "protocol",
            "transport",
            "transport_protocol",
        ],
        default="tcp",
    ).lower()

    if protocol not in {"tcp", "udp"}:
        protocol = "tcp"

    if port_number is not None:
        return f"{port_number}/{protocol}"

    raw = _string_value(
        properties,
        [
            "port",
            "port_number",
            "number",
            "value",
            "name",
            "id",
        ],
        default="",
    )

    return raw or "unknown"


def _normalize_banner(
    properties: Dict[str, Any],
) -> str:
    """
    Extract banner/service text.
    """
    value = _first_value(
        properties,
        [
            "banner",
            "service_banner",
            "serviceBanner",
            "value",
            "description",
            "name",
            "service",
        ],
        default="",
    )

    if value is None:
        return ""

    return str(value).strip()


# ============================================================
# NEO4J IDENTIFIERS
# ============================================================

def _node_element_id(node: Any) -> str:
    """
    Safely retrieve Neo4j node element ID.
    """
    if node is None:
        return ""

    try:
        return str(node.element_id)
    except Exception:
        return ""


def _relationship_element_id(
    relationship: Any,
) -> str:
    """
    Safely retrieve Neo4j relationship element ID.
    """
    if relationship is None:
        return ""

    try:
        return str(relationship.element_id)
    except Exception:
        return ""


def _relationship_type(
    relationship: Any,
) -> str:
    """
    Safely retrieve relationship type.
    """
    if relationship is None:
        return ""

    try:
        return str(relationship.type)
    except Exception:
        return ""


# ============================================================
# NODE VALUE EXTRACTION
# ============================================================

def _node_identifier_value(
    node: Any,
    node_type: str,
) -> str:
    """
    Extract the most meaningful identifier from a node.
    """
    properties = _node_properties(node)

    keys = {
        "Domain": [
            "domain",
            "fqdn",
            "hostname",
            "name",
            "value",
            "id",
        ],
        "Subdomain": [
            "subdomain",
            "fqdn",
            "hostname",
            "domain",
            "name",
            "value",
            "id",
        ],
        "IPAddress": [
            "ip",
            "ip_address",
            "address",
            "value",
            "name",
            "id",
        ],
        "ASN": [
            "asn",
            "asn_number",
            "number",
            "value",
            "name",
            "id",
        ],
        "Organization": [
            "organization",
            "org",
            "name",
            "value",
            "id",
        ],
        "Certificate": [
            "certificate_id",
            "cert_id",
            "serial_number",
            "id",
            "value",
            "name",
        ],
        "Port": [
            "port",
            "port_number",
            "number",
            "value",
            "name",
            "id",
        ],
        "ServiceBanner": [
            "banner",
            "service_banner",
            "serviceBanner",
            "value",
            "description",
            "name",
            "id",
        ],
    }

    return _string_value(
        properties,
        keys.get(
            node_type,
            [
                "name",
                "value",
                "id",
            ],
        ),
        default="",
    )


def _node_display_label(
    node: Any,
    node_type: str,
) -> str:
    """
    Create a readable graph label.
    """
    value = _node_identifier_value(
        node,
        node_type,
    )

    if not value:
        return node_type

    if node_type == "ASN":
        if value.upper().startswith("AS"):
            return value.upper()

        return f"AS{value}"

    if node_type == "ServiceBanner":
        if len(value) > 100:
            return value[:97] + "..."

    return value


# ============================================================
# FIND TARGET DOMAIN
# ============================================================

def _find_target_domain(
    session: Any,
    domain: str,
) -> Tuple[Optional[Any], Optional[str]]:
    """
    Find the target Domain node.

    The Cypher query intentionally does not reference any
    potentially missing Domain properties.

    Matching is performed in Python.
    """
    requested = _normalize_domain(domain)

    result = session.run(
        """
        MATCH (d:Domain)
        RETURN d
        """
    )

    for record in result:
        node = record["d"]

        properties = _node_properties(node)

        candidate = _string_value(
            properties,
            [
                "domain",
                "fqdn",
                "hostname",
                "name",
                "value",
                "id",
            ],
            default="",
        )

        if _normalize_domain(candidate) == requested:
            return (
                node,
                _node_element_id(node),
            )

    return (
        None,
        None,
    )


# ============================================================
# TARGET-SCOPED GRAPH LOADING
# ============================================================

def _load_graph_context(
    session: Any,
    domain: str,
) -> Dict[str, Any]:
    """
    Load only graph data belonging to the requested Domain node.

    All traversals are directed and rooted at the target Domain.
    """

    domain_node, domain_id = _find_target_domain(
        session,
        domain,
    )

    if domain_node is None or not domain_id:
        raise ValueError(
            f"Domain '{domain}' was not found in Neo4j."
        )

    context = {
        "domain_node": domain_node,
        "domain_id": domain_id,

        "subdomains": [],
        "subdomain_relationships": [],

        "ips": [],
        "resolve_relationships": [],

        "asns": [],
        "asn_relationships": [],

        "organizations": [],
        "organization_relationships": [],

        "certificates": [],
        "certificate_relationships": [],

        "ports": [],
        "port_relationships": [],

        "banners": [],
        "banner_relationships": [],
    }

    # --------------------------------------------------------
    # DOMAIN -> SUBDOMAIN
    # --------------------------------------------------------

    result = session.run(
        """
        MATCH (d:Domain)-[r:HAS_SUBDOMAIN]->(s:Subdomain)
        WHERE elementId(d) = $domain_id
        RETURN s, r
        """,
        domain_id=domain_id,
    )

    for record in result:
        context["subdomains"].append(record["s"])
        context["subdomain_relationships"].append(record["r"])

    # --------------------------------------------------------
    # DOMAIN -> IP
    # --------------------------------------------------------

    result = session.run(
        """
        MATCH (d:Domain)-[r:RESOLVES_TO]->(ip:IPAddress)
        WHERE elementId(d) = $domain_id
        RETURN ip, r
        """,
        domain_id=domain_id,
    )

    for record in result:
        context["ips"].append(record["ip"])
        context["resolve_relationships"].append(record["r"])

    # --------------------------------------------------------
    # IP -> ASN
    # --------------------------------------------------------

    result = session.run(
        """
        MATCH (d:Domain)-[:RESOLVES_TO]->(ip:IPAddress)
              -[r:BELONGS_TO_ASN]->(asn:ASN)
        WHERE elementId(d) = $domain_id
        RETURN asn, r
        """,
        domain_id=domain_id,
    )

    for record in result:
        context["asns"].append(record["asn"])
        context["asn_relationships"].append(record["r"])

    # --------------------------------------------------------
    # IP -> ORGANIZATION
    # --------------------------------------------------------

    result = session.run(
        """
        MATCH (d:Domain)-[:RESOLVES_TO]->(ip:IPAddress)
              -[r:ASSOCIATED_WITH]->(org:Organization)
        WHERE elementId(d) = $domain_id
        RETURN org, r
        """,
        domain_id=domain_id,
    )

    for record in result:
        context["organizations"].append(record["org"])
        context["organization_relationships"].append(
            record["r"]
        )

    # --------------------------------------------------------
    # DOMAIN -> CERTIFICATE
    # --------------------------------------------------------

    result = session.run(
        """
        MATCH (d:Domain)-[r:HAS_CERTIFICATE]->(c:Certificate)
        WHERE elementId(d) = $domain_id
        RETURN c, r
        """,
        domain_id=domain_id,
    )

    for record in result:
        context["certificates"].append(record["c"])
        context["certificate_relationships"].append(
            record["r"]
        )

    # --------------------------------------------------------
    # IP -> PORT
    # --------------------------------------------------------

    result = session.run(
        """
        MATCH (d:Domain)-[:RESOLVES_TO]->(ip:IPAddress)
              -[r:HAS_OPEN_PORT]->(p:Port)
        WHERE elementId(d) = $domain_id
        RETURN ip, p, r
        """,
        domain_id=domain_id,
    )

    for record in result:
        context["ports"].append(
            (
                record["ip"],
                record["p"],
            )
        )

        context["port_relationships"].append(
            record["r"]
        )

    # --------------------------------------------------------
    # PORT -> SERVICE BANNER
    # --------------------------------------------------------

    result = session.run(
        """
        MATCH (d:Domain)-[:RESOLVES_TO]->(ip:IPAddress)
              -[:HAS_OPEN_PORT]->(p:Port)
              -[r:HAS_BANNER]->(b:ServiceBanner)
        WHERE elementId(d) = $domain_id
        RETURN ip, p, b, r
        """,
        domain_id=domain_id,
    )

    for record in result:
        context["banners"].append(
            (
                record["ip"],
                record["p"],
                record["b"],
            )
        )

        context["banner_relationships"].append(
            record["r"]
        )

    return context


# ============================================================
# DEDUPLICATION
# ============================================================

def _deduplicate_nodes(
    nodes: List[Any],
) -> List[Any]:
    """
    Deduplicate Neo4j nodes using element IDs.
    """
    result = []
    seen = set()

    for node in nodes:
        element_id = _node_element_id(node)

        if not element_id:
            continue

        if element_id in seen:
            continue

        seen.add(element_id)
        result.append(node)

    return result


def _deduplicate_relationships(
    relationships: List[Any],
) -> List[Any]:
    """
    Deduplicate Neo4j relationships using element IDs.
    """
    result = []
    seen = set()

    for relationship in relationships:
        element_id = _relationship_element_id(
            relationship
        )

        if not element_id:
            continue

        if element_id in seen:
            continue

        seen.add(element_id)
        result.append(relationship)

    return result


# ============================================================
# RELATIONSHIP COUNTS
# ============================================================

def _count_relationships(
    relationships: List[Any],
) -> int:
    """
    Count actual unique Neo4j relationships.

    This intentionally counts the relationship objects loaded
    from the exact target-scoped queries.

    This is especially important for HAS_BANNER.

    We do NOT count rows from a broad graph traversal.
    """
    return len(
        _deduplicate_relationships(
            relationships
        )
    )


def _get_relationship_counts(
    context: Dict[str, Any],
) -> Dict[str, int]:
    """
    Build relationship statistics from exact target-scoped
    relationship collections.
    """

    return {
        "HAS_SUBDOMAIN": _count_relationships(
            context["subdomain_relationships"]
        ),

        "RESOLVES_TO": _count_relationships(
            context["resolve_relationships"]
        ),

        "BELONGS_TO_ASN": _count_relationships(
            context["asn_relationships"]
        ),

        "ASSOCIATED_WITH": _count_relationships(
            context["organization_relationships"]
        ),

        "HAS_CERTIFICATE": _count_relationships(
            context["certificate_relationships"]
        ),

        "HAS_OPEN_PORT": _count_relationships(
            context["port_relationships"]
        ),

        "HAS_BANNER": _count_relationships(
            context["banner_relationships"]
        ),
    }


# ============================================================
# SUBDOMAIN PATTERN ANALYSIS
# ============================================================

def _subdomain_pattern_analysis(
    subdomains: List[Any],
    target_domain: str,
) -> Dict[str, Any]:
    """
    Analyze subdomain naming patterns.

    Definitions:

        numeric_leading
            First subdomain label begins with a digit.

        contains_hyphen
            At least one subdomain label contains "-".

        deep_subdomains
            At least two labels precede the base domain.

    Compatibility aliases are included because other parts
    of DomainAtlas may use older names.
    """

    normalized_target = _normalize_domain(
        target_domain
    )

    numeric_leading = 0
    contains_hyphen = 0
    deep = 0

    prefix_counts = defaultdict(int)

    unique_values = set()

    for node in subdomains:
        properties = _node_properties(node)

        value = _string_value(
            properties,
            [
                "subdomain",
                "fqdn",
                "hostname",
                "domain",
                "name",
                "value",
                "id",
            ],
            default="",
        )

        normalized = _normalize_domain(value)

        if not normalized:
            continue

        if normalized in unique_values:
            continue

        unique_values.add(normalized)

        # ----------------------------------------------------
        # Determine labels belonging to the subdomain portion.
        # ----------------------------------------------------

        prefix_labels = []

        suffix = "." + normalized_target

        if normalized.endswith(suffix):
            prefix = normalized[: -len(suffix)]

            prefix_labels = [
                label
                for label in prefix.split(".")
                if label
            ]

        elif normalized == normalized_target:
            prefix_labels = []

        else:
            # If the value is not directly under the target,
            # analyze its labels conservatively.
            labels = [
                label
                for label in normalized.split(".")
                if label
            ]

            if len(labels) > 2:
                prefix_labels = labels[:-2]
            else:
                prefix_labels = labels[:1]

        # ----------------------------------------------------
        # NUMERIC LEADING
        # ----------------------------------------------------

        if prefix_labels:
            if re.match(
                r"^\d",
                prefix_labels[0],
            ):
                numeric_leading += 1

        # ----------------------------------------------------
        # CONTAINS HYPHEN
        # ----------------------------------------------------

        if any(
            "-" in label
            for label in prefix_labels
        ):
            contains_hyphen += 1

        # ----------------------------------------------------
        # DEEP / MULTI-LEVEL
        # ----------------------------------------------------

        if len(prefix_labels) >= 2:
            deep += 1

        # ----------------------------------------------------
        # COMMON PREFIXES
        # ----------------------------------------------------

        if prefix_labels:
            first_prefix = prefix_labels[0]

            if first_prefix:
                prefix_counts[first_prefix] += 1

    total = len(unique_values)

    common_prefixes = [
        {
            "prefix": prefix,
            "count": count,
        }
        for prefix, count in sorted(
            prefix_counts.items(),
            key=lambda item: (
                -item[1],
                item[0],
            ),
        )
    ]

    # IMPORTANT:
    # Keep every expected key present even when there are zero
    # subdomains. This prevents KeyError exceptions elsewhere.
    return {
        "total": total,

        "numeric_leading": numeric_leading,

        "contains_hyphen": contains_hyphen,

        # Compatibility alias.
        "hyphenated": contains_hyphen,

        "deep": deep,

        # Compatibility alias.
        "deep_subdomains": deep,

        # Compatibility alias for older code.
        "multi_level": deep,

        "common_prefixes": common_prefixes,
    }


# ============================================================
# IP VERSION ANALYSIS
# ============================================================

def _ip_version_summary(
    ips: List[Any],
) -> Dict[str, int]:
    """
    Count unique IPv4, IPv6 and unknown addresses.
    """

    summary = {
        "ipv4": 0,
        "ipv6": 0,
        "unknown": 0,
    }

    seen = set()

    for node in ips:
        properties = _node_properties(node)

        value = _string_value(
            properties,
            [
                "ip",
                "ip_address",
                "address",
                "value",
                "name",
                "id",
            ],
            default="",
        )

        value = _normalize_ip(value)

        if not value:
            continue

        if value in seen:
            continue

        seen.add(value)

        version = _classify_ip_version(
            value
        )

        summary[version] += 1

    return summary


# ============================================================
# INFRASTRUCTURE
# ============================================================

def _build_infrastructure(
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Build normalized infrastructure information.
    """

    # --------------------------------------------------------
    # SUBDOMAINS
    # --------------------------------------------------------

    subdomains = []
    seen = set()

    for node in context["subdomains"]:
        properties = _node_properties(node)

        value = _string_value(
            properties,
            [
                "subdomain",
                "fqdn",
                "hostname",
                "domain",
                "name",
                "value",
                "id",
            ],
            default="",
        )

        value = _normalize_domain(value)

        if not value:
            continue

        if value in seen:
            continue

        seen.add(value)
        subdomains.append(value)

    # --------------------------------------------------------
    # IP ADDRESSES
    # --------------------------------------------------------

    ip_addresses = []
    seen = set()

    for node in context["ips"]:
        properties = _node_properties(node)

        value = _string_value(
            properties,
            [
                "ip",
                "ip_address",
                "address",
                "value",
                "name",
                "id",
            ],
            default="",
        )

        value = _normalize_ip(value)

        if not value:
            continue

        if value in seen:
            continue

        seen.add(value)
        ip_addresses.append(value)

    # --------------------------------------------------------
    # ASNs
    # --------------------------------------------------------

    asns = []
    seen = set()

    for node in context["asns"]:
        properties = _node_properties(node)

        value = _string_value(
            properties,
            [
                "asn",
                "asn_number",
                "number",
                "value",
                "name",
                "id",
            ],
            default="",
        )

        if not value:
            continue

        if value.upper().startswith("AS"):
            display = value.upper()
        else:
            display = f"AS{value}"

        if display in seen:
            continue

        seen.add(display)
        asns.append(display)

    # --------------------------------------------------------
    # ORGANIZATIONS
    # --------------------------------------------------------

    organizations = []
    seen = set()

    for node in context["organizations"]:
        properties = _node_properties(node)

        value = _string_value(
            properties,
            [
                "organization",
                "org",
                "name",
                "value",
                "id",
            ],
            default="",
        )

        if not value:
            continue

        if value in seen:
            continue

        seen.add(value)
        organizations.append(value)

       # --------------------------------------------------------
    # CERTIFICATES
    # --------------------------------------------------------

    certificates = []
    certificate_details = []
    seen = set()

    for node in context["certificates"]:

        properties = _node_properties(node)

        # ----------------------------------------------------
        # Certificate identifier
        # ----------------------------------------------------

        value = _string_value(
            properties,
            [
                "certificate_id",
                "cert_id",
                "serial_number",
                "entity_value",
                "value",
                "name",
            ],
            default="",
        )

        if not value:
            continue

        if value in seen:
            continue

        seen.add(value)

        # Preserve the existing simple certificate list.
        certificates.append(value)

        # ----------------------------------------------------
        # Certificate metadata
        # ----------------------------------------------------

        certificate_sha256 = _string_value(
            properties,
            [
                "certificate_sha256",
                "cert_sha256",
            ],
            default="",
        )

        public_key_sha256 = _string_value(
            properties,
            [
                "public_key_sha256",
                "pubkey_sha256",
            ],
            default="",
        )

        not_before = _string_value(
            properties,
            [
                "not_before",
                "valid_from",
                "validity_start",
            ],
            default="",
        )

        not_after = _string_value(
            properties,
            [
                "not_after",
                "valid_until",
                "validity_end",
            ],
            default="",
        )

        revoked_value = _first_value(
            properties,
            [
                "revoked",
            ],
            default=False,
        )

        if isinstance(revoked_value, str):
            revoked = (
                revoked_value.strip().lower()
                in {
                    "true",
                    "1",
                    "yes",
                    "revoked",
                }
            )
        else:
            revoked = bool(revoked_value)

        certificate_details.append(
            {
                "id": value,
                "certificate_sha256": (
                    certificate_sha256
                ),
                "public_key_sha256": (
                    public_key_sha256
                ),
                "not_before": (
                    not_before
                ),
                "not_after": (
                    not_after
                ),
                "revoked": revoked,
            }
        )

    # --------------------------------------------------------
    # OPEN PORTS
    # --------------------------------------------------------

    open_ports = defaultdict(list)

    for ip_node, port_node in context["ports"]:

        ip_properties = _node_properties(
            ip_node
        )

        port_properties = _node_properties(
            port_node
        )

        ip_value = _string_value(
            ip_properties,
            [
                "ip",
                "ip_address",
                "address",
                "value",
                "name",
                "id",
            ],
            default="",
        )

        ip_value = _normalize_ip(
            ip_value
        )

        if not ip_value:
            continue

        raw_port = _first_value(
            port_properties,
            [
                "port",
                "port_number",
                "number",
                "value",
                "name",
                "id",
            ],
            default=None,
        )

        port_number = _normalize_port(
            raw_port
        )

        display = _port_display(
            port_properties,
            port_number,
        )

        if display not in open_ports[ip_value]:
            open_ports[ip_value].append(
                display
            )

    def port_sort_key(value: str):
        number = _normalize_port(value)

        if number is None:
            return (
                999999,
                value,
            )

        return (
            number,
            value,
        )

    for ip_value in open_ports:
        open_ports[ip_value] = sorted(
            open_ports[ip_value],
            key=port_sort_key,
        )

    return {
        "subdomains": sorted(
            subdomains
        ),

        "ip_addresses": sorted(
            ip_addresses
        ),

        "asns": sorted(
            asns
        ),

        "organizations": sorted(
            organizations
        ),

        "certificates": sorted(
            certificates
        ),

        "certificate_details": sorted(
            certificate_details,
            key=lambda item: item.get(
                "id",
                "",
            ),
        ),

        "open_ports": dict(
            sorted(
                open_ports.items()
            )
        ),
    }


# ============================================================
# PORT SCAN ANALYSIS
# ============================================================

def _build_port_scan_analysis(
    context: Dict[str, Any],
    relationship_counts: Dict[str, int],
) -> Dict[str, Any]:
    """
    Build port-scan information from the graph.

    Important:

        total_open_ports
            Based on actual HAS_OPEN_PORT relationships.

        ports_with_banners
            Based on actual HAS_BANNER relationships.

    No hardcoded counts are used.
    """

    open_ports_by_ip = defaultdict(list)

    scanned_ips = set()

    port_keys = set()

    banner_keys = set()

    banners = {}

    banner_details = []

    # --------------------------------------------------------
    # OPEN PORTS
    # --------------------------------------------------------

    for ip_node, port_node in context["ports"]:

        ip_properties = _node_properties(
            ip_node
        )

        port_properties = _node_properties(
            port_node
        )

        ip_value = _string_value(
            ip_properties,
            [
                "ip",
                "ip_address",
                "address",
                "value",
                "name",
                "id",
            ],
            default="",
        )

        ip_value = _normalize_ip(
            ip_value
        )

        if not ip_value:
            continue

        scanned_ips.add(ip_value)

        raw_port = _first_value(
            port_properties,
            [
                "port",
                "port_number",
                "number",
                "value",
                "name",
                "id",
            ],
            default=None,
        )

        port_number = _normalize_port(
            raw_port
        )

        port_display = _port_display(
            port_properties,
            port_number,
        )

        key = (
            ip_value,
            port_display,
        )

        if key in port_keys:
            continue

        port_keys.add(key)

        open_ports_by_ip[ip_value].append(
            port_display
        )

    # --------------------------------------------------------
    # BANNERS
    # --------------------------------------------------------

    for (
        ip_node,
        port_node,
        banner_node,
    ) in context["banners"]:

        ip_properties = _node_properties(
            ip_node
        )

        port_properties = _node_properties(
            port_node
        )

        banner_properties = _node_properties(
            banner_node
        )

        ip_value = _string_value(
            ip_properties,
            [
                "ip",
                "ip_address",
                "address",
                "value",
                "name",
                "id",
            ],
            default="",
        )

        ip_value = _normalize_ip(
            ip_value
        )

        if not ip_value:
            continue

        raw_port = _first_value(
            port_properties,
            [
                "port",
                "port_number",
                "number",
                "value",
                "name",
                "id",
            ],
            default=None,
        )

        port_number = _normalize_port(
            raw_port
        )

        port_display = _port_display(
            port_properties,
            port_number,
        )

        banner_value = _normalize_banner(
            banner_properties
        )

        # A ServiceBanner node without usable text is still
        # represented in the graph, but cannot be placed in
        # the human-readable banners dictionary.
        if not banner_value:
            continue

        key = (
            ip_value,
            port_display,
        )

        if key in banner_keys:
            continue

        banner_keys.add(key)

        readable_key = (
            f"{ip_value}:{port_display}"
        )

        banners[readable_key] = (
            banner_value
        )

        banner_details.append(
            {
                "ip": ip_value,
                "port": port_display,
                "banner": banner_value,
            }
        )

    # --------------------------------------------------------
    # SORT PORTS
    # --------------------------------------------------------

    def port_sort_key(value: str):
        number = _normalize_port(value)

        if number is None:
            return (
                999999,
                value,
            )

        return (
            number,
            value,
        )

    for ip_value in open_ports_by_ip:
        open_ports_by_ip[ip_value] = sorted(
            set(
                open_ports_by_ip[ip_value]
            ),
            key=port_sort_key,
        )

    # --------------------------------------------------------
    # SORT BANNER DETAILS
    # --------------------------------------------------------

    banner_details = sorted(
        banner_details,
        key=lambda item: (
            item["ip"],
            (
                _normalize_port(
                    item["port"]
                )
                if _normalize_port(
                    item["port"]
                ) is not None
                else 999999
            ),
            item["port"],
        ),
    )

    # --------------------------------------------------------
    # EXACT GRAPH COUNTS
    # --------------------------------------------------------

    total_open_ports = int(
        relationship_counts.get(
            "HAS_OPEN_PORT",
            0,
        )
    )

    total_banner_relationships = int(
        relationship_counts.get(
            "HAS_BANNER",
            0,
        )
    )

    # The relationship count is authoritative for graph
    # analysis. The banner text dictionary can only contain
    # entries that have usable banner text.
    ports_with_banners = min(
        total_banner_relationships,
        len(banner_keys),
    )

    if total_open_ports > 0:
        banner_coverage_percentage = round(
            (
                ports_with_banners
                / total_open_ports
            )
            * 100,
            1,
        )
    else:
        banner_coverage_percentage = 0.0

    ips_with_open_ports = sum(
        1
        for values in open_ports_by_ip.values()
        if values
    )

    return {
        "scanned_ips": sorted(
            scanned_ips
        ),

        "total_open_ports": (
            total_open_ports
        ),

        "ips_with_open_ports": (
            ips_with_open_ports
        ),

        "ports_with_banners": (
            ports_with_banners
        ),

        "banner_coverage_percentage": (
            banner_coverage_percentage
        ),

        "open_ports_by_ip": dict(
            sorted(
                open_ports_by_ip.items()
            )
        ),

        "banners": dict(
            sorted(
                banners.items()
            )
        ),

        "banner_details": (
            banner_details
        ),
    }


# ============================================================
# VIRUSTOTAL
# ============================================================

def _extract_virustotal(
    domain_properties: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Extract VirusTotal intelligence.

    Supports:
        - direct properties
        - nested VirusTotal dictionaries
        - security_summary
        - last_analysis_stats
    """

    nested = {}

    for key in [
        "virustotal",
        "virus_total",
        "virusTotal",
        "vt",
        "vt_intelligence",
        "virus_total_intelligence",
    ]:

        if key not in domain_properties:
            continue

        parsed = safe_json_load(
            domain_properties[key],
            fallback=None,
        )

        if isinstance(parsed, dict):
            nested = parsed
            break

    security_summary = safe_json_load(
        nested.get(
            "security_summary"
        ),
        fallback=nested.get(
            "security_summary",
            {},
        ),
    )

    if not isinstance(
        security_summary,
        dict,
    ):
        security_summary = {}

    last_analysis_stats = safe_json_load(
        nested.get(
            "last_analysis_stats"
        ),
        fallback=nested.get(
            "last_analysis_stats",
            {},
        ),
    )

    if not isinstance(
        last_analysis_stats,
        dict,
    ):
        last_analysis_stats = {}

    def get_value(
        direct_keys,
        nested_keys,
        default=None,
    ):
        value = _first_value(
            domain_properties,
            direct_keys,
            default=None,
        )

        if value is not None:
            return value

        value = _first_value(
            nested,
            nested_keys,
            default=None,
        )

        if value is not None:
            return value

        value = _first_value(
            security_summary,
            nested_keys,
            default=None,
        )

        if value is not None:
            return value

        value = _first_value(
            last_analysis_stats,
            nested_keys,
            default=None,
        )

        if value is not None:
            return value

        return default

    risk_score = get_value(
        [
            "vt_risk_score",
            "virus_total_risk_score",
            "risk_score",
        ],
        [
            "risk_score",
        ],
        0,
    )

    reputation = get_value(
        [
            "vt_reputation",
            "virus_total_reputation",
            "reputation",
        ],
        [
            "reputation",
        ],
        0,
    )

    malicious = get_value(
        [
            "vt_malicious",
            "virus_total_malicious",
            "malicious",
        ],
        [
            "malicious",
        ],
        0,
    )

    suspicious = get_value(
        [
            "vt_suspicious",
            "virus_total_suspicious",
            "suspicious",
        ],
        [
            "suspicious",
        ],
        0,
    )

    harmless = get_value(
        [
            "vt_harmless",
            "virus_total_harmless",
            "harmless",
        ],
        [
            "harmless",
        ],
        0,
    )

    undetected = get_value(
        [
            "vt_undetected",
            "virus_total_undetected",
            "undetected",
        ],
        [
            "undetected",
        ],
        0,
    )

    timeout = get_value(
        [
            "vt_timeout",
            "virus_total_timeout",
            "timeout",
        ],
        [
            "timeout",
        ],
        0,
    )

    total_vendors = get_value(
        [
            "vt_total_vendors",
            "virus_total_total_vendors",
            "total_vendors",
        ],
        [
            "total_vendors",
        ],
        None,
    )

    registrar = get_value(
        [
            "vt_registrar",
            "virus_total_registrar",
            "registrar",
        ],
        [
            "registrar",
        ],
        "",
    )

    categories = get_value(
        [
            "vt_categories",
            "virus_total_categories",
            "categories",
        ],
        [
            "categories",
        ],
        {},
    )

    def as_int(value: Any) -> int:
        try:
            return int(float(value))
        except (
            TypeError,
            ValueError,
        ):
            return 0

    risk_score = as_int(
        risk_score
    )

    reputation = as_int(
        reputation
    )

    malicious = as_int(
        malicious
    )

    suspicious = as_int(
        suspicious
    )

    harmless = as_int(
        harmless
    )

    undetected = as_int(
        undetected
    )

    timeout = as_int(
        timeout
    )

    if total_vendors is None:
        total_vendors = (
            malicious
            + suspicious
            + harmless
            + undetected
            + timeout
        )
    else:
        total_vendors = as_int(
            total_vendors
        )

    if not isinstance(
        categories,
        dict,
    ):
        categories = {}

    registrar = (
        str(registrar).strip()
        if registrar is not None
        else ""
    )

    available = bool(nested)

    if not available:
        available = any(
            key in domain_properties
            for key in [
                "vt_risk_score",
                "virus_total_risk_score",
                "risk_score",
                "virustotal",
                "virus_total",
                "virusTotal",
                "vt",
            ]
        )

    return {
        "available": available,

        "risk_score": risk_score,

        "reputation": reputation,

        "malicious": malicious,

        "suspicious": suspicious,

        "harmless": harmless,

        "undetected": undetected,

        "timeout": timeout,

        "total_vendors": total_vendors,

        "registrar": registrar,

        "categories": _json_safe(
            categories
        ),

        "security_summary": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": timeout,
            "total_vendors": total_vendors,
        },
    }


# ============================================================
# OBSERVATIONS
# ============================================================

def _generate_observations(
    statistics: Dict[str, int],
    ip_versions: Dict[str, int],
    subdomain_patterns: Dict[str, Any],
    infrastructure: Dict[str, Any],
    port_scan: Dict[str, Any],
    virustotal: Dict[str, Any],
) -> List[str]:
    """
    Generate deterministic observations.

    These are observations of collected data only.
    They do not establish ownership, compromise,
    maliciousness, benignness or overall security posture.
    """

    observations = []

    subdomain_count = statistics.get(
        "subdomains",
        0,
    )

    ip_count = statistics.get(
        "ip_addresses",
        0,
    )

    asn_count = statistics.get(
        "asns",
        0,
    )

    organization_count = statistics.get(
        "organizations",
        0,
    )

    certificate_count = statistics.get(
        "certificates",
        0,
    )

    open_port_count = statistics.get(
        "open_ports",
        0,
    )

    # --------------------------------------------------------
    # SUBDOMAINS
    # --------------------------------------------------------

    if subdomain_count == 0:
        observations.append(
            "No subdomains were observed in the collected "
            "DomainAtlas data."
        )

    elif subdomain_count == 1:
        observations.append(
            "1 subdomain was observed in the collected "
            "DomainAtlas data."
        )

    else:
        observations.append(
            f"{subdomain_count} subdomains were observed "
            "in the collected DomainAtlas data."
        )

    numeric_leading = subdomain_patterns.get(
        "numeric_leading",
        0,
    )

    contains_hyphen = subdomain_patterns.get(
        "contains_hyphen",
        subdomain_patterns.get(
            "hyphenated",
            0,
        ),
    )

    deep = subdomain_patterns.get(
        "deep_subdomains",
        subdomain_patterns.get(
            "deep",
            subdomain_patterns.get(
                "multi_level",
                0,
            ),
        ),
    )

    if numeric_leading > 0:
        observations.append(
            f"{numeric_leading} subdomain"
            f"{'' if numeric_leading == 1 else 's'} "
            "had a first label beginning with a numeric character."
        )

    if contains_hyphen > 0:
        observations.append(
            f"{contains_hyphen} subdomain"
            f"{'' if contains_hyphen == 1 else 's'} "
            "contained a hyphen in at least one label."
        )

    if deep > 0:
        observations.append(
            f"{deep} subdomain"
            f"{'' if deep == 1 else 's'} "
            "had at least two labels preceding the base domain."
        )

    # --------------------------------------------------------
    # IP VERSIONS
    # --------------------------------------------------------

    ipv4 = ip_versions.get(
        "ipv4",
        0,
    )

    ipv6 = ip_versions.get(
        "ipv6",
        0,
    )

    unknown = ip_versions.get(
        "unknown",
        0,
    )

    if ipv4 == 1:
        observations.append(
            "1 IPv4 address was observed."
        )

    elif ipv4 > 1:
        observations.append(
            f"{ipv4} IPv4 addresses were observed."
        )

    if ipv6 == 1:
        observations.append(
            "1 IPv6 address was observed."
        )

    elif ipv6 > 1:
        observations.append(
            f"{ipv6} IPv6 addresses were observed."
        )

    if unknown == 1:
        observations.append(
            "1 observed address could not be classified "
            "as IPv4 or IPv6."
        )

    elif unknown > 1:
        observations.append(
            f"{unknown} observed addresses could not be "
            "classified as IPv4 or IPv6."
        )

    # --------------------------------------------------------
    # ASN
    # --------------------------------------------------------

    if asn_count == 1:
        asns = infrastructure.get(
            "asns",
            [],
        )

        if asns:
            observations.append(
                "One ASN was associated with the observed "
                f"infrastructure: {asns[0]}."
            )
        else:
            observations.append(
                "One ASN was associated with the observed "
                "infrastructure."
            )

    elif asn_count > 1:
        observations.append(
            f"{asn_count} ASNs were associated with "
            "the observed infrastructure."
        )

    # --------------------------------------------------------
    # ORGANIZATION
    # --------------------------------------------------------

    if organization_count == 1:
        organizations = infrastructure.get(
            "organizations",
            [],
        )

        if organizations:
            observations.append(
                "One organization was associated with the "
                f"observed infrastructure: {organizations[0]}."
            )
        else:
            observations.append(
                "One organization was associated with the "
                "observed infrastructure."
            )

    elif organization_count > 1:
        observations.append(
            f"{organization_count} organizations were associated "
            "with the observed infrastructure."
        )

    # --------------------------------------------------------
    # CERTIFICATES
    # --------------------------------------------------------

    if certificate_count == 1:
        observations.append(
            "One certificate was observed for the target domain."
        )

    elif certificate_count > 1:
        observations.append(
            f"{certificate_count} certificates were observed "
            "for the target domain."
        )

    # --------------------------------------------------------
    # PORTS
    # --------------------------------------------------------

    if open_port_count == 0:
        observations.append(
            "No open TCP ports were represented in the analyzed graph."
        )

    elif open_port_count == 1:
        observations.append(
            "1 open TCP port was represented in the analyzed graph."
        )

    else:
        observations.append(
            f"{open_port_count} open TCP ports were represented "
            "in the analyzed graph."
        )

    ports_with_banners = port_scan.get(
        "ports_with_banners",
        0,
    )

    coverage = port_scan.get(
        "banner_coverage_percentage",
        0.0,
    )

    if open_port_count > 0:
        observations.append(
            "Service banners were associated with "
            f"{ports_with_banners} of {open_port_count} "
            "represented open TCP ports "
            f"({coverage:.1f}% graph banner coverage)."
        )

    # --------------------------------------------------------
    # VIRUSTOTAL
    # --------------------------------------------------------

    if virustotal.get(
        "available",
        False,
    ):
        malicious = virustotal.get(
            "malicious",
            0,
        )

        suspicious = virustotal.get(
            "suspicious",
            0,
        )

        total_vendors = virustotal.get(
            "total_vendors",
            0,
        )

        risk_score = virustotal.get(
            "risk_score",
            0,
        )

        observations.append(
            "VirusTotal reported "
            f"{malicious} malicious and "
            f"{suspicious} suspicious detections "
            f"among {total_vendors} vendor results, "
            f"with a reported risk score of "
            f"{risk_score}/100. "
            "These are external multi-vendor observations "
            "and do not independently establish maliciousness."
        )

    return observations


# ============================================================
# DOMAIN ANALYSIS
# ============================================================

def _build_domain_analysis(
    context: Dict[str, Any],
    relationship_counts: Dict[str, int],
    requested_domain: str,
) -> Dict[str, Any]:
    """
    Build the complete analysis result.
    """

    domain_node = context[
        "domain_node"
    ]

    domain_properties = _node_properties(
        domain_node
    )

    actual_domain = _string_value(
        domain_properties,
        [
            "domain",
            "fqdn",
            "hostname",
            "name",
            "value",
            "id",
        ],
        default=requested_domain,
    )

    actual_domain = _normalize_domain(
        actual_domain
    )

    unique_subdomains = _deduplicate_nodes(
        context["subdomains"]
    )

    unique_ips = _deduplicate_nodes(
        context["ips"]
    )

    unique_asns = _deduplicate_nodes(
        context["asns"]
    )

    unique_organizations = _deduplicate_nodes(
        context["organizations"]
    )

    unique_certificates = _deduplicate_nodes(
        context["certificates"]
    )

    infrastructure = _build_infrastructure(
        context
    )

    statistics = {
        "subdomains": len(
            unique_subdomains
        ),

        "ip_addresses": len(
            unique_ips
        ),

        "asns": len(
            unique_asns
        ),

        "organizations": len(
            unique_organizations
        ),

        "certificates": len(
            unique_certificates
        ),

        "open_ports": int(
            relationship_counts.get(
                "HAS_OPEN_PORT",
                0,
            )
        ),
    }

    ip_versions = _ip_version_summary(
        unique_ips
    )

    subdomain_patterns = (
        _subdomain_pattern_analysis(
            unique_subdomains,
            actual_domain,
        )
    )

    port_scan = _build_port_scan_analysis(
        context,
        relationship_counts,
    )

    virustotal = _extract_virustotal(
        domain_properties
    )

    observations = _generate_observations(
        statistics=statistics,
        ip_versions=ip_versions,
        subdomain_patterns=subdomain_patterns,
        infrastructure=infrastructure,
        port_scan=port_scan,
        virustotal=virustotal,
    )

    return {
        "domain": actual_domain,

        "statistics": statistics,

        "relationships": relationship_counts,

        "ip_version_summary": ip_versions,

        "subdomain_patterns": subdomain_patterns,

        "infrastructure": infrastructure,

        "port_scan": port_scan,

        "virustotal": virustotal,

        "observations": observations,
    }


# ============================================================
# CYTOSCAPE GRAPH
# ============================================================

def _add_cytoscape_node(
    node: Any,
    node_type: str,
    nodes_output: List[Dict[str, Any]],
    node_id_map: Dict[str, str],
    used_graph_ids: Dict[str, str],
) -> str:
    """
    Add one Neo4j node to Cytoscape output.
    """

    element_id = _node_element_id(
        node
    )

    if not element_id:
        return ""

    if element_id in node_id_map:
        return node_id_map[
            element_id
        ]

    value = _node_identifier_value(
        node,
        node_type,
    )

    if value:
        cleaned = re.sub(
            r"[^A-Za-z0-9_.:@/-]+",
            "_",
            value,
        )

        candidate = (
            f"{node_type.lower()}:{cleaned}"
        )

        if candidate not in used_graph_ids:
            graph_id = candidate

        elif (
            used_graph_ids[candidate]
            == element_id
        ):
            graph_id = candidate

        else:
            graph_id = (
                f"{node_type.lower()}:"
                f"{element_id}"
            )

    else:
        graph_id = (
            f"{node_type.lower()}:"
            f"{element_id}"
        )

    used_graph_ids[
        graph_id
    ] = element_id

    node_id_map[
        element_id
    ] = graph_id

    nodes_output.append(
        {
            "data": {
                "id": graph_id,

                "label": _node_display_label(
                    node,
                    node_type,
                ),

                "type": node_type,

                "properties": _json_safe(
                    _node_properties(node)
                ),
            }
        }
    )

    return graph_id


def _add_cytoscape_edge(
    relationship: Any,
    node_id_map: Dict[str, str],
    edges_output: List[Dict[str, Any]],
    used_relationship_ids: set,
) -> None:
    """
    Add one actual directed Neo4j relationship.
    """

    if relationship is None:
        return

    relationship_id = (
        _relationship_element_id(
            relationship
        )
    )

    if not relationship_id:
        return

    if relationship_id in used_relationship_ids:
        return

    try:
        start_node = relationship.start_node
        end_node = relationship.end_node

        start_id = _node_element_id(
            start_node
        )

        end_id = _node_element_id(
            end_node
        )

    except Exception:
        return

    source = node_id_map.get(
        start_id
    )

    target = node_id_map.get(
        end_id
    )

    if not source or not target:
        return

    relationship_type = (
        _relationship_type(
            relationship
        )
    )

    used_relationship_ids.add(
        relationship_id
    )

    edges_output.append(
        {
            "data": {
                "id": (
                    f"{relationship_type.lower()}:"
                    f"{relationship_id}"
                ),

                "source": source,

                "target": target,

                "label": relationship_type,

                "type": relationship_type,

                "properties": _json_safe(
                    _relationship_properties(
                        relationship
                    )
                ),
            }
        }
    )


def _build_cytoscape_graph(
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Build the complete target-scoped Cytoscape graph.
    """

    nodes_output = []
    edges_output = []

    node_id_map = {}
    used_graph_ids = {}
    used_relationship_ids = set()

    # --------------------------------------------------------
    # DOMAIN
    # --------------------------------------------------------

    _add_cytoscape_node(
        context["domain_node"],
        "Domain",
        nodes_output,
        node_id_map,
        used_graph_ids,
    )

    # --------------------------------------------------------
    # SUBDOMAINS
    # --------------------------------------------------------

    for node in _deduplicate_nodes(
        context["subdomains"]
    ):
        _add_cytoscape_node(
            node,
            "Subdomain",
            nodes_output,
            node_id_map,
            used_graph_ids,
        )

    # --------------------------------------------------------
    # IPs
    # --------------------------------------------------------

    for node in _deduplicate_nodes(
        context["ips"]
    ):
        _add_cytoscape_node(
            node,
            "IPAddress",
            nodes_output,
            node_id_map,
            used_graph_ids,
        )

    # --------------------------------------------------------
    # ASNs
    # --------------------------------------------------------

    for node in _deduplicate_nodes(
        context["asns"]
    ):
        _add_cytoscape_node(
            node,
            "ASN",
            nodes_output,
            node_id_map,
            used_graph_ids,
        )

    # --------------------------------------------------------
    # ORGANIZATIONS
    # --------------------------------------------------------

    for node in _deduplicate_nodes(
        context["organizations"]
    ):
        _add_cytoscape_node(
            node,
            "Organization",
            nodes_output,
            node_id_map,
            used_graph_ids,
        )

    # --------------------------------------------------------
    # CERTIFICATES
    # --------------------------------------------------------

    for node in _deduplicate_nodes(
        context["certificates"]
    ):
        _add_cytoscape_node(
            node,
            "Certificate",
            nodes_output,
            node_id_map,
            used_graph_ids,
        )

    # --------------------------------------------------------
    # PORTS
    # --------------------------------------------------------

    port_nodes = _deduplicate_nodes(
        [
            port_node
            for _, port_node
            in context["ports"]
        ]
    )

    for node in port_nodes:
        _add_cytoscape_node(
            node,
            "Port",
            nodes_output,
            node_id_map,
            used_graph_ids,
        )

    # --------------------------------------------------------
    # SERVICE BANNERS
    # --------------------------------------------------------

    banner_nodes = _deduplicate_nodes(
        [
            banner_node
            for _, _, banner_node
            in context["banners"]
        ]
    )

    for node in banner_nodes:
        _add_cytoscape_node(
            node,
            "ServiceBanner",
            nodes_output,
            node_id_map,
            used_graph_ids,
        )

    # --------------------------------------------------------
    # RELATIONSHIPS
    # --------------------------------------------------------

    relationships = []

    relationships.extend(
        context[
            "subdomain_relationships"
        ]
    )

    relationships.extend(
        context[
            "resolve_relationships"
        ]
    )

    relationships.extend(
        context[
            "asn_relationships"
        ]
    )

    relationships.extend(
        context[
            "organization_relationships"
        ]
    )

    relationships.extend(
        context[
            "certificate_relationships"
        ]
    )

    relationships.extend(
        context[
            "port_relationships"
        ]
    )

    relationships.extend(
        context[
            "banner_relationships"
        ]
    )

    relationships = (
        _deduplicate_relationships(
            relationships
        )
    )

    for relationship in relationships:
        _add_cytoscape_edge(
            relationship,
            node_id_map,
            edges_output,
            used_relationship_ids,
        )

    return {
        "nodes": nodes_output,
        "edges": edges_output,
    }


# ============================================================
# PUBLIC FUNCTION: GRAPH
# ============================================================

def get_domain_graph(
    domain: str,
    password: str,
) -> Dict[str, Any]:
    """
    Return Cytoscape-compatible graph data.

    Signature intentionally preserved:
        get_domain_graph(domain, password)
    """

    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(
            NEO4J_USERNAME,
            password,
        ),
    )

    try:
        with driver.session(
            database="neo4j"
        ) as session:

            context = _load_graph_context(
                session,
                domain,
            )

            return _build_cytoscape_graph(
                context
            )

    finally:
        driver.close()


# ============================================================
# PUBLIC FUNCTION: ANALYSIS
# ============================================================

def get_domain_analysis(
    domain: str,
    password: str,
) -> Dict[str, Any]:
    """
    Return complete deterministic graph analysis.

    Signature intentionally preserved:
        get_domain_analysis(domain, password)
    """

    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(
            NEO4J_USERNAME,
            password,
        ),
    )

    try:
        with driver.session(
            database="neo4j"
        ) as session:

            context = _load_graph_context(
                session,
                domain,
            )

            # IMPORTANT:
            #
            # Counts are derived from the exact target-scoped
            # relationships already loaded above.
            #
            # This avoids broad Cypher traversals and prevents
            # HAS_BANNER from being inflated by unrelated paths.
            relationship_counts = (
                _get_relationship_counts(
                    context
                )
            )

            return _build_domain_analysis(
                context=context,
                relationship_counts=relationship_counts,
                requested_domain=domain,
            )

    finally:
        driver.close()


# ============================================================
# CLI OUTPUT
# ============================================================

def _print_analysis(
    analysis: Dict[str, Any],
) -> None:
    """
    Print a human-readable analysis.
    """

    print()
    print("=" * 70)

    print(
        f"Domain: "
        f"{analysis.get('domain', 'Unknown')}"
    )

    print("=" * 70)

    # --------------------------------------------------------
    # STATISTICS
    # --------------------------------------------------------

    statistics = analysis.get(
        "statistics",
        {},
    )

    print()
    print("Statistics:")

    print(
        f"  subdomains: "
        f"{statistics.get('subdomains', 0)}"
    )

    print(
        f"  ip_addresses: "
        f"{statistics.get('ip_addresses', 0)}"
    )

    print(
        f"  asns: "
        f"{statistics.get('asns', 0)}"
    )

    print(
        f"  organizations: "
        f"{statistics.get('organizations', 0)}"
    )

    print(
        f"  certificates: "
        f"{statistics.get('certificates', 0)}"
    )
    print()
    print("Certificate Details:")

    certificate_details = (
        analysis
        .get("infrastructure", {})
        .get("certificate_details", [])
    )

    print(
        json.dumps(
            certificate_details,
            indent=2,
            ensure_ascii=False,
        )
    )
    print(
        f"  open_ports: "
        f"{statistics.get('open_ports', 0)}"
    )

    # --------------------------------------------------------
    # RELATIONSHIPS
    # --------------------------------------------------------

    relationships = analysis.get(
        "relationships",
        {},
    )

    print()
    print("Relationship Summary:")

    for relationship_type in [
        "HAS_SUBDOMAIN",
        "RESOLVES_TO",
        "BELONGS_TO_ASN",
        "ASSOCIATED_WITH",
        "HAS_CERTIFICATE",
        "HAS_OPEN_PORT",
        "HAS_BANNER",
    ]:
        print(
            f"  {relationship_type}: "
            f"{relationships.get(relationship_type, 0)}"
        )

    # --------------------------------------------------------
    # IP VERSION
    # --------------------------------------------------------

    ip_versions = analysis.get(
        "ip_version_summary",
        {},
    )

    print()
    print("IP Version Summary:")

    print(
        f"  IPv4: "
        f"{ip_versions.get('ipv4', 0)}"
    )

    print(
        f"  IPv6: "
        f"{ip_versions.get('ipv6', 0)}"
    )

    print(
        f"  Unknown: "
        f"{ip_versions.get('unknown', 0)}"
    )

    # --------------------------------------------------------
    # SUBDOMAIN PATTERNS
    # --------------------------------------------------------

    patterns = analysis.get(
        "subdomain_patterns",
        {},
    )

    print()
    print("Subdomain Pattern Analysis:")

    print(
        f"  Numeric-leading: "
        f"{patterns.get('numeric_leading', 0)}"
    )

    print(
        f"  Contains hyphen: "
        f"{patterns.get('contains_hyphen', 0)}"
    )

    print(
        f"  Deep / Multi-level: "
        f"{patterns.get('deep_subdomains', 0)}"
    )

    # --------------------------------------------------------
    # PORT SCAN
    # --------------------------------------------------------

    port_scan = analysis.get(
        "port_scan",
        {},
    )

    print()
    print("TCP Port Scan:")

    print(
        f"  Scanned IPs: "
        f"{len(port_scan.get('scanned_ips', []))}"
    )

    print(
        f"  Open Ports: "
        f"{port_scan.get('total_open_ports', 0)}"
    )

    print(
        f"  IPs With Open Ports: "
        f"{port_scan.get('ips_with_open_ports', 0)}"
    )

    print(
        f"  Ports With Banners: "
        f"{port_scan.get('ports_with_banners', 0)}"
    )

    print(
        f"  Banner Coverage: "
        f"{port_scan.get('banner_coverage_percentage', 0.0):.1f}%"
    )

    # --------------------------------------------------------
    # VIRUSTOTAL
    # --------------------------------------------------------

    virustotal = analysis.get(
        "virustotal",
        {},
    )

    if virustotal.get(
        "available",
        False,
    ):
        print()
        print("VirusTotal:")

        print(
            f"  Risk Score: "
            f"{virustotal.get('risk_score', 0)}/100"
        )

        print(
            f"  Malicious: "
            f"{virustotal.get('malicious', 0)}"
        )

        print(
            f"  Suspicious: "
            f"{virustotal.get('suspicious', 0)}"
        )

        print(
            f"  Harmless: "
            f"{virustotal.get('harmless', 0)}"
        )

        print(
            f"  Undetected: "
            f"{virustotal.get('undetected', 0)}"
        )

        print(
            f"  Timeout: "
            f"{virustotal.get('timeout', 0)}"
        )

        print(
            f"  Total Vendors: "
            f"{virustotal.get('total_vendors', 0)}"
        )

        registrar = virustotal.get(
            "registrar",
            "",
        )

        if registrar:
            print(
                f"  Registrar: "
                f"{registrar}"
            )

    # --------------------------------------------------------
    # OBSERVATIONS
    # --------------------------------------------------------

    observations = analysis.get(
        "observations",
        [],
    )

    if observations:
        print()
        print("Observations:")

        for observation in observations:
            print(
                f"  - {observation}"
            )

    print()
    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    import getpass

    print()
    print("DomainAtlas Graph Analyzer")
    print("-" * 40)

    domain_input = input(
        "Enter domain: "
    ).strip()

    password_input = getpass.getpass(
        "Neo4j password: "
    )

    try:
        result = get_domain_analysis(
            domain_input,
            password_input,
        )

        _print_analysis(
            result
        )

    except Exception as exc:
        print()
        print(
            f"[!] Analysis error: {exc}"
        )