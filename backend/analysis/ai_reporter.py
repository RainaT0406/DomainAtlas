"""
DomainAtlas - AI-Assisted Intelligence Reporter

Generates a structured intelligence assessment from deterministic
DomainAtlas graph analysis.

Design principles:
    1. Deterministic DomainAtlas data is authoritative.
    2. Ollama is used only for natural-language interpretation.
    3. The LLM must not invent, alter, or contradict observations.
    4. Port/service/banner observations are extracted from the actual
       DomainAtlas port-scan structure.
    5. Numeric and factual contradictions are detected automatically.
    6. Missing critical observations are also detected.
    7. VirusTotal values are normalized deterministically.
    8. IP-version observations are supplied explicitly.
    9. If Ollama fails or times out, a deterministic report is returned.
   10. DomainAtlas appends the final analytical limitation itself.
"""

import json
import os
import re
from typing import Any, Dict, List, Optional

import requests

# Load .env before reading any OLLAMA_* variable so the pipeline
# picks up overrides from DomainAtlas/.env automatically.
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    # python-dotenv is optional; fall back to process environment.
    pass


# ============================================================
# CONFIGURATION
# ============================================================

OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://localhost:11434/api/generate",
)

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "llama3.2:1b",
)

OLLAMA_TIMEOUT = int(
    os.getenv(
        "OLLAMA_TIMEOUT",
        "180",
    )
)

OLLAMA_MAX_TOKENS = int(
    os.getenv(
        "OLLAMA_MAX_TOKENS",
        "220",
    )
)


# ============================================================
# REQUIRED REPORT STRUCTURE
# ============================================================

REQUIRED_HEADINGS = [
    "Domain Infrastructure",
    "Network Relationships",
    "Organizational Associations",
    "Certificate Observations",
    "Infrastructure Patterns",
    "Key Takeaways",
]


ANALYTICAL_LIMITATION = (
    "The report reflects only the collected DomainAtlas OSINT and "
    "TCP scan data and does not independently establish domain "
    "ownership, maliciousness, benignness, compromise, vulnerability, "
    "or overall security posture."
)


# ============================================================
# GENERAL HELPERS
# ============================================================

def safe_int(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def unique_values(values: Any) -> List[Any]:
    result: List[Any] = []
    seen = set()
    for value in safe_list(values):
        if value is None:
            continue
        if isinstance(value, str):
            value = value.strip()
            if not value:
                continue
        key = str(value)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def clean_text(value: Any, default: str = "Unknown") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def plural(count: int, singular: str, plural_form: Optional[str] = None) -> str:
    if count == 1:
        return singular
    return plural_form or f"{singular}s"


def be_verb(count: int) -> str:
    return "was" if count == 1 else "were"


# ============================================================
# PORT HELPERS
# ============================================================

COMMON_PORT_SERVICES = {
    20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    111: "RPC", 119: "NNTP", 123: "NTP", 135: "MSRPC", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP Submission", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2375: "Docker",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP Alternate", 8443: "HTTPS Alternate",
}


def normalize_port(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value if 0 <= value <= 65535 else None
    text = str(value).strip().lower()
    if not text:
        return None
    match = re.search(r"\b(\d{1,5})\b", text)
    if not match:
        return None
    port = safe_int(match.group(1), -1)
    if 0 <= port <= 65535:
        return port
    return None


def normalize_banner_text(banner: Any) -> Optional[str]:
    if banner is None:
        return None
    if isinstance(banner, bytes):
        try:
            banner = banner.decode("utf-8", errors="replace")
        except Exception:
            banner = str(banner)
    text = str(banner).strip()
    if not text:
        return None
    return re.sub(r"\s+", " ", text)


def get_observed_service_label(
    port: int,
    banner: Optional[str] = None,
    service: Optional[str] = None,
) -> str:
    normalized_service = clean_text(service, "")
    if normalized_service:
        return normalized_service
    conventional = COMMON_PORT_SERVICES.get(port)
    if conventional:
        return conventional
    return "Unknown service"


def extract_port_scan_container(analysis: Dict[str, Any]) -> Dict[str, Any]:
    candidates = [
        analysis.get("port_scan"),
        analysis.get("port_scan_results"),
    ]
    for candidate in candidates:
        if isinstance(candidate, dict):
            return candidate
    return {}


def extract_port_results(port_scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(port_scan, dict):
        return []
    results = port_scan.get("results")
    if isinstance(results, list):
        return [item for item in results if isinstance(item, dict)]
    return []


def extract_open_port_records(port_scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    results = extract_port_results(port_scan)
    for result in results:
        ip = clean_text(result.get("ip"), "")
        if not ip:
            continue
        open_ports = result.get("open_ports", [])
        if not isinstance(open_ports, list):
            continue
        for raw_port in open_ports:
            if not isinstance(raw_port, dict):
                continue
            port = normalize_port(raw_port.get("port"))
            if port is None:
                continue
            protocol = clean_text(raw_port.get("protocol", "tcp"), "tcp").lower()
            state = clean_text(raw_port.get("state", "open"), "open").lower()
            banner = normalize_banner_text(raw_port.get("banner"))
            service = clean_text(raw_port.get("service"), "")
            banner_available = raw_port.get("banner_available")
            if banner_available is None:
                banner_available = bool(banner)
            records.append({
                "ip": ip,
                "port": port,
                "protocol": protocol,
                "state": state,
                "service": service,
                "banner": banner,
                "banner_available": bool(banner_available),
            })
    return records


def normalize_open_ports(open_ports: Any) -> Dict[str, List[int]]:
    result: Dict[str, List[int]] = {}
    if not isinstance(open_ports, dict):
        return result
    for ip, ports in open_ports.items():
        if not ip:
            continue
        normalized: List[int] = []
        for raw_port in safe_list(ports):
            if isinstance(raw_port, dict):
                raw_port = raw_port.get("port")
            normalized_port = normalize_port(raw_port)
            if normalized_port is None:
                continue
            if normalized_port not in normalized:
                normalized.append(normalized_port)
        normalized.sort()
        result[str(ip)] = normalized
    return result


def extract_banner_map(port_scan: Dict[str, Any]) -> Dict[str, Dict[int, str]]:
    result: Dict[str, Dict[int, str]] = {}
    if not isinstance(port_scan, dict):
        return result

    records = extract_open_port_records(port_scan)
    for record in records:
        banner = record.get("banner")
        if not banner:
            continue
        ip = str(record["ip"])
        port = record["port"]
        result.setdefault(ip, {})
        result[ip][port] = banner

    for key in ("banners", "port_banners", "service_banners", "banner_map"):
        raw = port_scan.get(key)
        if not isinstance(raw, dict):
            continue
        for ip, banners in raw.items():
            if not isinstance(banners, dict):
                continue
            ip_key = str(ip)
            result.setdefault(ip_key, {})
            for port, banner in banners.items():
                normalized_port = normalize_port(port)
                if normalized_port is None:
                    continue
                normalized_banner = normalize_banner_text(banner)
                if not normalized_banner:
                    continue
                result[ip_key][normalized_port] = normalized_banner
    return result


def extract_service_map(port_scan: Dict[str, Any]) -> Dict[str, Dict[int, str]]:
    result: Dict[str, Dict[int, str]] = {}
    records = extract_open_port_records(port_scan)
    for record in records:
        ip = str(record["ip"])
        port = record["port"]
        service = clean_text(record.get("service"), "")
        if not service:
            continue
        result.setdefault(ip, {})
        result[ip][port] = service
    return result


def build_open_ports_from_records(records: List[Dict[str, Any]]) -> Dict[str, List[int]]:
    result: Dict[str, List[int]] = {}
    for record in records:
        ip = clean_text(record.get("ip"), "")
        port = normalize_port(record.get("port"))
        if not ip or port is None:
            continue
        result.setdefault(ip, [])
        if port not in result[ip]:
            result[ip].append(port)
    for ip in result:
        result[ip].sort()
    return result


def build_port_observations(
    open_ports_by_ip: Dict[str, List[int]],
    banner_map: Dict[str, Dict[int, str]],
    service_map: Optional[Dict[str, Dict[int, str]]] = None,
) -> List[Dict[str, Any]]:
    if service_map is None:
        service_map = {}
    observations: List[Dict[str, Any]] = []
    for ip in sorted(open_ports_by_ip.keys()):
        for port in sorted(open_ports_by_ip.get(ip, [])):
            banner = banner_map.get(ip, {}).get(port)
            explicit_service = service_map.get(ip, {}).get(port)
            service = get_observed_service_label(port, banner, explicit_service)
            observations.append({
                "ip": ip,
                "port": port,
                "protocol": "tcp",
                "banner": banner,
                "service": service,
                "banner_observed": bool(banner),
            })
    return observations


def format_port_observations(port_observations: List[Dict[str, Any]]) -> List[str]:
    lines: List[str] = []
    for observation in port_observations:
        ip = clean_text(observation.get("ip"), "Unknown IP")
        port = normalize_port(observation.get("port"))
        if port is None:
            continue
        service = clean_text(observation.get("service"), "Unknown service")
        banner = normalize_banner_text(observation.get("banner"))
        lines.append(f"- {ip}:{port}/tcp")
        lines.append(f"  Service: {service}")
        if banner:
            lines.append(f"  Banner: {banner}")
        else:
            lines.append("  Banner: Not observed")
    return lines


# ============================================================
# VIRUSTOTAL
# ============================================================

def normalize_virustotal(virustotal: Any) -> Dict[str, Any]:
    if not isinstance(virustotal, dict):
        return {}

    security_summary = virustotal.get("security_summary")
    if not isinstance(security_summary, dict):
        security_summary = {}

    last_analysis_stats = virustotal.get("last_analysis_stats")
    if not isinstance(last_analysis_stats, dict):
        last_analysis_stats = {}

    def first_value(key: str, default: Any = None) -> Any:
        for container in (virustotal, security_summary, last_analysis_stats):
            value = container.get(key)
            if value is not None:
                return value
        return default

    result = {
        "risk_score": first_value("risk_score", 0),
        "reputation": first_value("reputation", 0),
        "malicious": first_value("malicious", 0),
        "suspicious": first_value("suspicious", 0),
        "harmless": first_value("harmless", 0),
        "undetected": first_value("undetected", 0),
        "timeout": first_value("timeout", 0),
        "total_vendors": first_value("total_vendors", None),
        "registrar": first_value("registrar", None),
    }

    for field in ["risk_score", "reputation", "malicious", "suspicious",
                  "harmless", "undetected", "timeout"]:
        result[field] = safe_int(result[field])

    if result["total_vendors"] is not None:
        result["total_vendors"] = safe_int(result["total_vendors"])

    if result["total_vendors"] is None:
        result["total_vendors"] = sum(
            result[field] for field in
            ["malicious", "suspicious", "harmless", "undetected", "timeout"]
        )

    return result


def virustotal_has_meaningful_data(vt: Dict[str, Any]) -> bool:
    if not isinstance(vt, dict):
        return False
    fields = ["risk_score", "reputation", "malicious", "suspicious",
              "harmless", "undetected", "timeout", "total_vendors"]
    if any(safe_int(vt.get(field)) > 0 for field in fields):
        return True
    return bool(vt.get("registrar"))


def extract_virustotal_from_observations(observations: Any) -> Dict[str, Any]:
    if not isinstance(observations, list):
        return {}
    combined = "\n".join(str(item) for item in observations)
    if not re.search(r"virustotal", combined, re.IGNORECASE):
        return {}

    patterns = {
        "risk_score": [r"risk\s*score\s*[:=]\s*(\d+)"],
        "reputation": [r"reputation\s*[:=]\s*(-?\d+)"],
        "malicious": [r"malicious(?:\s+detections?)?\s*[:=]\s*(\d+)"],
        "suspicious": [r"suspicious(?:\s+detections?)?\s*[:=]\s*(\d+)"],
        "harmless": [r"harmless(?:\s+results?)?\s*[:=]\s*(\d+)"],
        "undetected": [r"undetected(?:\s+results?)?\s*[:=]\s*(\d+)"],
        "timeout": [r"timeout(?:\s+results?)?\s*[:=]\s*(\d+)"],
        "total_vendors": [
            r"total\s+vendors?\s*[:=]\s*(\d+)",
            r"across\s+(\d+)\s+vendors?",
        ],
        "registrar": [r"registrar\s*[:=]\s*([^\n,;]+)"],
    }

    result: Dict[str, Any] = {}
    for field, field_patterns in patterns.items():
        for pattern in field_patterns:
            match = re.search(pattern, combined, re.IGNORECASE)
            if not match:
                continue
            value = match.group(1).strip()
            if field == "registrar":
                result[field] = value
            else:
                result[field] = safe_int(value)
            break

    if "total_vendors" not in result and any(
        field in result for field in
        ["malicious", "suspicious", "harmless", "undetected", "timeout"]
    ):
        result["total_vendors"] = sum(
            safe_int(result.get(field)) for field in
            ["malicious", "suspicious", "harmless", "undetected", "timeout"]
        )

    if not result:
        return {}
    return normalize_virustotal(result)


def analyze_virustotal(virustotal: Any, observations: Any = None) -> Dict[str, Any]:
    vt = normalize_virustotal(virustotal)
    if not virustotal_has_meaningful_data(vt):
        recovered = extract_virustotal_from_observations(observations)
        if virustotal_has_meaningful_data(recovered):
            vt = recovered

    if not vt:
        return {
            "available": False,
            "risk_score": 0, "reputation": 0, "malicious": 0,
            "suspicious": 0, "harmless": 0, "undetected": 0,
            "timeout": 0, "total_vendors": 0, "registrar": None,
        }

    return {
        "available": True,
        "risk_score": safe_int(vt.get("risk_score")),
        "reputation": safe_int(vt.get("reputation")),
        "malicious": safe_int(vt.get("malicious")),
        "suspicious": safe_int(vt.get("suspicious")),
        "harmless": safe_int(vt.get("harmless")),
        "undetected": safe_int(vt.get("undetected")),
        "timeout": safe_int(vt.get("timeout")),
        "total_vendors": safe_int(vt.get("total_vendors")),
        "registrar": vt.get("registrar"),
    }


# ============================================================
# DETERMINISTIC ANALYSIS
# ============================================================

def build_deterministic_analysis(analysis: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(analysis, dict):
        analysis = {}

    domain = clean_text(analysis.get("domain"), "Unknown domain")

    infrastructure = analysis.get("infrastructure", {})
    if not isinstance(infrastructure, dict):
        infrastructure = {}

    subdomains = unique_values(infrastructure.get("subdomains", []))
    ip_addresses = unique_values(infrastructure.get("ip_addresses", []))
    asns = unique_values(infrastructure.get("asns", []))
    organizations = unique_values(infrastructure.get("organizations", []))
    certificates = unique_values(infrastructure.get("certificates", []))

    port_scan = extract_port_scan_container(analysis)
    scanner_records = extract_open_port_records(port_scan)

    open_ports_by_ip = build_open_ports_from_records(scanner_records)

    if not open_ports_by_ip:
        open_ports_by_ip = normalize_open_ports(infrastructure.get("open_ports", {}))

    if not open_ports_by_ip:
        for item in safe_list(analysis.get("ports")):
            if not isinstance(item, dict):
                continue
            ip = item.get("ip")
            port = normalize_port(item.get("port"))
            if not ip or port is None:
                continue
            ip_key = str(ip)
            open_ports_by_ip.setdefault(ip_key, [])
            if port not in open_ports_by_ip[ip_key]:
                open_ports_by_ip[ip_key].append(port)
        for ip in open_ports_by_ip:
            open_ports_by_ip[ip].sort()

    calculated_total_open_ports = sum(len(ports) for ports in open_ports_by_ip.values())
    reported_total_open_ports = safe_int(
        port_scan.get("total_open_ports",
                      port_scan.get("open_ports_total", -1)), -1)

    if calculated_total_open_ports > 0:
        total_open_ports = calculated_total_open_ports
    elif reported_total_open_ports >= 0:
        total_open_ports = reported_total_open_ports
    else:
        total_open_ports = 0

    scanned_ips = unique_values(port_scan.get("scanned_ips", []))
    if not scanned_ips:
        scanned_ips = list(open_ports_by_ip.keys())
    if not scanned_ips and ip_addresses:
        scanned_ips = list(ip_addresses)

    ips_with_open_ports = sum(1 for ports in open_ports_by_ip.values() if ports)

    banner_map = extract_banner_map(port_scan)
    service_map = extract_service_map(port_scan)

    if scanner_records:
        for record in scanner_records:
            ip_key = str(record["ip"])
            port = record["port"]
            banner = record.get("banner")
            service = record.get("service")
            if banner:
                banner_map.setdefault(ip_key, {})
                banner_map[ip_key][port] = banner
            if service:
                service_map.setdefault(ip_key, {})
                service_map[ip_key][port] = service

    ports_with_banners = 0
    for ip, ports in open_ports_by_ip.items():
        per_port = banner_map.get(ip, {})
        for port in ports:
            if per_port.get(port):
                ports_with_banners += 1

    if total_open_ports > 0 and ports_with_banners > total_open_ports:
        ports_with_banners = total_open_ports

    banner_coverage = (
        round((ports_with_banners / total_open_ports) * 100, 2)
        if total_open_ports > 0 else 0.0
    )

    port_observations = build_port_observations(open_ports_by_ip, banner_map, service_map)

    ip_version_summary = analysis.get("ip_version_summary", {})
    if not isinstance(ip_version_summary, dict):
        ip_version_summary = {}

    ipv4_count = safe_int(ip_version_summary.get("IPv4", ip_version_summary.get("ipv4", 0)))
    ipv6_count = safe_int(ip_version_summary.get("IPv6", ip_version_summary.get("ipv6", 0)))
    unknown_ip_count = safe_int(ip_version_summary.get("Unknown", ip_version_summary.get("unknown", 0)))

    relationships = analysis.get("relationships", {})
    if not isinstance(relationships, dict):
        relationships = {}

    subdomain_patterns = analysis.get("subdomain_patterns", {})
    if not isinstance(subdomain_patterns, dict):
        subdomain_patterns = {}

    infrastructure_metrics = analysis.get("infrastructure_metrics", {})
    if not isinstance(infrastructure_metrics, dict):
        infrastructure_metrics = {}

    observations = safe_list(analysis.get("observations", []))

    raw_virustotal = analysis.get("virustotal",
                     analysis.get("virus_total",
                     analysis.get("vt", {})))
    virustotal = analyze_virustotal(raw_virustotal, observations)

    authoritative_facts = {
        "domain": domain,
        "subdomain_count": len(subdomains),
        "subdomains": subdomains,
        "ip_count": len(ip_addresses),
        "ip_addresses": ip_addresses,
        "asn_count": len(asns),
        "asns": asns,
        "organization_count": len(organizations),
        "organizations": organizations,
        "certificate_count": len(certificates),
        "certificates": certificates,
        "total_open_ports": total_open_ports,
        "scanned_ip_count": len(scanned_ips),
        "scanned_ips": scanned_ips,
        "ips_with_open_ports": ips_with_open_ports,
        "ports_with_banners": ports_with_banners,
        "banner_coverage_percentage": banner_coverage,
        "open_ports_by_ip": open_ports_by_ip,
        "banner_map": banner_map,
        "service_map": service_map,
        "port_observations": port_observations,
        "ipv4_count": ipv4_count,
        "ipv6_count": ipv6_count,
        "unknown_ip_count": unknown_ip_count,
        "virustotal": virustotal,
    }

    return {
        "domain": domain,
        "statistics": {
            "subdomains": len(subdomains),
            "ip_addresses": len(ip_addresses),
            "asns": len(asns),
            "organizations": len(organizations),
            "certificates": len(certificates),
            "open_ports": total_open_ports,
        },
        "relationships": relationships,
        "subdomain_patterns": subdomain_patterns,
        "infrastructure_metrics": infrastructure_metrics,
        "ip_version_summary": {
            "IPv4": ipv4_count,
            "IPv6": ipv6_count,
            "Unknown": unknown_ip_count,
        },
        "port_scan": {
            "scanned_ips": scanned_ips,
            "total_open_ports": total_open_ports,
            "ips_with_open_ports": ips_with_open_ports,
            "ports_with_banners": ports_with_banners,
            "banner_coverage_percentage": banner_coverage,
            "open_ports_by_ip": open_ports_by_ip,
            "banners": banner_map,
            "service_map": service_map,
            "port_observations": port_observations,
        },
        "infrastructure": {
            "subdomains": subdomains,
            "ip_addresses": ip_addresses,
            "asns": asns,
            "organizations": organizations,
            "certificates": certificates,
            "open_ports": open_ports_by_ip,
        },
        "virustotal": virustotal,
        "authoritative_facts": authoritative_facts,
        "observations": observations,
    }


# ============================================================
# AUTHORITATIVE FACTS BLOCK
# ============================================================

def format_authoritative_facts(deterministic: Dict[str, Any]) -> str:
    facts = deterministic["authoritative_facts"]
    vt = facts["virustotal"]

    lines = [
        "AUTHORITATIVE DOMAINATLAS FACTS",
        "These deterministic values are immutable.",
        "",
        f"Domain: {facts['domain']}",
        "",
        f"Subdomains: {facts['subdomain_count']}",
        "Subdomain names: " + (
            ", ".join(str(x) for x in facts["subdomains"])
            if facts["subdomains"] else "none"
        ),
        "",
        f"IP addresses: {facts['ip_count']}",
        "IP address values: " + (
            ", ".join(str(x) for x in facts["ip_addresses"])
            if facts["ip_addresses"] else "none"
        ),
        f"IPv4: {facts['ipv4_count']}",
        f"IPv6: {facts['ipv6_count']}",
        f"Unknown IP version: {facts['unknown_ip_count']}",
        "",
        f"ASNs: {facts['asn_count']}",
        "ASN values: " + (
            ", ".join(str(x) for x in facts["asns"])
            if facts["asns"] else "none"
        ),
        "",
        f"Organizations: {facts['organization_count']}",
        "Organization values: " + (
            ", ".join(str(x) for x in facts["organizations"])
            if facts["organizations"] else "none"
        ),
        "",
        f"Certificates: {facts['certificate_count']}",
        "Certificate identifiers: " + (
            ", ".join(str(x) for x in facts["certificates"])
            if facts["certificates"] else "none"
        ),
        "",
        f"Scanned IP count: {facts['scanned_ip_count']}",
        "Scanned IP values: " + (
            ", ".join(str(x) for x in facts["scanned_ips"])
            if facts["scanned_ips"] else "none"
        ),
        f"Open TCP ports: {facts['total_open_ports']}",
        f"IPs with open ports: {facts['ips_with_open_ports']}",
        f"Ports with banners: {facts['ports_with_banners']}",
        f"Banner coverage: {facts['banner_coverage_percentage']:.2f}%",
        "",
        "OPEN TCP PORT OBSERVATIONS:",
    ]

    port_lines = format_port_observations(facts["port_observations"])
    lines.extend(port_lines if port_lines else ["- none"])

    lines.extend([
        "",
        "VIRUSTOTAL OBSERVATIONS:",
        f"- Available: {vt['available']}",
        f"- Risk score: {vt['risk_score']}/100",
        f"- Reputation: {vt['reputation']}",
        f"- Malicious detections: {vt['malicious']}",
        f"- Suspicious detections: {vt['suspicious']}",
        f"- Harmless results: {vt['harmless']}",
        f"- Undetected results: {vt['undetected']}",
        f"- Timeout results: {vt['timeout']}",
        f"- Total vendors: {vt['total_vendors']}",
        "- Registrar: " + clean_text(vt["registrar"], "Not available"),
    ])

    return "\n".join(lines)


# ============================================================
# SYSTEM PROMPT
# ============================================================

SYSTEM_PROMPT = """
You are the AI-assisted interpretation component of DomainAtlas.

Write ONLY one concise factual paragraph of 3 to 5 sentences from the
verified facts supplied by DomainAtlas.

STRICT RULES:
- The supplied DomainAtlas facts are the only source of truth.
- Preserve every number exactly. In particular, if Open TCP ports=4,
  you must say 4 open TCP ports, not 2.
- Do not recalculate, reinterpret, estimate, or generalize counts.
- Describe ports as observations of IP:port pairs. Two unique port numbers
  can still represent more than two open TCP observations across multiple IPs.
- Preserve the scanner service labels exactly. Do not infer HTTPS from
  port 443, and do not infer a service from a conventional port number.
- A 100% banner coverage value means a banner was observed for every
  represented open-port observation. It does NOT imply many services,
  service diversity, complexity, security, or any other property.
- VirusTotal results are external multi-vendor observations only. State
  the reported/calculated score and detection counts without interpreting
  them as an overall risk or security rating.
- Do not claim or imply that the domain is safe, unsafe, secure, insecure,
  low-risk, high-risk, malicious, benign, compromised, vulnerable, or has
  any particular security posture.
- Do not infer ownership, hosting-provider role, hosting-service status,
  application type, website purpose, infrastructure complexity, or intent.
- Do not infer security properties from certificates or HTTPS.
- Do not use phrases such as "appears to", "seems to", "suggests",
  "indicates", "may indicate", or "could indicate" to make an unsupported
  inference about security, hosting, application type, complexity, or risk.
- Do not create headings, lists, recommendations, warnings, or new facts.
- Do not repeat the analytical limitation.

Prefer wording such as "The collected observations show", "The observed
infrastructure includes", and "VirusTotal reported". The paragraph must
remain descriptive and evidence-bound.
"""


# ============================================================
# USER PROMPT
# ============================================================

def format_llm_port_observations(port_observations: List[Dict[str, Any]]) -> List[str]:
    lines: List[str] = []
    for observation in port_observations:
        ip = clean_text(observation.get("ip"), "Unknown IP")
        port = normalize_port(observation.get("port"))
        service = clean_text(observation.get("service"), "Unknown service")
        banner = normalize_banner_text(observation.get("banner"))
        if port is None:
            continue
        if banner:
            signature = re.sub(r"\s+", " ", banner)[:90]
            lines.append(
                f"- {ip}:{port}/tcp | service={service} | "
                f"banner=observed | signature={signature}"
            )
        else:
            lines.append(
                f"- {ip}:{port}/tcp | service={service} | banner=not observed"
            )
    return lines


def build_user_prompt(deterministic: Dict[str, Any]) -> str:
    facts = deterministic["authoritative_facts"]
    vt = facts["virustotal"]

    services = []
    for item in facts["port_observations"]:
        services.append(
            f"{item['port']}/tcp={item['service']} "
            f"(banner={'observed' if item.get('banner') else 'not observed'})"
        )

    return "\n".join([
        "VERIFIED DOMAINATLAS FACTS — USE THESE VALUES EXACTLY:",
        f"Domain={facts['domain']}",
        f"Subdomains={facts['subdomain_count']}",
        f"IPs={facts['ip_count']} ({facts['ipv4_count']} IPv4, {facts['ipv6_count']} IPv6, {facts['unknown_ip_count']} unknown)",
        f"ASNs={', '.join(map(str, facts['asns'])) if facts['asns'] else 'none'}",
        f"Organizations={', '.join(map(str, facts['organizations'])) if facts['organizations'] else 'none'}",
        f"Certificates={facts['certificate_count']}",
        f"Scanned IPs={facts['scanned_ip_count']}",
        f"Open TCP observations={facts['total_open_ports']}",
        f"IPs with open ports={facts['ips_with_open_ports']}",
        f"Service banners={facts['ports_with_banners']}",
        f"Banner coverage={facts['banner_coverage_percentage']:.2f}%",
        f"Services={'; '.join(services) if services else 'none'}",
        f"VirusTotal risk score={vt['risk_score']}/100; malicious={vt['malicious']}; suspicious={vt['suspicious']}; harmless={vt['harmless']}; undetected={vt['undetected']}; timeout={vt['timeout']}; total vendors={vt['total_vendors']}",
        "TASK: Write exactly 3 to 5 factual sentences about these observations.",
        f"MANDATORY: State the open TCP observation count as {facts['total_open_ports']} open TCP ports. Do not replace it with the number of unique port numbers.",
        "MANDATORY: Treat banner coverage only as evidence that banners were or were not observed for the represented open-port observations.",
        "MANDATORY: Treat VirusTotal only as an external observation; never convert its score or detections into an overall risk or security conclusion.",
        "MANDATORY: Do not infer hosting, application type, complexity, ownership, purpose, security, safety, maliciousness, benignness, compromise, vulnerability, or intent.",
        "Return only the paragraph."
    ])


# ============================================================
# OLLAMA
# ============================================================

def call_ollama(prompt: str, system_prompt: str = SYSTEM_PROMPT) -> str:
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "system": system_prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": OLLAMA_MAX_TOKENS,
        },
        "keep_alive": "5m",
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
    except requests.exceptions.Timeout as error:
        raise TimeoutError(
            f"Ollama request timed out after {OLLAMA_TIMEOUT} seconds."
        ) from error
    except requests.exceptions.RequestException as error:
        raise RuntimeError(f"Ollama request failed: {error}") from error

    response.raise_for_status()

    try:
        data = response.json()
    except ValueError as error:
        raise RuntimeError("Ollama returned invalid JSON.") from error

    report = data.get("response")
    if not report:
        raise RuntimeError("Ollama returned an empty response.")

    return str(report).strip()


# ============================================================
# MARKDOWN HEADING VALIDATION
# ============================================================

def normalize_heading_line(line: str) -> str:
    value = str(line).strip()
    value = re.sub(r"^#+\s*", "", value)
    value = re.sub(r"^\d+\.\s*", "", value)
    value = re.sub(r"^[-*+]\s*", "", value)
    value = value.replace("**", "").replace("__", "").replace("*", "")
    value = re.sub(r"[:\-]+$", "", value)
    return value.strip().lower()


def find_heading_occurrences(report: str, heading: str) -> int:
    target = heading.strip().lower()
    return sum(
        1 for line in report.splitlines()
        if normalize_heading_line(line) == target
    )


def validate_required_headings(report: str) -> List[str]:
    errors: List[str] = []
    for heading in REQUIRED_HEADINGS:
        count = find_heading_occurrences(report, heading)
        if count == 0:
            errors.append(f"Missing section: {heading}")
        elif count > 1:
            errors.append(f"Duplicated section: {heading}")
    return errors


# ============================================================
# REPORT NORMALIZATION
# ============================================================

def canonicalize_headings(report: str) -> str:
    lines: List[str] = []
    heading_lookup = {heading.lower(): heading for heading in REQUIRED_HEADINGS}
    for line in report.splitlines():
        normalized = normalize_heading_line(line)
        if normalized in heading_lookup:
            lines.append(f"## {heading_lookup[normalized]}")
        else:
            lines.append(line.rstrip())
    return "\n".join(lines).strip()


def remove_code_fences(report: str) -> str:
    text = report.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def remove_duplicate_limitation(report: str) -> str:
    if not report:
        return report
    report = report.replace(ANALYTICAL_LIMITATION, "")
    report = re.sub(
        r"(?is)(?:^|\n)\s*(?:#+\s*)?"
        r"(?:analytical\s+limitation|limitations?)\s*:?\s*\n"
        r".*?(?=\n\s*#+\s|\Z)",
        "\n",
        report,
    )
    return report.strip()


def clean_report(report: str) -> str:
    report = remove_code_fences(report)
    report = remove_duplicate_limitation(report)
    report = canonicalize_headings(report)
    report = re.sub(r"\n{3,}", "\n\n", report)
    return report.strip()


def append_limitation(report: str) -> str:
    cleaned = report.replace(ANALYTICAL_LIMITATION, "").strip()
    return (
        cleaned
        + "\n\n"
        + "### Analytical Limitation\n\n"
        + ANALYTICAL_LIMITATION
    )


# ============================================================
# FACTUAL CONSISTENCY VALIDATION
# ============================================================

def validate_numeric_consistency(report: str, deterministic: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    facts = deterministic["authoritative_facts"]
    lower = report.lower()

    subdomain_count = facts["subdomain_count"]
    if subdomain_count == 0:
        if re.search(
            r"\b(?:one|a single|a)\s+subdomain\b"
            r"|\bwith\s+(?:one|a)\s+subdomain\b"
            r"|\bhas\s+(?:one|a)\s+subdomain\b"
            r"|\b\d+\s+observed\s+subdomains?\b",
            lower,
        ):
            errors.append(
                "Report describes a subdomain even though the "
                "authoritative subdomain count is 0."
            )
    elif subdomain_count == 1:
        if re.search(r"\bmultiple\s+subdomains?\b|\bseveral\s+subdomains?\b", lower):
            errors.append(
                "Report describes multiple subdomains but only one was observed."
            )

    ip_count = facts["ip_count"]
    if ip_count == 0:
        if re.search(
            r"\b(?:one|a single|multiple|several)\s+"
            r"(?:observed\s+)?ip(?:\s+addresses?)?\b",
            lower,
        ):
            errors.append(
                "Report describes observed IP addresses even though "
                "the authoritative IP count is 0."
            )
    elif ip_count == 1:
        if re.search(
            r"\bmultiple\s+ip\s+addresses?\b"
            r"|\bmultiple\s+ips\b"
            r"|\bseveral\s+ip\s+addresses?\b"
            r"|\bmultiple\s+addresses\b",
            lower,
        ):
            errors.append(
                "Report describes multiple IP addresses but only one was observed."
            )

    ipv4_count = facts["ipv4_count"]
    if ipv4_count > 0:
        if re.search(
            r"\bno\s+ipv4(?:\s+addresses?)?\b"
            r"|\bwithout\s+ipv4\b"
            r"|\bipv4\s+addresses?\s+were\s+not\s+observed\b"
            r"|\bzero\s+ipv4\s+addresses?\b",
            lower,
        ):
            errors.append(
                f"Report says no IPv4 addresses were observed but "
                f"the authoritative IPv4 count is {ipv4_count}."
            )
    else:
        if re.search(
            r"\b(?:observed|identified)\s+ipv4\s+addresses?\b"
            r"|\bipv4\s+addresses?\s+were\s+observed\b"
            r"|\bone\s+ipv4\s+address\b"
            r"|\bmultiple\s+ipv4\s+addresses\b",
            lower,
        ):
            errors.append(
                "Report describes IPv4 addresses even though the "
                "authoritative IPv4 count is 0."
            )

    ipv6_count = facts["ipv6_count"]
    if ipv6_count > 0:
        if re.search(
            r"\bno\s+ipv6(?:\s+addresses?)?\b"
            r"|\bwithout\s+ipv6\b"
            r"|\bipv6\s+addresses?\s+were\s+not\s+observed\b"
            r"|\bzero\s+ipv6\s+addresses?\b",
            lower,
        ):
            errors.append(
                f"Report says no IPv6 addresses were observed but "
                f"the authoritative IPv6 count is {ipv6_count}."
            )
    else:
        if re.search(
            r"\b(?:observed|identified)\s+ipv6\s+addresses?\b"
            r"|\bipv6\s+addresses?\s+were\s+observed\b"
            r"|\bone\s+ipv6\s+address\b"
            r"|\bmultiple\s+ipv6\s+addresses\b",
            lower,
        ):
            errors.append(
                "Report describes IPv6 addresses even though the "
                "authoritative IPv6 count is 0."
            )

    open_port_count = facts["total_open_ports"]
    if open_port_count > 0:
        if re.search(
            r"\bno\s+open\s+(?:tcp\s+)?ports?\b"
            r"|\bzero\s+open\s+ports\b"
            r"|\bwithout\s+open\s+ports\b"
            r"|\bhas\s+no\s+open\s+ports\b"
            r"|\bno\s+open\s+tcp\s+ports\b",
            lower,
        ):
            errors.append(
                f"Report says there are no open ports, but "
                f"{open_port_count} open TCP ports were observed."
            )
    else:
        if re.search(
            r"\b\d{1,5}/tcp\b|\bopen\s+tcp\s+ports?\b|\bopen\s+ports?\b",
            lower,
        ):
            errors.append(
                "Report describes open ports even though the "
                "authoritative open-port count is 0."
            )

    certificate_count = facts["certificate_count"]
    if certificate_count == 0:
        if re.search(
            r"\b(?:one|a single|multiple|several)\s+certificates?\b",
            lower,
        ):
            errors.append(
                "Report describes certificates even though the "
                "authoritative certificate count is 0."
            )
    elif certificate_count == 1:
        if re.search(r"\bmultiple\s+certificates\b|\bseveral\s+certificates\b", lower):
            errors.append(
                "Report describes multiple certificates but only one was observed."
            )

    vt = facts["virustotal"]
    if vt.get("available"):
        malicious = safe_int(vt.get("malicious"))
        suspicious = safe_int(vt.get("suspicious"))
        total_vendors = safe_int(vt.get("total_vendors"))
        risk_score = safe_int(vt.get("risk_score"))

        if malicious > 0:
            if re.search(
                r"\bno\s+malicious\s+(?:detections?|results?|findings?)\b",
                lower,
            ):
                errors.append(
                    f"Report says there are no malicious detections but "
                    f"VirusTotal reports {malicious}."
                )
        elif re.search(r"\b\d+\s+malicious\s+detections?\b", lower):
            errors.append(
                "Report contains a positive malicious detection count "
                "even though the authoritative count is 0."
            )

        if suspicious > 0:
            if re.search(
                r"\bno\s+suspicious\s+(?:detections?|results?)\b",
                lower,
            ):
                errors.append(
                    f"Report says there are no suspicious detections but "
                    f"VirusTotal reports {suspicious}."
                )

        if total_vendors > 0:
            if re.search(r"\bno\s+(?:security\s+)?vendors?\b", lower):
                errors.append(
                    f"Report says no vendors were involved even though "
                    f"{total_vendors} VirusTotal vendors were recorded."
                )

        risk_patterns = re.findall(
            r"(?:risk\s+score|score)\s*(?:of|is|:)?\s*(\d{1,3})\s*/\s*100",
            lower,
        )
        for reported_score in risk_patterns:
            if safe_int(reported_score, risk_score) != risk_score:
                errors.append(
                    f"Report contains a VirusTotal risk score that "
                    f"does not match the authoritative value of "
                    f"{risk_score}/100."
                )
                break

    return errors


# ============================================================
# PORT/BANNER VALIDATION
# ============================================================

def validate_port_counts(report: str, deterministic: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    facts = deterministic["authoritative_facts"]
    lower = report.lower()

    open_port_count = safe_int(facts["total_open_ports"])
    banner_count = safe_int(facts["ports_with_banners"])
    coverage = safe_float(facts["banner_coverage_percentage"])

    # ---- open-port count statement ----
    if open_port_count > 0:
        port_stated = (
            re.search(rf"\b{open_port_count}\s+open\s+tcp\s+ports?\b", lower)
            or re.search(rf"\b{open_port_count}\s+open\s+ports?\b", lower)
            or re.search(rf"\b{open_port_count}\s+open\s+tcp\s+observations?\b", lower)
            or re.search(rf"\b{open_port_count}\s+tcp\s+ports?\b", lower)
        )
        if not port_stated:
            errors.append(
                f"Report does not state the authoritative open TCP port "
                f"count of {open_port_count}."
            )
    elif re.search(r"\b(?:\d{1,5}/tcp|open\s+tcp\s+ports?|open\s+ports?)\b", lower):
        errors.append(
            "Report describes open ports even though the authoritative "
            "open-port count is 0."
        )

    # ---- banner count statements ----
    reported_counts = [
        safe_int(value) for value in re.findall(
            r"\b(\d+)\s+(?:service\s+)?banners?\b", lower
        )
    ]

    for reported in reported_counts:
        if reported != banner_count:
            errors.append(
                f"Report contains a banner count of {reported}, but "
                f"DomainAtlas observed {banner_count}."
            )
            break

    # ---- coverage % statements ----
    reported_coverages = [
        safe_float(value) for value in re.findall(
            r"\b(\d+(?:\.\d+)?)%\s+banner\s+coverage\b", lower
        )
    ]
    for reported in reported_coverages:
        if abs(reported - coverage) > 0.01:
            errors.append(
                f"Report contains banner coverage of {reported:.2f}%, but "
                f"the authoritative value is {coverage:.2f}%."
            )
            break

    if banner_count > 0:
        forbidden_no_banner_patterns = [
            r"\bno\s+observed\s+banners?\b",
            r"\bno\s+service\s+banners?\b",
            r"\bno\s+banners?\s+were\s+observed\b(?!\s+on\s+(?:tcp\s+)?ports?)",
            r"\bwith\s+no\s+observed\s+banners?\b",
            r"\bwithout\s+any\s+observed\s+banners?\b",
        ]
        if any(re.search(pattern, lower) for pattern in forbidden_no_banner_patterns):
            errors.append(
                f"Report incorrectly states that no banners were observed. "
                f"DomainAtlas observed {banner_count} service banners."
            )

    return errors


# ============================================================
# SERVICE OBSERVATION VALIDATION
# ============================================================

def validate_service_observations(report: str, deterministic: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    facts = deterministic["authoritative_facts"]
    lower = report.lower()
    observations = facts["port_observations"]

    for observation in observations:
        port = observation["port"]
        service = clean_text(observation.get("service"), "")
        banner = normalize_banner_text(observation.get("banner"))
        observed_text = " ".join(
            part for part in (service, banner) if part
        ).lower()

        # 443 HTTP/Apache must not become HTTPS.
        if port == 443 and "http" in observed_text and "apache" in observed_text:
            if re.search(r"\b443/tcp\b[^.\n]{0,160}\bhttps\b", lower) or \
               re.search(r"\bport\s+443\b[^.\n]{0,160}\bhttps\b", lower):
                errors.append(
                    "Report classifies observed 443/tcp as HTTPS although "
                    "the supplied observation is HTTP (Apache)."
                )

        # Preserve IMAP/POP3 (Dovecot).
        if "dovecot" in service.lower() and "imap/pop3" in service.lower():
            port_pattern = rf"\b{port}/tcp\b[^.\n]{{0,160}}"
            if re.search(port_pattern + r"\bpop3\b", lower) and \
               not re.search(port_pattern + r"\bimap/pop3\b", lower):
                errors.append(
                    f"Report reduces observed {port}/tcp IMAP/POP3 "
                    "(Dovecot) information to POP3 only."
                )
            if re.search(port_pattern + r"\bimap\b", lower) and \
               not re.search(port_pattern + r"\bimap/pop3\b", lower):
                errors.append(
                    f"Report reduces observed {port}/tcp IMAP/POP3 "
                    "(Dovecot) information to IMAP only."
                )

        # A banner cannot be contradicted by saying the same port had no banner.
        if banner:
            no_banner_patterns = [
                rf"\b{port}/tcp\b[^.\n]{{0,120}}\bno\s+(?:service\s+)?banner\b",
                rf"\bport\s+{port}\b[^.\n]{{0,120}}\bno\s+(?:service\s+)?banner\b",
            ]
            for pattern in no_banner_patterns:
                if re.search(pattern, lower):
                    errors.append(
                        f"Report says {port}/tcp had no banner although a "
                        "banner was observed."
                    )
                    break

    # Require distinctive service labels to survive generation.
    for observation in observations:
        port = observation["port"]
        service = clean_text(observation.get("service"), "")
        if not service:
            continue
        distinctive_labels = []
        if "Pure-FTPd" in service:
            distinctive_labels.append("pure-ftpd")
        if "OpenSSH" in service:
            distinctive_labels.append("openssh")
        if "Apache" in service:
            distinctive_labels.append("apache")
        if "Dovecot" in service:
            distinctive_labels.append("dovecot")
        if not distinctive_labels:
            continue
        if not any(label in lower for label in distinctive_labels):
            errors.append(
                f"Report omits the distinctive observed service "
                f"information for {port}/tcp ({service})."
            )

    return errors


# ============================================================
# SECURITY CLAIM VALIDATION
# ============================================================

def validate_security_claims(report: str) -> List[str]:
    errors: List[str] = []
    lower = report.lower()

    forbidden_patterns = [
        (r"\bthe\s+domain\s+is\s+malicious\b", "categorical maliciousness claim"),
        (r"\bthe\s+domain\s+is\s+benign\b", "categorical benignness claim"),
        (r"\bthe\s+domain\s+is\s+safe\b", "categorical safety claim"),
        (r"\bthe\s+domain\s+is\s+compromised\b", "categorical compromise claim"),
        (r"\bthe\s+domain\s+has\s+been\s+compromised\b", "categorical compromise claim"),
        (r"\bthe\s+domain\s+is\s+vulnerable\b", "categorical vulnerability claim"),
        (r"\bno\s+security\s+risk\b", "categorical security-risk claim"),
        (r"\bcompletely\s+secure\b", "categorical security claim"),
        (r"\bfully\s+secure\b", "categorical security claim"),
        (r"\bthe\s+domain\s+is\s+secure\b", "categorical security claim"),
        (r"\b(?:appears|seems)\s+to\s+be\s+(?:a\s+)?hosting\s+service\b",
         "unsupported hosting-service inference"),
        (r"\b(?:appears|seems)\s+to\s+have\s+(?:a\s+)?(?:low|high)\s+risk\b",
         "risk inference"),
        (r"\b(?:low|high|relatively\s+low|relatively\s+high)\s+risk\s+(?:profile|level)\b",
         "risk inference"),
        (r"\b(?:suggests?|indicates?|demonstrates?)\s+(?:that\s+)?(?:the\s+)?domain\s+(?:is|may\s+be|could\s+be|uses?|hosts?)\b",
         "unsupported domain inference"),
        (r"\b(?:suggests?|indicates?|could\s+indicate|may\s+indicate)\b[^.]{0,180}\b(?:hosting|hosted|web\s+application|application\s+server|complex\s+infrastructure|security|risk|safe|secure)\b",
         "infrastructure or security inference"),
        (r"\b(?:indicat(?:e|ing)|suggest(?:s|ing))\b[^.]{0,180}\b(?:security|secure|risk|safe|safety)\b",
         "unsupported security inference"),
        (r"\b(?:certificate|certificates)\b[^.]{0,120}\b(?:security|secure|safe|protection|protected)\b",
         "unsupported certificate-security inference"),
        (r"\b(?:hosting\s+web\s+applications?|web\s+applications?\s+are\s+hosted|application\s+hosting)\b",
         "application-hosting inference"),
        (r"\b(?:more\s+complex|complex|sophisticated)\s+(?:infrastructure|architecture)\b",
         "unsupported infrastructure-complexity inference"),
    ]

    for pattern, description in forbidden_patterns:
        if re.search(pattern, lower):
            errors.append(f"Unsupported {description}.")

    return errors


# ============================================================
# AI INTERPRETATION VALIDATION (RELAXED)
# ============================================================

def validate_ai_interpretation(interpretation: str, deterministic: Dict[str, Any]) -> List[str]:
    errors = validate_security_claims(interpretation)
    text = str(interpretation or "").strip()
    lower = text.lower()
    facts = deterministic["authoritative_facts"]

    if not text:
        errors.append("AI interpretation is empty.")
        return errors

    if re.search(r"(?m)^\s*#+\s+", text):
        errors.append("AI interpretation contains a heading.")

    if re.search(r"(?m)^\s*(?:[-*+]\s+|\d+\.\s+)", text):
        errors.append("AI interpretation contains a list item.")

    # ---- open TCP count ----
    open_ports = safe_int(facts["total_open_ports"])
    if open_ports > 0:
        port_ok = (
            re.search(rf"\b{open_ports}\s+open\s+tcp\s+ports?\b", lower)
            or re.search(rf"\b{open_ports}\s+open\s+tcp\s+observations?\b", lower)
            or re.search(rf"\b{open_ports}\s+open\s+ports?\b", lower)
            or re.search(rf"\b{open_ports}\s+tcp\s+ports?\b", lower)
        )
        if not port_ok:
            errors.append(
                f"AI interpretation does not state the authoritative open "
                f"TCP count of {open_ports}."
            )

        contradictory_patterns = [
            r"\ba\s+total\s+of\s+(\d+)\s+open\s+tcp\s+ports?\b",
            r"\boverall\s+(\d+)\s+open\s+tcp\s+ports?\b",
            r"\bin\s+total,?\s+(\d+)\s+open\s+tcp\s+ports?\b",
        ]
        for pattern in contradictory_patterns:
            match = re.search(pattern, lower)
            if match and safe_int(match.group(1), open_ports) != open_ports:
                errors.append(
                    "AI interpretation contains an overall open TCP count "
                    "that conflicts with the authoritative count."
                )
                break

    # ---- banner count / coverage ----
    banner_count = safe_int(facts["ports_with_banners"])
    coverage = safe_float(facts["banner_coverage_percentage"])

    if banner_count > 0:
        if re.search(
            r"\bno\s+(?:service\s+)?banners?\s+(?:were\s+)?observed\b",
            lower,
        ):
            errors.append(
                "AI interpretation incorrectly states that no banners were observed."
            )

        has_banner_fact = (
            re.search(rf"\b{banner_count}\b", lower)
            or re.search(rf"\b{coverage:.2f}%\b", lower)
            or re.search(rf"\b{coverage:.1f}%\b", lower)
            or (re.search(r"\b100(?:\.0+)?%\b", lower) and coverage == 100.0)
            or re.search(r"\bbanners?\b", lower)
        )
        if not has_banner_fact:
            errors.append(
                "AI interpretation does not preserve the banner "
                "observation facts."
            )
    elif banner_count == 0:
        if re.search(
            r"\b(?:all|\d+)\s+(?:open\s+)?(?:tcp\s+)?ports?\s+"
            r"(?:had|have)\s+banners?\b",
            lower,
        ):
            errors.append(
                "AI interpretation claims banners were observed on all "
                "ports even though none were recorded."
            )

    # ---- broad inferential language ----
    broad_inference_patterns = [
        (r"\b(?:may|might|could|can)\s+(?:indicate|suggest|imply)\b",
         "unsupported speculative inference"),
        (r"\b(?:indicates?|suggests?|implies?)\b[^.]{0,160}\b"
         r"(?:risk|security|hosting|application|complexity|purpose|ownership)\b",
         "inference"),
    ]
    for pattern, description in broad_inference_patterns:
        if re.search(pattern, lower):
            errors.append(f"Unsupported {description}.")

    # ========================================================
    # HALLUCINATED-NUMBER DETECTION
    # ========================================================
    # The LLM paragraph may only cite numbers that match the
    # authoritative facts. Any "N <category>" phrase where the
    # category maps to a known count and N is wrong is rejected.
    # ========================================================

    authoritative_counts = {
        # ports
        "open tcp port": safe_int(facts["total_open_ports"]),
        "open tcp ports": safe_int(facts["total_open_ports"]),
        "open port": safe_int(facts["total_open_ports"]),
        "open ports": safe_int(facts["total_open_ports"]),
        "tcp port": safe_int(facts["total_open_ports"]),
        "tcp ports": safe_int(facts["total_open_ports"]),
        "open tcp observation": safe_int(facts["total_open_ports"]),
        "open tcp observations": safe_int(facts["total_open_ports"]),

        # banners
        "banner": safe_int(facts["ports_with_banners"]),
        "banners": safe_int(facts["ports_with_banners"]),
        "service banner": safe_int(facts["ports_with_banners"]),
        "service banners": safe_int(facts["ports_with_banners"]),
        "observed banner": safe_int(facts["ports_with_banners"]),
        "observed banners": safe_int(facts["ports_with_banners"]),

        # subdomains / ips
        "subdomain": safe_int(facts["subdomain_count"]),
        "subdomains": safe_int(facts["subdomain_count"]),
        "observed subdomain": safe_int(facts["subdomain_count"]),
        "observed subdomains": safe_int(facts["subdomain_count"]),

        "ip address": safe_int(facts["ip_count"]),
        "ip addresses": safe_int(facts["ip_count"]),
        "observed ip address": safe_int(facts["ip_count"]),
        "observed ip addresses": safe_int(facts["ip_count"]),
        "ip": safe_int(facts["ip_count"]),
        "ips": safe_int(facts["ip_count"]),

        "ipv4 address": safe_int(facts["ipv4_count"]),
        "ipv4 addresses": safe_int(facts["ipv4_count"]),
        "ipv6 address": safe_int(facts["ipv6_count"]),
        "ipv6 addresses": safe_int(facts["ipv6_count"]),

        "scanned ip": safe_int(facts["scanned_ip_count"]),
        "scanned ips": safe_int(facts["scanned_ip_count"]),
        "scanned ip address": safe_int(facts["scanned_ip_count"]),
        "scanned ip addresses": safe_int(facts["scanned_ip_count"]),

        # graph categories
        "asn": safe_int(facts["asn_count"]),
        "asns": safe_int(facts["asn_count"]),
        "organization": safe_int(facts["organization_count"]),
        "organizations": safe_int(facts["organization_count"]),
        "certificate": safe_int(facts["certificate_count"]),
        "certificates": safe_int(facts["certificate_count"]),
    }

    # Normalise a candidate category phrase: collapse whitespace,
    # strip trailing connective noise.
    def _normalize_category(text: str) -> str:
        text = re.sub(r"\s+", " ", text.strip().lower())
        for cut in (
            " were", " was", " is", " are", " have", " has",
            " observed", " identified", " recorded", " reported",
            " being", " across",
        ):
            if text.endswith(cut):
                text = text[: -len(cut)].strip()
        return text

    # Match "N <optional modifiers> <category>" where category is
    # a short noun phrase. We look ahead up to ~6 words.
    numeric_claim_re = re.compile(
        r"\b(\d+)\s+"
        r"(?:(?:different|separate|distinct|total|overall|individual)\s+)?"
        r"([a-z][a-z0-9_\- ]{2,40}?)\b"
    )

    for match in numeric_claim_re.finditer(lower):
        raw_number = match.group(1)
        raw_category = _normalize_category(match.group(2))

        # Try progressively shorter category suffixes to find a match.
        tokens = raw_category.split()
        candidates = [" ".join(tokens[i:]) for i in range(len(tokens))]

        matched_category = None
        for candidate in candidates:
            if candidate in authoritative_counts:
                matched_category = candidate
                break

        if matched_category is None:
            continue

        authoritative = authoritative_counts[matched_category]
        reported = safe_int(raw_number, authoritative)

        if reported != authoritative:
            errors.append(
                f"AI interpretation claims {reported} {matched_category} "
                f"but the authoritative count is {authoritative}."
            )

    # --------------------------------------------------------
    # Reject multiple banner coverage percentages / ranges.
    # There is exactly one authoritative coverage value.
    # --------------------------------------------------------
    if re.search(
        r"\b\d+\s+(?:different\s+|separate\s+|distinct\s+)?"
        r"banner\s+coverage\s+percentages?\b",
        lower,
    ):
        errors.append(
            "AI interpretation claims multiple banner coverage "
            "percentages even though there is a single authoritative value."
        )

    if re.search(
        r"\branging\s+from\s+\d+(?:\.\d+)?%\s+to\s+\d+(?:\.\d+)?%",
        lower,
    ):
        errors.append(
            "AI interpretation describes a range of percentages that "
            "does not correspond to any authoritative metric."
        )

    # --------------------------------------------------------
    # Reject "open TCP ports ... IPv4/IPv6" misassociation.
    # --------------------------------------------------------
    if re.search(r"\bopen\s+tcp\s+ports?\b[^.]{0,120}\bipv[46]\b", lower):
        errors.append(
            "AI interpretation incorrectly associates open TCP ports "
            "with IP versions."
        )

    # --------------------------------------------------------
    # Reject "N of them being X and M being Y" style claims
    # where the numbers don't add up to the parent category.
    # --------------------------------------------------------
    # e.g. "4 open TCP ports, with 2 of them being IPv4 and 2 IPv6"
    #      -> "of them being" splits are fine ONLY when the parent
    #         category is an IP-version split. Otherwise reject.
    for match in re.finditer(
        r"\b(\d+)\s+open\s+tcp\s+ports?\b[^.]{0,120}"
        r"\bwith\s+(\d+)\s+of\s+them\s+being\b",
        lower,
    ):
        errors.append(
            "AI interpretation misattributes IP-version counts to open TCP ports."
        )
        break

    return list(dict.fromkeys(errors))
# ============================================================
# SAFE AI FALLBACK
# ============================================================

def build_safe_ai_interpretation(deterministic: Dict[str, Any]) -> str:
    facts = deterministic["authoritative_facts"]
    vt = facts["virustotal"]

    services: List[str] = []
    for item in facts["port_observations"]:
        ip = clean_text(item.get("ip"), "Unknown IP")
        port = normalize_port(item.get("port"))
        if port is None:
            continue
        service = clean_text(item.get("service"), "Unknown service")
        services.append(f"{ip}:{port}/tcp ({service})")

    ip_sentence = (
        f"The collected observations include "
        f"{facts['ip_count']} "
        f"{plural(facts['ip_count'], 'IP address', 'IP addresses')}, "
        f"with {facts['ipv4_count']} IPv4 and "
        f"{facts['ipv6_count']} IPv6 addresses."
    )

    port_sentence = (
        f"TCP scanning identified "
        f"{facts['total_open_ports']} open TCP "
        f"{plural(facts['total_open_ports'], 'port', 'ports')} "
        f"across {facts['scanned_ip_count']} scanned IP "
        f"{plural(facts['scanned_ip_count'], 'address', 'addresses')}, "
        f"with service banners observed for "
        f"{facts['ports_with_banners']} of those observations "
        f"({facts['banner_coverage_percentage']:.2f}% coverage)."
    )

    if services:
        service_sentence = "Observed services include " + ", ".join(services) + "."
    else:
        service_sentence = (
            "No service labels were reported for the observed open TCP ports."
        )

    if vt["available"]:
        vt_sentence = (
            f"VirusTotal reported a calculated risk score of "
            f"{vt['risk_score']}/100, with "
            f"{vt['malicious']} malicious and "
            f"{vt['suspicious']} suspicious results among "
            f"{vt['total_vendors']} vendor results; "
            "these are external observations."
        )
    else:
        vt_sentence = (
            "VirusTotal intelligence was not available in the collected analysis."
        )

    return " ".join([ip_sentence, port_sentence, service_sentence, vt_sentence])


# ============================================================
# DOMAIN VALIDATION
# ============================================================

def validate_domain(report: str, domain: str) -> List[str]:
    if not domain:
        return []
    if domain.lower() not in report.lower():
        return ["Report does not explicitly identify the target domain."]
    return []


# ============================================================
# KEY TAKEAWAYS VALIDATION
# ============================================================

def validate_key_takeaways(report: str) -> List[str]:
    errors: List[str] = []
    match = re.search(
        r"(?is)##\s+Key\s+Takeaways\s*\n(.*?)(?=\n##\s+|\n###\s+|\Z)",
        report,
    )
    if not match:
        errors.append("Key Takeaways section could not be parsed.")
        return errors
    section = match.group(1)
    numbered_points = re.findall(r"(?m)^\s*\d+\.\s+", section)
    if len(numbered_points) != 3:
        errors.append("Key Takeaways must contain exactly three numbered points.")
    return errors


# ============================================================
# COMPLETE VALIDATION
# ============================================================

def validate_report(report: str, deterministic: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    errors.extend(validate_required_headings(report))
    errors.extend(validate_numeric_consistency(report, deterministic))
    errors.extend(validate_port_counts(report, deterministic))
    errors.extend(validate_service_observations(report, deterministic))
    errors.extend(validate_security_claims(report))
    errors.extend(validate_domain(report, deterministic["domain"]))
    errors.extend(validate_key_takeaways(report))
    return errors


# ============================================================
# DETERMINISTIC FALLBACK
# ============================================================

def build_deterministic_fallback(deterministic: Dict[str, Any]) -> str:
    facts = deterministic["authoritative_facts"]
    domain = facts["domain"]
    subdomains = facts["subdomains"]
    ip_addresses = facts["ip_addresses"]
    asns = facts["asns"]
    organizations = facts["organizations"]
    certificates = facts["certificates"]
    port_observations = facts["port_observations"]

    open_port_count = safe_int(facts["total_open_ports"])
    banner_count = safe_int(facts["ports_with_banners"])
    banner_coverage = safe_float(facts["banner_coverage_percentage"])
    ipv4_count = safe_int(facts["ipv4_count"])
    ipv6_count = safe_int(facts["ipv6_count"])
    unknown_ip_count = safe_int(facts["unknown_ip_count"])
    scanned_ip_count = safe_int(facts["scanned_ip_count"])
    ips_with_open_ports = safe_int(facts["ips_with_open_ports"])
    vt = facts["virustotal"]

    # ---- Domain Infrastructure ----
    domain_lines: List[str] = [
        "## Domain Infrastructure",
        "",
        f"Target domain: {domain}",
        "",
        f"Subdomains observed: {len(subdomains)}",
    ]
    if subdomains:
        domain_lines.append("Observed subdomains:")
        for subdomain in subdomains:
            domain_lines.append(f"- {subdomain}")
    else:
        domain_lines.append("- No observed subdomains were identified.")

    domain_lines.extend(["", f"IP addresses observed: {len(ip_addresses)}"])
    if ip_addresses:
        domain_lines.append("Observed IP addresses:")
        for ip in ip_addresses:
            domain_lines.append(f"- {ip}")
    else:
        domain_lines.append("- No observed IP addresses were identified.")

    domain_lines.extend([
        "",
        "IP version summary:",
        f"- IPv4: {ipv4_count}",
        f"- IPv6: {ipv6_count}",
        f"- Unknown: {unknown_ip_count}",
    ])
    domain_infrastructure = "\n".join(domain_lines)

    # ---- Network Relationships ----
    network_lines: List[str] = ["## Network Relationships", ""]
    if asns:
        network_lines.append(f"ASN associations: {len(asns)}")
        for asn in asns:
            network_lines.append(f"- {asn}")
    else:
        network_lines.append("ASN associations: None observed")

    network_lines.extend([
        "",
        f"Scanned IP addresses: {scanned_ip_count}",
        f"IPs with open TCP ports: {ips_with_open_ports}",
        f"Open TCP observations: {open_port_count}",
    ])
    if port_observations:
        network_lines.extend(["", "Observed TCP services:"])
        network_lines.extend(format_port_observations(port_observations))
    else:
        network_lines.extend([
            "",
            "Observed TCP services:",
            "- No open TCP services were observed.",
        ])
    network_relationships = "\n".join(network_lines)

    # ---- Organizational Associations ----
    organization_lines: List[str] = [
        "## Organizational Associations",
        "",
        f"Organizations observed: {len(organizations)}",
    ]
    if organizations:
        for organization in organizations:
            organization_lines.append(f"- {organization}")
    else:
        organization_lines.append("- No organization associations were observed.")
    organizational_associations = "\n".join(organization_lines)

    # ---- Certificate Observations ----
    certificate_lines: List[str] = [
        "## Certificate Observations",
        "",
        f"Certificate observations: {len(certificates)}",
    ]
    if certificates:
        certificate_lines.append("Observed certificate identifiers:")
        for certificate in certificates:
            certificate_lines.append(f"- {certificate}")
    else:
        certificate_lines.append("- No certificate observations were identified.")
    certificate_observations = "\n".join(certificate_lines)

    # ---- Infrastructure Patterns ----
    pattern_lines: List[str] = ["## Infrastructure Patterns", ""]
    if len(ip_addresses) == 1:
        pattern_lines.append("The collected infrastructure includes 1 observed IP address.")
    elif len(ip_addresses) > 1:
        pattern_lines.append(
            f"The collected infrastructure includes {len(ip_addresses)} observed IP addresses."
        )
    else:
        pattern_lines.append("No observed IP addresses were identified.")

    pattern_lines.extend([
        "",
        "TCP exposure:",
        f"- Open TCP observations: {open_port_count}",
        f"- Service banners observed: {banner_count}",
        f"- Banner coverage: {banner_coverage:.2f}%",
    ])

    no_banner_observations: List[str] = []
    for observation in port_observations:
        banner = normalize_banner_text(observation.get("banner"))
        if not banner:
            ip = clean_text(observation.get("ip"), "Unknown IP")
            port = normalize_port(observation.get("port"))
            if port is not None:
                no_banner_observations.append(f"{ip}:{port}/tcp")

    if no_banner_observations:
        pattern_lines.extend(["", "Open TCP observations without banners:"])
        for item in no_banner_observations:
            pattern_lines.append(f"- {item}")

    if vt["available"]:
        pattern_lines.extend([
            "",
            "VirusTotal observations:",
            f"- Risk score: {vt['risk_score']}/100",
            f"- Malicious detections: {vt['malicious']}",
            f"- Suspicious detections: {vt['suspicious']}",
            f"- Harmless results: {vt['harmless']}",
            f"- Undetected results: {vt['undetected']}",
            f"- Timeout results: {vt['timeout']}",
            f"- Total vendors: {vt['total_vendors']}",
        ])
        registrar = clean_text(vt.get("registrar"), "")
        if registrar:
            pattern_lines.append(f"- Registrar: {registrar}")
    else:
        pattern_lines.extend([
            "",
            "VirusTotal observations:",
            "- VirusTotal intelligence was not available.",
        ])
    infrastructure_patterns = "\n".join(pattern_lines)

    # ---- Key Takeaways ----
    if len(subdomains) == 0:
        takeaway_1 = (
            f"No observed subdomains were identified; "
            f"{len(ip_addresses)} "
            f"{plural(len(ip_addresses), 'IP address', 'IP addresses')} "
            f"{be_verb(len(ip_addresses))} observed."
        )
    elif len(subdomains) == 1:
        takeaway_1 = (
            f"1 observed subdomain and {len(ip_addresses)} "
            f"{plural(len(ip_addresses), 'IP address', 'IP addresses')} were identified."
        )
    else:
        takeaway_1 = (
            f"{len(subdomains)} observed subdomains and {len(ip_addresses)} "
            f"{plural(len(ip_addresses), 'IP address', 'IP addresses')} were identified."
        )

    if open_port_count > 0:
        takeaway_2 = (
            f"TCP scanning identified {open_port_count} open TCP "
            f"{plural(open_port_count, 'port', 'ports')}; {banner_count} "
            f"{plural(banner_count, 'service banner', 'service banners')} "
            f"were observed, representing {banner_coverage:.2f}% banner coverage."
        )
    else:
        takeaway_2 = "No open TCP ports were observed."

    if vt["available"]:
        takeaway_3 = (
            f"VirusTotal recorded {vt['malicious']} malicious and "
            f"{vt['suspicious']} suspicious results among "
            f"{vt['total_vendors']} vendor results, with a reported score of "
            f"{vt['risk_score']}/100."
        )
    else:
        takeaway_3 = (
            "VirusTotal intelligence was not available in the collected "
            "DomainAtlas analysis."
        )

    key_takeaways = (
        "## Key Takeaways\n\n"
        f"1. {takeaway_1}\n"
        f"2. {takeaway_2}\n"
        f"3. {takeaway_3}"
    )

    return "\n\n".join([
        domain_infrastructure,
        network_relationships,
        organizational_associations,
        certificate_observations,
        infrastructure_patterns,
        key_takeaways,
    ])


# ============================================================
# AI PARAGRAPH INSERTION
# ============================================================

AI_INTERPRETATION_MARKER = "## Infrastructure Patterns"


def insert_ai_interpretation(report: str, ai_interpretation: str) -> str:
    if not ai_interpretation:
        return report

    block = (
        AI_INTERPRETATION_MARKER
        + "\n\n"
        + "AI-Assisted Interpretation: "
        + ai_interpretation.strip()
        + "\n\n"
    )

    pattern = (
        re.escape(AI_INTERPRETATION_MARKER)
        + r"\s*\n\s*AI-Assisted Interpretation:.*?(?=\n\n|\n##|\n###|\Z)"
    )
    if re.search(pattern, report, re.DOTALL):
        return re.sub(pattern, block.rstrip(), report, count=1, flags=re.DOTALL)

    if AI_INTERPRETATION_MARKER in report:
        return report.replace(AI_INTERPRETATION_MARKER, block.rstrip(), 1)

    return report


# ============================================================
# MAIN GENERATION FUNCTION
# ============================================================

def generate_ai_report(
    analysis: Dict[str, Any],
    port_scan: Optional[Dict[str, Any]] = None,
) -> str:
    analysis_input = dict(analysis) if isinstance(analysis, dict) else {}
    if isinstance(port_scan, dict):
        analysis_input["port_scan"] = port_scan

    deterministic = build_deterministic_analysis(analysis_input)
    facts = deterministic["authoritative_facts"]

    print("\n[AI REPORTER] Authoritative port facts:")
    print(f"    Open TCP ports: {facts['total_open_ports']}")
    print(f"    Service banners: {facts['ports_with_banners']}")
    print(f"    Banner coverage: {facts['banner_coverage_percentage']:.2f}%")
    print(f"    Ollama timeout: {OLLAMA_TIMEOUT}s | model: {OLLAMA_MODEL}")

    # 1. Deterministic body.
    deterministic_body = build_deterministic_fallback(deterministic)
    deterministic_body = clean_report(deterministic_body)

    body_errors = validate_report(deterministic_body, deterministic)
    if body_errors:
        print("[!] Deterministic report body failed validation.")
        for error in body_errors:
            print(f"    - {error}")
        raise RuntimeError("Deterministic DomainAtlas report failed validation.")

    # 2. AI paragraph.
    ai_interpretation: Optional[str] = None

    try:
        prompt = build_user_prompt(deterministic)
        candidate = call_ollama(prompt, system_prompt=SYSTEM_PROMPT)
        candidate = clean_report(candidate)

        interpretation_errors = validate_ai_interpretation(candidate, deterministic)

        if interpretation_errors:
            print("[!] AI interpretation failed deterministic validation.")
            for error in interpretation_errors:
                print(f"    - {error}")

            print("[*] Requesting one corrected AI interpretation from Ollama...")
            correction_prompt = (
                build_user_prompt(deterministic)
                + "\n\nPREVIOUS AI OUTPUT:\n"
                + candidate
                + "\n\nCORRECTION REQUIRED:\n"
                + "Return a new 3 to 5 sentence factual paragraph. "
                + f"Use the exact authoritative open TCP count of "
                + f"{facts['total_open_ports']}. Do not use risk, "
                + "security-posture, hosting, application-type, ownership, "
                + "complexity, or speculative inference language. "
                + "Return only the paragraph."
            )

            try:
                corrected = call_ollama(correction_prompt, system_prompt=SYSTEM_PROMPT)
                corrected = clean_report(corrected)
                corrected_errors = validate_ai_interpretation(corrected, deterministic)

                if corrected_errors:
                    print("[!] Corrected AI interpretation still failed validation.")
                    for error in corrected_errors:
                        print(f"    - {error}")
                    print("[!] Using safe deterministic interpretation fallback.")
                    ai_interpretation = build_safe_ai_interpretation(deterministic)
                else:
                    ai_interpretation = corrected
                    print("[+] Corrected AI interpretation passed validation.")
            except Exception as error:
                print("[!] AI correction failed.")
                print(f"    {error}")
                print("[!] Using safe deterministic interpretation fallback.")
                ai_interpretation = build_safe_ai_interpretation(deterministic)
        else:
            ai_interpretation = candidate
            print("[+] AI interpretation generated successfully.")

    except TimeoutError as error:
        print("[!] Ollama timed out.")
        print(f"    {error}")
        print("[!] Using safe deterministic interpretation fallback.")
        ai_interpretation = build_safe_ai_interpretation(deterministic)

    except Exception as error:
        print("[!] Ollama report generation failed.")
        print(f"    {error}")
        print("[!] Using safe deterministic interpretation fallback.")
        ai_interpretation = build_safe_ai_interpretation(deterministic)

    if ai_interpretation is None:
        ai_interpretation = build_safe_ai_interpretation(deterministic)

    remaining_ai_errors = validate_ai_interpretation(ai_interpretation, deterministic)
    if remaining_ai_errors:
        print("[!] AI interpretation still failing after fallback; using safe version.")
        for error in remaining_ai_errors:
            print(f"    - {error}")
        ai_interpretation = build_safe_ai_interpretation(deterministic)

    # 3. Compose report.
    report = insert_ai_interpretation(deterministic_body, ai_interpretation)
    report = clean_report(report)

    final_errors = validate_report(report, deterministic)

    if final_errors:
        print("[!] Final report validation failed.")
        for error in final_errors:
            print(f"    - {error}")

        # Rebuild the deterministic body only; re-insert the AI paragraph.
        deterministic_body = build_deterministic_fallback(deterministic)
        deterministic_body = clean_report(deterministic_body)
        report = insert_ai_interpretation(deterministic_body, ai_interpretation)
        report = clean_report(report)

        remaining = validate_report(report, deterministic)
        if remaining:
            print("[!] Rebuilt report still failed validation.")
            for error in remaining:
                print(f"    - {error}")
            raise RuntimeError("Deterministic DomainAtlas report failed validation.")

    report = append_limitation(report)
    return report


# ============================================================
# COMMAND-LINE EXECUTION
# ============================================================

if __name__ == "__main__":
    print("DomainAtlas AI-Assisted Intelligence Reporter")
    print("=" * 60)

    input_file = input("Enter normalized analysis JSON path: ").strip()

    if not input_file:
        print("[!] No input file supplied.")
        raise SystemExit(1)

    try:
        with open(input_file, "r", encoding="utf-8") as file:
            analysis_data = json.load(file)
    except Exception as error:
        print("[!] Failed to load analysis JSON:")
        print(f"    {error}")
        raise SystemExit(1)

    try:
        final_report = generate_ai_report(analysis_data)
        print("\n" + "=" * 60)
        print("AI-ASSISTED INTELLIGENCE REPORT")
        print("=" * 60 + "\n")
        print(final_report)
        print("\n" + "=" * 60)
        print("END OF REPORT")
        print("=" * 60)
    except Exception as error:
        print("\n[!] AI reporting failed:")
        print(f"    {error}")
        raise SystemExit(1)