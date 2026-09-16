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
        "500",
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

Your task is to transform verified DomainAtlas observations into concise,
section-specific intelligence prose.

Return EXACTLY these five labeled sections and nothing else:

DOMAIN_INFRASTRUCTURE:
NETWORK_RELATIONSHIPS:
ORGANIZATIONAL_ASSOCIATIONS:
CERTIFICATE_OBSERVATIONS:
INFRASTRUCTURE_PATTERNS:

Each label must be followed by one concise paragraph of 2 to 4 sentences.

STRICT RULES:

- The supplied DomainAtlas facts are the only source of truth.
- Deterministic DomainAtlas counts are authoritative.
- Preserve numerical values exactly.
- Do not invent, estimate, recalculate, or reinterpret counts.
- Do not list all subdomains, IP addresses, certificate identifiers, or
  port observations. Synthesize recurring patterns and relationships
  instead.
- Use supplied subdomain pattern analysis when discussing namespace
  structure.
- If pattern information is unavailable, describe only the structural
  observations that are actually supplied.
- Describe TCP observations as IP:port observations.
- Preserve scanner-provided service labels exactly.
- Never infer a service from a conventional port number.
- Do not call port 443 HTTPS unless HTTPS was explicitly supplied as the
  observed service.
- Banner observations describe collected response/banner data only.
- Banner coverage describes the proportion of represented open TCP
  observations for which a banner was obtained. Do not interpret it as
  security, complexity, service diversity, or reliability.
- VirusTotal values are external multi-vendor observations only.
- Report VirusTotal detection counts and vendor counts exactly when used.
- Do not turn a VirusTotal score into an overall risk or security rating.
- Do not claim that the domain is safe, unsafe, secure, insecure,
  malicious, benign, compromised, vulnerable, or has a particular
  security posture.
- Do not infer domain ownership.
- Do not infer that an organization is the owner of the domain.
- Do not infer hosting-provider role, application type, website purpose,
  infrastructure complexity, or intent.
- Do not infer security properties from certificates.
- Do not use speculative language such as "may indicate", "could indicate",
  "suggests", "appears to", or "seems to" for unsupported conclusions.
- Do not provide recommendations or warnings.
- Do not generate Key Takeaways.
- Do not generate Markdown headings.
- Do not repeat the analytical limitation.
- Keep every statement evidence-bound.

The objective is analytical synthesis, not inventory reproduction.
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

    port_lines = format_llm_port_observations(
        facts["port_observations"]
    )

    subdomain_patterns = deterministic.get("subdomain_patterns", {})
    if not isinstance(subdomain_patterns, dict):
        subdomain_patterns = {}

    infrastructure_metrics = deterministic.get(
        "infrastructure_metrics",
        {},
    )
    if not isinstance(infrastructure_metrics, dict):
        infrastructure_metrics = {}

    relationships = deterministic.get("relationships", {})
    if not isinstance(relationships, dict):
        relationships = {}

        return "\n".join([
        "VERIFIED DOMAINATLAS FACTS — THESE VALUES ARE AUTHORITATIVE:",
        "",
        f"Domain={facts['domain']}",
        f"Subdomains={facts['subdomain_count']}",
        (
            f"IPs={facts['ip_count']} "
            f"({facts['ipv4_count']} IPv4, "
            f"{facts['ipv6_count']} IPv6, "
            f"{facts['unknown_ip_count']} unknown)"
        ),
        (
            f"ASNs={', '.join(map(str, facts['asns']))}"
            if facts["asns"]
            else "ASNs=none"
        ),
        (
            f"Organizations={', '.join(map(str, facts['organizations']))}"
            if facts["organizations"]
            else "Organizations=none"
        ),
        f"Certificates={facts['certificate_count']}",
        f"Scanned IPs={facts['scanned_ip_count']}",
        f"IPs with open TCP ports={facts['ips_with_open_ports']}",
        f"Open TCP observations={facts['total_open_ports']}",
        f"Service banners={facts['ports_with_banners']}",
        f"Banner coverage={facts['banner_coverage_percentage']:.2f}%",
        "",
        "SUBDOMAIN PATTERN ANALYSIS:",
        json.dumps(
            subdomain_patterns,
            ensure_ascii=False,
            default=str,
        ),
        "",
        "INFRASTRUCTURE METRICS:",
        json.dumps(
            infrastructure_metrics,
            ensure_ascii=False,
            default=str,
        ),
        "",
        "GRAPH RELATIONSHIPS:",
        json.dumps(
            relationships,
            ensure_ascii=False,
            default=str,
        ),
        "",
        "OPEN TCP OBSERVATIONS:",
        "\n".join(port_lines) if port_lines else "- none",
        "",
        "VIRUSTOTAL OBSERVATIONS:",
        f"Available={vt['available']}",
        f"Risk score={vt['risk_score']}/100",
        f"Malicious={vt['malicious']}",
        f"Suspicious={vt['suspicious']}",
        f"Harmless={vt['harmless']}",
        f"Undetected={vt['undetected']}",
        f"Timeout={vt['timeout']}",
        f"Total vendors={vt['total_vendors']}",
        f"Registrar={clean_text(vt.get('registrar'), 'Not available')}",
        "",
        "TASK:",
        "Synthesize the observations into five section-specific paragraphs.",
        "",
        "DOMAIN_INFRASTRUCTURE:",
        "Focus on the discovered namespace and recurring subdomain patterns.",
        "Do not enumerate all subdomains.",
        "",
        "NETWORK_RELATIONSHIPS:",
        "Focus on IP versions, ASN relationships, scanned IPs, open TCP",
        "observations, observed services, and banner observations.",
        "",
        "ORGANIZATIONAL_ASSOCIATIONS:",
        "Describe the organizations and ASN associations present in the",
        "collected data without treating them as domain ownership.",
        "",
        "CERTIFICATE_OBSERVATIONS:",
        "Describe certificate counts and the nature of the certificate",
        "inventory without listing every certificate identifier.",
        "",
        "INFRASTRUCTURE_PATTERNS:",
        "Synthesize recurring namespace, network, service, banner, and",
        "environment-oriented patterns that are explicitly supported by",
        "the supplied observations.",
        "",
        "MANDATORY:",
        f"If discussing open TCP observations, use the authoritative count "
        f"of {facts['total_open_ports']}.",
        f"If discussing subdomains, use the authoritative count of "
        f"{facts['subdomain_count']}.",
        f"If discussing certificates, use the authoritative count of "
        f"{facts['certificate_count']}.",
        "Do not invent missing pattern information.",
        "Do not provide Key Takeaways.",
        "Return only the five labeled sections.",
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

        (
            r"\b(?:appears|seems)\s+to\s+be\s+(?:a\s+)?hosting\s+service\b",
            "unsupported hosting-service inference",
        ),

        (
            r"\b(?:appears|seems)\s+to\s+have\s+(?:a\s+)?(?:low|high)\s+risk\b",
            "risk inference",
        ),

        (
            r"\b(?:low|high|relatively\s+low|relatively\s+high)\s+risk\s+(?:profile|level)\b",
            "risk inference",
        ),

        (
            r"\b(?:suggests?|indicates?|demonstrates?)\s+(?:that\s+)?(?:the\s+)?domain\s+(?:is|may\s+be|could\s+be|uses?|hosts?)\b",
            "unsupported domain inference",
        ),

        (
            r"\b(?:suggests?|indicates?|could\s+indicate|may\s+indicate)\b"
            r"[^.]{0,180}\b(?:hosting|hosted|web\s+application|application\s+server|"
            r"complex\s+infrastructure|security|risk|safe|secure)\b",
            "infrastructure or security inference",
        ),

        (
            r"\b(?:indicat(?:e|ing)|suggest(?:s|ing))\b"
            r"[^.]{0,180}\b(?:security|secure|risk|safe|safety)\b",
            "unsupported security inference",
        ),

        (
            r"\b(?:hosting\s+web\s+applications?|web\s+applications?\s+are\s+hosted|"
            r"application\s+hosting)\b",
            "application-hosting inference",
        ),

        (
            r"\b(?:more\s+complex|complex|sophisticated)\s+"
            r"(?:infrastructure|architecture)\b",
            "unsupported infrastructure-complexity inference",
        ),
    ]

    for pattern, description in forbidden_patterns:
        if re.search(pattern, lower):
            errors.append(f"Unsupported {description}.")

    return errors


# ============================================================
# AI INTERPRETATION VALIDATION (RELAXED)
# ============================================================

def validate_ai_interpretation(
    interpretation: str,
    deterministic: Dict[str, Any],
) -> List[str]:
    errors = validate_security_claims(interpretation)

    text = str(interpretation or "").strip()
    lower = text.lower()
    facts = deterministic["authoritative_facts"]

    if not text:
        errors.append("AI interpretation is empty.")
        return list(dict.fromkeys(errors))

    required_labels = [
        "DOMAIN_INFRASTRUCTURE:",
        "NETWORK_RELATIONSHIPS:",
        "ORGANIZATIONAL_ASSOCIATIONS:",
        "CERTIFICATE_OBSERVATIONS:",
        "INFRASTRUCTURE_PATTERNS:",
    ]

    # ------------------------------------------------------------
    # Required structured sections
    # ------------------------------------------------------------

    for label in required_labels:
        if label.lower() not in lower:
            errors.append(f"AI interpretation is missing {label}")

    if errors:
        return list(dict.fromkeys(errors))

    # ------------------------------------------------------------
    # Extract each AI section
    # ------------------------------------------------------------

    section_pattern = re.compile(
        r"(?is)"
        r"(DOMAIN_INFRASTRUCTURE|"
        r"NETWORK_RELATIONSHIPS|"
        r"ORGANIZATIONAL_ASSOCIATIONS|"
        r"CERTIFICATE_OBSERVATIONS|"
        r"INFRASTRUCTURE_PATTERNS)"
        r"\s*:\s*"
        r"(.*?)"
        r"(?=\n\s*(?:DOMAIN_INFRASTRUCTURE|"
        r"NETWORK_RELATIONSHIPS|"
        r"ORGANIZATIONAL_ASSOCIATIONS|"
        r"CERTIFICATE_OBSERVATIONS|"
        r"INFRASTRUCTURE_PATTERNS)\s*:|\Z)",
    )

    sections = {
        match.group(1).upper(): match.group(2).strip()
        for match in section_pattern.finditer(text)
    }

    for label in required_labels:
        key = label.rstrip(":")
        if not sections.get(key):
            errors.append(f"AI section {label} is empty.")

    if errors:
        return list(dict.fromkeys(errors))

    # ------------------------------------------------------------
    # Reject accidental Markdown headings/lists
    # ------------------------------------------------------------

    for section_text in sections.values():
        if re.search(r"(?m)^\s*#+\s+", section_text):
            errors.append("AI interpretation contains a Markdown heading.")

        if re.search(r"(?m)^\s*(?:[-*+]\s+|\d+\.\s+)", section_text):
            errors.append("AI interpretation contains a list item.")

    # ------------------------------------------------------------
    # Authoritative counts
    # ------------------------------------------------------------

    subdomain_count = safe_int(facts["subdomain_count"])
    ip_count = safe_int(facts["ip_count"])
    ipv4_count = safe_int(facts["ipv4_count"])
    ipv6_count = safe_int(facts["ipv6_count"])
    certificate_count = safe_int(facts["certificate_count"])
    open_port_count = safe_int(facts["total_open_ports"])
    banner_count = safe_int(facts["ports_with_banners"])
    scanned_ip_count = safe_int(facts["scanned_ip_count"])
    organization_count = safe_int(facts["organization_count"])
    asn_count = safe_int(facts["asn_count"])

    vt = facts["virustotal"]

    # ------------------------------------------------------------
    # Narrow category-specific numeric validation
    #
    # Do NOT use a broad "N + arbitrary noun phrase" regex.
    # ------------------------------------------------------------

    numeric_patterns = [
        (
            r"\b(\d+)\s+(?:observed\s+)?subdomains?\b",
            subdomain_count,
            "subdomains",
        ),
        (
            r"\b(\d+)\s+(?:observed\s+)?ip\s+addresses?\b",
            ip_count,
            "IP addresses",
        ),
        (
            r"\b(\d+)\s+ipv4(?:\s+addresses?)?\b",
            ipv4_count,
            "IPv4 addresses",
        ),
        (
            r"\b(\d+)\s+ipv6(?:\s+addresses?)?\b",
            ipv6_count,
            "IPv6 addresses",
        ),
        (
            r"\b(\d+)\s+(?:observed\s+)?certificates?\b",
            certificate_count,
            "certificates",
        ),
        (
            r"\b(\d+)\s+(?:open\s+tcp\s+)?(?:observations?|ports?)\b",
            open_port_count,
            "open TCP observations/ports",
        ),
        (
            r"\b(\d+)\s+(?:service\s+)?banners?\b",
            banner_count,
            "service banners",
        ),
        (
            r"\b(\d+)\s+scanned\s+ip\s+addresses?\b",
            scanned_ip_count,
            "scanned IP addresses",
        ),
        (
            r"\b(\d+)\s+organization\s+associations?\b",
            organization_count,
            "organization associations",
        ),
        (
            r"\b(\d+)\s+asn\s+associations?\b",
            asn_count,
            "ASN associations",
        ),
    ]

    for pattern, expected, label in numeric_patterns:
        for match in re.finditer(pattern, lower):
            reported = safe_int(match.group(1), expected)

            if reported != expected:
                errors.append(
                    f"AI interpretation reports {reported} {label}; "
                    f"authoritative value is {expected}."
                )

    # ------------------------------------------------------------
    # Open TCP observations must be represented when present
    # ------------------------------------------------------------

    if open_port_count > 0:
        if not re.search(
            rf"\b{open_port_count}\s+"
            r"(?:open\s+tcp\s+(?:ports?|observations?)|"
            r"open\s+ports?)\b",
            lower,
        ):
            errors.append(
                f"AI interpretation does not state the authoritative "
                f"open TCP observation count of {open_port_count}."
            )

    # ------------------------------------------------------------
    # Banner consistency
    # ------------------------------------------------------------

    if banner_count > 0:
        if re.search(
            r"\bno\s+(?:service\s+)?banners?\s+(?:were\s+)?observed\b",
            lower,
        ):
            errors.append(
                "AI interpretation incorrectly states that no banners "
                "were observed."
            )

    elif banner_count == 0:
        if re.search(
            r"\b(?:all|\d+)\s+(?:open\s+)?(?:tcp\s+)?ports?\s+"
            r"(?:had|have)\s+banners?\b",
            lower,
        ):
            errors.append(
                "AI interpretation claims banners were observed even "
                "though none were recorded."
            )

    # ------------------------------------------------------------
    # Banner coverage consistency
    # ------------------------------------------------------------

    coverage = safe_float(facts["banner_coverage_percentage"])

    coverage_values = [
        safe_float(value)
        for value in re.findall(
            r"\b(\d+(?:\.\d+)?)%\s+(?:banner\s+)?coverage\b",
            lower,
        )
    ]

    for reported in coverage_values:
        if abs(reported - coverage) > 0.01:
            errors.append(
                f"AI interpretation reports banner coverage of "
                f"{reported:.2f}%, but the authoritative value is "
                f"{coverage:.2f}%."
            )

    # ------------------------------------------------------------
    # VirusTotal consistency
    # ------------------------------------------------------------

    if vt.get("available"):
        malicious = safe_int(vt.get("malicious"))
        suspicious = safe_int(vt.get("suspicious"))
        total_vendors = safe_int(vt.get("total_vendors"))
        risk_score = safe_int(vt.get("risk_score"))

        malicious_claims = re.findall(
            r"\b(\d+)\s+malicious\b",
            lower,
        )

        suspicious_claims = re.findall(
            r"\b(\d+)\s+suspicious\b",
            lower,
        )

        vendor_claims = re.findall(
            r"\b(\d+)\s+vendor\s+results?\b",
            lower,
        )

        score_claims = re.findall(
            r"(?:risk\s+score|score)"
            r"\s*(?:of|is|:)?\s*(\d{1,3})\s*/\s*100",
            lower,
        )

        for value in malicious_claims:
            if safe_int(value) != malicious:
                errors.append(
                    f"AI interpretation reports {value} malicious "
                    f"results; authoritative value is {malicious}."
                )

        for value in suspicious_claims:
            if safe_int(value) != suspicious:
                errors.append(
                    f"AI interpretation reports {value} suspicious "
                    f"results; authoritative value is {suspicious}."
                )

        for value in vendor_claims:
            if safe_int(value) != total_vendors:
                errors.append(
                    f"AI interpretation reports {value} vendor results; "
                    f"authoritative value is {total_vendors}."
                )

        for value in score_claims:
            if safe_int(value) != risk_score:
                errors.append(
                    f"AI interpretation reports VirusTotal score "
                    f"{value}/100; authoritative value is "
                    f"{risk_score}/100."
                )

    # ------------------------------------------------------------
    # Do not associate open TCP counts with IP versions
    # ------------------------------------------------------------

    if re.search(
        r"\bopen\s+tcp\s+(?:ports?|observations?)\b"
        r"[^.]{0,120}\bipv[46]\b",
        lower,
    ):
        errors.append(
            "AI interpretation incorrectly associates open TCP "
            "observations with IP versions."
        )

    # ------------------------------------------------------------
    # Reject unsupported inferential language
    # ------------------------------------------------------------

    broad_inference_patterns = [
        (
            r"\b(?:may|might|could)\s+"
            r"(?:indicate|suggest|imply)\b",
            "unsupported speculative inference",
        ),
        (
            r"\b(?:indicates?|suggests?|implies?)\b[^.]{0,160}"
            r"\b(?:risk|security|hosting|application|complexity|"
            r"purpose|ownership)\b",
            "unsupported inference",
        ),
    ]

    for pattern, description in broad_inference_patterns:
        if re.search(pattern, lower):
            errors.append(f"Unsupported {description}.")

    # ------------------------------------------------------------
    # AI must not generate Key Takeaways or analytical limitation
    # ------------------------------------------------------------

    if "key takeaways" in lower:
        errors.append("AI interpretation must not generate Key Takeaways.")

    if "analytical limitation" in lower:
        errors.append(
            "AI interpretation must not generate the analytical limitation."
        )

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
    subdomain_count = safe_int(facts["subdomain_count"])
    ip_count = safe_int(facts["ip_count"])
    asn_count = safe_int(facts["asn_count"])
    organization_count = safe_int(facts["organization_count"])
    certificate_count = safe_int(facts["certificate_count"])

    open_port_count = safe_int(facts["total_open_ports"])
    banner_count = safe_int(facts["ports_with_banners"])
    banner_coverage = safe_float(facts["banner_coverage_percentage"])

    ipv4_count = safe_int(facts["ipv4_count"])
    ipv6_count = safe_int(facts["ipv6_count"])
    unknown_ip_count = safe_int(facts["unknown_ip_count"])

    scanned_ip_count = safe_int(facts["scanned_ip_count"])
    ips_with_open_ports = safe_int(facts["ips_with_open_ports"])

    asns = facts["asns"]
    organizations = facts["organizations"]
    port_observations = facts["port_observations"]
    vt = facts["virustotal"]

    # ------------------------------------------------------------
    # Domain Infrastructure
    # ------------------------------------------------------------

    domain_lines = [
        "## Domain Infrastructure",
        "",
        f"Target domain: {domain}",
        "",
        (
            f"DomainAtlas identified {subdomain_count} "
            f"{plural(subdomain_count, 'subdomain', 'subdomains')} "
            f"associated with {domain}."
        ),
        (
            f"The collected infrastructure contains {ip_count} "
            f"{plural(ip_count, 'IP address', 'IP addresses')}, "
            f"including {ipv4_count} IPv4, {ipv6_count} IPv6, and "
            f"{unknown_ip_count} with an unknown IP version."
        ),
        (
            f"The discovered namespace and infrastructure inventory remain "
            f"available in the underlying DomainAtlas data."
        ),
    ]

    domain_infrastructure = "\n".join(domain_lines)

    # ------------------------------------------------------------
    # Network Relationships
    # ------------------------------------------------------------

    network_lines = [
        "## Network Relationships",
        "",
        (
            f"The collected graph contains {asn_count} "
            f"{plural(asn_count, 'ASN association', 'ASN associations')} "
            f"and {scanned_ip_count} scanned "
            f"{plural(scanned_ip_count, 'IP address', 'IP addresses')}."
        ),
        (
            f"{ips_with_open_ports} "
            f"{plural(ips_with_open_ports, 'IP address', 'IP addresses')} "
            f"had observed open TCP ports, producing {open_port_count} "
            f"open TCP observations."
        ),
        (
            f"Service banners were observed for {banner_count} of those "
            f"observations, representing {banner_coverage:.2f}% banner coverage."
        ),
    ]

    if port_observations:
        observed_services = []
        seen_services = set()

        for observation in port_observations:
            service = clean_text(
                observation.get("service"),
                "Unknown service",
            )

            key = service.lower()

            if key in seen_services:
                continue

            seen_services.add(key)
            observed_services.append(service)

        if observed_services:
            network_lines.append(
                "Observed service labels include "
                + ", ".join(observed_services)
                + "."
            )

    network_relationships = "\n".join(network_lines)

    # ------------------------------------------------------------
    # Organizational Associations
    # ------------------------------------------------------------

    if organizations:
        organization_text = ", ".join(
            str(value) for value in organizations
        )
        organization_sentence = (
            f"The collected infrastructure contains "
            f"{organization_count} "
            f"{plural(organization_count, 'organization association', 'organization associations')}: "
            f"{organization_text}."
        )
    else:
        organization_sentence = (
            "No organization associations were observed in the collected data."
        )

    organizational_associations = "\n".join([
        "## Organizational Associations",
        "",
        organization_sentence,
        (
            "These associations are reported from the collected "
            "IP/ASN intelligence and do not independently establish "
            "domain ownership."
        ),
    ])

    # ------------------------------------------------------------
    # Certificate Observations
    # ------------------------------------------------------------

    certificate_observations = "\n".join([
        "## Certificate Observations",
        "",
        (
            f"DomainAtlas identified {certificate_count} "
            f"{plural(certificate_count, 'certificate observation', 'certificate observations')} "
            f"during collection."
        ),
        (
            "The certificate inventory is retained in the underlying "
            "DomainAtlas data; certificate identifiers are not repeated "
            "individually in the primary intelligence assessment."
        ),
        (
            "Certificate presence alone does not establish current validity, "
            "ownership, or security posture."
        ),
    ])

    # ------------------------------------------------------------
    # Infrastructure Patterns
    # ------------------------------------------------------------

    pattern_lines = [
        "## Infrastructure Patterns",
        "",
        (
            f"The collected infrastructure includes {ip_count} "
            f"{plural(ip_count, 'IP address', 'IP addresses')} and "
            f"{open_port_count} open TCP observations."
        ),
        (
            f"Banner data was available for {banner_count} observations, "
            f"representing {banner_coverage:.2f}% coverage of the "
            f"represented open TCP observations."
        ),
    ]

    # Keep concrete observed service/banner information available without
    # turning the main report into an inventory dump.
    banner_services = []
    seen_banner_services = set()

    for observation in port_observations:
        banner = normalize_banner_text(observation.get("banner"))
        service = clean_text(
            observation.get("service"),
            "Unknown service",
        )

        if not banner:
            continue

        key = service.lower()

        if key in seen_banner_services:
            continue

        seen_banner_services.add(key)
        banner_services.append(service)

    if banner_services:
        pattern_lines.append(
            "Banner-bearing observations include the following observed "
            "service labels: "
            + ", ".join(banner_services)
            + "."
        )

    if vt["available"]:
        pattern_lines.append(
            f"VirusTotal reported {vt['malicious']} malicious and "
            f"{vt['suspicious']} suspicious results among "
            f"{vt['total_vendors']} vendor results."
        )
    else:
        pattern_lines.append(
            "VirusTotal intelligence was not available in the collected analysis."
        )

    infrastructure_patterns = "\n".join(pattern_lines)

    # ------------------------------------------------------------
    # Key Takeaways
    # ------------------------------------------------------------

    if subdomain_count > 0:
        takeaway_1 = (
            f"{subdomain_count} "
            f"{plural(subdomain_count, 'subdomain', 'subdomains')} "
            f"were identified across the collected namespace, with "
            f"recurring naming patterns retained in the DomainAtlas "
            f"analysis data."
        )
    else:
        takeaway_1 = (
            "No observed subdomains were identified in the collected data."
        )

    if open_port_count > 0:
        takeaway_2 = (
            f"{ip_count} "
            f"{plural(ip_count, 'IP address', 'IP addresses')} were observed, "
            f"with {open_port_count} open TCP observations across "
            f"{scanned_ip_count} scanned "
            f"{plural(scanned_ip_count, 'IP address', 'IP addresses')}."
        )
    else:
        takeaway_2 = (
            f"{ip_count} "
            f"{plural(ip_count, 'IP address', 'IP addresses')} were observed, "
            "with no open TCP observations recorded."
        )

    if vt["available"]:
        takeaway_3 = (
            f"VirusTotal reported {vt['malicious']} malicious and "
            f"{vt['suspicious']} suspicious results among "
            f"{vt['total_vendors']} vendor results."
        )
    else:
        takeaway_3 = (
            "VirusTotal intelligence was not available in the collected analysis."
        )

    key_takeaways = "\n".join([
        "## Key Takeaways",
        "",
        f"1. {takeaway_1}",
        f"2. {takeaway_2}",
        f"3. {takeaway_3}",
    ])

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


def insert_ai_interpretation(
    report: str,
    ai_interpretation: str,
) -> str:
    if not ai_interpretation:
        return report

    text = str(ai_interpretation).strip()

    section_pattern = re.compile(
        r"(?is)"
        r"(DOMAIN_INFRASTRUCTURE|"
        r"NETWORK_RELATIONSHIPS|"
        r"ORGANIZATIONAL_ASSOCIATIONS|"
        r"CERTIFICATE_OBSERVATIONS|"
        r"INFRASTRUCTURE_PATTERNS)"
        r"\s*:\s*"
        r"(.*?)"
        r"(?=\n\s*(?:DOMAIN_INFRASTRUCTURE|"
        r"NETWORK_RELATIONSHIPS|"
        r"ORGANIZATIONAL_ASSOCIATIONS|"
        r"CERTIFICATE_OBSERVATIONS|"
        r"INFRASTRUCTURE_PATTERNS)\s*:|\Z)",
    )

    generated_sections = {
        match.group(1).upper(): match.group(2).strip()
        for match in section_pattern.finditer(text)
    }

    section_mapping = {
        "DOMAIN_INFRASTRUCTURE": "Domain Infrastructure",
        "NETWORK_RELATIONSHIPS": "Network Relationships",
        "ORGANIZATIONAL_ASSOCIATIONS": "Organizational Associations",
        "CERTIFICATE_OBSERVATIONS": "Certificate Observations",
        "INFRASTRUCTURE_PATTERNS": "Infrastructure Patterns",
    }

    result = report

    for generated_key, report_heading in section_mapping.items():
        generated_text = generated_sections.get(generated_key)

        if not generated_text:
            continue

        pattern = re.compile(
            rf"(?is)"
            rf"(^##\s+{re.escape(report_heading)}\s*$)"
            rf"(.*?)"
            rf"(?=^##\s+|\Z)",
            re.MULTILINE,
        )

        match = pattern.search(result)

        if not match:
            continue

        replacement = (
            match.group(1)
            + "\n\n"
            + generated_text.strip()
            + "\n"
        )

        result = (
            result[:match.start()]
            + replacement
            + result[match.end():]
        )

    return result.strip()

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