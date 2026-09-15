import json
import os
import hashlib
from datetime import datetime, timezone


# =============================================================
# TIMESTAMP
# =============================================================

def current_timestamp():
    return datetime.now(timezone.utc).isoformat()


# =============================================================
# ADD ENTITY
# =============================================================

def add_entity(
    entities,
    entity_index,
    entity_type,
    value,
    source,
    method,
    recorded_at,
    properties=None,
):
    if value is None:
        return

    value = str(value).strip()

    if not value:
        return

    key = (
        entity_type,
        value,
    )

    provenance = {
        "source": source,
        "method": method,
        "recorded_at": recorded_at,
    }

    # ---------------------------------------------------------
    # ENTITY ALREADY EXISTS
    # ---------------------------------------------------------

    if key in entity_index:
        entity = entity_index[key]

        if provenance not in entity["provenance"]:
            entity["provenance"].append(provenance)

        # Preserve/update additional properties.
        if properties:
            entity.setdefault("properties", {})

            for prop_key, prop_value in properties.items():
                if prop_value is not None:
                    entity["properties"][prop_key] = prop_value

        return

    # ---------------------------------------------------------
    # NEW ENTITY
    # ---------------------------------------------------------

    entity = {
        "type": entity_type,
        "value": value,
        "provenance": [
            provenance
        ],
    }

    if properties:
        entity["properties"] = properties

    entities.append(entity)
    entity_index[key] = entity


# =============================================================
# ADD RELATIONSHIP
# =============================================================

def add_relationship(
    relationships,
    relationship_index,
    from_type,
    from_value,
    relationship,
    to_type,
    to_value,
    source,
    method,
    recorded_at,
    properties=None,
):
    if not from_value or not to_value:
        return

    from_value = str(from_value).strip()
    to_value = str(to_value).strip()

    if not from_value or not to_value:
        return

    relationship_key = (
        from_type,
        from_value,
        relationship,
        to_type,
        to_value,
    )

    provenance = {
        "source": source,
        "method": method,
        "recorded_at": recorded_at,
    }

    # ---------------------------------------------------------
    # RELATIONSHIP ALREADY EXISTS
    # ---------------------------------------------------------

    if relationship_key in relationship_index:
        existing_relationship = relationship_index[
            relationship_key
        ]

        if provenance not in existing_relationship["provenance"]:
            existing_relationship["provenance"].append(
                provenance
            )

        if properties:
            existing_relationship.setdefault(
                "properties",
                {},
            )

            for prop_key, prop_value in properties.items():
                if prop_value is not None:
                    existing_relationship["properties"][
                        prop_key
                    ] = prop_value

        return

    # ---------------------------------------------------------
    # NEW RELATIONSHIP
    # ---------------------------------------------------------

    new_relationship = {
        "from": {
            "type": from_type,
            "value": from_value,
        },
        "relationship": relationship,
        "to": {
            "type": to_type,
            "value": to_value,
        },
        "provenance": [
            provenance
        ],
    }

    if properties:
        new_relationship["properties"] = properties

    relationships.append(new_relationship)
    relationship_index[
        relationship_key
    ] = new_relationship


# =============================================================
# NORMALIZE DATA
# =============================================================

def normalize_data(data):
    entities = []
    relationships = []
    entity_index = {}
    relationship_index = {}

    domain = data.get("domain")

    if domain:
        domain = (
            str(domain)
            .strip()
            .lower()
            .rstrip(".")
        )

    # One timestamp for this normalization run.
    recorded_at = current_timestamp()

    # =========================================================
    # DOMAIN
    # =========================================================

    if domain:
        add_entity(
            entities,
            entity_index,
            "Domain",
            domain,
            "User Input",
            "Domain supplied by analyst",
            recorded_at,
        )

    # =========================================================
    # SUBDOMAINS
    # =========================================================

    for subdomain_data in data.get("subdomains", []):

        # -----------------------------------------------------
        # NEW SOURCE-AWARE FORMAT
        #
        # {
        #     "subdomain": "www.example.com",
        #     "sources": ["Subfinder", "Amass"]
        # }
        # -----------------------------------------------------

        if isinstance(subdomain_data, dict):

            subdomain = subdomain_data.get("subdomain")

            sources = subdomain_data.get(
                "sources",
                [],
            )

            if not isinstance(sources, list):
                sources = []

            if not subdomain:
                continue

            subdomain = str(subdomain).strip()

            if not subdomain:
                continue

            # -------------------------------------------------
            # Add Subdomain Entity
            # -------------------------------------------------

            if sources:
                for source in sources:
                    add_entity(
                        entities,
                        entity_index,
                        "Subdomain",
                        subdomain,
                        source,
                        "Subdomain discovery",
                        recorded_at,
                    )
            else:
                add_entity(
                    entities,
                    entity_index,
                    "Subdomain",
                    subdomain,
                    "Subdomain Enumeration",
                    "Subdomain discovery",
                    recorded_at,
                )

            # -------------------------------------------------
            # Domain → Subdomain
            # -------------------------------------------------

            if sources:
                for source in sources:
                    add_relationship(
                        relationships,
                        relationship_index,
                        "Domain",
                        domain,
                        "HAS_SUBDOMAIN",
                        "Subdomain",
                        subdomain,
                        source,
                        "Subdomain discovery",
                        recorded_at,
                    )
            else:
                add_relationship(
                    relationships,
                    relationship_index,
                    "Domain",
                    domain,
                    "HAS_SUBDOMAIN",
                    "Subdomain",
                    subdomain,
                    "Subdomain Enumeration",
                    "Subdomain discovery",
                    recorded_at,
                )

        # -----------------------------------------------------
        # BACKWARD COMPATIBILITY
        #
        # "subdomains": [
        #     "www.example.com"
        # ]
        # -----------------------------------------------------

        elif isinstance(subdomain_data, str):

            subdomain = subdomain_data.strip()

            if not subdomain:
                continue

            add_entity(
                entities,
                entity_index,
                "Subdomain",
                subdomain,
                "Subdomain Enumeration",
                "Subdomain discovery",
                recorded_at,
            )

            add_relationship(
                relationships,
                relationship_index,
                "Domain",
                domain,
                "HAS_SUBDOMAIN",
                "Subdomain",
                subdomain,
                "Subdomain Enumeration",
                "Subdomain discovery",
                recorded_at,
            )

    # =========================================================
    # IP ADDRESSES
    # =========================================================

    for ip in data.get("ips", []):

        if not isinstance(ip, str):
            continue

        ip = ip.strip()

        if not ip:
            continue

        add_entity(
            entities,
            entity_index,
            "IPAddress",
            ip,
            "DNS",
            "DNS resolution",
            recorded_at,
        )

        add_relationship(
            relationships,
            relationship_index,
            "Domain",
            domain,
            "RESOLVES_TO",
            "IPAddress",
            ip,
            "DNS",
            "DNS resolution",
            recorded_at,
        )

    # =========================================================
    # IP METADATA
    # =========================================================

    for metadata in data.get("ip_metadata", []):

        if not isinstance(metadata, dict):
            continue

        ip = metadata.get("ip")

        if not ip:
            continue

        ip = str(ip).strip()

        # -----------------------------------------------------
        # Make sure IP exists
        # -----------------------------------------------------

        add_entity(
            entities,
            entity_index,
            "IPAddress",
            ip,
            "IP Metadata",
            "IP metadata lookup",
            recorded_at,
        )

        # -----------------------------------------------------
        # ASN
        # -----------------------------------------------------

        asn = metadata.get("asn")

        if asn is not None:

            asn = str(asn).strip()

            if asn:
                add_entity(
                    entities,
                    entity_index,
                    "ASN",
                    asn,
                    "IP Metadata",
                    "IP to ASN lookup",
                    recorded_at,
                )

                add_relationship(
                    relationships,
                    relationship_index,
                    "IPAddress",
                    ip,
                    "BELONGS_TO_ASN",
                    "ASN",
                    asn,
                    "IP Metadata",
                    "IP to ASN lookup",
                    recorded_at,
                )

        # -----------------------------------------------------
        # ORGANIZATION
        # -----------------------------------------------------

        organization = metadata.get("organization")

        if organization:

            organization = str(
                organization
            ).strip()

            if organization:

                add_entity(
                    entities,
                    entity_index,
                    "Organization",
                    organization,
                    "IP Metadata",
                    "IP organization lookup",
                    recorded_at,
                )

                add_relationship(
                    relationships,
                    relationship_index,
                    "IPAddress",
                    ip,
                    "ASSOCIATED_WITH",
                    "Organization",
                    organization,
                    "IP Metadata",
                    "IP organization lookup",
                    recorded_at,
                )

    # =========================================================
    # PORT SCAN RESULTS
    # =========================================================

    port_scan_data = data.get(
        "port_scan",
        {},
    )

    if (
        isinstance(port_scan_data, dict)
        and not port_scan_data.get("error")
    ):

        for ip_result in port_scan_data.get(
            "results",
            [],
        ):

            if not isinstance(ip_result, dict):
                continue

            ip = ip_result.get("ip")

            if not ip:
                continue

            ip = str(ip).strip()

            if not ip:
                continue

            # -------------------------------------------------
            # Ensure IP entity exists
            # -------------------------------------------------

            add_entity(
                entities,
                entity_index,
                "IPAddress",
                ip,
                "Port Scanner",
                "Port scanning",
                recorded_at,
            )

            # -------------------------------------------------
            # Open Ports
            # -------------------------------------------------

            for port_info in ip_result.get(
                "open_ports",
                [],
            ):

                if not isinstance(port_info, dict):
                    continue

                port = port_info.get("port")

                if port is None:
                    continue

                protocol = (
                    port_info.get(
                        "protocol",
                        "tcp",
                    )
                    or "tcp"
                )

                protocol = str(
                    protocol
                ).strip().lower()

                service = (
                    port_info.get(
                        "service",
                        "unknown",
                    )
                    or "unknown"
                )

                service = str(
                    service
                ).strip()

                banner = port_info.get(
                    "banner"
                )

                if banner is not None:
                    banner = str(
                        banner
                    ).strip()

                # -------------------------------------------------
                # Port value
                # -------------------------------------------------

                port_value = f"{port}/{protocol}"

                # -------------------------------------------------
                # Port entity
                #
                # Store service information as properties so
                # Neo4j/frontend can display:
                #
                # 22/tcp → SSH
                # 80/tcp → HTTP
                # -------------------------------------------------

                add_entity(
                    entities,
                    entity_index,
                    "Port",
                    port_value,
                    "Port Scanner",
                    f"Port scanning (service: {service})",
                    recorded_at,
                    properties={
                        "port": int(port)
                        if str(port).isdigit()
                        else str(port),
                        "protocol": protocol,
                        "service": service,
                        "state": "open",
                    },
                )

                # -------------------------------------------------
                # IP → HAS_OPEN_PORT → Port
                # -------------------------------------------------

                add_relationship(
                    relationships,
                    relationship_index,
                    "IPAddress",
                    ip,
                    "HAS_OPEN_PORT",
                    "Port",
                    port_value,
                    "Port Scanner",
                    f"Port {port}/{protocol} is open",
                    recorded_at,
                    properties={
                        "service": service,
                        "protocol": protocol,
                    },
                )

                # -------------------------------------------------
                # SERVICE BANNER
                # -------------------------------------------------

                if banner:

                    # Deterministic hash.
                    #
                    # SHA-256 is used as an identifier.
                    banner_hash = hashlib.sha256(
                        banner.encode("utf-8")
                    ).hexdigest()[:16]

                    banner_entity = (
                        f"banner_{banner_hash}"
                    )

                    add_entity(
                        entities,
                        entity_index,
                        "ServiceBanner",
                        banner_entity,
                        "Port Scanner",
                        f"Banner for {port}/{protocol}",
                        recorded_at,
                        properties={
                            "banner": banner,
                            "service": service,
                            "port": int(port)
                            if str(port).isdigit()
                            else str(port),
                            "protocol": protocol,
                        },
                    )

                    # -------------------------------------------------
                    # Port → HAS_BANNER → ServiceBanner
                    # -------------------------------------------------

                    add_relationship(
                        relationships,
                        relationship_index,
                        "Port",
                        port_value,
                        "HAS_BANNER",
                        "ServiceBanner",
                        banner_entity,
                        "Port Scanner",
                        "Service banner captured",
                        recorded_at,
                    )

    # =========================================================
    # CERTIFICATES
    # =========================================================

        # =========================================================
    # CERTIFICATES
    # =========================================================

    for certificate in data.get(
        "certificates",
        [],
    ):
        if not isinstance(
            certificate,
            dict,
        ):
            continue

        certificate_id = certificate.get(
            "id"
        )

        if not certificate_id:
            continue

        certificate_id = str(
            certificate_id
        ).strip()

        if not certificate_id:
            continue

        # -----------------------------------------------------
        # Certificate metadata
        # -----------------------------------------------------

        certificate_sha256 = certificate.get(
            "certificate_sha256"
        )

        public_key_sha256 = certificate.get(
            "public_key_sha256"
        )

        not_before = certificate.get(
            "not_before"
        )

        not_after = certificate.get(
            "not_after"
        )

        revoked = certificate.get(
            "revoked",
            False,
        )

        # -----------------------------------------------------
        # Certificate entity
        #
        # Store certificate metadata as properties so it can
        # be displayed in Neo4j/frontend without creating
        # unnecessary additional nodes.
        # -----------------------------------------------------

        add_entity(
            entities,
            entity_index,
            "Certificate",
            certificate_id,
            "Certificate Transparency",
            "Cert Spotter certificate lookup",
            recorded_at,
            properties={
                "certificate_sha256": certificate_sha256,
                "public_key_sha256": public_key_sha256,
                "not_before": not_before,
                "not_after": not_after,
                "revoked": bool(revoked),
            },
        )

        # -----------------------------------------------------
        # Domain → HAS_CERTIFICATE → Certificate
        # -----------------------------------------------------

        add_relationship(
            relationships,
            relationship_index,
            "Domain",
            domain,
            "HAS_CERTIFICATE",
            "Certificate",
            certificate_id,
            "Certificate Transparency",
            "Cert Spotter certificate lookup",
            recorded_at,
        )
    # =========================================================
    # VIRUSTOTAL INTELLIGENCE
    # =========================================================

    virustotal_data = data.get(
        "virustotal",
        {},
    )

    if not isinstance(
        virustotal_data,
        dict,
    ):
        virustotal_data = {}

    normalized_virustotal = {}

    if virustotal_data:

        # -----------------------------------------------------
        # Domain
        # -----------------------------------------------------

        normalized_virustotal["domain"] = (
            virustotal_data.get("domain")
            or domain
        )

        # -----------------------------------------------------
        # Reputation
        # -----------------------------------------------------

        normalized_virustotal["reputation"] = (
            virustotal_data.get("reputation")
        )

        # -----------------------------------------------------
        # RISK SCORE
        #
        # New VirusTotal collector format:
        #
        # {
        #     "risk_score": 65
        # }
        #
        # Keep the value if it is present.
        # -----------------------------------------------------

        risk_score = virustotal_data.get(
            "risk_score"
        )

        if risk_score is not None:
            try:
                risk_score = float(risk_score)

                # Store as integer when the score is a
                # whole number.
                if risk_score.is_integer():
                    risk_score = int(risk_score)

            except (
                TypeError,
                ValueError,
            ):
                risk_score = None

        normalized_virustotal[
            "risk_score"
        ] = risk_score

        # -----------------------------------------------------
        # ANALYSIS STATISTICS
        #
        # Preferred format:
        #
        # "security_summary": {
        #     "malicious": 17,
        #     "suspicious": 1,
        #     "harmless": 71,
        #     "undetected": 0,
        #     "timeout": 0,
        #     "total_vendors": 89
        # }
        #
        # Backward compatibility:
        #
        # "last_analysis_stats": {
        #     ...
        # }
        # -----------------------------------------------------

        security_summary = virustotal_data.get(
            "security_summary",
            {},
        )

        if not isinstance(
            security_summary,
            dict,
        ):
            security_summary = {}

        last_analysis_stats = virustotal_data.get(
            "last_analysis_stats",
            {},
        )

        if not isinstance(
            last_analysis_stats,
            dict,
        ):
            last_analysis_stats = {}

        # Prefer security_summary when available.
        if security_summary:

            analysis_stats = security_summary

        else:

            analysis_stats = last_analysis_stats

        # -----------------------------------------------------
        # Individual detection counts
        # -----------------------------------------------------

        malicious = analysis_stats.get(
            "malicious",
            0,
        )

        suspicious = analysis_stats.get(
            "suspicious",
            0,
        )

        harmless = analysis_stats.get(
            "harmless",
            0,
        )

        undetected = analysis_stats.get(
            "undetected",
            0,
        )

        timeout = analysis_stats.get(
            "timeout",
            0,
        )

        # Safely convert counts to integers.
        def safe_int(value, default=0):
            try:
                return int(value)
            except (
                TypeError,
                ValueError,
            ):
                return default

        malicious = safe_int(malicious)
        suspicious = safe_int(suspicious)
        harmless = safe_int(harmless)
        undetected = safe_int(undetected)
        timeout = safe_int(timeout)

        # -----------------------------------------------------
        # Total vendors
        #
        # Use collector-provided total_vendors when available.
        # Otherwise calculate it from the individual counts.
        # -----------------------------------------------------

        total_vendors = analysis_stats.get(
            "total_vendors"
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
            total_vendors = safe_int(
                total_vendors,
                malicious
                + suspicious
                + harmless
                + undetected
                + timeout,
            )

        # -----------------------------------------------------
        # Store normalized security summary
        # -----------------------------------------------------

        normalized_virustotal[
            "security_summary"
        ] = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": timeout,
            "total_vendors": total_vendors,
        }

        # -----------------------------------------------------
        # Also preserve last_analysis_stats for
        # backward compatibility with existing code.
        # -----------------------------------------------------

        normalized_virustotal[
            "last_analysis_stats"
        ] = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": timeout,
        }

        # -----------------------------------------------------
        # Categories
        # -----------------------------------------------------

        categories = virustotal_data.get(
            "categories",
            {},
        )

        if not isinstance(
            categories,
            dict,
        ):
            categories = {}

        normalized_virustotal[
            "categories"
        ] = categories

        # -----------------------------------------------------
        # Registrar
        # -----------------------------------------------------

        normalized_virustotal[
            "registrar"
        ] = virustotal_data.get(
            "registrar"
        )

        # -----------------------------------------------------
        # Creation Date
        # -----------------------------------------------------

        normalized_virustotal[
            "creation_date"
        ] = virustotal_data.get(
            "creation_date"
        )

        # -----------------------------------------------------
        # Last Modification Date
        # -----------------------------------------------------

        normalized_virustotal[
            "last_modification_date"
        ] = virustotal_data.get(
            "last_modification_date"
        )

        # -----------------------------------------------------
        # DNS Records
        #
        # Support both:
        #   dns_records
        #   last_dns_records
        # -----------------------------------------------------

        dns_records = virustotal_data.get(
            "dns_records"
        )

        if dns_records is None:
            dns_records = virustotal_data.get(
                "last_dns_records",
                [],
            )

        if not isinstance(
            dns_records,
            list,
        ):
            dns_records = []

        normalized_virustotal[
            "dns_records"
        ] = dns_records

        # Keep the old field too for compatibility.
        normalized_virustotal[
            "last_dns_records"
        ] = dns_records

        # -----------------------------------------------------
        # Popularity Ranks
        # -----------------------------------------------------

        popularity_ranks = virustotal_data.get(
            "popularity_ranks",
            {},
        )

        if not isinstance(
            popularity_ranks,
            dict,
        ):
            popularity_ranks = {}

        normalized_virustotal[
            "popularity_ranks"
        ] = popularity_ranks

        # -----------------------------------------------------
        # Source Metadata
        # -----------------------------------------------------

        normalized_virustotal[
            "source"
        ] = "VirusTotal"

        normalized_virustotal[
            "method"
        ] = "VirusTotal domain intelligence API"

        normalized_virustotal[
            "recorded_at"
        ] = recorded_at

        # -----------------------------------------------------
        # DEBUG OUTPUT
        #
        # This confirms that the normalizer has retained the
        # values before Neo4j loading.
        # -----------------------------------------------------

        print(
            "[+] VirusTotal normalized."
        )

        print(
            f"    Risk Score: "
            f"{normalized_virustotal.get('risk_score')}/100"
        )

        print(
            f"    Malicious: "
            f"{malicious}"
        )

        print(
            f"    Suspicious: "
            f"{suspicious}"
        )

        print(
            f"    Harmless: "
            f"{harmless}"
        )

        print(
            f"    Undetected: "
            f"{undetected}"
        )

        print(
            f"    Timeout: "
            f"{timeout}"
        )

        print(
            f"    Total Vendors: "
            f"{total_vendors}"
        )

    # =========================================================
    # FINAL OUTPUT
    # =========================================================

    return {
        "domain": domain,
        "normalized_at": recorded_at,
        "entities": entities,
        "relationships": relationships,
        "virustotal": normalized_virustotal,
    }


# =============================================================
# NORMALIZE FILE
# =============================================================

def normalize_file(
    input_path,
    output_path,
):

    with open(
        input_path,
        "r",
        encoding="utf-8",
    ) as file:

        data = json.load(file)

    normalized_data = normalize_data(
        data
    )

    output_directory = os.path.dirname(
        output_path
    )

    if output_directory:

        os.makedirs(
            output_directory,
            exist_ok=True,
        )

    with open(
        output_path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            normalized_data,
            file,
            indent=2,
            ensure_ascii=False,
        )

    return normalized_data


# =============================================================
# STANDALONE EXECUTION
# =============================================================

if __name__ == "__main__":

    domain = input(
        "Enter domain: "
    ).strip()

    input_path = (
        f"data/raw/{domain}.json"
    )

    output_path = (
        f"data/normalized/{domain}.json"
    )

    if not os.path.exists(
        input_path
    ):

        print(
            f"[!] Raw data not found: {input_path}"
        )

        print(
            "[!] Run Module 1 collection first."
        )

    else:

        normalize_file(
            input_path,
            output_path,
        )

        print(
            "\n[+] Entity normalization complete."
        )

        print(
            f"[+] Normalized data saved to: "
            f"{output_path}"
        )