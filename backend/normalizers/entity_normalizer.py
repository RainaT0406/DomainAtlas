import json
import os
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
    recorded_at
):
    if value is None:
        return

    value = str(value).strip()

    if not value:
        return

    key = (
        entity_type,
        value
    )

    provenance = {
        "source": source,
        "method": method,
        "recorded_at": recorded_at
    }

    # ---------------------------------------------------------
    # ENTITY ALREADY EXISTS
    # ---------------------------------------------------------

    if key in entity_index:

        entity = entity_index[key]

        if provenance not in entity["provenance"]:
            entity["provenance"].append(provenance)

        return

    # ---------------------------------------------------------
    # NEW ENTITY
    # ---------------------------------------------------------

    entity = {
        "type": entity_type,
        "value": value,
        "provenance": [
            provenance
        ]
    }

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
    recorded_at
):
    if not from_value or not to_value:
        return

    from_value = str(from_value).strip()
    to_value = str(to_value).strip()

    relationship_key = (
        from_type,
        from_value,
        relationship,
        to_type,
        to_value
    )

    provenance = {
        "source": source,
        "method": method,
        "recorded_at": recorded_at
    }

    # ---------------------------------------------------------
    # RELATIONSHIP ALREADY EXISTS
    # ---------------------------------------------------------

    if relationship_key in relationship_index:

        existing_relationship = (
            relationship_index[relationship_key]
        )

        if provenance not in existing_relationship["provenance"]:
            existing_relationship["provenance"].append(
                provenance
            )

        return

    # ---------------------------------------------------------
    # NEW RELATIONSHIP
    # ---------------------------------------------------------

    new_relationship = {
        "from": {
            "type": from_type,
            "value": from_value
        },

        "relationship": relationship,

        "to": {
            "type": to_type,
            "value": to_value
        },

        "provenance": [
            provenance
        ]
    }

    relationships.append(new_relationship)

    relationship_index[relationship_key] = (
        new_relationship
    )


# =============================================================
# NORMALIZE DATA
# =============================================================

def normalize_data(data):

    entities = []
    relationships = []

    entity_index = {}
    relationship_index = {}

    domain = data.get("domain")

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
            recorded_at
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
                []
            )

            if not isinstance(sources, list):
                sources = []

            if not subdomain:
                continue

            # -------------------------------------------------
            # Add Subdomain Entity
            # -------------------------------------------------

            # If both tools found it, preserve both as
            # separate provenance records.

            if sources:

                for source in sources:

                    add_entity(
                        entities,
                        entity_index,
                        "Subdomain",
                        subdomain,
                        source,
                        "Subdomain discovery",
                        recorded_at
                    )

            else:

                add_entity(
                    entities,
                    entity_index,
                    "Subdomain",
                    subdomain,
                    "Subdomain Enumeration",
                    "Subdomain discovery",
                    recorded_at
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
                        recorded_at
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
                    recorded_at
                )

        # -----------------------------------------------------
        # BACKWARD COMPATIBILITY
        #
        # Supports old format:
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
                recorded_at
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
                recorded_at
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
            recorded_at
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
            recorded_at
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
            recorded_at
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
                    recorded_at
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
                    recorded_at
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
                    recorded_at
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
                    recorded_at
                )

    # =========================================================
    # CERTIFICATES
    # =========================================================

    for certificate in data.get("certificates", []):

        if not isinstance(certificate, dict):
            continue

        certificate_id = certificate.get("id")

        if not certificate_id:
            continue

        certificate_id = str(
            certificate_id
        ).strip()

        # -----------------------------------------------------
        # Certificate Entity
        # -----------------------------------------------------

        add_entity(
            entities,
            entity_index,
            "Certificate",
            certificate_id,
            "Certificate Transparency",
            "Cert Spotter certificate lookup",
            recorded_at
        )

        # -----------------------------------------------------
        # Domain → Certificate
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
            recorded_at
        )

    # =========================================================
    # VIRUSTOTAL INTELLIGENCE
    # =========================================================
    #
    # VirusTotal observations are intentionally kept as
    # structured attributes rather than creating nodes for
    # every numeric/statistical field.
    #
    # We do NOT create:
    #
    # Domain → HAS_REPUTATION → 0
    # Domain → HAS_HARMLESS_COUNT → 57
    # Domain → HAS_UNDETECTED_COUNT → 34
    #
    # These are properties of a VirusTotal observation.
    #
    # =========================================================

    virustotal_data = data.get(
        "virustotal",
        {}
    )

    if not isinstance(
        virustotal_data,
        dict
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
        # Analysis Statistics
        # -----------------------------------------------------

        analysis_stats = (
            virustotal_data.get(
                "last_analysis_stats",
                {}
            )
        )

        if not isinstance(
            analysis_stats,
            dict
        ):
            analysis_stats = {}

        normalized_virustotal[
            "last_analysis_stats"
        ] = {

            "malicious": analysis_stats.get(
                "malicious",
                0
            ),

            "suspicious": analysis_stats.get(
                "suspicious",
                0
            ),

            "harmless": analysis_stats.get(
                "harmless",
                0
            ),

            "undetected": analysis_stats.get(
                "undetected",
                0
            ),

            "timeout": analysis_stats.get(
                "timeout",
                0
            )
        }

        # -----------------------------------------------------
        # Categories
        # -----------------------------------------------------

        categories = (
            virustotal_data.get(
                "categories",
                {}
            )
        )

        if not isinstance(
            categories,
            dict
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
        # -----------------------------------------------------

        dns_records = (
            virustotal_data.get(
                "last_dns_records",
                []
            )
        )

        if not isinstance(
            dns_records,
            list
        ):
            dns_records = []

        normalized_virustotal[
            "last_dns_records"
        ] = dns_records

        # -----------------------------------------------------
        # Popularity Ranks
        # -----------------------------------------------------

        popularity_ranks = (
            virustotal_data.get(
                "popularity_ranks",
                {}
            )
        )

        if not isinstance(
            popularity_ranks,
            dict
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

    # =========================================================
    # FINAL OUTPUT
    # =========================================================

    return {

        "domain": domain,

        "normalized_at": recorded_at,

        "entities": entities,

        "relationships": relationships,

        "virustotal": normalized_virustotal
    }


# =============================================================
# NORMALIZE FILE
# =============================================================

def normalize_file(
    input_path,
    output_path
):

    with open(
        input_path,
        "r",
        encoding="utf-8"
    ) as file:

        data = json.load(file)

    normalized_data = normalize_data(data)

    output_directory = os.path.dirname(
        output_path
    )

    if output_directory:

        os.makedirs(
            output_directory,
            exist_ok=True
        )

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            normalized_data,
            file,
            indent=2,
            ensure_ascii=False
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
            output_path
        )

        print(
            "\n[+] Entity normalization complete."
        )

        print(
            f"[+] Normalized data saved to: "
            f"{output_path}"
        )