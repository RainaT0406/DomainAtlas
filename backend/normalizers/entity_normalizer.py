import json
import os
from datetime import datetime, timezone


def current_timestamp():
    return datetime.now(timezone.utc).isoformat()


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

    key = (entity_type, value)

    provenance = {
        "source": source,
        "method": method,
        "recorded_at": recorded_at
    }

    # Entity already exists
    if key in entity_index:
        entity = entity_index[key]

        # Avoid duplicate provenance entries
        if provenance not in entity["provenance"]:
            entity["provenance"].append(provenance)

        return

    # New entity
    entity = {
        "type": entity_type,
        "value": value,
        "provenance": [provenance]
    }

    entities.append(entity)
    entity_index[key] = entity


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

    relationship_key = (
        from_type,
        str(from_value),
        relationship,
        to_type,
        str(to_value)
    )

    provenance = {
        "source": source,
        "method": method,
        "recorded_at": recorded_at
    }

    # Relationship already exists
    if relationship_key in relationship_index:
        existing_relationship = relationship_index[relationship_key]

        if provenance not in existing_relationship["provenance"]:
            existing_relationship["provenance"].append(provenance)

        return

    new_relationship = {
        "from": {
            "type": from_type,
            "value": str(from_value)
        },
        "relationship": relationship,
        "to": {
            "type": to_type,
            "value": str(to_value)
        },
        "provenance": [provenance]
    }

    relationships.append(new_relationship)
    relationship_index[relationship_key] = new_relationship


def normalize_data(data):

    entities = []
    relationships = []

    entity_index = {}
    relationship_index = {}

    domain = data.get("domain")

    # One timestamp for this normalization run.
    recorded_at = current_timestamp()

    # ---------------------------------------------------------
    # DOMAIN
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # SUBDOMAINS
    # ---------------------------------------------------------

    for subdomain in data.get("subdomains", []):

        if not isinstance(subdomain, str):
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

    # ---------------------------------------------------------
    # IP ADDRESSES
    # ---------------------------------------------------------

    for ip in data.get("ips", []):

        if not isinstance(ip, str):
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

    # ---------------------------------------------------------
    # IP METADATA
    # ---------------------------------------------------------

    for metadata in data.get("ip_metadata", []):

        if not isinstance(metadata, dict):
            continue

        ip = metadata.get("ip")

        if not ip:
            continue

        # Make sure IP exists as an entity.
        add_entity(
            entities,
            entity_index,
            "IPAddress",
            ip,
            "IP Metadata",
            "IP metadata lookup",
            recorded_at
        )

        # -------------------------
        # ASN
        # -------------------------

        asn = metadata.get("asn")

        if asn:

            asn = str(asn).strip()

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

        # -------------------------
        # ORGANIZATION
        # -------------------------

        organization = metadata.get("organization")

        if organization:

            organization = str(organization).strip()

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

    # ---------------------------------------------------------
    # CERTIFICATES
    # ---------------------------------------------------------

    for certificate in data.get("certificates", []):

        if not isinstance(certificate, dict):
            continue

        certificate_id = certificate.get("id")

        if not certificate_id:
            continue

        certificate_id = str(certificate_id)

        # Certificate entity
        add_entity(
            entities,
            entity_index,
            "Certificate",
            certificate_id,
            "Certificate Transparency",
            "Cert Spotter certificate lookup",
            recorded_at
        )

        # Domain → Certificate
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

    # ---------------------------------------------------------
    # FINAL OUTPUT
    # ---------------------------------------------------------

    return {
        "domain": domain,
        "normalized_at": recorded_at,
        "entities": entities,
        "relationships": relationships
    }


def normalize_file(input_path, output_path):

    with open(input_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    normalized_data = normalize_data(data)

    output_directory = os.path.dirname(output_path)

    if output_directory:
        os.makedirs(output_directory, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(
            normalized_data,
            file,
            indent=2
        )

    return normalized_data


if __name__ == "__main__":

    domain = input("Enter domain: ").strip()

    input_path = f"data/raw/{domain}.json"
    output_path = f"data/normalized/{domain}.json"

    if not os.path.exists(input_path):

        print(f"[!] Raw data not found: {input_path}")
        print("[!] Run Module 1 collection first.")

    else:

        normalize_file(
            input_path,
            output_path
        )

        print("\n[+] Entity normalization complete.")
        print(f"[+] Normalized data saved to: {output_path}")