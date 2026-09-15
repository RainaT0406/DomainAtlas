import json
import os
import hashlib
from collections import defaultdict
from neo4j import GraphDatabase


# ============================================================
# NEO4J CONFIGURATION
# ============================================================

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USERNAME = "neo4j"

# Number of records sent to Neo4j per batch.
BATCH_SIZE = 1000


# ============================================================
# SUPPORTED ENTITY / RELATIONSHIP TYPES
# ============================================================

ALLOWED_ENTITY_TYPES = {
    "Domain",
    "Subdomain",
    "IPAddress",
    "ASN",
    "Organization",
    "Certificate",
    "Port",
    "ServiceBanner",
}


ALLOWED_RELATIONSHIP_TYPES = {
    "HAS_SUBDOMAIN",
    "RESOLVES_TO",
    "BELONGS_TO_ASN",
    "ASSOCIATED_WITH",
    "HAS_CERTIFICATE",
    "HAS_OPEN_PORT",
    "HAS_BANNER",
}


# ============================================================
# DOMAIN-SCOPED ENTITY TYPES
#
# These entities represent observations/infrastructure that
# belong specifically to the current DomainAtlas investigation.
#
# IP, Port and ServiceBanner are intentionally domain-scoped.
#
# This prevents:
#
# Domain A -> shared IP -> ports/banners from Domain B
#
# from contaminating Domain A's analysis.
# ============================================================

DOMAIN_SCOPED_ENTITY_TYPES = {
    "IPAddress",
    "Port",
    "ServiceBanner",
}


# ============================================================
# PROVENANCE RELATIONSHIP TYPES
# ============================================================

PROVENANCE_ENTITY_RELATIONSHIP = "OBSERVED"
PROVENANCE_FROM_RELATIONSHIP = "OBSERVES_FROM"
PROVENANCE_TO_RELATIONSHIP = "OBSERVES_TO"


# ============================================================
# NORMALIZATION HELPERS
# ============================================================

def normalize_domain(value):
    """
    Normalize a domain name consistently.
    """
    if value is None:
        return None

    return (
        str(value)
        .strip()
        .lower()
        .rstrip(".")
    )


def normalize_entity_value(entity_type, value):
    """
    Normalize entity values before storing them.
    """
    if value is None:
        return None

    value = str(value).strip()

    if entity_type in {"Domain", "Subdomain"}:
        return normalize_domain(value)

    return value


def make_scoped_value(domain, value):
    """
    Create a deterministic domain-scoped identity.

    Example:

        domain = example.com
        value  = 1.2.3.4

        result:
            example.com|1.2.3.4

    The original value is still stored separately in
    `entity_value` for display and analysis.
    """
    return f"{domain}|{value}"


# ============================================================
# LOAD NORMALIZED DATA OBJECT
# ============================================================

def load_normalized_data_object(
    data,
    password,
):
    """
    Load normalized OSINT data into Neo4j.

    Pipeline:

        Normalized JSON
              |
              v
        Clear previous domain graph
              |
              v
        Create entity nodes
              |
              v
        Create entity relationships
              |
              v
        Create provenance observations
              |
              v
        Add VirusTotal intelligence
              |
              v
        Complete

    Important graph-isolation rule:

        IPAddress
        Port
        ServiceBanner

    are domain-scoped.

    This prevents infrastructure relationships from one
    DomainAtlas investigation from appearing in another
    investigation merely because two domains share an IP.
    """

    if not isinstance(data, dict):
        raise ValueError(
            "Normalized data must be a dictionary."
        )

    domain = data.get("domain")

    if not domain:
        raise ValueError(
            "Normalized data does not contain a target domain."
        )

    domain = normalize_domain(domain)

    if not domain:
        raise ValueError(
            "Target domain is empty."
        )

    print(
        "\n============================================================"
    )
    print("NEO4J GRAPH LOADING")
    print("============================================================")
    print(f"[*] Target domain: {domain}")

    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(
            NEO4J_USERNAME,
            password,
        ),
    )

    try:
        # ----------------------------------------------------
        # VERIFY CONNECTION
        # ----------------------------------------------------

        driver.verify_connectivity()

        print(
            "[+] Neo4j connection established."
        )

        with driver.session(
            database="neo4j"
        ) as session:

            # ------------------------------------------------
            # 1. CREATE CONSTRAINTS
            # ------------------------------------------------

            print(
                "[*] Checking Neo4j constraints..."
            )

            create_constraints(session)

            print(
                "[+] Constraints ready."
            )

            # ------------------------------------------------
            # 2. CLEAR PREVIOUS DOMAIN GRAPH
            # ------------------------------------------------

            clear_domain_graph(
                session,
                domain,
            )

            # ------------------------------------------------
            # 3. CREATE ENTITIES
            # ------------------------------------------------

            entities = data.get(
                "entities",
                [],
            )

            if not isinstance(entities, list):
                entities = []

            print(
                f"[*] Loading {len(entities)} entities..."
            )

            create_entities(
                session,
                entities,
                domain,
            )

            # ------------------------------------------------
            # 4. CREATE MAIN RELATIONSHIPS
            # ------------------------------------------------

            relationships = data.get(
                "relationships",
                [],
            )

            if not isinstance(relationships, list):
                relationships = []

            print(
                f"[*] Loading {len(relationships)} relationships..."
            )

            create_relationships(
                session,
                relationships,
                domain,
            )

            # ------------------------------------------------
            # 5. CREATE PROVENANCE
            # ------------------------------------------------

            print(
                "[*] Loading provenance observations..."
            )

            create_provenance_observations(
                session,
                entities,
                relationships,
                domain,
            )

            # ------------------------------------------------
            # 6. VIRUSTOTAL
            # ------------------------------------------------

            print(
                "[*] Adding VirusTotal intelligence..."
            )

            vt_data = data.get(
                "virustotal",
                {},
            )

            if not isinstance(vt_data, dict):
                vt_data = {}

            # ------------------------------------------------
            # DEBUG VIRUSTOTAL INPUT
            # ------------------------------------------------

            print(
                "\n========== VIRUSTOTAL INPUT DEBUG =========="
            )

            print(
                json.dumps(
                    vt_data,
                    indent=2,
                    ensure_ascii=False,
                )
            )

            print(
                "============================================\n"
            )

            create_virustotal_properties(
                session,
                domain,
                vt_data,
            )

            # ------------------------------------------------
            # FINAL VERIFICATION
            # ------------------------------------------------

            print(
                "\n[*] Verifying target graph..."
            )

            verify_domain_graph(
                session,
                domain,
            )

            print(
                "[+] Neo4j graph loading complete."
            )

    finally:
        driver.close()


# ============================================================
# FILE-BASED LOADER
# ============================================================

def load_normalized_data(
    file_path,
    password,
):
    """
    Load normalized JSON data from a file into Neo4j.
    """

    with open(
        file_path,
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    load_normalized_data_object(
        data,
        password,
    )


# ============================================================
# CONSTRAINTS
# ============================================================

def create_constraints(session):
    """
    Create uniqueness constraints.

    Global entities:
        Domain
        Subdomain
        ASN
        Organization
        Certificate

    Domain-scoped entities:
        IPAddress
        Port
        ServiceBanner

    Domain-scoped entities use a `scope_key` property.

    This allows:

        example.com|1.2.3.4
        another.com|1.2.3.4

    to exist as separate IPAddress nodes.
    """

    constraints = [

        # ----------------------------------------------------
        # GLOBAL ENTITIES
        # ----------------------------------------------------

        """
        CREATE CONSTRAINT domain_value_unique IF NOT EXISTS
        FOR (n:Domain)
        REQUIRE n.value IS UNIQUE
        """,

        """
        CREATE CONSTRAINT subdomain_value_unique IF NOT EXISTS
        FOR (n:Subdomain)
        REQUIRE n.value IS UNIQUE
        """,

        """
        CREATE CONSTRAINT asn_value_unique IF NOT EXISTS
        FOR (n:ASN)
        REQUIRE n.value IS UNIQUE
        """,

        """
        CREATE CONSTRAINT organization_value_unique IF NOT EXISTS
        FOR (n:Organization)
        REQUIRE n.value IS UNIQUE
        """,

        """
        CREATE CONSTRAINT certificate_value_unique IF NOT EXISTS
        FOR (n:Certificate)
        REQUIRE n.value IS UNIQUE
        """,

        # ----------------------------------------------------
        # DOMAIN-SCOPED ENTITIES
        # ----------------------------------------------------

        """
        CREATE CONSTRAINT ip_scope_key_unique IF NOT EXISTS
        FOR (n:IPAddress)
        REQUIRE n.scope_key IS UNIQUE
        """,

        """
        CREATE CONSTRAINT port_scope_key_unique IF NOT EXISTS
        FOR (n:Port)
        REQUIRE n.scope_key IS UNIQUE
        """,

        """
        CREATE CONSTRAINT service_banner_scope_key_unique IF NOT EXISTS
        FOR (n:ServiceBanner)
        REQUIRE n.scope_key IS UNIQUE
        """,

        # ----------------------------------------------------
        # OBSERVATIONS
        # ----------------------------------------------------

        """
        CREATE CONSTRAINT observation_id_unique IF NOT EXISTS
        FOR (n:Observation)
        REQUIRE n.observation_id IS UNIQUE
        """,
    ]

    for constraint in constraints:
        try:
            session.run(
                constraint
            ).consume()
        except Exception as error:
            print(
                f"[!] Constraint warning: {error}"
            )


# ============================================================
# CLEAR EXISTING DOMAIN GRAPH
# ============================================================

def clear_domain_graph(
    session,
    domain,
):
    """
    Safely remove the previous investigation graph for a domain.

    Domain-scoped infrastructure nodes are deleted completely.

    Shared global entities such as ASN, Organization and
    Certificate are preserved when still connected elsewhere.
    """

    print(
        f"[*] Clearing previous graph for '{domain}'..."
    )

    # --------------------------------------------------------
    # STEP 1
    #
    # Delete observations associated with this domain.
    # --------------------------------------------------------

    query_delete_domain_observations = """
    MATCH (d:Domain {value: $domain})

    OPTIONAL MATCH (o:Observation)-[:OBSERVED]->(d)
    OPTIONAL MATCH (o2:Observation)-[:OBSERVES_FROM]->(d)
    OPTIONAL MATCH (o3:Observation)-[:OBSERVES_TO]->(d)

    WITH
        collect(DISTINCT o)
        +
        collect(DISTINCT o2)
        +
        collect(DISTINCT o3)
        AS observations

    UNWIND observations AS observation

    WITH DISTINCT observation

    WHERE observation IS NOT NULL

    DETACH DELETE observation
    """

    session.run(
        query_delete_domain_observations,
        domain=domain,
    ).consume()

    # --------------------------------------------------------
    # STEP 2
    #
    # Find domain-scoped infrastructure connected to the
    # target domain.
    #
    # These nodes are safe to delete because their identity
    # belongs specifically to this investigation.
    # --------------------------------------------------------

    query_delete_scoped_infrastructure = """
    MATCH (d:Domain {value: $domain})

    OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip:IPAddress)

    OPTIONAL MATCH (ip)-[:HAS_OPEN_PORT]->(p:Port)

    OPTIONAL MATCH (p)-[:HAS_BANNER]->(b:ServiceBanner)

    WITH
        collect(DISTINCT ip)
        +
        collect(DISTINCT p)
        +
        collect(DISTINCT b)
        AS nodes

    UNWIND nodes AS node

    WITH DISTINCT node

    WHERE node IS NOT NULL

    DETACH DELETE node
    """

    session.run(
        query_delete_scoped_infrastructure,
        domain=domain,
    ).consume()

    # --------------------------------------------------------
    # STEP 3
    #
    # Remove all remaining outgoing relationships from the
    # target domain.
    # --------------------------------------------------------

    query_remove_domain_relationships = """
    MATCH (d:Domain {value: $domain})

    OPTIONAL MATCH (d)-[r]->()

    DELETE r
    """

    session.run(
        query_remove_domain_relationships,
        domain=domain,
    ).consume()

    # --------------------------------------------------------
    # STEP 4
    #
    # Delete the old domain node.
    # --------------------------------------------------------

    query_delete_domain = """
    MATCH (d:Domain {value: $domain})

    DETACH DELETE d
    """

    session.run(
        query_delete_domain,
        domain=domain,
    ).consume()

    # --------------------------------------------------------
    # STEP 5
    #
    # Delete orphaned global infrastructure nodes.
    # --------------------------------------------------------

    orphan_labels = [
        "Subdomain",
        "ASN",
        "Organization",
        "Certificate",
    ]

    for label in orphan_labels:

        query = f"""
        MATCH (n:{label})

        WHERE NOT (n)--()

        DELETE n
        """

        session.run(
            query
        ).consume()

    # --------------------------------------------------------
    # STEP 6
    #
    # Delete orphaned observations.
    # --------------------------------------------------------

    query_delete_orphan_observations = """
    MATCH (o:Observation)

    WHERE NOT (o)--()

    DELETE o
    """

    session.run(
        query_delete_orphan_observations
    ).consume()

    print(
        f"[+] Previous graph for '{domain}' cleared safely."
    )


# ============================================================
# CHUNK HELPER
# ============================================================

def chunk_list(
    items,
    batch_size=BATCH_SIZE,
):
    """
    Yield lists of at most batch_size items.
    """

    for index in range(
        0,
        len(items),
        batch_size,
    ):
        yield items[
            index:index + batch_size
        ]


# ============================================================
# CREATE ENTITIES
# ============================================================

def create_entities(
    session,
    entities,
    domain,
):
    """
    Create entity nodes in batches.

    Global entities use:

        value

    Domain-scoped entities use:

        scope_key = domain|value

    The original entity value is retained in:

        value
        entity_value
    """

    if not entities:
        print(
            "[!] No entities to load."
        )
        return

    grouped_entities = defaultdict(list)

    skipped = 0

    for entity in entities:

        if not isinstance(
            entity,
            dict,
        ):
            skipped += 1
            continue

        entity_type = entity.get(
            "type"
        )

        value = entity.get(
            "value"
        )

        if (
            not entity_type
            or not value
        ):
            skipped += 1
            continue

        if entity_type not in ALLOWED_ENTITY_TYPES:

            print(
                f"[!] Skipping unsupported entity type: "
                f"{entity_type}"
            )

            skipped += 1
            continue

        value = normalize_entity_value(
            entity_type,
            value,
        )

        if not value:
            skipped += 1
            continue

        provenance = entity.get(
            "provenance",
            [],
        )

        if not isinstance(
            provenance,
            list,
        ):
            provenance = []

        provenance_json = json.dumps(
            provenance,
            ensure_ascii=False,
        )

        properties = entity.get(
            "properties",
            {},
        )

        if not isinstance(
            properties,
            dict,
        ):
            properties = {}

        # ----------------------------------------------------
        # Clean Neo4j properties
        # ----------------------------------------------------

        clean_properties = {}

        for prop_key, prop_value in properties.items():

            if prop_value is None:
                continue

            if isinstance(
                prop_value,
                (
                    str,
                    int,
                    float,
                    bool,
                ),
            ):
                clean_properties[
                    prop_key
                ] = prop_value

        # ----------------------------------------------------
        # DOMAIN NODE
        # ----------------------------------------------------

        if entity_type == "Domain":

            grouped_entities[
                entity_type
            ].append(
                {
                    "value": value,
                    "entity_value": value,
                    "scope_key": value,
                    "scope_domain": domain,
                    "provenance": provenance_json,
                    "properties": clean_properties,
                }
            )

        # ----------------------------------------------------
        # DOMAIN-SCOPED ENTITIES
        # ----------------------------------------------------

        elif entity_type in DOMAIN_SCOPED_ENTITY_TYPES:

            scoped_value = make_scoped_value(
                domain,
                value,
            )

            grouped_entities[
                entity_type
            ].append(
                {
                    "value": value,
                    "entity_value": value,
                    "scope_key": scoped_value,
                    "scope_domain": domain,
                    "provenance": provenance_json,
                    "properties": clean_properties,
                }
            )

        # ----------------------------------------------------
        # GLOBAL ENTITIES
        # ----------------------------------------------------

        else:

            grouped_entities[
                entity_type
            ].append(
                {
                    "value": value,
                    "entity_value": value,
                    "scope_key": value,
                    "scope_domain": domain,
                    "provenance": provenance_json,
                    "properties": clean_properties,
                }
            )

    total_loaded = 0

    # --------------------------------------------------------
    # BATCH INSERT
    # --------------------------------------------------------

    for entity_type, entity_list in grouped_entities.items():

        print(
            f"[*] Loading {len(entity_list)} "
            f"{entity_type} nodes..."
        )

        query = f"""
        UNWIND $entities AS entity

        MERGE (n:{entity_type} {{
            scope_key: entity.scope_key
        }})

        SET
            n.value = entity.value,
            n.entity_value = entity.entity_value,
            n.scope_domain = entity.scope_domain,
            n.provenance = entity.provenance

        SET n += entity.properties
        """

        batches = list(
            chunk_list(
                entity_list
            )
        )

        for (
            batch_number,
            batch,
        ) in enumerate(
            batches,
            start=1,
        ):

            session.run(
                query,
                entities=batch,
            ).consume()

            total_loaded += len(
                batch
            )

            if len(batches) > 1:

                print(
                    f"    [+] {entity_type}: "
                    f"batch {batch_number}/{len(batches)} "
                    f"({len(batch)} nodes)"
                )

    print(
        f"[+] Entities loaded: {total_loaded}"
    )

    if skipped:

        print(
            f"[!] Entities skipped: {skipped}"
        )


# ============================================================
# RELATIONSHIP NODE MATCH EXPRESSION
# ============================================================

def relationship_match_expression(
    entity_type,
    variable,
):
    """
    Return the Cypher property expression used to identify
    an entity during relationship creation.

    Domain-scoped entities require:
        scope_domain + value

    Global entities require:
        value
    """

    if entity_type in DOMAIN_SCOPED_ENTITY_TYPES:

        return (
            f"{variable}.scope_key = "
            f"$domain + '|' + {variable}.input_value"
        )

    return (
        f"{variable}.value = {variable}.input_value"
    )


# ============================================================
# CREATE RELATIONSHIPS
# ============================================================

def create_relationships(
    session,
    relationships,
    domain,
):
    """
    Create entity relationships in batches.

    Domain-scoped entities are matched using:

        domain|entity_value

    Global entities are matched using:

        entity_value
    """

    if not relationships:
        print(
            "[!] No relationships to load."
        )
        return

    grouped_relationships = defaultdict(list)

    skipped = 0

    for relationship in relationships:

        if not isinstance(
            relationship,
            dict,
        ):
            skipped += 1
            continue

        from_entity = relationship.get(
            "from"
        )

        to_entity = relationship.get(
            "to"
        )

        relationship_type = relationship.get(
            "relationship"
        )

        provenance = relationship.get(
            "provenance",
            [],
        )

        if (
            not isinstance(
                from_entity,
                dict,
            )
            or not isinstance(
                to_entity,
                dict,
            )
            or not relationship_type
        ):
            skipped += 1
            continue

        from_type = from_entity.get(
            "type"
        )

        from_value = from_entity.get(
            "value"
        )

        to_type = to_entity.get(
            "type"
        )

        to_value = to_entity.get(
            "value"
        )

        if not all(
            [
                from_type,
                from_value,
                to_type,
                to_value,
            ]
        ):
            skipped += 1
            continue

        if (
            from_type not in ALLOWED_ENTITY_TYPES
            or to_type not in ALLOWED_ENTITY_TYPES
        ):

            print(
                "[!] Skipping relationship with "
                "unsupported entity type."
            )

            skipped += 1
            continue

        if (
            relationship_type
            not in ALLOWED_RELATIONSHIP_TYPES
        ):

            print(
                f"[!] Skipping unsupported relationship: "
                f"{relationship_type}"
            )

            skipped += 1
            continue

        from_value = normalize_entity_value(
            from_type,
            from_value,
        )

        to_value = normalize_entity_value(
            to_type,
            to_value,
        )

        if (
            not from_value
            or not to_value
        ):
            skipped += 1
            continue

        if not isinstance(
            provenance,
            list,
        ):
            provenance = []

        provenance_json = json.dumps(
            provenance,
            ensure_ascii=False,
        )

        properties = relationship.get(
            "properties",
            {},
        )

        if not isinstance(
            properties,
            dict,
        ):
            properties = {}

        clean_properties = {}

        for prop_key, prop_value in properties.items():

            if prop_value is None:
                continue

            if isinstance(
                prop_value,
                (
                    str,
                    int,
                    float,
                    bool,
                ),
            ):
                clean_properties[
                    prop_key
                ] = prop_value

        grouping_key = (
            from_type,
            to_type,
            relationship_type,
        )

        grouped_relationships[
            grouping_key
        ].append(
            {
                "from_value": from_value,
                "to_value": to_value,
                "provenance": provenance_json,
                "properties": clean_properties,
            }
        )

    total_loaded = 0

    # --------------------------------------------------------
    # PROCESS GROUPS
    # --------------------------------------------------------

    for (
        from_type,
        to_type,
        relationship_type,
    ), relationship_list in grouped_relationships.items():

        print(
            f"[*] Loading {len(relationship_list)} "
            f"{from_type} -[{relationship_type}]-> "
            f"{to_type} relationships..."
        )

        # ----------------------------------------------------
        # Determine whether endpoint is domain-scoped.
        # ----------------------------------------------------

        from_is_scoped = (
            from_type in DOMAIN_SCOPED_ENTITY_TYPES
        )

        to_is_scoped = (
            to_type in DOMAIN_SCOPED_ENTITY_TYPES
        )

        if from_is_scoped:

            from_match = """
            a.scope_key = $domain + '|' + rel.from_value
            """

        else:

            from_match = """
            a.value = rel.from_value
            """

        if to_is_scoped:

            to_match = """
            b.scope_key = $domain + '|' + rel.to_value
            """

        else:

            to_match = """
            b.value = rel.to_value
            """

        query = f"""
        UNWIND $relationships AS rel

        MATCH (a:{from_type})
        WHERE {from_match}

        MATCH (b:{to_type})
        WHERE {to_match}

        MERGE (a)-[r:{relationship_type}]->(b)

        SET
            r.provenance = rel.provenance

        SET r += rel.properties
        """

        batches = list(
            chunk_list(
                relationship_list
            )
        )

        for (
            batch_number,
            batch,
        ) in enumerate(
            batches,
            start=1,
        ):

            result = session.run(
                query,
                relationships=batch,
                domain=domain,
            )

            summary = result.consume()

            total_loaded += len(
                batch
            )

            if len(batches) > 1:

                print(
                    f"    [+] {relationship_type}: "
                    f"batch {batch_number}/{len(batches)} "
                    f"({len(batch)} relationships)"
                )

    print(
        f"[+] Relationships loaded: {total_loaded}"
    )

    if skipped:

        print(
            f"[!] Relationships skipped: {skipped}"
        )


# ============================================================
# GENERATE OBSERVATION ID
# ============================================================

def generate_observation_id(
    observation_type,
    source,
    method,
    recorded_at,
    entity_type=None,
    entity_value=None,
    from_type=None,
    from_value=None,
    relationship=None,
    to_type=None,
    to_value=None,
):
    """
    Generate a deterministic identifier for an Observation.

    This prevents duplicate Observation nodes when the same
    provenance record is loaded more than once.
    """

    raw = "|".join(
        [
            str(observation_type or ""),
            str(source or ""),
            str(method or ""),
            str(recorded_at or ""),
            str(entity_type or ""),
            str(entity_value or ""),
            str(from_type or ""),
            str(from_value or ""),
            str(relationship or ""),
            str(to_type or ""),
            str(to_value or ""),
        ]
    )

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()


# ============================================================
# CREATE ENTITY PROVENANCE OBSERVATIONS
# ============================================================

def create_entity_observations(
    session,
    entities,
    domain,
):
    """
    Create Observation nodes for entity provenance.
    """

    observations = []

    for entity in entities:

        if not isinstance(
            entity,
            dict,
        ):
            continue

        entity_type = entity.get(
            "type"
        )

        entity_value = entity.get(
            "value"
        )

        provenance = entity.get(
            "provenance",
            [],
        )

        if (
            entity_type not in ALLOWED_ENTITY_TYPES
            or not entity_value
            or not isinstance(
                provenance,
                list,
            )
        ):
            continue

        entity_value = normalize_entity_value(
            entity_type,
            entity_value,
        )

        for item in provenance:

            if not isinstance(
                item,
                dict,
            ):
                continue

            source = item.get(
                "source"
            )

            method = item.get(
                "method"
            )

            recorded_at = item.get(
                "recorded_at"
            )

            source = (
                source
                if source
                else "Unknown"
            )

            method = (
                method
                if method
                else "Unknown"
            )

            recorded_at = (
                recorded_at
                if recorded_at
                else "Unknown"
            )

            observation_id = generate_observation_id(
                "ENTITY",
                source,
                method,
                recorded_at,
                entity_type=entity_type,
                entity_value=entity_value,
            )

            observations.append(
                {
                    "observation_id": observation_id,
                    "observation_type": "ENTITY",
                    "source": str(source),
                    "method": str(method),
                    "recorded_at": str(recorded_at),
                    "entity_type": entity_type,
                    "entity_value": entity_value,
                }
            )

    if not observations:
        return 0

    # --------------------------------------------------------
    # IMPORTANT
    #
    # Domain-scoped entities must be matched using scope_key.
    # --------------------------------------------------------

    query = """
    UNWIND $observations AS observation

    MATCH (e)

    WHERE
        any(
            label IN labels(e)
            WHERE label = observation.entity_type
        )

        AND
        CASE
            WHEN observation.entity_type IN [
                'IPAddress',
                'Port',
                'ServiceBanner'
            ]
            THEN e.scope_key =
                 $domain + '|' + observation.entity_value

            ELSE e.value =
                 observation.entity_value
        END

    MERGE (o:Observation {
        observation_id: observation.observation_id
    })

    SET
        o.observation_type = observation.observation_type,
        o.source = observation.source,
        o.method = observation.method,
        o.recorded_at = observation.recorded_at,
        o.entity_type = observation.entity_type,
        o.entity_value = observation.entity_value,
        o.scope_domain = $domain

    MERGE (o)-[:OBSERVED]->(e)
    """

    total = 0

    for batch in chunk_list(
        observations
    ):

        session.run(
            query,
            observations=batch,
            domain=domain,
        ).consume()

        total += len(
            batch
        )

    return total


# ============================================================
# CREATE RELATIONSHIP PROVENANCE OBSERVATIONS
# ============================================================

def create_relationship_observations(
    session,
    relationships,
    domain,
):
    """
    Create Observation nodes for relationship provenance.
    """

    observations = []

    for relationship in relationships:

        if not isinstance(
            relationship,
            dict,
        ):
            continue

        from_entity = relationship.get(
            "from"
        )

        to_entity = relationship.get(
            "to"
        )

        relationship_type = relationship.get(
            "relationship"
        )

        provenance = relationship.get(
            "provenance",
            [],
        )

        if (
            not isinstance(
                from_entity,
                dict,
            )
            or not isinstance(
                to_entity,
                dict,
            )
            or relationship_type
            not in ALLOWED_RELATIONSHIP_TYPES
            or not isinstance(
                provenance,
                list,
            )
        ):
            continue

        from_type = from_entity.get(
            "type"
        )

        from_value = from_entity.get(
            "value"
        )

        to_type = to_entity.get(
            "type"
        )

        to_value = to_entity.get(
            "value"
        )

        if not all(
            [
                from_type,
                from_value,
                to_type,
                to_value,
            ]
        ):
            continue

        from_value = normalize_entity_value(
            from_type,
            from_value,
        )

        to_value = normalize_entity_value(
            to_type,
            to_value,
        )

        for item in provenance:

            if not isinstance(
                item,
                dict,
            ):
                continue

            source = item.get(
                "source"
            )

            method = item.get(
                "method"
            )

            recorded_at = item.get(
                "recorded_at"
            )

            source = (
                source
                if source
                else "Unknown"
            )

            method = (
                method
                if method
                else "Unknown"
            )

            recorded_at = (
                recorded_at
                if recorded_at
                else "Unknown"
            )

            observation_id = generate_observation_id(
                "RELATIONSHIP",
                source,
                method,
                recorded_at,
                from_type=from_type,
                from_value=from_value,
                relationship=relationship_type,
                to_type=to_type,
                to_value=to_value,
            )

            observations.append(
                {
                    "observation_id": observation_id,
                    "observation_type": "RELATIONSHIP",
                    "source": str(source),
                    "method": str(method),
                    "recorded_at": str(recorded_at),
                    "from_type": from_type,
                    "from_value": from_value,
                    "relationship": relationship_type,
                    "to_type": to_type,
                    "to_value": to_value,
                }
            )

    if not observations:
        return 0

    query = """
    UNWIND $observations AS observation

    MATCH (a)

    WHERE
        any(
            label IN labels(a)
            WHERE label = observation.from_type
        )

        AND
        CASE
            WHEN observation.from_type IN [
                'IPAddress',
                'Port',
                'ServiceBanner'
            ]
            THEN a.scope_key =
                 $domain + '|' + observation.from_value

            ELSE a.value =
                 observation.from_value
        END

    MATCH (b)

    WHERE
        any(
            label IN labels(b)
            WHERE label = observation.to_type
        )

        AND
        CASE
            WHEN observation.to_type IN [
                'IPAddress',
                'Port',
                'ServiceBanner'
            ]
            THEN b.scope_key =
                 $domain + '|' + observation.to_value

            ELSE b.value =
                 observation.to_value
        END

    MERGE (o:Observation {
        observation_id: observation.observation_id
    })

    SET
        o.observation_type = observation.observation_type,
        o.source = observation.source,
        o.method = observation.method,
        o.recorded_at = observation.recorded_at,
        o.relationship = observation.relationship,
        o.from_type = observation.from_type,
        o.from_value = observation.from_value,
        o.to_type = observation.to_type,
        o.to_value = observation.to_value,
        o.scope_domain = $domain

    MERGE (o)-[:OBSERVES_FROM]->(a)

    MERGE (o)-[:OBSERVES_TO]->(b)
    """

    total = 0

    for batch in chunk_list(
        observations
    ):

        session.run(
            query,
            observations=batch,
            domain=domain,
        ).consume()

        total += len(
            batch
        )

    return total


# ============================================================
# CREATE ALL PROVENANCE OBSERVATIONS
# ============================================================

def create_provenance_observations(
    session,
    entities,
    relationships,
    domain,
):
    """
    Create graph-based provenance for entities
    and relationships.
    """

    entity_observation_count = (
        create_entity_observations(
            session,
            entities,
            domain,
        )
    )

    print(
        f"[+] Entity observations loaded: "
        f"{entity_observation_count}"
    )

    relationship_observation_count = (
        create_relationship_observations(
            session,
            relationships,
            domain,
        )
    )

    print(
        f"[+] Relationship observations loaded: "
        f"{relationship_observation_count}"
    )

    total = (
        entity_observation_count
        + relationship_observation_count
    )

    print(
        f"[+] Total provenance observations: {total}"
    )


# ============================================================
# VIRUSTOTAL PROPERTIES
# ============================================================

def create_virustotal_properties(
    session,
    domain,
    virustotal,
):
    """
    Store VirusTotal intelligence as properties on
    the corresponding Domain node.

    Supports the current normalized VirusTotal structure
    using security_summary, while retaining compatibility
    with the original VirusTotal API structure.
    """

    if not domain:
        return

    if not isinstance(
        virustotal,
        dict,
    ):
        return

    if not virustotal:

        print(
            "[!] No VirusTotal data available "
            "for this domain."
        )

        return

    # --------------------------------------------------------
    # RISK SCORE
    # --------------------------------------------------------

    risk_score = virustotal.get(
        "risk_score"
    )

    # --------------------------------------------------------
    # ANALYSIS STATISTICS
    # --------------------------------------------------------

    analysis_stats = virustotal.get(
        "security_summary",
        {},
    )

    if not isinstance(
        analysis_stats,
        dict,
    ):
        analysis_stats = {}

    if not analysis_stats:

        analysis_stats = virustotal.get(
            "last_analysis_stats",
            {},
        )

    if not isinstance(
        analysis_stats,
        dict,
    ):
        analysis_stats = {}

    # --------------------------------------------------------
    # CATEGORIES
    # --------------------------------------------------------

    categories = virustotal.get(
        "categories",
        {},
    )

    if not isinstance(
        categories,
        dict,
    ):
        categories = {}

    # --------------------------------------------------------
    # DNS RECORDS
    # --------------------------------------------------------

    dns_records = virustotal.get(
        "dns_records",
        virustotal.get(
            "last_dns_records",
            [],
        ),
    )

    if not isinstance(
        dns_records,
        list,
    ):
        dns_records = []

    # --------------------------------------------------------
    # POPULARITY RANKS
    # --------------------------------------------------------

    popularity_ranks = virustotal.get(
        "popularity_ranks",
        {},
    )

    if not isinstance(
        popularity_ranks,
        dict,
    ):
        popularity_ranks = {}

    # --------------------------------------------------------
    # SERIALIZE STRUCTURED VALUES
    # --------------------------------------------------------

    categories_json = json.dumps(
        categories,
        ensure_ascii=False,
    )

    dns_records_json = json.dumps(
        dns_records,
        ensure_ascii=False,
    )

    popularity_ranks_json = json.dumps(
        popularity_ranks,
        ensure_ascii=False,
    )

    # --------------------------------------------------------
    # EXTRACT DETECTION COUNTS
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # UPDATE DOMAIN
    # --------------------------------------------------------

    query = """
    MATCH (d:Domain {
        value: $domain
    })

    SET
        d.vt_risk_score = $risk_score,
        d.vt_reputation = $reputation,
        d.vt_malicious = $malicious,
        d.vt_suspicious = $suspicious,
        d.vt_harmless = $harmless,
        d.vt_undetected = $undetected,
        d.vt_timeout = $timeout,
        d.vt_total_vendors = $total_vendors,
        d.vt_categories = $categories,
        d.vt_registrar = $registrar,
        d.vt_creation_date = $creation_date,
        d.vt_last_modification_date =
            $last_modification_date,
        d.vt_dns_records = $dns_records,
        d.vt_popularity_ranks =
            $popularity_ranks,
        d.vt_source = $source,
        d.vt_method = $method,
        d.vt_recorded_at = $recorded_at
    """

    session.run(
        query,
        domain=domain,
        risk_score=risk_score,
        reputation=virustotal.get(
            "reputation"
        ),
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        timeout=timeout,
        total_vendors=total_vendors,
        categories=categories_json,
        registrar=virustotal.get(
            "registrar"
        ),
        creation_date=virustotal.get(
            "creation_date"
        ),
        last_modification_date=virustotal.get(
            "last_modification_date"
        ),
        dns_records=dns_records_json,
        popularity_ranks=popularity_ranks_json,
        source=virustotal.get(
            "source",
            "VirusTotal",
        ),
        method=virustotal.get(
            "method",
            "VirusTotal domain intelligence API",
        ),
        recorded_at=virustotal.get(
            "recorded_at"
        ),
    ).consume()

    print(
        "[+] VirusTotal intelligence added "
        "to Domain node."
    )

    # --------------------------------------------------------
    # DEBUG / VERIFICATION OUTPUT
    # --------------------------------------------------------

    print(
        f"    Risk Score: {risk_score}/100"
    )

    print(
        f"    Malicious: {malicious}"
    )

    print(
        f"    Suspicious: {suspicious}"
    )

    print(
        f"    Harmless: {harmless}"
    )

    print(
        f"    Undetected: {undetected}"
    )

    print(
        f"    Total Vendors: {total_vendors}"
    )


# ============================================================
# VERIFY TARGET GRAPH
# ============================================================

def verify_domain_graph(
    session,
    domain,
):
    """
    Verify the graph actually stored for the target domain.

    This is deliberately target-scoped and therefore provides
    a useful sanity check before the analyzer runs.
    """

    query = """
    MATCH (d:Domain {value: $domain})

    OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip:IPAddress)

    WITH
        d,
        collect(DISTINCT ip) AS ips

    UNWIND ips AS ip

    WITH
        d,
        ip

    OPTIONAL MATCH (ip)-[:HAS_OPEN_PORT]->(p:Port)

    WITH
        d,
        ip,
        collect(DISTINCT p) AS ports

    UNWIND ports AS p

    OPTIONAL MATCH (p)-[:HAS_BANNER]->(b:ServiceBanner)

    RETURN
        count(DISTINCT d) AS domains,
        count(DISTINCT ip) AS ip_addresses,
        count(DISTINCT p) AS open_ports,
        count(DISTINCT b) AS service_banners
    """

    record = session.run(
        query,
        domain=domain,
    ).single()

    if record:

        print(
            "\n========== TARGET GRAPH VERIFICATION =========="
        )

        print(
            f"    Domains: {record['domains']}"
        )

        print(
            f"    IP addresses: {record['ip_addresses']}"
        )

        print(
            f"    Open ports: {record['open_ports']}"
        )

        print(
            f"    Service banners: {record['service_banners']}"
        )

        print(
            "================================================\n"
        )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    domain = input(
        "Enter domain: "
    ).strip()

    password = input(
        "Enter Neo4j password: "
    )

    domain = normalize_domain(
        domain
    )

    file_path = (
        f"data/normalized/{domain}.json"
    )

    if not os.path.exists(
        file_path
    ):

        print(
            f"[!] Normalized data not found: "
            f"{file_path}"
        )

        print(
            "[!] Run entity normalization first."
        )

    else:

        print(
            "\n[*] Loading normalized data "
            "into Neo4j..."
        )

        try:

            load_normalized_data(
                file_path,
                password,
            )

            print(
                "[+] Neo4j graph loading complete."
            )

        except Exception as error:

            print(
                f"[!] Neo4j loading error: {error}"
            )