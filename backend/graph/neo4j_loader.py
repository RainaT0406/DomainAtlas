
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
# PROVENANCE RELATIONSHIP TYPES
# ============================================================

PROVENANCE_ENTITY_RELATIONSHIP = "OBSERVED"
PROVENANCE_FROM_RELATIONSHIP = "OBSERVES_FROM"
PROVENANCE_TO_RELATIONSHIP = "OBSERVES_TO"


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

    Provenance is represented using Observation nodes.
    """

    domain = data.get("domain")

    if not domain:
        raise ValueError(
            "Normalized data does not contain a target domain."
        )

    domain = (
        str(domain)
        .strip()
        .lower()
        .rstrip(".")
    )

    if not domain:
        raise ValueError(
            "Target domain is empty."
        )

    print(
        "\n============================================================"
    )
    print("NEO4J GRAPH LOADING")
    print("============================================================")
    print(
        f"[*] Target domain: {domain}"
    )

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

            create_constraints(
                session
            )

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

            print(
                f"[*] Loading {len(entities)} entities..."
            )

            create_entities(
                session,
                entities,
            )

            # ------------------------------------------------
            # 4. CREATE MAIN RELATIONSHIPS
            # ------------------------------------------------

            relationships = data.get(
                "relationships",
                [],
            )

            print(
                f"[*] Loading {len(relationships)} relationships..."
            )

            create_relationships(
                session,
                relationships,
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
            )

            # ------------------------------------------------
            # 6. VIRUSTOTAL
            # ------------------------------------------------

            print(
                "[*] Adding VirusTotal intelligence..."
            )

            create_virustotal_properties(
                session,
                domain,
                data.get(
                    "virustotal",
                    {},
                ),
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
    Create uniqueness constraints for supported entity types.

    Entity identity:
        Entity Type + Entity Value

    Observation identity:
        observation_id
    """

    constraints = [

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
        CREATE CONSTRAINT ip_value_unique IF NOT EXISTS
        FOR (n:IPAddress)
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

        """
        CREATE CONSTRAINT port_value_unique IF NOT EXISTS
        FOR (n:Port)
        REQUIRE n.value IS UNIQUE
        """,

        """
        CREATE CONSTRAINT service_banner_value_unique IF NOT EXISTS
        FOR (n:ServiceBanner)
        REQUIRE n.value IS UNIQUE
        """,

        """
        CREATE CONSTRAINT observation_id_unique IF NOT EXISTS
        FOR (n:Observation)
        REQUIRE n.observation_id IS UNIQUE
        """,
    ]

    for constraint in constraints:

        session.run(
            constraint
        ).consume()


# ============================================================
# CLEAR EXISTING DOMAIN GRAPH
# ============================================================

def clear_domain_graph(
    session,
    domain,
):
    """
    Safely remove the previous investigation graph for a domain.

    Shared infrastructure nodes are preserved if they are still
    connected to another investigation.
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
    # Remove all outgoing relationships from target domain.
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
    # STEP 3
    #
    # Delete old domain.
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
    # STEP 4
    #
    # Delete orphaned infrastructure nodes.
    # --------------------------------------------------------

    orphan_labels = [
        "Subdomain",
        "IPAddress",
        "ASN",
        "Organization",
        "Certificate",
        "Port",
        "ServiceBanner",
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
    # STEP 5
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
):
    """
    Create entity nodes in batches.

    Entity properties are loaded from the normalized
    properties object.

    Provenance is retained as JSON for compatibility.
    Graph-based provenance is created separately.
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

        value = str(
            value
        ).strip()

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
        # Neo4j accepts primitive values and arrays of
        # primitive values. We therefore filter properties
        # to avoid passing dictionaries/lists accidentally.
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

        grouped_entities[
            entity_type
        ].append(
            {
                "value": value,
                "provenance": provenance_json,
                "properties": clean_properties,
            }
        )

    total_loaded = 0

    # --------------------------------------------------------
    # BATCH INSERT
    # --------------------------------------------------------

    for (
        entity_type,
        entity_list,
    ) in grouped_entities.items():

        print(
            f"[*] Loading {len(entity_list)} "
            f"{entity_type} nodes..."
        )

        query = f"""

        UNWIND $entities AS entity

        MERGE (n:{entity_type} {{
            value: entity.value
        }})

        SET
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
# CREATE RELATIONSHIPS
# ============================================================

def create_relationships(
    session,
    relationships,
):
    """
    Create entity relationships in batches.
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

        if not all([
            from_type,
            from_value,
            to_type,
            to_value,
        ]):

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

        from_value = str(
            from_value
        ).strip()

        to_value = str(
            to_value
        ).strip()

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

        query = f"""

        UNWIND $relationships AS rel

        MATCH (a:{from_type} {{
            value: rel.from_value
        }})

        MATCH (b:{to_type} {{
            value: rel.to_value
        }})

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

            session.run(
                query,
                relationships=batch,
            ).consume()

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

    raw = "|".join([
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
    ])

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()


# ============================================================
# CREATE ENTITY PROVENANCE OBSERVATIONS
# ============================================================

def create_entity_observations(
    session,
    entities,
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

        entity_value = str(
            entity_value
        ).strip()

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

    # IMPORTANT:
    # Match using both entity type and value.
    # This prevents a Port, IPAddress, Certificate, etc.
    # from being confused when values happen to overlap.

    query = """

    UNWIND $observations AS observation

    MATCH (e)

    WHERE
        any(label IN labels(e)
            WHERE label = observation.entity_type)
        AND e.value = observation.entity_value

    MERGE (o:Observation {
        observation_id: observation.observation_id
    })

    SET
        o.observation_type = observation.observation_type,
        o.source = observation.source,
        o.method = observation.method,
        o.recorded_at = observation.recorded_at,
        o.entity_type = observation.entity_type

    MERGE (o)-[:OBSERVED]->(e)

    """

    total = 0

    for batch in chunk_list(
        observations
    ):

        session.run(
            query,
            observations=batch,
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

        if not all([
            from_type,
            from_value,
            to_type,
            to_value,
        ]):
            continue

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
                    "from_value": str(
                        from_value
                    ).strip(),
                    "relationship": relationship_type,
                    "to_type": to_type,
                    "to_value": str(
                        to_value
                    ).strip(),
                }
            )

    if not observations:
        return 0

    query = """

    UNWIND $observations AS observation

    MATCH (a)

    WHERE
        any(label IN labels(a)
            WHERE label = observation.from_type)
        AND a.value = observation.from_value

    MATCH (b)

    WHERE
        any(label IN labels(b)
            WHERE label = observation.to_type)
        AND b.value = observation.to_value

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
        o.to_type = observation.to_type

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
):
    """
    Create graph-based provenance for entities
    and relationships.
    """

    entity_observation_count = (
        create_entity_observations(
            session,
            entities,
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

    Existing frontend / analysis compatibility is preserved.
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
    # ANALYSIS STATISTICS
    # --------------------------------------------------------

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
        "last_dns_records",
        [],
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
    # UPDATE DOMAIN
    # --------------------------------------------------------

    query = """

    MATCH (d:Domain {
        value: $domain
    })

    SET
        d.vt_reputation = $reputation,

        d.vt_malicious = $malicious,

        d.vt_suspicious = $suspicious,

        d.vt_harmless = $harmless,

        d.vt_undetected = $undetected,

        d.vt_timeout = $timeout,

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

        reputation=virustotal.get(
            "reputation"
        ),

        malicious=analysis_stats.get(
            "malicious",
            0,
        ),

        suspicious=analysis_stats.get(
            "suspicious",
            0,
        ),

        harmless=analysis_stats.get(
            "harmless",
            0,
        ),

        undetected=analysis_stats.get(
            "undetected",
            0,
        ),

        timeout=analysis_stats.get(
            "timeout",
            0,
        ),

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

    domain = (
        domain
        .lower()
        .rstrip(".")
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
