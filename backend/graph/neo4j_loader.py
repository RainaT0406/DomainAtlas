import json
import os

from neo4j import GraphDatabase


NEO4J_URI = "bolt://localhost:7687"
NEO4J_USERNAME = "neo4j"


# ============================================================
# LOAD NORMALIZED DATA OBJECT
# ============================================================

def load_normalized_data_object(data, password):
    """
    Load normalized OSINT data directly into Neo4j.

    Intended for the FastAPI pipeline.

    The normalized data is supplied as a Python dictionary,
    so no intermediate normalized JSON file is required.
    """

    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(NEO4J_USERNAME, password)
    )

    try:
        with driver.session(database="neo4j") as session:

            # ------------------------------------------------
            # 1. CREATE CONSTRAINTS
            # ------------------------------------------------

            create_constraints(session)

            # ------------------------------------------------
            # 2. CREATE ENTITIES
            # ------------------------------------------------

            create_entities(
                session,
                data.get("entities", [])
            )

            # ------------------------------------------------
            # 3. CREATE RELATIONSHIPS
            # ------------------------------------------------

            create_relationships(
                session,
                data.get("relationships", [])
            )

    finally:
        driver.close()


# ============================================================
# FILE-BASED LOADER
# ============================================================

def load_normalized_data(file_path, password):
    """
    Existing file-based loader.

    Kept for command-line execution.
    """

    with open(file_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    load_normalized_data_object(
        data,
        password
    )


# ============================================================
# CONSTRAINTS
# ============================================================

def create_constraints(session):
    """
    Create uniqueness constraints for all entity types.

    These prevent duplicate nodes of the same entity type
    with the same value.
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
        """
    ]

    for constraint in constraints:
        session.run(constraint)


# ============================================================
# CREATE ENTITIES
# ============================================================

def create_entities(session, entities):
    """
    Create or update entity nodes.

    Entity identity is based on:

        Entity Type + Entity Value

    Example:

        Domain + google.com

        IPAddress + 142.251.220.14

    Provenance is stored as a JSON string on the node.
    """

    for entity in entities:

        entity_type = entity.get("type")
        value = entity.get("value")
        provenance = entity.get("provenance", [])

        if not entity_type or not value:
            continue

        value = str(value).strip()

        if not value:
            continue

        provenance_json = json.dumps(
            provenance,
            ensure_ascii=False
        )

        query = f"""
        MERGE (n:{entity_type} {{value: $value}})
        SET n.provenance = $provenance
        """

        session.run(
            query,
            value=value,
            provenance=provenance_json
        )


# ============================================================
# CREATE RELATIONSHIPS
# ============================================================

def create_relationships(session, relationships):
    """
    Create relationships between existing entity nodes.

    Example:

        Domain
          |
          | RESOLVES_TO
          v
        IPAddress
          |
          | BELONGS_TO_ASN
          v
        ASN

    Relationship provenance is stored on the relationship
    as a JSON string.
    """

    for relationship in relationships:

        from_entity = relationship.get("from")
        to_entity = relationship.get("to")
        relationship_type = relationship.get("relationship")
        provenance = relationship.get("provenance", [])

        if (
            not from_entity
            or not to_entity
            or not relationship_type
        ):
            continue

        from_type = from_entity.get("type")
        from_value = from_entity.get("value")

        to_type = to_entity.get("type")
        to_value = to_entity.get("value")

        if not all([
            from_type,
            from_value,
            to_type,
            to_value
        ]):
            continue

        from_value = str(from_value).strip()
        to_value = str(to_value).strip()

        if not from_value or not to_value:
            continue

        provenance_json = json.dumps(
            provenance,
            ensure_ascii=False
        )

        query = f"""
        MATCH (a:{from_type} {{value: $from_value}})
        MATCH (b:{to_type} {{value: $to_value}})

        MERGE (a)-[r:{relationship_type}]->(b)

        SET r.provenance = $provenance
        """

        session.run(
            query,
            from_value=from_value,
            to_value=to_value,
            provenance=provenance_json
        )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    domain = input("Enter domain: ").strip()
    password = input("Enter Neo4j password: ")

    file_path = f"data/normalized/{domain}.json"

    if not os.path.exists(file_path):

        print(
            f"[!] Normalized data not found: {file_path}"
        )

        print(
            "[!] Run entity normalization first."
        )

    else:

        print(
            "\n[*] Loading normalized data into Neo4j..."
        )

        try:

            load_normalized_data(
                file_path,
                password
            )

            print(
                "[+] Neo4j graph loading complete."
            )

        except Exception as error:

            print(
                f"[!] Neo4j loading error: {error}"
            )