import asyncio
import io
import json
import os
from collections import deque
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from neo4j import GraphDatabase
from pydantic import BaseModel

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from backend.services.pipeline_service import run_osint_pipeline


# ============================================================
# ENVIRONMENT
# ============================================================

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")


# ============================================================
# CONSTANTS
# ============================================================

INITIAL_SUBDOMAIN_LIMIT = 5
GRAPH_IP_LIMIT = 20


# ============================================================
# PROGRESS TRACKING
# ============================================================

progress_queue = deque(maxlen=100)
progress_subscribers = []

active_scans = {}
scan_cancelled = {}
progress_store = {}


def publish_progress(update: dict):
    """Publish a progress update to all connected SSE subscribers."""
    progress_queue.append(update)

    for subscriber in progress_subscribers:
        subscriber.append(update)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="Domain-Centric OSINT API",
    description="API for the Domain-Centric OSINT analysis pipeline",
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# REQUEST MODELS
# ============================================================

class AnalyzeRequest(BaseModel):
    domain: str


class StopRequest(BaseModel):
    domain: Optional[str] = None
    scan_id: Optional[str] = None


# ============================================================
# HELPERS
# ============================================================

def normalize_domain(domain: str) -> str:
    """Normalize a domain or hostname."""
    return domain.strip().lower().rstrip(".")


def create_neo4j_driver(password: str):
    """Create a Neo4j driver."""
    if not password:
        raise RuntimeError("Neo4j password is not configured.")

    return GraphDatabase.driver(
        NEO4J_URI,
        auth=(NEO4J_USERNAME, password),
    )


def node_to_cytoscape(record):
    """Convert a Neo4j node record to Cytoscape format."""
    labels = record["labels"] or []
    value = record["value"]

    node_type = labels[0] if labels else "Entity"

    return {
        "data": {
            "id": record["id"],
            "label": str(value) if value is not None else node_type,
            "type": node_type,
        }
    }


def extract_provenance(normalized_data: dict) -> list:
    """
    Extract provenance from both entities and relationships.
    """

    provenance_records = []

    # --------------------------------------------------------
    # ENTITY PROVENANCE
    # --------------------------------------------------------

    for entity in normalized_data.get("entities", []):
        entity_type = entity.get("type", "Entity")
        entity_value = entity.get("value", "")

        for provenance in entity.get("provenance", []):
            provenance_records.append(
                {
                    "entity_type": entity_type,
                    "entity_value": entity_value,
                    "source": provenance.get("source", "Unknown"),
                    "method": provenance.get("method", "Unknown"),
                    "recorded_at": provenance.get("recorded_at", ""),
                }
            )

    # --------------------------------------------------------
    # RELATIONSHIP PROVENANCE
    # --------------------------------------------------------

    for relationship in normalized_data.get("relationships", []):
        from_entity = relationship.get("from", {})
        to_entity = relationship.get("to", {})

        relationship_type = relationship.get(
            "relationship",
            "RELATED_TO",
        )

        relationship_value = (
            f"{from_entity.get('value', '')} "
            f"{relationship_type} "
            f"{to_entity.get('value', '')}"
        )

        for provenance in relationship.get("provenance", []):
            provenance_records.append(
                {
                    "entity_type": "Relationship",
                    "entity_value": relationship_value,
                    "source": provenance.get("source", "Unknown"),
                    "method": provenance.get("method", "Unknown"),
                    "recorded_at": provenance.get("recorded_at", ""),
                }
            )

    return provenance_records


# ============================================================
# GRAPH EXTRACTION
# ============================================================

def get_graph_data(
    domain: str,
    password: str,
):
    """
    Extract the initial dashboard graph.

    IMPORTANT:
    Only the first 5 subdomains are included here.

    The complete subdomain inventory remains available through
    get_all_subdomains().

    A specific subdomain can later be loaded through:
        /subdomains/graph
    """

    domain = normalize_domain(domain)

    driver = create_neo4j_driver(password)

    try:
        with driver.session(database="neo4j") as session:

            # ------------------------------------------------
            # CORE GRAPH
            # ------------------------------------------------

            query = """
            MATCH (d:Domain {value: $domain})

            OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip:IPAddress)
            OPTIONAL MATCH (ip)-[:BELONGS_TO_ASN]->(asn:ASN)
            OPTIONAL MATCH (ip)-[:ASSOCIATED_WITH]->(org:Organization)
            OPTIONAL MATCH (d)-[:HAS_CERTIFICATE]->(cert:Certificate)

            WITH
                d,
                collect(DISTINCT ip)[0..$ip_limit] AS ips,
                collect(DISTINCT asn) AS asns,
                collect(DISTINCT org) AS orgs,
                collect(DISTINCT cert) AS certs

            UNWIND (
                [d] +
                ips +
                asns +
                orgs +
                certs
            ) AS node

            WITH DISTINCT node

            RETURN
                elementId(node) AS id,
                labels(node) AS labels,
                node.value AS value
            """

            result = session.run(
                query,
                domain=domain,
                ip_limit=GRAPH_IP_LIMIT,
            )

            nodes = []
            node_ids = set()

            for record in result:
                node_id = record["id"]

                if node_id in node_ids:
                    continue

                nodes.append(node_to_cytoscape(record))
                node_ids.add(node_id)

            # ------------------------------------------------
            # INITIAL 5 SUBDOMAINS ONLY
            # ------------------------------------------------

            subdomain_query = """
            MATCH (d:Domain {value: $domain})
                  -[:HAS_SUBDOMAIN]->
                  (s:Subdomain)

            RETURN
                elementId(s) AS id,
                s.value AS value

            ORDER BY s.value
            LIMIT $limit
            """

            subdomain_result = session.run(
                subdomain_query,
                domain=domain,
                limit=INITIAL_SUBDOMAIN_LIMIT,
            )

            for record in subdomain_result:
                node_id = record["id"]

                if node_id in node_ids:
                    continue

                nodes.append(
                    {
                        "data": {
                            "id": node_id,
                            "label": str(record["value"]),
                            "type": "Subdomain",
                        }
                    }
                )

                node_ids.add(node_id)

            # ------------------------------------------------
            # RELATIONSHIPS
            # ------------------------------------------------

            if not node_ids:
                return {
                    "nodes": [],
                    "edges": [],
                }

            relationship_query = """
            MATCH (a)-[r]->(b)

            WHERE
                elementId(a) IN $node_ids
                AND elementId(b) IN $node_ids

            RETURN
                elementId(a) AS source,
                elementId(b) AS target,
                type(r) AS relationship
            """

            relationship_result = session.run(
                relationship_query,
                node_ids=list(node_ids),
            )

            edges = []

            for index, record in enumerate(relationship_result):
                edges.append(
                    {
                        "data": {
                            "id": f"edge-{index}",
                            "source": record["source"],
                            "target": record["target"],
                            "label": record["relationship"],
                        }
                    }
                )

            print(
                f"[+] Initial graph extracted: "
                f"{len(nodes)} nodes, "
                f"{len(edges)} relationships."
            )

            return {
                "nodes": nodes,
                "edges": edges,
            }

    finally:
        driver.close()


# ============================================================
# TARGETED SUBDOMAIN GRAPH
# ============================================================

def get_subdomain_graph(
    domain: str,
    subdomain: str,
    password: str,
):
    """
    Retrieve a specific subdomain and its related infrastructure.

    This is intentionally separate from get_graph_data().

    The initial graph contains only 5 subdomains, but this function
    allows ANY subdomain from the inventory to be loaded dynamically.

    Returned graph may contain:

        Domain
          |
          +-- Subdomain
                 |
                 +-- IP Address
                        |
                        +-- ASN
                        |
                        +-- Organization

    Provenance is also returned separately.
    """

    domain = normalize_domain(domain)
    subdomain = normalize_domain(subdomain)

    driver = create_neo4j_driver(password)

    try:
        with driver.session(database="neo4j") as session:

            # ------------------------------------------------
            # FIND SPECIFIC SUBDOMAIN
            # ------------------------------------------------

            subdomain_query = """
            MATCH (d:Domain {value: $domain})
                  -[:HAS_SUBDOMAIN]->
                  (s:Subdomain {value: $subdomain})

            OPTIONAL MATCH (s)-[r1:RESOLVES_TO]->(ip:IPAddress)
            OPTIONAL MATCH (ip)-[r2:BELONGS_TO_ASN]->(asn:ASN)
            OPTIONAL MATCH (ip)-[r3:ASSOCIATED_WITH]->(org:Organization)

            RETURN
                d,
                s,
                r1,
                ip,
                r2,
                asn,
                r3,
                org
            """

            records = list(
                session.run(
                    subdomain_query,
                    domain=domain,
                    subdomain=subdomain,
                )
            )

            if not records:
                return None

            # ------------------------------------------------
            # BUILD NODES
            # ------------------------------------------------

            nodes = []
            node_ids = set()

            def add_node(node):
                if node is None:
                    return

                node_id = str(node.element_id)

                if node_id in node_ids:
                    return

                labels = list(node.labels)

                node_type = (
                    labels[0]
                    if labels
                    else "Entity"
                )

                value = node.get("value")

                nodes.append(
                    {
                        "data": {
                            "id": node_id,
                            "label": (
                                str(value)
                                if value is not None
                                else node_type
                            ),
                            "type": node_type,
                        }
                    }
                )

                node_ids.add(node_id)

            for record in records:
                add_node(record["d"])
                add_node(record["s"])
                add_node(record["ip"])
                add_node(record["asn"])
                add_node(record["org"])

            # ------------------------------------------------
            # BUILD EDGES
            # ------------------------------------------------

            edges = []
            edge_ids = set()

            def add_relationship(source, target, relationship):
                if (
                    source is None
                    or target is None
                    or relationship is None
                ):
                    return

                edge_id = (
                    f"{source.element_id}-"
                    f"{relationship.type}-"
                    f"{target.element_id}"
                )

                if edge_id in edge_ids:
                    return

                edges.append(
                    {
                        "data": {
                            "id": edge_id,
                            "source": str(source.element_id),
                            "target": str(target.element_id),
                            "label": relationship.type,
                        }
                    }
                )

                edge_ids.add(edge_id)

            for record in records:

                domain_node = record["d"]
                subdomain_node = record["s"]
                ip_node = record["ip"]
                asn_node = record["asn"]
                org_node = record["org"]

                # Domain -> Subdomain
                if domain_node and subdomain_node:
                    add_relationship(
                        domain_node,
                        subdomain_node,
                        session.run(
                            """
                            MATCH (d:Domain {value: $domain})
                                  -[r:HAS_SUBDOMAIN]->
                                  (s:Subdomain {value: $subdomain})

                            RETURN r
                            """,
                            domain=domain,
                            subdomain=subdomain,
                        ).single()["r"],
                    )

                # Subdomain -> IP
                add_relationship(
                    subdomain_node,
                    ip_node,
                    record["r1"],
                )

                # IP -> ASN
                add_relationship(
                    ip_node,
                    asn_node,
                    record["r2"],
                )

                # IP -> Organization
                add_relationship(
                    ip_node,
                    org_node,
                    record["r3"],
                )

            # ------------------------------------------------
            # PROVENANCE
            # ------------------------------------------------
            #
            # Provenance is retrieved from the Neo4j nodes and
            # relationships when those properties exist.
            #
            # This supports both:
            #   provenance: [...]
            # and
            #   source / method / recorded_at
            # properties.

            provenance = []

            relevant_nodes = [
                record["d"]
                for record in records
            ]

            for record in records:
                relevant_nodes.extend(
                    [
                        record["s"],
                        record["ip"],
                        record["asn"],
                        record["org"],
                    ]
                )

            seen_nodes = set()

            for node in relevant_nodes:

                if node is None:
                    continue

                node_id = str(node.element_id)

                if node_id in seen_nodes:
                    continue

                seen_nodes.add(node_id)

                labels = list(node.labels)

                node_type = (
                    labels[0]
                    if labels
                    else "Entity"
                )

                value = node.get("value", "")

                # --------------------------------------------
                # LIST-BASED PROVENANCE
                # --------------------------------------------

                node_provenance = node.get(
                    "provenance",
                    [],
                )

                if isinstance(node_provenance, list):

                    for item in node_provenance:

                        if not isinstance(item, dict):
                            continue

                        provenance.append(
                            {
                                "entity_type": node_type,
                                "entity_value": str(value),
                                "source": item.get(
                                    "source",
                                    "Unknown",
                                ),
                                "method": item.get(
                                    "method",
                                    "Unknown",
                                ),
                                "recorded_at": item.get(
                                    "recorded_at",
                                    "",
                                ),
                            }
                        )

                # --------------------------------------------
                # DIRECT PROVENANCE PROPERTIES
                # --------------------------------------------

                elif (
                    node.get("source")
                    or node.get("method")
                    or node.get("recorded_at")
                ):
                    provenance.append(
                        {
                            "entity_type": node_type,
                            "entity_value": str(value),
                            "source": node.get(
                                "source",
                                "Unknown",
                            ),
                            "method": node.get(
                                "method",
                                "Unknown",
                            ),
                            "recorded_at": node.get(
                                "recorded_at",
                                "",
                            ),
                        }
                    )

            print(
                f"[+] Targeted subdomain graph loaded: "
                f"{subdomain}"
            )

            return {
                "nodes": nodes,
                "edges": edges,
                "provenance": provenance,
                "subdomain": subdomain,
                "domain": domain,
            }

    finally:
        driver.close()


# ============================================================
# GET ALL SUBDOMAINS
# ============================================================

def get_all_subdomains(
    domain: str,
    password: str,
):
    """
    Retrieve the COMPLETE subdomain inventory.

    No graph visualization limit is applied here.
    """

    domain = normalize_domain(domain)

    driver = create_neo4j_driver(password)

    try:
        with driver.session(database="neo4j") as session:

            query = """
            MATCH (d:Domain {value: $domain})
                  -[:HAS_SUBDOMAIN]->
                  (s:Subdomain)

            RETURN s.value AS value

            ORDER BY s.value
            """

            result = session.run(
                query,
                domain=domain,
            )

            return [
                str(record["value"])
                for record in result
                if record["value"] is not None
            ]

    finally:
        driver.close()


# ============================================================
# GENERATE SUBDOMAIN PDF
# ============================================================

def create_subdomain_pdf(
    domain: str,
    subdomains: list,
):
    """Generate a PDF containing the complete subdomain list."""

    buffer = io.BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=f"{domain} - Subdomain Intelligence Report",
        author="Domain-Centric OSINT",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=18,
        spaceAfter=10,
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontSize=12,
        spaceAfter=8,
    )

    normal_style = ParagraphStyle(
        "ReportNormal",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
    )

    cell_style = ParagraphStyle(
        "Cell",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
    )

    story = [
        Paragraph(
            "Domain-Centric OSINT",
            title_style,
        ),
        Paragraph(
            "Complete Subdomain Enumeration Report",
            heading_style,
        ),
        Paragraph(
            f"<b>Target Domain:</b> {domain}",
            normal_style,
        ),
        Spacer(1, 5 * mm),
        Paragraph(
            f"<b>Total Subdomains:</b> {len(subdomains):,}",
            normal_style,
        ),
        Spacer(1, 8 * mm),
    ]

    table_data = [
        [
            Paragraph("<b>#</b>", cell_style),
            Paragraph("<b>Subdomain</b>", cell_style),
        ]
    ]

    chunk_size = 1000

    for index, subdomain in enumerate(
        subdomains,
        start=1,
    ):

        table_data.append(
            [
                Paragraph(
                    str(index),
                    cell_style,
                ),
                Paragraph(
                    str(subdomain),
                    cell_style,
                ),
            ]
        )

        if (
            len(table_data) >= chunk_size + 1
            or index == len(subdomains)
        ):

            table = Table(
                table_data,
                colWidths=[
                    15 * mm,
                    165 * mm,
                ],
                repeatRows=1,
            )

            table.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, 0),
                            colors.HexColor("#172033"),
                        ),
                        (
                            "TEXTCOLOR",
                            (0, 0),
                            (-1, 0),
                            colors.white,
                        ),
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.25,
                            colors.grey,
                        ),
                        (
                            "VALIGN",
                            (0, 0),
                            (-1, -1),
                            "TOP",
                        ),
                        (
                            "LEFTPADDING",
                            (0, 0),
                            (-1, -1),
                            4,
                        ),
                        (
                            "RIGHTPADDING",
                            (0, 0),
                            (-1, -1),
                            4,
                        ),
                        (
                            "TOPPADDING",
                            (0, 0),
                            (-1, -1),
                            3,
                        ),
                        (
                            "BOTTOMPADDING",
                            (0, 0),
                            (-1, -1),
                            3,
                        ),
                    ]
                )
            )

            story.append(table)

            table_data = [
                [
                    Paragraph("<b>#</b>", cell_style),
                    Paragraph("<b>Subdomain</b>", cell_style),
                ]
            ]

            if index < len(subdomains):
                story.append(
                    Spacer(1, 5 * mm)
                )

    document.build(story)

    buffer.seek(0)

    return buffer


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "message": "Domain-Centric OSINT API is running"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "ok"
    }


# ============================================================
# PROGRESS STREAM
# ============================================================

@app.get("/analyze/progress")
async def analyze_progress():

    async def event_generator():

        subscriber = deque(maxlen=10)

        progress_subscribers.append(subscriber)

        try:

            for update in progress_queue:
                yield (
                    f"data: {json.dumps(update)}\n\n"
                )

            while True:

                if subscriber:
                    update = subscriber.popleft()

                    yield (
                        f"data: {json.dumps(update)}\n\n"
                    )

                else:
                    await asyncio.sleep(0.1)

        finally:

            if subscriber in progress_subscribers:
                progress_subscribers.remove(
                    subscriber
                )

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ============================================================
# GET PROGRESS BY SCAN ID
# ============================================================

@app.get("/analyze/progress/{scan_id}")
async def get_progress_by_scan_id(scan_id: str):

    if scan_id in progress_store:
        return progress_store[scan_id]

    if scan_id in active_scans:
        return {
            "progress": active_scans[scan_id].get(
                "progress",
                0,
            ),
            "status": active_scans[scan_id].get(
                "status",
                "running",
            ),
            "steps": {},
            "domain": active_scans[scan_id].get(
                "domain",
                "",
            ),
        }

    raise HTTPException(
        status_code=404,
        detail="Scan not found",
    )


# ============================================================
# STOP ANALYSIS
# ============================================================

@app.post("/analyze/stop")
async def stop_analysis(request: StopRequest):

    domain = request.domain
    scan_id = request.scan_id

    print(
        f"[*] Stop request received: "
        f"domain={domain}, scan_id={scan_id}"
    )

    # --------------------------------------------------------
    # CANCEL ALL SCANS FOR DOMAIN
    # --------------------------------------------------------

    if domain:

        domain = normalize_domain(domain)

        cancelled_count = 0

        for sid in list(active_scans):

            if (
                normalize_domain(
                    active_scans[sid].get(
                        "domain",
                        "",
                    )
                )
                == domain
            ):

                scan_cancelled[sid] = True
                cancelled_count += 1

                if sid in progress_store:
                    progress_store[sid][
                        "status"
                    ] = "cancelled"

                    progress_store[sid][
                        "progress"
                    ] = 0

                print(
                    f"[*] Cancelled scan "
                    f"{sid} for domain {domain}"
                )

        if cancelled_count:
            return {
                "success": True,
                "message": (
                    f"Cancelled "
                    f"{cancelled_count} scan(s) "
                    f"for {domain}"
                ),
            }

    # --------------------------------------------------------
    # CANCEL SPECIFIC SCAN
    # --------------------------------------------------------

    if scan_id and scan_id in active_scans:

        scan_cancelled[scan_id] = True

        if scan_id in progress_store:
            progress_store[scan_id][
                "status"
            ] = "cancelled"

            progress_store[scan_id][
                "progress"
            ] = 0

        print(
            f"[*] Cancelled scan {scan_id}"
        )

        return {
            "success": True,
            "message": (
                f"Stop signal sent "
                f"for scan {scan_id}"
            ),
        }

    return {
        "success": True,
        "message": "Stop signal received",
    }


# ============================================================
# GET SCAN STATUS
# ============================================================

@app.get("/analyze/status/{scan_id}")
async def get_scan_status(scan_id: str):

    if scan_id in active_scans:
        return active_scans[scan_id]

    raise HTTPException(
        status_code=404,
        detail="Scan not found",
    )


# ============================================================
# GET COMPLETE SUBDOMAIN INVENTORY
# ============================================================

@app.get("/subdomains")
def get_subdomain_inventory(domain: str):

    domain = normalize_domain(domain)

    if not domain:
        raise HTTPException(
            status_code=400,
            detail="Domain cannot be empty.",
        )

    if not NEO4J_PASSWORD:
        raise HTTPException(
            status_code=500,
            detail="Neo4j password is not configured.",
        )

    try:

        subdomains = get_all_subdomains(
            domain,
            NEO4J_PASSWORD,
        )

        return {
            "domain": domain,
            "count": len(subdomains),
            "subdomains": subdomains,
        }

    except Exception as error:

        print(
            f"[!] Failed to retrieve "
            f"subdomain inventory: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to retrieve "
                f"subdomain inventory: {str(error)}"
            ),
        )


# ============================================================
# GET SPECIFIC SUBDOMAIN GRAPH
# ============================================================

@app.get("/subdomains/graph")
def get_specific_subdomain_graph(
    domain: str,
    subdomain: str,
):
    """
    Dynamically load ANY subdomain from the inventory.

    Example:

        /subdomains/graph
        ?domain=geeksforgeeks.org
        &subdomain=api.aa.geeksforgeeks.org
    """

    domain = normalize_domain(domain)
    subdomain = normalize_domain(subdomain)

    if not domain:
        raise HTTPException(
            status_code=400,
            detail="Domain cannot be empty.",
        )

    if not subdomain:
        raise HTTPException(
            status_code=400,
            detail="Subdomain cannot be empty.",
        )

    if not NEO4J_PASSWORD:
        raise HTTPException(
            status_code=500,
            detail="Neo4j password is not configured.",
        )

    try:

        graph = get_subdomain_graph(
            domain,
            subdomain,
            NEO4J_PASSWORD,
        )

        if not graph:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"Subdomain '{subdomain}' "
                    f"was not found for '{domain}'."
                ),
            )

        return {
            "success": True,
            **graph,
        }

    except HTTPException:
        raise

    except Exception as error:

        print(
            f"[!] Failed to load subdomain graph: "
            f"{error}"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to load subdomain graph: "
                f"{str(error)}"
            ),
        )


# ============================================================
# DOWNLOAD COMPLETE SUBDOMAIN PDF
# ============================================================

@app.get("/subdomains/pdf")
def download_subdomains_pdf(domain: str):

    domain = normalize_domain(domain)

    if not domain:
        raise HTTPException(
            status_code=400,
            detail="Domain cannot be empty.",
        )

    if not NEO4J_PASSWORD:
        raise HTTPException(
            status_code=500,
            detail=(
                "Neo4j password is not configured "
                "in the environment."
            ),
        )

    try:

        print(
            f"[*] Generating complete "
            f"subdomain PDF for: {domain}"
        )

        subdomains = get_all_subdomains(
            domain,
            NEO4J_PASSWORD,
        )

        if not subdomains:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"No subdomains found "
                    f"for '{domain}'."
                ),
            )

        print(
            f"[+] Found {len(subdomains):,} "
            f"subdomains for PDF export."
        )

        pdf_buffer = create_subdomain_pdf(
            domain,
            subdomains,
        )

        filename = (
            f"{domain}-subdomains.pdf"
        )

        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={
                "Content-Disposition": (
                    f'attachment; '
                    f'filename="{filename}"'
                )
            },
        )

    except HTTPException:
        raise

    except Exception as error:

        print(
            f"[!] Subdomain PDF generation failed: "
            f"{error}"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to generate "
                f"subdomain PDF: {str(error)}"
            ),
        )


# ============================================================
# DOMAIN ANALYSIS
# ============================================================

@app.post("/analyze")
def analyze_domain(request: AnalyzeRequest):

    domain = normalize_domain(
        request.domain
    )

    if not domain:
        raise HTTPException(
            status_code=400,
            detail="Domain cannot be empty.",
        )

    if not NEO4J_PASSWORD:
        raise HTTPException(
            status_code=500,
            detail=(
                "Neo4j password is not configured "
                "in the environment."
            ),
        )

    scan_id = (
        f"{domain}_"
        f"{datetime.now().timestamp()}"
    )

    active_scans[scan_id] = {
        "domain": domain,
        "status": "running",
        "progress": 0,
        "started_at": datetime.now().isoformat(),
    }

    scan_cancelled[scan_id] = False

    progress_store[scan_id] = {
        "domain": domain,
        "progress": 0,
        "status": "running",
        "steps": {},
    }

    print("\n" + "=" * 60)
    print(
        f"[*] Starting analysis for: {domain}"
    )
    print(
        f"[*] Scan ID: {scan_id}"
    )
    print("=" * 60)

    # --------------------------------------------------------
    # PROGRESS CALLBACK
    # --------------------------------------------------------

    def progress_callback(update):

        if scan_cancelled.get(
            scan_id,
            False,
        ):
            return

        progress_value = update.get(
            "progress",
            0,
        )

        active_scans[scan_id][
            "progress"
        ] = progress_value

        progress_store[scan_id][
            "progress"
        ] = progress_value

        progress_store[scan_id][
            "status"
        ] = update.get(
            "status",
            "running",
        )

        step = update.get("step")

        if step:
            progress_store[scan_id][
                "steps"
            ][step] = update

        publish_progress(update)

    try:

        # ----------------------------------------------------
        # PRE-START CANCELLATION
        # ----------------------------------------------------

        if scan_cancelled.get(
            scan_id,
            False,
        ):

            active_scans[scan_id][
                "status"
            ] = "cancelled"

            progress_store[scan_id][
                "status"
            ] = "cancelled"

            publish_progress(
                {
                    "step": "cancelled",
                    "progress": 0,
                    "status": "cancelled",
                    "message": (
                        "Scan cancelled by user"
                    ),
                }
            )

            return {
                "success": False,
                "message": "Scan cancelled",
            }

        # ----------------------------------------------------
        # RUN PIPELINE
        # ----------------------------------------------------

        result = run_osint_pipeline(
            domain,
            NEO4J_PASSWORD,
            progress_callback=progress_callback,
            scan_id=scan_id,
            is_cancelled=lambda: scan_cancelled.get(
                scan_id,
                False,
            ),
        )

        # ----------------------------------------------------
        # POST-PIPELINE CANCELLATION
        # ----------------------------------------------------

        if scan_cancelled.get(
            scan_id,
            False,
        ):

            active_scans[scan_id][
                "status"
            ] = "cancelled"

            progress_store[scan_id][
                "status"
            ] = "cancelled"

            publish_progress(
                {
                    "step": "cancelled",
                    "progress": 0,
                    "status": "cancelled",
                    "message": (
                        "Scan cancelled by user"
                    ),
                }
            )

            return {
                "success": False,
                "message": "Scan cancelled",
            }

        # ----------------------------------------------------
        # GRAPH ANALYSIS
        # ----------------------------------------------------

        analysis = result.get(
            "graph_analysis"
        )

        if not analysis:
            raise RuntimeError(
                "Graph analysis data was not returned."
            )

        # ----------------------------------------------------
        # INFRASTRUCTURE
        # ----------------------------------------------------

        infrastructure = analysis.get(
            "infrastructure",
            {},
        )

        subdomains = infrastructure.get(
            "subdomains",
            [],
        )

        ip_addresses = infrastructure.get(
            "ip_addresses",
            [],
        )

        asns = infrastructure.get(
            "asns",
            [],
        )

        organizations = infrastructure.get(
            "organizations",
            [],
        )

        certificates = infrastructure.get(
            "certificates",
            [],
        )

        # ----------------------------------------------------
        # INITIAL GRAPH
        # ----------------------------------------------------

        print(
            "[*] Extracting graph "
            "for dashboard..."
        )

        graph = get_graph_data(
            domain,
            NEO4J_PASSWORD,
        )

        # ----------------------------------------------------
        # PROVENANCE
        # ----------------------------------------------------

        print(
            "[*] Extracting provenance data..."
        )

        normalized_data = result.get(
            "normalized_data",
            {},
        )

        all_provenance = extract_provenance(
            normalized_data
        )

        print(
            f"[+] Extracted "
            f"{len(all_provenance)} "
            f"provenance records."
        )

        graph["provenance"] = all_provenance

        # ----------------------------------------------------
        # COMPLETE
        # ----------------------------------------------------

        active_scans[scan_id][
            "status"
        ] = "completed"

        active_scans[scan_id][
            "progress"
        ] = 100

        progress_store[scan_id][
            "status"
        ] = "completed"

        progress_store[scan_id][
            "progress"
        ] = 100

        # ----------------------------------------------------
        # RESPONSE
        # ----------------------------------------------------

        response = {
            "success": True,
            "scan_id": scan_id,
            "domain": result.get(
                "domain",
                domain,
            ),
            "statistics": analysis.get(
                "statistics",
                {},
            ),
            "relationships": analysis.get(
                "relationships",
                {},
            ),
            "ip_version_summary": analysis.get(
                "ip_version_summary",
                {},
            ),
            "subdomain_patterns": analysis.get(
                "subdomain_patterns",
                {},
            ),
            "infrastructure": {
                "subdomains": subdomains,
                "subdomain_count": len(
                    subdomains
                ),
                "ip_addresses": ip_addresses,
                "asns": asns,
                "organizations": organizations,
                "certificates": certificates,
            },
            "provenance": all_provenance,
            "observations": analysis.get(
                "observations",
                [],
            ),
            "virustotal": analysis.get(
                "virustotal",
                {},
            ),
            "ai_report": result.get(
                "ai_report",
                "",
            ),
            "graph": graph,
        }

        print("=" * 60)
        print(
            "[+] Domain analysis complete."
        )
        print("=" * 60)

        # Keep completed progress available for the frontend.
        scan_cancelled.pop(
            scan_id,
            None,
        )

        return response

    except ValueError as error:

        print(
            f"[!] Validation error: {error}"
        )

        active_scans[scan_id][
            "status"
        ] = "failed"

        progress_store[scan_id][
            "status"
        ] = "failed"

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except Exception as error:

        print(
            f"[!] Pipeline execution failed: "
            f"{error}"
        )

        active_scans[scan_id][
            "status"
        ] = "failed"

        progress_store[scan_id][
            "status"
        ] = "failed"

        raise HTTPException(
            status_code=500,
            detail=(
                "Pipeline execution failed: "
                f"{str(error)}"
            ),
        )