import asyncio
import io
import json
import os
import uuid

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

NEO4J_URI = os.getenv(
    "NEO4J_URI",
    "bolt://localhost:7687",
)

NEO4J_USERNAME = os.getenv(
    "NEO4J_USERNAME",
    "neo4j",
)

NEO4J_PASSWORD = os.getenv(
    "NEO4J_PASSWORD"
)


# ============================================================
# CONSTANTS
# ============================================================

INITIAL_SUBDOMAIN_LIMIT = 5
GRAPH_IP_LIMIT = 20

# Keep only a small amount of global history.
GLOBAL_PROGRESS_HISTORY_LIMIT = 100

# Per-scan progress history.
SCAN_PROGRESS_HISTORY_LIMIT = 100


# ============================================================
# PROGRESS / SCAN STATE
# ============================================================

# Global progress history.
#
# IMPORTANT:
# Every update contains scan_id.
# This prevents updates from different scans from being
# indistinguishable.
progress_queue = deque(
    maxlen=GLOBAL_PROGRESS_HISTORY_LIMIT
)

# Connected subscribers for the global SSE endpoint.
progress_subscribers = []

# Connected subscribers by scan ID.
scan_subscribers = {}

# Currently running scans only.
active_scans = {}

# Cancellation flags.
scan_cancelled = {}

# Final/current progress state for every scan.
#
# Unlike active_scans, this dictionary is intentionally retained
# after completion/cancellation/failure so the frontend can
# retrieve the final state.
progress_store = {}

# Individual progress history per scan.
scan_progress_history = {}


# ============================================================
# PROGRESS HELPERS
# ============================================================

def publish_progress(update: dict):
    """
    Publish a progress update.

    Every update MUST contain scan_id.

    The update is:
        1. Stored globally.
        2. Stored in the scan-specific history.
        3. Sent to global subscribers.
        4. Sent to subscribers of the specific scan.
    """

    scan_id = update.get("scan_id")

    if not scan_id:
        print(
            "[!] Progress update ignored because scan_id is missing."
        )
        return

    # --------------------------------------------------------
    # GLOBAL HISTORY
    # --------------------------------------------------------

    progress_queue.append(update)

    # --------------------------------------------------------
    # SCAN-SPECIFIC HISTORY
    # --------------------------------------------------------

    if scan_id not in scan_progress_history:
        scan_progress_history[scan_id] = deque(
            maxlen=SCAN_PROGRESS_HISTORY_LIMIT
        )

    scan_progress_history[scan_id].append(update)

    # --------------------------------------------------------
    # GLOBAL SUBSCRIBERS
    # --------------------------------------------------------

    for subscriber in list(progress_subscribers):
        subscriber.append(update)

    # --------------------------------------------------------
    # SCAN-SPECIFIC SUBSCRIBERS
    # --------------------------------------------------------

    subscribers = scan_subscribers.get(
        scan_id,
        [],
    )

    for subscriber in list(subscribers):
        subscriber.append(update)


def set_scan_status(
    scan_id: str,
    status: str,
    progress: Optional[int] = None,
):
    """
    Safely update the current state of a scan.
    """

    if scan_id not in progress_store:
        return

    progress_data = progress_store[scan_id]

    progress_data["status"] = status

    if progress is not None:
        progress_data["progress"] = progress

    if scan_id in active_scans:
        active_scans[scan_id]["status"] = status

        if progress is not None:
            active_scans[scan_id]["progress"] = progress


def remove_active_scan(scan_id: str):
    """
    Remove a scan from the active scan registry.

    The completed/final state remains in progress_store.
    """

    active_scans.pop(scan_id, None)
    scan_cancelled.pop(scan_id, None)


def is_scan_cancelled(scan_id: str) -> bool:
    """
    Return True if the scan has been cancelled.
    """

    return scan_cancelled.get(
        scan_id,
        False,
    )


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
    """
    Normalize a domain or hostname.
    """

    return (
        domain
        .strip()
        .lower()
        .rstrip(".")
    )


def create_neo4j_driver(password: str):
    """
    Create a Neo4j driver.
    """

    if not password:
        raise RuntimeError(
            "Neo4j password is not configured."
        )

    return GraphDatabase.driver(
        NEO4J_URI,
        auth=(
            NEO4J_USERNAME,
            password,
        ),
    )


def node_to_cytoscape(record):
    """
    Convert a Neo4j node record to Cytoscape format.
    """

    labels = record["labels"] or []
    value = record["value"]

    node_type = (
        labels[0]
        if labels
        else "Entity"
    )

    return {
        "data": {
            "id": record["id"],
            "label": (
                str(value)
                if value is not None
                else node_type
            ),
            "type": node_type,
        }
    }


# ============================================================
# PROVENANCE
# ============================================================

def extract_provenance(
    normalized_data: dict,
) -> list:
    """
    Extract provenance from both entities
    and relationships.
    """

    provenance_records = []

    # --------------------------------------------------------
    # ENTITY PROVENANCE
    # --------------------------------------------------------

    for entity in normalized_data.get(
        "entities",
        [],
    ):

        entity_type = entity.get(
            "type",
            "Entity",
        )

        entity_value = entity.get(
            "value",
            "",
        )

        for provenance in entity.get(
            "provenance",
            [],
        ):

            provenance_records.append(
                {
                    "entity_type": entity_type,
                    "entity_value": entity_value,
                    "source": provenance.get(
                        "source",
                        "Unknown",
                    ),
                    "method": provenance.get(
                        "method",
                        "Unknown",
                    ),
                    "recorded_at": provenance.get(
                        "recorded_at",
                        "",
                    ),
                }
            )

    # --------------------------------------------------------
    # RELATIONSHIP PROVENANCE
    # --------------------------------------------------------

    for relationship in normalized_data.get(
        "relationships",
        [],
    ):

        from_entity = relationship.get(
            "from",
            {},
        )

        to_entity = relationship.get(
            "to",
            {},
        )

        relationship_type = relationship.get(
            "relationship",
            "RELATED_TO",
        )

        relationship_value = (
            f"{from_entity.get('value', '')} "
            f"{relationship_type} "
            f"{to_entity.get('value', '')}"
        )

        for provenance in relationship.get(
            "provenance",
            [],
        ):

            provenance_records.append(
                {
                    "entity_type": "Relationship",
                    "entity_value": relationship_value,
                    "source": provenance.get(
                        "source",
                        "Unknown",
                    ),
                    "method": provenance.get(
                        "method",
                        "Unknown",
                    ),
                    "recorded_at": provenance.get(
                        "recorded_at",
                        "",
                    ),
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

    Only the first five subdomains are included.

    The complete inventory remains available through
    /subdomains.

    A specific subdomain can be loaded through
    /subdomains/graph.
    """

    domain = normalize_domain(domain)

    driver = create_neo4j_driver(
        password
    )

    try:

        with driver.session(
            database="neo4j"
        ) as session:

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

                nodes.append(
                    node_to_cytoscape(
                        record
                    )
                )

                node_ids.add(node_id)

            # ------------------------------------------------
            # INITIAL SUBDOMAINS
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
                            "label": str(
                                record["value"]
                            ),
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

            for index, record in enumerate(
                relationship_result
            ):

                edges.append(
                    {
                        "data": {
                            "id": f"edge-{index}",
                            "source": record["source"],
                            "target": record["target"],
                            "label": record[
                                "relationship"
                            ],
                        }
                    }
                )

            print(
                "[+] Initial graph extracted: "
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
    Retrieve a specific subdomain and its related
    infrastructure.

    Returned graph:

        Domain
           |
           +-- Subdomain
                  |
                  +-- IP Address
                         |
                         +-- ASN
                         |
                         +-- Organization

    Provenance is returned separately.
    """

    domain = normalize_domain(domain)
    subdomain = normalize_domain(subdomain)

    driver = create_neo4j_driver(
        password
    )

    try:

        with driver.session(
            database="neo4j"
        ) as session:

            # ------------------------------------------------
            # FIND SUBDOMAIN
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

                node_id = str(
                    node.element_id
                )

                if node_id in node_ids:
                    return

                labels = list(
                    node.labels
                )

                node_type = (
                    labels[0]
                    if labels
                    else "Entity"
                )

                value = node.get(
                    "value"
                )

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

            def add_relationship(
                source,
                target,
                relationship,
            ):

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
                            "source": str(
                                source.element_id
                            ),
                            "target": str(
                                target.element_id
                            ),
                            "label": relationship.type,
                        }
                    }
                )

                edge_ids.add(edge_id)

            # ------------------------------------------------
            # RELATIONSHIPS
            # ------------------------------------------------

            for record in records:

                domain_node = record["d"]
                subdomain_node = record["s"]
                ip_node = record["ip"]
                asn_node = record["asn"]
                org_node = record["org"]

                # Domain -> Subdomain
                if (
                    domain_node
                    and subdomain_node
                ):

                    has_subdomain_result = session.run(
                        """
                        MATCH (d:Domain {value: $domain})
                              -[r:HAS_SUBDOMAIN]->
                              (s:Subdomain {value: $subdomain})
                        RETURN r
                        """,
                        domain=domain,
                        subdomain=subdomain,
                    ).single()

                    if has_subdomain_result:

                        add_relationship(
                            domain_node,
                            subdomain_node,
                            has_subdomain_result["r"],
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

            provenance = []

            relevant_nodes = []

            for record in records:

                relevant_nodes.extend(
                    [
                        record["d"],
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

                node_id = str(
                    node.element_id
                )

                if node_id in seen_nodes:
                    continue

                seen_nodes.add(node_id)

                labels = list(
                    node.labels
                )

                node_type = (
                    labels[0]
                    if labels
                    else "Entity"
                )

                value = node.get(
                    "value",
                    "",
                )

                # --------------------------------------------
                # LIST-BASED PROVENANCE
                # --------------------------------------------

                node_provenance = node.get(
                    "provenance",
                    [],
                )

                if isinstance(
                    node_provenance,
                    list,
                ):

                    for item in node_provenance:

                        if not isinstance(
                            item,
                            dict,
                        ):
                            continue

                        provenance.append(
                            {
                                "entity_type": node_type,
                                "entity_value": str(
                                    value
                                ),
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
                            "entity_value": str(
                                value
                            ),
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
                "[+] Targeted subdomain graph loaded: "
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
    Retrieve the complete subdomain inventory.
    """

    domain = normalize_domain(domain)

    driver = create_neo4j_driver(
        password
    )

    try:

        with driver.session(
            database="neo4j"
        ) as session:

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
    """
    Generate a PDF containing the complete
    subdomain list.
    """

    buffer = io.BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=(
            f"{domain} - "
            "Subdomain Intelligence Report"
        ),
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
        Spacer(
            1,
            5 * mm,
        ),
        Paragraph(
            f"<b>Total Subdomains:</b> "
            f"{len(subdomains):,}",
            normal_style,
        ),
        Spacer(
            1,
            8 * mm,
        ),
    ]

    table_data = [
        [
            Paragraph(
                "<b>#</b>",
                cell_style,
            ),
            Paragraph(
                "<b>Subdomain</b>",
                cell_style,
            ),
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
            len(table_data)
            >= chunk_size + 1
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
                            colors.HexColor(
                                "#172033"
                            ),
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
                    Paragraph(
                        "<b>#</b>",
                        cell_style,
                    ),
                    Paragraph(
                        "<b>Subdomain</b>",
                        cell_style,
                    ),
                ]
            ]

            if index < len(subdomains):
                story.append(
                    Spacer(
                        1,
                        5 * mm,
                    )
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
        "message": (
            "Domain-Centric OSINT API is running"
        )
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
# GLOBAL PROGRESS STREAM
# ============================================================

@app.get("/analyze/progress")
async def analyze_progress():

    async def event_generator():

        subscriber = deque(
            maxlen=SCAN_PROGRESS_HISTORY_LIMIT
        )

        progress_subscribers.append(
            subscriber
        )

        try:

            # ------------------------------------------------
            # SEND RECENT GLOBAL HISTORY
            # ------------------------------------------------

            for update in list(
                progress_queue
            ):

                yield (
                    f"data: "
                    f"{json.dumps(update)}\n\n"
                )

            # ------------------------------------------------
            # WAIT FOR NEW UPDATES
            # ------------------------------------------------

            while True:

                if subscriber:

                    update = subscriber.popleft()

                    yield (
                        f"data: "
                        f"{json.dumps(update)}\n\n"
                    )

                else:

                    await asyncio.sleep(
                        0.1
                    )

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
# SCAN-SPECIFIC PROGRESS STREAM
# ============================================================

@app.get("/analyze/progress/stream/{scan_id}")
async def analyze_scan_progress_stream(
    scan_id: str,
):
    """
    Scan-specific SSE endpoint.

    This is preferable for the frontend because updates
    from previous scans cannot leak into the current scan.
    """

    if scan_id not in progress_store:

        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    async def event_generator():

        subscriber = deque(
            maxlen=SCAN_PROGRESS_HISTORY_LIMIT
        )

        if scan_id not in scan_subscribers:

            scan_subscribers[scan_id] = []

        scan_subscribers[scan_id].append(
            subscriber
        )

        try:

            # ------------------------------------------------
            # REPLAY THIS SCAN ONLY
            # ------------------------------------------------

            for update in list(
                scan_progress_history.get(
                    scan_id,
                    [],
                )
            ):

                yield (
                    f"data: "
                    f"{json.dumps(update)}\n\n"
                )

            # ------------------------------------------------
            # LIVE UPDATES
            # ------------------------------------------------

            while True:

                if subscriber:

                    update = subscriber.popleft()

                    yield (
                        f"data: "
                        f"{json.dumps(update)}\n\n"
                    )

                else:

                    # If the scan is finished and there
                    # are no more events, continue briefly
                    # so the final event can be consumed.
                    current_status = progress_store.get(
                        scan_id,
                        {},
                    ).get(
                        "status"
                    )

                    if current_status in {
                        "completed",
                        "cancelled",
                        "failed",
                    }:

                        await asyncio.sleep(
                            0.25
                        )

                    else:

                        await asyncio.sleep(
                            0.1
                        )

        finally:

            subscribers = scan_subscribers.get(
                scan_id,
                [],
            )

            if subscriber in subscribers:

                subscribers.remove(
                    subscriber
                )

            if not subscribers:

                scan_subscribers.pop(
                    scan_id,
                    None,
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
async def get_progress_by_scan_id(
    scan_id: str,
):

    # --------------------------------------------------------
    # FINAL / CURRENT STATE
    # --------------------------------------------------------

    if scan_id in progress_store:

        return progress_store[scan_id]

    # --------------------------------------------------------
    # ACTIVE STATE FALLBACK
    # --------------------------------------------------------

    if scan_id in active_scans:

        return {
            "scan_id": scan_id,
            "progress": active_scans[
                scan_id
            ].get(
                "progress",
                0,
            ),
            "status": active_scans[
                scan_id
            ].get(
                "status",
                "running",
            ),
            "steps": {},
            "domain": active_scans[
                scan_id
            ].get(
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
async def stop_analysis(
    request: StopRequest,
):

    domain = request.domain
    scan_id = request.scan_id

    print(
        "[*] Stop request received: "
        f"domain={domain}, "
        f"scan_id={scan_id}"
    )

    # ========================================================
    # SPECIFIC SCAN
    # ========================================================

    if scan_id:

        if scan_id not in active_scans:

            # The scan may already have completed.
            if scan_id in progress_store:

                current_status = progress_store[
                    scan_id
                ].get(
                    "status"
                )

                return {
                    "success": False,
                    "message": (
                        f"Scan {scan_id} is already "
                        f"{current_status}."
                    ),
                }

            return {
                "success": False,
                "message": "Scan not found.",
            }

        # ----------------------------------------------------
        # CANCEL
        # ----------------------------------------------------

        scan_cancelled[scan_id] = True

        set_scan_status(
            scan_id,
            "cancelled",
            0,
        )

        publish_progress(
            {
                "scan_id": scan_id,
                "step": "cancelled",
                "progress": 0,
                "status": "cancelled",
                "message": "Scan cancelled by user",
            }
        )

        print(
            f"[*] Cancel signal sent for "
            f"scan {scan_id}"
        )

        return {
            "success": True,
            "scan_id": scan_id,
            "message": (
                f"Stop signal sent for scan "
                f"{scan_id}"
            ),
        }

    # ========================================================
    # CANCEL RUNNING SCANS FOR DOMAIN
    # ========================================================

    if domain:

        domain = normalize_domain(
            domain
        )

        cancelled_scan_ids = []

        for sid, scan_info in list(
            active_scans.items()
        ):

            # IMPORTANT:
            # Only running scans are stored in active_scans.
            if normalize_domain(
                scan_info.get(
                    "domain",
                    "",
                )
            ) != domain:

                continue

            current_status = scan_info.get(
                "status"
            )

            if current_status not in {
                "running",
            }:

                continue

            scan_cancelled[sid] = True

            set_scan_status(
                sid,
                "cancelled",
                0,
            )

            publish_progress(
                {
                    "scan_id": sid,
                    "step": "cancelled",
                    "progress": 0,
                    "status": "cancelled",
                    "message": (
                        "Scan cancelled by user"
                    ),
                }
            )

            cancelled_scan_ids.append(
                sid
            )

            print(
                f"[*] Cancelled scan {sid} "
                f"for domain {domain}"
            )

        if cancelled_scan_ids:

            return {
                "success": True,
                "domain": domain,
                "scan_ids": cancelled_scan_ids,
                "message": (
                    f"Cancelled "
                    f"{len(cancelled_scan_ids)} "
                    f"scan(s) for {domain}"
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
async def get_scan_status(
    scan_id: str,
):

    # --------------------------------------------------------
    # CURRENT / FINAL STATE
    # --------------------------------------------------------

    if scan_id in progress_store:

        return progress_store[scan_id]

    # --------------------------------------------------------
    # ACTIVE STATE FALLBACK
    # --------------------------------------------------------

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
def get_subdomain_inventory(
    domain: str,
):

    domain = normalize_domain(
        domain
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
                "Neo4j password is not configured."
            ),
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
            "[!] Failed to retrieve "
            f"subdomain inventory: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to retrieve "
                "subdomain inventory: "
                f"{str(error)}"
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

    domain = normalize_domain(
        domain
    )

    subdomain = normalize_domain(
        subdomain
    )

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
            detail=(
                "Neo4j password is not configured."
            ),
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
                    f"was not found for "
                    f"'{domain}'."
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
            "[!] Failed to load "
            f"subdomain graph: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to load "
                "subdomain graph: "
                f"{str(error)}"
            ),
        )


# ============================================================
# DOWNLOAD COMPLETE SUBDOMAIN PDF
# ============================================================

@app.get("/subdomains/pdf")
def download_subdomains_pdf(
    domain: str,
):

    domain = normalize_domain(
        domain
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

    try:

        print(
            "[*] Generating complete "
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
            "subdomains for PDF export."
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
                    "attachment; "
                    f'filename="{filename}"'
                )
            },
        )

    except HTTPException:
        raise

    except Exception as error:

        print(
            "[!] Subdomain PDF "
            f"generation failed: {error}"
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
def analyze_domain(
    request: AnalyzeRequest,
):

    domain = normalize_domain(
        request.domain
    )

    # ========================================================
    # VALIDATION
    # ========================================================

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

    # ========================================================
    # CREATE UNIQUE SCAN ID
    # ========================================================

    scan_id = (
        f"{domain}_"
        f"{datetime.now().strftime('%Y%m%d%H%M%S')}_"
        f"{uuid.uuid4().hex[:8]}"
    )

    # ========================================================
    # INITIALIZE SCAN
    # ========================================================

    active_scans[scan_id] = {
        "scan_id": scan_id,
        "domain": domain,
        "status": "running",
        "progress": 0,
        "started_at": datetime.now().isoformat(),
    }

    scan_cancelled[scan_id] = False

    progress_store[scan_id] = {
        "scan_id": scan_id,
        "domain": domain,
        "progress": 0,
        "status": "running",
        "steps": {},
        "started_at": active_scans[
            scan_id
        ]["started_at"],
    }

    scan_progress_history[scan_id] = deque(
        maxlen=SCAN_PROGRESS_HISTORY_LIMIT
    )

    print("\n" + "=" * 60)

    print(
        f"[*] Starting analysis for: {domain}"
    )

    print(
        f"[*] Scan ID: {scan_id}"
    )

    print("=" * 60)

    # ========================================================
    # PROGRESS CALLBACK
    # ========================================================

    def progress_callback(update):

        # ----------------------------------------------------
        # DO NOT PROCESS OLD / CANCELLED SCAN UPDATES
        # ----------------------------------------------------

        if is_scan_cancelled(
            scan_id
        ):

            return

        if scan_id not in active_scans:

            return

        # ----------------------------------------------------
        # COPY UPDATE
        # ----------------------------------------------------

        progress_update = dict(
            update
        )

        # IMPORTANT:
        # Always attach scan_id.
        progress_update["scan_id"] = scan_id

        progress_value = progress_update.get(
            "progress",
            0,
        )

        status = progress_update.get(
            "status",
            "running",
        )

        # ----------------------------------------------------
        # UPDATE ACTIVE STATE
        # ----------------------------------------------------

        active_scans[scan_id][
            "progress"
        ] = progress_value

        active_scans[scan_id][
            "status"
        ] = status

        # ----------------------------------------------------
        # UPDATE STORED STATE
        # ----------------------------------------------------

        progress_store[scan_id][
            "progress"
        ] = progress_value

        progress_store[scan_id][
            "status"
        ] = status

        step = progress_update.get(
            "step"
        )

        if step:

            progress_store[scan_id][
                "steps"
            ][step] = progress_update

        # ----------------------------------------------------
        # PUBLISH
        # ----------------------------------------------------

        publish_progress(
            progress_update
        )

    try:

        # ====================================================
        # PRE-START CANCELLATION
        # ====================================================

        if is_scan_cancelled(
            scan_id
        ):

            set_scan_status(
                scan_id,
                "cancelled",
                0,
            )

            publish_progress(
                {
                    "scan_id": scan_id,
                    "step": "cancelled",
                    "progress": 0,
                    "status": "cancelled",
                    "message": (
                        "Scan cancelled by user"
                    ),
                }
            )

            remove_active_scan(
                scan_id
            )

            return {
                "success": False,
                "scan_id": scan_id,
                "message": "Scan cancelled",
            }

        # ====================================================
        # RUN PIPELINE
        # ====================================================

        result = run_osint_pipeline(
            domain,
            NEO4J_PASSWORD,
            progress_callback=progress_callback,
            scan_id=scan_id,
            is_cancelled=lambda: (
                is_scan_cancelled(
                    scan_id
                )
            ),
        )

        # ====================================================
        # POST-PIPELINE CANCELLATION
        # ====================================================

        if is_scan_cancelled(
            scan_id
        ):

            set_scan_status(
                scan_id,
                "cancelled",
                0,
            )

            publish_progress(
                {
                    "scan_id": scan_id,
                    "step": "cancelled",
                    "progress": 0,
                    "status": "cancelled",
                    "message": (
                        "Scan cancelled by user"
                    ),
                }
            )

            remove_active_scan(
                scan_id
            )

            return {
                "success": False,
                "scan_id": scan_id,
                "message": "Scan cancelled",
            }

        # ====================================================
        # GRAPH ANALYSIS
        # ====================================================

        analysis = result.get(
            "graph_analysis"
        )

        if not analysis:

            raise RuntimeError(
                "Graph analysis data was not returned."
            )

        # ====================================================
        # INFRASTRUCTURE
        # ====================================================

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
        certificate_details = infrastructure.get(
              "certificate_details",
            [],
)

        # ====================================================
        # INITIAL GRAPH
        # ====================================================

        print(
            "[*] Extracting graph "
            "for dashboard..."
        )

        graph = get_graph_data(
            domain,
            NEO4J_PASSWORD,
        )

        # ====================================================
        # PROVENANCE
        # ====================================================

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
            "provenance records."
        )

        graph["provenance"] = all_provenance

        # ====================================================
        # COMPLETE
        # ====================================================

        completion_time = (
            datetime.now().isoformat()
        )

        set_scan_status(
            scan_id,
            "completed",
            100,
        )

        progress_store[scan_id][
            "completed_at"
        ] = completion_time

        # ----------------------------------------------------
        # FINAL PROGRESS EVENT
        # ----------------------------------------------------

        publish_progress(
            {
                "scan_id": scan_id,
                "step": "complete",
                "progress": 100,
                "status": "completed",
                "message": (
                    "Domain analysis complete."
                ),
            }
        )

        # ----------------------------------------------------
        # REMOVE FROM ACTIVE SCANS
        #
        # IMPORTANT:
        # A completed scan must NOT remain in active_scans.
        # Otherwise a later stop request for the same domain
        # can incorrectly affect this old scan.
        # ----------------------------------------------------

        remove_active_scan(
            scan_id
        )

        # ====================================================
        # RESPONSE
        # ====================================================

        raw_data = result.get(
            "raw_data",
            {},
        )

        port_scan_data = raw_data.get(
            "port_scan",
            {},
        )

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
    "certificate_details": certificate_details,
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

            "port_scan": port_scan_data,
        }

        print("=" * 60)

        print(
            "[+] Domain analysis complete."
        )

        print(
            f"[+] Scan ID: {scan_id}"
        )

        print("=" * 60)

        return response

    # ========================================================
    # VALIDATION ERROR
    # ========================================================

    except ValueError as error:

        print(
            f"[!] Validation error: {error}"
        )

        set_scan_status(
            scan_id,
            "failed",
        )

        progress_store[scan_id][
            "error"
        ] = str(error)

        progress_store[scan_id][
            "completed_at"
        ] = datetime.now().isoformat()

        publish_progress(
            {
                "scan_id": scan_id,
                "step": "failed",
                "progress": 0,
                "status": "failed",
                "message": str(error),
            }
        )

        remove_active_scan(
            scan_id
        )

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    # ========================================================
    # GENERAL ERROR
    # ========================================================

    except Exception as error:

        print(
            "[!] Pipeline execution failed: "
            f"{error}"
        )

        set_scan_status(
            scan_id,
            "failed",
        )

        progress_store[scan_id][
            "error"
        ] = str(error)

        progress_store[scan_id][
            "completed_at"
        ] = datetime.now().isoformat()

        publish_progress(
            {
                "scan_id": scan_id,
                "step": "failed",
                "progress": 0,
                "status": "failed",
                "message": (
                    f"Pipeline execution failed: "
                    f"{str(error)}"
                ),
            }
        )

        remove_active_scan(
            scan_id
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Pipeline execution failed: "
                f"{str(error)}"
            ),
        )