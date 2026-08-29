import io
import os
import asyncio
import json
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
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from backend.services.pipeline_service import (
    run_osint_pipeline
)


# ============================================================
# ENVIRONMENT
# ============================================================

load_dotenv()

NEO4J_URI = os.getenv(
    "NEO4J_URI",
    "bolt://localhost:7687"
)

NEO4J_USERNAME = os.getenv(
    "NEO4J_USERNAME",
    "neo4j"
)

NEO4J_PASSWORD = os.getenv(
    "NEO4J_PASSWORD"
)


# ============================================================
# PROGRESS TRACKING
# ============================================================

# Global queue to store recent progress updates
progress_queue = deque(maxlen=100)

# List of active subscribers (for SSE)
progress_subscribers = []

# Store active scans
active_scans = {}
scan_cancelled = {}

# Store detailed progress for each scan
progress_store = {}


def publish_progress(update):
    """Publish progress update to all subscribers."""
    progress_queue.append(update)
    
    for subscriber in progress_subscribers:
        subscriber.append(update)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="Domain-Centric OSINT API",
    description=(
        "API for the Domain-Centric OSINT "
        "analysis pipeline"
    ),
    version="1.0.0"
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
# REQUEST MODEL
# ============================================================

class AnalyzeRequest(BaseModel):
    domain: str


class StopRequest(BaseModel):
    domain: Optional[str] = None
    scan_id: Optional[str] = None


# ============================================================
# NEO4J DRIVER
# ============================================================

def create_neo4j_driver(password: str):
    """
    Create a Neo4j driver using the configured
    environment variables.
    """

    if not password:
        raise RuntimeError(
            "Neo4j password is not configured."
        )

    return GraphDatabase.driver(
        NEO4J_URI,
        auth=(
            NEO4J_USERNAME,
            password
        )
    )


# ============================================================
# GRAPH EXTRACTION
# ============================================================

def get_graph_data(
    domain: str,
    password: str
):
    """
    Extract a manageable visualization graph.

    The complete OSINT dataset remains stored in Neo4j.

    Dashboard visualization contains:
        - Target Domain
        - IP Addresses
        - ASN
        - Organization
        - Certificates
        - Up to 5 Subdomains

    IMPORTANT:
    The 5 subdomain limit applies ONLY to visualization.
    """

    domain = (
        domain
        .strip()
        .lower()
        .rstrip(".")
    )

    driver = create_neo4j_driver(password)

    try:

        with driver.session(
            database="neo4j"
        ) as session:

            # =================================================
            # FIND TARGET DOMAIN
            # =================================================

            domain_query = """
            MATCH (d:Domain {value: $domain})
            RETURN elementId(d) AS id
            """

            domain_record = session.run(
                domain_query,
                domain=domain
            ).single()

            if not domain_record:

                print(
                    f"[!] Domain '{domain}' "
                    "was not found in Neo4j."
                )

                return {
                    "nodes": [],
                    "edges": []
                }

            # =================================================
            # GET CORE INFRASTRUCTURE NODES
            # =================================================

            node_query = """
            MATCH (d:Domain {value: $domain})

            OPTIONAL MATCH
                (d)-[:RESOLVES_TO]->(ip:IPAddress)

            OPTIONAL MATCH
                (ip)-[:BELONGS_TO_ASN]->(asn:ASN)

            OPTIONAL MATCH
                (ip)-[:ASSOCIATED_WITH]->(org:Organization)

            OPTIONAL MATCH
                (d)-[:HAS_CERTIFICATE]->(cert:Certificate)

            WITH
                d,
                collect(DISTINCT ip)[0..20] AS ips,
                collect(DISTINCT asn) AS asns,
                collect(DISTINCT org) AS orgs,
                collect(DISTINCT cert) AS certs

            UNWIND
                [d]
                + ips
                + asns
                + orgs
                + certs
                AS node

            WITH DISTINCT node

            RETURN
                elementId(node) AS id,
                labels(node) AS labels,
                node.value AS value
            """

            node_result = session.run(
                node_query,
                domain=domain
            )

            nodes = []
            node_ids = set()

            for record in node_result:

                node_id = record["id"]

                if node_id in node_ids:
                    continue

                labels = record["labels"] or []

                value = record["value"]

                node_type = (
                    labels[0]
                    if labels
                    else "Entity"
                )

                display_value = (
                    str(value)
                    if value is not None
                    else node_type
                )

                nodes.append({
                    "data": {
                        "id": node_id,
                        "label": display_value,
                        "type": node_type
                    }
                })

                node_ids.add(node_id)

            # =================================================
            # ADD UP TO 5 SUBDOMAINS
            # =================================================

            subdomain_query = """
            MATCH
                (d:Domain {value: $domain})
                -[:HAS_SUBDOMAIN]->
                (s:Subdomain)

            RETURN
                elementId(s) AS id,
                s.value AS value

            LIMIT 5
            """

            subdomain_result = session.run(
                subdomain_query,
                domain=domain
            )

            for record in subdomain_result:

                node_id = record["id"]

                if node_id in node_ids:
                    continue

                nodes.append({
                    "data": {
                        "id": node_id,
                        "label": str(
                            record["value"]
                        ),
                        "type": "Subdomain"
                    }
                })

                node_ids.add(node_id)

            # =================================================
            # GET RELATIONSHIPS
            # =================================================

            if not node_ids:

                return {
                    "nodes": [],
                    "edges": []
                }

            relationship_query = """
            MATCH (a)-[r]->(b)

            WHERE
                elementId(a) IN $node_ids
                AND
                elementId(b) IN $node_ids

            RETURN
                elementId(a) AS source,
                elementId(b) AS target,
                type(r) AS relationship
            """

            relationship_result = session.run(
                relationship_query,
                node_ids=list(node_ids)
            )

            edges = []

            for index, record in enumerate(
                relationship_result
            ):

                edges.append({
                    "data": {
                        "id": f"edge-{index}",
                        "source": record["source"],
                        "target": record["target"],
                        "label": record["relationship"]
                    }
                })

            # =================================================
            # RETURN GRAPH
            # =================================================

            print(
                f"[+] Dashboard graph extracted: "
                f"{len(nodes)} nodes, "
                f"{len(edges)} relationships."
            )

            return {
                "nodes": nodes,
                "edges": edges
            }

    finally:
        driver.close()


# ============================================================
# GET ALL SUBDOMAINS
# ============================================================

def get_all_subdomains(
    domain: str,
    password: str
):
    """
    Retrieve the COMPLETE subdomain list from Neo4j.

    No visualization limit is applied here.
    """

    domain = (
        domain
        .strip()
        .lower()
        .rstrip(".")
    )

    driver = create_neo4j_driver(password)

    try:

        with driver.session(
            database="neo4j"
        ) as session:

            query = """
            MATCH
                (d:Domain {value: $domain})
                -[:HAS_SUBDOMAIN]->
                (s:Subdomain)

            RETURN
                s.value AS value

            ORDER BY s.value
            """

            result = session.run(
                query,
                domain=domain
            )

            subdomains = []

            for record in result:

                value = record["value"]

                if value is not None:
                    subdomains.append(
                        str(value)
                    )

            return subdomains

    finally:
        driver.close()


# ============================================================
# GENERATE SUBDOMAIN PDF
# ============================================================

def create_subdomain_pdf(
    domain: str,
    subdomains: list
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
            f"{domain} - Subdomain Intelligence Report"
        ),
        author="Domain-Centric OSINT"
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=18,
        spaceAfter=10
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontSize=12,
        spaceAfter=8
    )

    normal_style = ParagraphStyle(
        "ReportNormal",
        parent=styles["Normal"],
        fontSize=9,
        leading=12
    )

    cell_style = ParagraphStyle(
        "Cell",
        parent=styles["Normal"],
        fontSize=8,
        leading=10
    )

    story = []

    # ========================================================
    # TITLE
    # ========================================================

    story.append(
        Paragraph(
            "Domain-Centric OSINT",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Complete Subdomain Enumeration Report",
            heading_style
        )
    )

    story.append(
        Paragraph(
            f"<b>Target Domain:</b> {domain}",
            normal_style
        )
    )

    story.append(Spacer(1, 5 * mm))

    story.append(
        Paragraph(
            f"<b>Total Subdomains:</b> "
            f"{len(subdomains):,}",
            normal_style
        )
    )

    story.append(Spacer(1, 8 * mm))

    # ========================================================
    # SUBDOMAIN TABLE
    # ========================================================

    table_data = [
        [
            Paragraph(
                "<b>#</b>",
                cell_style
            ),
            Paragraph(
                "<b>Subdomain</b>",
                cell_style
            )
        ]
    ]

    # Keep tables reasonably sized.
    # This avoids creating one enormous ReportLab table.
    chunk_size = 1000

    for index, subdomain in enumerate(
        subdomains,
        start=1
    ):

        table_data.append([
            Paragraph(
                str(index),
                cell_style
            ),
            Paragraph(
                subdomain,
                cell_style
            )
        ])

        if (
            len(table_data) >= chunk_size + 1
            or index == len(subdomains)
        ):

            table = Table(
                table_data,
                colWidths=[
                    15 * mm,
                    165 * mm
                ],
                repeatRows=1
            )

            table.setStyle(
                TableStyle([
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor(
                            "#172033"
                        )
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.25,
                        colors.grey
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP"
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        4
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        4
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        3
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        3
                    ),
                ])
            )

            story.append(table)

            table_data = [
                [
                    Paragraph(
                        "<b>#</b>",
                        cell_style
                    ),
                    Paragraph(
                        "<b>Subdomain</b>",
                        cell_style
                    )
                ]
            ]

            # Start a fresh table for the next chunk.
            if index < len(subdomains):
                story.append(
                    Spacer(1, 5 * mm)
                )

    # ========================================================
    # BUILD PDF
    # ========================================================

    document.build(story)

    buffer.seek(0)

    return buffer


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
def root():

    return {
        "message":
            "Domain-Centric OSINT API is running"
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
# PROGRESS STREAM (Server-Sent Events)
# ============================================================

@app.get("/analyze/progress")
async def analyze_progress():
    """
    Stream progress updates using Server-Sent Events.
    """
    async def event_generator():
        subscriber = deque(maxlen=10)
        progress_subscribers.append(subscriber)
        
        try:
            # Send any existing progress
            for update in progress_queue:
                yield f"data: {json.dumps(update)}\n\n"
            
            # Send updates as they happen
            while True:
                if subscriber:
                    update = subscriber.popleft()
                    yield f"data: {json.dumps(update)}\n\n"
                else:
                    await asyncio.sleep(0.1)
        finally:
            progress_subscribers.remove(subscriber)
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


# ============================================================
# GET PROGRESS BY SCAN ID
# ============================================================

@app.get("/analyze/progress/{scan_id}")
async def get_progress_by_scan_id(scan_id: str):
    """
    Get detailed progress for a specific scan.
    """
    print(f"[DEBUG] Progress request for scan_id: {scan_id}")
    
    # Check if we have detailed progress
    if scan_id in progress_store:
        print(f"[DEBUG] Found in progress_store: {progress_store[scan_id].get('progress', 0)}%")
        return progress_store[scan_id]
    
    # Fallback to active_scans
    if scan_id in active_scans:
        print(f"[DEBUG] Found in active_scans: {active_scans[scan_id].get('progress', 0)}%")
        return {
            "progress": active_scans[scan_id].get("progress", 0),
            "status": active_scans[scan_id].get("status", "running"),
            "steps": {},
            "domain": active_scans[scan_id].get("domain", "")
        }
    
    print(f"[DEBUG] scan_id {scan_id} not found")
    raise HTTPException(status_code=404, detail="Scan not found")


# ============================================================
# STOP ANALYSIS
# ============================================================

@app.post("/analyze/stop")
async def stop_analysis(request: StopRequest):
    """
    Stop an ongoing domain analysis scan.
    """
    try:
        domain = request.domain
        scan_id = request.scan_id
        
        print(f"[*] Stop request received: domain={domain}, scan_id={scan_id}")
        
        # Mark all scans for this domain as cancelled
        if domain:
            cancelled_count = 0
            for sid in list(active_scans.keys()):
                if active_scans[sid].get("domain") == domain:
                    scan_cancelled[sid] = True
                    cancelled_count += 1
                    print(f"[*] Cancelled scan {sid} for domain {domain}")
                    # Update progress_store
                    if sid in progress_store:
                        progress_store[sid]["status"] = "cancelled"
                        progress_store[sid]["progress"] = 0
            
            if cancelled_count > 0:
                return {"success": True, "message": f"Cancelled {cancelled_count} scan(s) for {domain}"}
        
        if scan_id and scan_id in active_scans:
            scan_cancelled[scan_id] = True
            if scan_id in progress_store:
                progress_store[scan_id]["status"] = "cancelled"
                progress_store[scan_id]["progress"] = 0
            print(f"[*] Cancelled scan {scan_id}")
            return {"success": True, "message": f"Stop signal sent for scan {scan_id}"}
        
        return {"success": True, "message": "Stop signal received"}
        
    except Exception as e:
        print(f"[!] Error stopping scan: {e}")
        return {"success": True, "message": f"Stop signal received (error: {str(e)})"}


# ============================================================
# GET SCAN STATUS
# ============================================================

@app.get("/analyze/status/{scan_id}")
async def get_scan_status(scan_id: str):
    """
    Get current status of a scan.
    """
    if scan_id in active_scans:
        return active_scans[scan_id]
    raise HTTPException(status_code=404, detail="Scan not found")


# ============================================================
# DOWNLOAD COMPLETE SUBDOMAIN PDF
# ============================================================

@app.get("/subdomains/pdf")
def download_subdomains_pdf(
    domain: str
):
    """
    Download the COMPLETE subdomain list
    for the specified domain as a PDF.
    """

    # --------------------------------------------------------
    # VALIDATE DOMAIN
    # --------------------------------------------------------

    domain = (
        domain
        .strip()
        .lower()
        .rstrip(".")
    )

    if not domain:

        raise HTTPException(
            status_code=400,
            detail="Domain cannot be empty."
        )

    # --------------------------------------------------------
    # CHECK NEO4J PASSWORD
    # --------------------------------------------------------

    if not NEO4J_PASSWORD:

        raise HTTPException(
            status_code=500,
            detail=(
                "Neo4j password is not configured "
                "in the environment."
            )
        )

    try:

        print(
            f"[*] Generating complete "
            f"subdomain PDF for: {domain}"
        )

        # ----------------------------------------------------
        # GET COMPLETE LIST
        # ----------------------------------------------------

        subdomains = get_all_subdomains(
            domain,
            NEO4J_PASSWORD
        )

        if not subdomains:

            raise HTTPException(
                status_code=404,
                detail=(
                    f"No subdomains found for "
                    f"'{domain}'."
                )
            )

        print(
            f"[+] Found {len(subdomains):,} "
            "subdomains for PDF export."
        )

        # ----------------------------------------------------
        # GENERATE PDF
        # ----------------------------------------------------

        pdf_buffer = create_subdomain_pdf(
            domain,
            subdomains
        )

        filename = (
            f"{domain}-subdomains.pdf"
        )

        # ----------------------------------------------------
        # RETURN FILE
        # ----------------------------------------------------

        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={
                "Content-Disposition":
                    f'attachment; filename="{filename}"'
            }
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
                "Failed to generate subdomain PDF: "
                f"{str(error)}"
            )
        )


# ============================================================
# DOMAIN ANALYSIS
# ============================================================

@app.post("/analyze")
def analyze_domain(
    request: AnalyzeRequest
):

    # ========================================================
    # VALIDATE DOMAIN
    # ========================================================

    domain = (
        request.domain
        .strip()
        .lower()
        .rstrip(".")
    )

    if not domain:

        raise HTTPException(
            status_code=400,
            detail="Domain cannot be empty."
        )

    # ========================================================
    # CHECK NEO4J PASSWORD
    # ========================================================

    if not NEO4J_PASSWORD:

        raise HTTPException(
            status_code=500,
            detail=(
                "Neo4j password is not configured "
                "in the environment."
            )
        )

    try:

        # ====================================================
        # GENERATE SCAN ID
        # ====================================================

        scan_id = f"{domain}_{datetime.now().timestamp()}"
        active_scans[scan_id] = {
            "domain": domain,
            "status": "running",
            "progress": 0,
            "started_at": datetime.now().isoformat()
        }
        scan_cancelled[scan_id] = False
        
        # IMPORTANT: Initialize progress_store for this scan
        progress_store[scan_id] = {
            "domain": domain,
            "progress": 0,
            "status": "running",
            "steps": {}
        }
        print(f"[DEBUG] Initialized progress_store for scan_id: {scan_id}")

        # ====================================================
        # RUN OSINT PIPELINE
        # ====================================================

        print("\n" + "=" * 60)

        print(
            f"[*] Starting analysis for: {domain}"
        )
        print(f"[*] Scan ID: {scan_id}")

        print("=" * 60)

        # Define progress callback
        def progress_callback(update):
            print(f"[DEBUG] progress_callback called: {update.get('step')} - {update.get('progress')}%")
            
            # Check if cancelled
            if scan_cancelled.get(scan_id, False):
                print(f"[DEBUG] Scan {scan_id} cancelled, ignoring update")
                return
            
            # Update progress tracking
            progress_value = update.get("progress", 0)
            active_scans[scan_id]["progress"] = progress_value
            
            # Update progress store
            if scan_id in progress_store:
                progress_store[scan_id]["progress"] = progress_value
                progress_store[scan_id]["status"] = update.get("status", "running")
                step = update.get("step")
                if step:
                    progress_store[scan_id]["steps"][step] = update
                print(f"[DEBUG] Updated progress_store[{scan_id}] to {progress_value}%")
            else:
                # Fallback: initialize it if missing
                print(f"[DEBUG] WARNING: scan_id {scan_id} not in progress_store! Initializing...")
                progress_store[scan_id] = {
                    "domain": domain,
                    "progress": progress_value,
                    "status": "running",
                    "steps": {}
                }
                if update.get("step"):
                    progress_store[scan_id]["steps"][update.get("step")] = update
            
            publish_progress(update)

        # Check if cancelled before starting
        if scan_cancelled.get(scan_id, False):
            active_scans[scan_id]["status"] = "cancelled"
            if scan_id in progress_store:
                progress_store[scan_id]["status"] = "cancelled"
            publish_progress({
                "step": "cancelled",
                "progress": 0,
                "status": "cancelled",
                "message": "Scan cancelled by user"
            })
            return {"success": False, "message": "Scan cancelled"}

        result = run_osint_pipeline(
            domain,
            NEO4J_PASSWORD,
            progress_callback=progress_callback,
            scan_id=scan_id,
            is_cancelled=lambda: scan_cancelled.get(scan_id, False)
        )

        # Check if cancelled during pipeline
        if scan_cancelled.get(scan_id, False):
            active_scans[scan_id]["status"] = "cancelled"
            if scan_id in progress_store:
                progress_store[scan_id]["status"] = "cancelled"
            publish_progress({
                "step": "cancelled",
                "progress": 0,
                "status": "cancelled",
                "message": "Scan cancelled by user"
            })
            return {"success": False, "message": "Scan cancelled"}

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
            {}
        )

        subdomains = infrastructure.get(
            "subdomains",
            []
        )

        ip_addresses = infrastructure.get(
            "ip_addresses",
            []
        )

        asns = infrastructure.get(
            "asns",
            []
        )

        organizations = infrastructure.get(
            "organizations",
            []
        )

        certificates = infrastructure.get(
            "certificates",
            []
        )

        # ====================================================
        # EXTRACT GRAPH FOR DASHBOARD
        # ====================================================

        print(
            "[*] Extracting graph "
            "for dashboard..."
        )

        graph = get_graph_data(
            domain,
            NEO4J_PASSWORD
        )

        # ====================================================
        # EXTRACT PROVENANCE
        # ====================================================

        print(
            "[*] Extracting provenance data..."
        )

        normalized_data = result.get(
            "normalized_data",
            {}
        )

        # Collect provenance from entities
        entity_provenance = []

        for entity in normalized_data.get(
            "entities",
            []
        ):

            entity_type = entity.get(
                "type",
                "Entity"
            )

            entity_value = entity.get(
                "value",
                ""
            )

            for provenance in entity.get(
                "provenance",
                []
            ):

                entity_provenance.append({

                    "entity_type":
                        entity_type,

                    "entity_value":
                        entity_value,

                    "source": provenance.get(
                        "source",
                        "Unknown"
                    ),

                    "method": provenance.get(
                        "method",
                        "Unknown"
                    ),

                    "recorded_at": provenance.get(
                        "recorded_at",
                        ""
                    )
                })

        # Collect provenance from relationships
        relationship_provenance = []

        for relationship in normalized_data.get(
            "relationships",
            []
        ):

            from_entity = relationship.get(
                "from",
                {}
            )

            to_entity = relationship.get(
                "to",
                {}
            )

            relationship_type = relationship.get(
                "relationship",
                "RELATED_TO"
            )

            for provenance in relationship.get(
                "provenance",
                []
            ):

                relationship_provenance.append({

                    "entity_type":
                        "Relationship",

                    "entity_value": (
                        f"{from_entity.get('value', '')} "
                        f"{relationship_type} "
                        f"{to_entity.get('value', '')}"
                    ),

                    "source": provenance.get(
                        "source",
                        "Unknown"
                    ),

                    "method": provenance.get(
                        "method",
                        "Unknown"
                    ),

                    "recorded_at": provenance.get(
                        "recorded_at",
                        ""
                    )
                })

        # Combine all provenance
        all_provenance = (
            entity_provenance
            + relationship_provenance
        )

        print(
            f"[+] Extracted {len(all_provenance)} "
            "provenance records."
        )

        # Update scan status
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["progress"] = 100
        if scan_id in progress_store:
            progress_store[scan_id]["status"] = "completed"
            progress_store[scan_id]["progress"] = 100

        # ====================================================
        # RESPONSE
        # ====================================================

        response = {

            "success": True,
            "scan_id": scan_id,

            "domain": result.get(
                "domain",
                domain
            ),

            "statistics": analysis.get(
                "statistics",
                {}
            ),

            "relationships": analysis.get(
                "relationships",
                {}
            ),

            "ip_version_summary": analysis.get(
                "ip_version_summary",
                {}
            ),

            "subdomain_patterns": analysis.get(
                "subdomain_patterns",
                {}
            ),

            "infrastructure": {

                "subdomains": subdomains,

                "subdomain_count": len(
                    subdomains
                ),

                "ip_addresses":
                    ip_addresses,

                "asns":
                    asns,

                "organizations":
                    organizations,

                "certificates":
                    certificates
            },

            "provenance": all_provenance,

            "observations": analysis.get(
                "observations",
                []
            ),

            "virustotal": analysis.get(
                "virustotal",
                {}
            ),

            "ai_report": result.get(
                "ai_report",
                ""
            ),

            "graph": graph
        }

        print("=" * 60)

        print(
            "[+] Domain analysis complete."
        )

        print("=" * 60)

        # Cleanup
        scan_cancelled.pop(scan_id, None)

        return response

    # ========================================================
    # VALIDATION ERROR
    # ========================================================

    except ValueError as error:

        print(
            f"[!] Validation error: {error}"
        )

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    # ========================================================
    # GENERAL ERROR
    # ========================================================

    except Exception as error:

        print(
            f"[!] Pipeline execution failed: "
            f"{error}"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Pipeline execution failed: "
                f"{str(error)}"
            )
        )