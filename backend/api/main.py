import io
import os

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
        - Up to 150 Subdomains

    IMPORTANT:
    The 150-subdomain limit applies ONLY to visualization.
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
            # ADD UP TO 150 SUBDOMAINS
            # =================================================

            subdomain_query = """
            MATCH
                (d:Domain {value: $domain})
                -[:HAS_SUBDOMAIN]->
                (s:Subdomain)

            RETURN
                elementId(s) AS id,
                s.value AS value

            LIMIT 150
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
        # RUN OSINT PIPELINE
        # ====================================================

        print("\n" + "=" * 60)

        print(
            f"[*] Starting analysis for: {domain}"
        )

        print("=" * 60)

        result = run_osint_pipeline(
            domain,
            NEO4J_PASSWORD
        )

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
        # RESPONSE
        # ====================================================

        response = {

            "success": True,

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