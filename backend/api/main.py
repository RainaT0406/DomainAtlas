import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

from backend.services.pipeline_service import run_osint_pipeline


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

load_dotenv()

NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="Domain-Centric OSINT API",
    description="API for the Domain-Centric OSINT analysis pipeline",
    version="1.0.0"
)


# ============================================================
# REQUEST MODEL
# ============================================================

class AnalyzeRequest(BaseModel):
    domain: str


# ============================================================
# ROOT ENDPOINT
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
# DOMAIN ANALYSIS ENDPOINT
# ============================================================

@app.post("/analyze")
def analyze_domain(request: AnalyzeRequest):

    domain = request.domain.strip()

    if not domain:
        raise HTTPException(
            status_code=400,
            detail="Domain cannot be empty."
        )

    if not NEO4J_PASSWORD:
        raise HTTPException(
            status_code=500,
            detail="Neo4j password is not configured."
        )

    try:

        result = run_osint_pipeline(
            domain,
            NEO4J_PASSWORD
        )

        analysis = result["graph_analysis"]

        return {
            "success": True,

            "domain": result["domain"],

            "statistics": analysis["statistics"],

            "relationships": analysis["relationships"],

            "ip_version_summary": analysis["ip_version_summary"],

            "subdomain_patterns": analysis["subdomain_patterns"],

            "infrastructure": {
                "ip_addresses": analysis["infrastructure"]["ip_addresses"],
                "asns": analysis["infrastructure"]["asns"],
                "organizations": analysis["infrastructure"]["organizations"],
                "certificates": analysis["infrastructure"]["certificates"],
                "subdomain_count": len(
                    analysis["infrastructure"]["subdomains"]
                )
            },

            "observations": analysis["observations"],

            "ai_report": result["ai_report"]
        }

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Pipeline execution failed: {str(error)}"
        )