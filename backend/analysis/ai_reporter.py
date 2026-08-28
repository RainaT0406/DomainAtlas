import ollama

from backend.analysis.graph_analyzer import get_domain_analysis


# ============================================================
# AI-ASSISTED INTELLIGENCE REPORTER
# ============================================================

def generate_ai_report(analysis):
    """
    Generate an AI-assisted intelligence report from
    graph-derived OSINT analysis.

    The LLM acts only as a reporting and interpretation layer.

    The LLM must:
        - use only supplied graph-analysis data
        - preserve graph relationship direction
        - avoid unsupported conclusions
        - attribute VirusTotal information correctly
        - avoid ownership/security/maliciousness claims
    """

    # ========================================================
    # VALIDATE INPUT
    # ========================================================

    if not isinstance(analysis, dict):
        raise ValueError(
            "Analysis data must be provided as a dictionary."
        )

    required_fields = [
        "domain",
        "statistics",
        "infrastructure"
    ]

    for field in required_fields:
        if field not in analysis:
            raise ValueError(
                f"Required analysis field missing: {field}"
            )

    # ========================================================
    # EXTRACT GRAPH ANALYSIS DATA
    # ========================================================

    domain = analysis["domain"]

    statistics = analysis.get(
        "statistics",
        {}
    )

    relationships = analysis.get(
        "relationships",
        {}
    )

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

    observations = analysis.get(
        "observations",
        []
    )

    # ========================================================
    # IP VERSION INFORMATION
    # ========================================================

    ip_version_summary = analysis.get(
        "ip_version_summary",
        {}
    )

    ipv4_count = ip_version_summary.get(
        "ipv4",
        0
    )

    ipv6_count = ip_version_summary.get(
        "ipv6",
        0
    )

    unknown_ip_count = ip_version_summary.get(
        "unknown",
        0
    )

    # ========================================================
    # VIRUSTOTAL INTELLIGENCE
    # ========================================================

    virustotal = analysis.get(
        "virustotal",
        {}
    )

    if not isinstance(virustotal, dict):
        virustotal = {}

    # ========================================================
    # PREPARE VIRUSTOTAL DATA
    # ========================================================

    if virustotal:

        virustotal_text = f"""
Source:
{virustotal.get("source", "Not available")}

Method:
{virustotal.get("method", "Not available")}

Recorded At:
{virustotal.get("recorded_at", "Not available")}

Reputation:
{virustotal.get("reputation", "Not available")}

Malicious detections:
{virustotal.get("malicious", "Not available")}

Suspicious detections:
{virustotal.get("suspicious", "Not available")}

Harmless detections:
{virustotal.get("harmless", "Not available")}

Undetected results:
{virustotal.get("undetected", "Not available")}

Timeout results:
{virustotal.get("timeout", "Not available")}

Registrar:
{virustotal.get("registrar", "Not available")}

Creation Date:
{virustotal.get("creation_date", "Not available")}

Last Modification Date:
{virustotal.get(
    "last_modification_date",
    "Not available"
)}

Categories:
{virustotal.get("categories", {})}

Popularity Ranks:
{virustotal.get("popularity_ranks", {})}

DNS Records:
{virustotal.get("dns_records", {})}
"""

    else:

        virustotal_text = (
            "No VirusTotal intelligence was available."
        )

    # ========================================================
    # FORMAT LISTS SAFELY
    # ========================================================

    def format_list(values):

        if not values:
            return "None observed."

        return "\n".join(
            f"- {str(value)}"
            for value in values
        )

    # ========================================================
    # FORMAT OBSERVATIONS
    # ========================================================

    if observations:

        observations_text = "\n".join(
            f"- {str(observation)}"
            for observation in observations
        )

    else:

        observations_text = (
            "No graph-derived observations were generated."
        )

    # ========================================================
    # FORMAT RELATIONSHIPS
    # ========================================================

    if relationships:

        relationships_text = "\n".join(
            f"- {key}: {value}"
            for key, value in relationships.items()
        )

    else:

        relationships_text = (
            "No relationship counts were available."
        )

    # ========================================================
    # SYSTEM INSTRUCTIONS
    # ========================================================

    system_prompt = """
You are a strict OSINT intelligence reporting assistant.

You are NOT an investigator, threat classifier, ownership
attribution engine, or external research agent.

You are ONLY a reporting layer.

Your output must contain observations that are directly
supported by the supplied data.

CRITICAL RULE:

NEVER add an interpretation merely because it sounds reasonable.

If a statement is not directly supported by the supplied data,
DO NOT write it.

NEVER use unsupported cybersecurity terminology such as:

- robust
- secure
- trusted
- trustworthy
- legitimate
- suspicious
- malicious
- benign
- compromised
- dangerous
- safe
- reliable
- resilient
- vulnerable
- high-risk
- low-risk

unless the supplied data explicitly supports that exact
conclusion.

In particular:

A large number of IP addresses does NOT mean infrastructure
is robust.

A certificate does NOT mean a domain is secure or legitimate.

An organization associated with an IP address does NOT prove
domain ownership.

A VirusTotal reputation score does NOT establish whether a
domain is malicious or benign.

VirusTotal detection counts MUST always be attributed to
VirusTotal.

Preserve graph relationship direction.

For example:

Domain
    |
    | RESOLVES_TO
    v
IPAddress
    |
    | BELONGS_TO_ASN
    v
ASN

This must be described as:

"The domain resolves to observed IP addresses, and those
IP addresses map to the observed ASN."

NEVER simplify this into:

"The domain belongs to ASN X."

Likewise:

Domain
    |
    | RESOLVES_TO
    v
IPAddress
    |
    | ASSOCIATED_WITH
    v
Organization

must be described as an organization associated with the
observed IP infrastructure.

It must NOT be described as domain ownership.

Do not invent facts, entities, relationships, IP addresses,
subdomains, organizations, certificates, or conclusions.

Do not perform external lookups.

Do not use external knowledge.

Do not create additional sections.

Do not rename the required sections.

Return only the requested report.
"""

    # ========================================================
    # BUILD USER PROMPT
    # ========================================================

    prompt = f"""
Generate an OSINT intelligence report using ONLY the data
provided below.

============================================================
DOMAIN
============================================================

{domain}

============================================================
GRAPH STATISTICS
============================================================

Observed subdomains:
{statistics.get("subdomains", 0)}

Observed IP addresses:
{statistics.get("ip_addresses", 0)}

Observed ASNs:
{statistics.get("asns", 0)}

Observed organizations:
{statistics.get("organizations", 0)}

Observed certificates:
{statistics.get("certificates", 0)}

============================================================
IP VERSION DISTRIBUTION
============================================================

IPv4:
{ipv4_count}

IPv6:
{ipv6_count}

Unknown:
{unknown_ip_count}

============================================================
GRAPH RELATIONSHIP COUNTS
============================================================

{relationships_text}

============================================================
GRAPH-DERIVED OBSERVATIONS
============================================================

{observations_text}

============================================================
OBSERVED IP ADDRESSES
============================================================

{format_list(ip_addresses)}

============================================================
OBSERVED ASNs
============================================================

{format_list(asns)}

============================================================
OBSERVED ORGANIZATIONS
============================================================

{format_list(organizations)}

============================================================
OBSERVED CERTIFICATES
============================================================

{format_list(certificates)}

============================================================
OBSERVED SUBDOMAINS
============================================================

Only the first 20 observed subdomains are supplied.

Do not reproduce the complete subdomain list.

{format_list(subdomains[:20])}

============================================================
VIRUSTOTAL INTELLIGENCE
============================================================

{virustotal_text}

============================================================
REPORT FORMAT
============================================================

Produce EXACTLY these six sections.

1. Domain Infrastructure

Describe:
- observed domain
- observed subdomain count
- observed IP address count
- IPv4/IPv6 distribution
- directly supported infrastructure observations

If ASN or organization information is mentioned, describe it
through the observed IP infrastructure.

Do NOT imply a direct Domain -> ASN relationship.

Do NOT imply a direct Domain -> Organization relationship.

------------------------------------------------------------

2. Network Relationships

Describe the observed graph relationships involving:

Domain
IP addresses
ASNs

Preserve relationship direction.

Example:

"The domain resolves to observed IP addresses, and those
IP addresses map to the observed ASN."

Do NOT write:

"The domain belongs to ASN X."

------------------------------------------------------------

3. Organizational Associations

Describe organizations associated with the observed IP
infrastructure.

Explicitly state that IP-organization association does not
establish domain ownership.

------------------------------------------------------------

4. Certificate Observations

Describe:
- number of observed certificates
- certificate identifiers where useful
- their observed relationship with the domain

Do NOT infer:
- security
- trust
- legitimacy
- ownership
- validity

from certificate presence alone.

------------------------------------------------------------

5. Notable Patterns

Describe only patterns explicitly supported by the data.

These may include:
- numeric-leading subdomains
- hyphenated subdomains
- multi-level subdomains
- common prefixes
- IPv4/IPv6 distribution
- ASN concentration
- organization count
- certificate count
- VirusTotal detection counts
- VirusTotal reputation
- registrar information

VirusTotal information MUST explicitly be attributed to
VirusTotal.

Do NOT interpret VirusTotal values as an independent
determination of maliciousness or benignness.

------------------------------------------------------------

6. Key Takeaways

Provide 3-5 concise points containing only directly observed
facts.

Do not introduce new information.

============================================================
LIMITATION
============================================================

After the six sections, provide ONE short limitation statement.

Do not create a heading for it.

State that the report reflects only the collected OSINT data
and does not independently establish:

- domain ownership
- maliciousness
- benignness
- compromise
- security posture

============================================================
FINAL RULE
============================================================

Return ONLY the report.

Exactly six section headings.

No additional headings.

No unsupported conclusions.

No external information.

No complete subdomain list.

No ownership claims.

No maliciousness claims.

No benignness claims.

No compromise claims.

No security-posture claims.

Do NOT describe the infrastructure as robust.

Do NOT describe the infrastructure as secure.

Do NOT describe the infrastructure as trusted.

Do NOT describe the infrastructure as suspicious.

Do NOT describe the infrastructure as malicious.

Do NOT describe the infrastructure as benign.
"""

    # ========================================================
    # CALL LOCAL OLLAMA MODEL
    # ========================================================

    response = ollama.chat(
        model="llama3.2:3b",
        messages=[
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        options={
            "temperature": 0
        }
    )

    # ========================================================
    # EXTRACT RESPONSE
    # ========================================================

    report = response.get(
        "message",
        {}
    ).get(
        "content",
        ""
    )

    if not report:
        raise RuntimeError(
            "Ollama returned an empty report."
        )

    report = report.strip()

    # ========================================================
    # POST-GENERATION VALIDATION
    # ========================================================

    # These terms should never appear unless explicitly
    # supported by a future controlled validation layer.
    forbidden_phrases = [
        "robust",
        "secure",
        "trusted",
        "trustworthy",
        "legitimate",
        "compromised",
        "dangerous",
        "safe",
        "resilient",
        "vulnerable",
        "high-risk",
        "low-risk"
    ]

    report_lower = report.lower()

    detected_forbidden = [
        phrase
        for phrase in forbidden_phrases
        if phrase in report_lower
    ]

    if detected_forbidden:
        raise RuntimeError(
            "AI report contained unsupported terminology: "
            + ", ".join(detected_forbidden)
        )

    # ========================================================
    # VALIDATE REQUIRED HEADINGS
    # ========================================================

    required_headings = [
        "Domain Infrastructure",
        "Network Relationships",
        "Organizational Associations",
        "Certificate Observations",
        "Notable Patterns",
        "Key Takeaways"
    ]

    missing_headings = [
        heading
        for heading in required_headings
        if heading.lower() not in report.lower()
    ]

    if missing_headings:
        raise RuntimeError(
            "AI report is missing required sections: "
            + ", ".join(missing_headings)
        )

    return report


# ================================================================
# COMMAND-LINE EXECUTION
# ================================================================

if __name__ == "__main__":

    domain = input(
        "Enter domain: "
    ).strip()

    password = input(
        "Enter Neo4j password: "
    )

    print(
        "\n[*] Analyzing graph..."
    )

    try:

        # --------------------------------------------------------
        # GET GRAPH ANALYSIS
        # --------------------------------------------------------

        analysis = get_domain_analysis(
            domain,
            password
        )

        if analysis is None:

            print(
                f"[!] Domain not found in Neo4j: {domain}"
            )

        else:

            print(
                "[+] Graph analysis complete."
            )

            print(
                "\n[*] Generating AI-assisted analysis...\n"
            )

            # ----------------------------------------------------
            # GENERATE REPORT
            # ----------------------------------------------------

            report = generate_ai_report(
                analysis
            )

            print(
                "[+] AI analysis complete.\n"
            )

            print(
                "=" * 70
            )

            print(
                "AI-ASSISTED INTELLIGENCE REPORT"
            )

            print(
                "=" * 70
            )

            print(report)

            print(
                "=" * 70
            )

    except Exception as error:

        print(
            f"[!] AI analysis error: {error}"
        )