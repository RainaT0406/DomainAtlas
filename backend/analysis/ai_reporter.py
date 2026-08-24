import ollama

from backend.analysis.graph_analyzer import get_domain_analysis


def generate_ai_report(analysis):
    """
    Generate an AI-assisted intelligence report from
    graph-derived OSINT observations.

    The LLM is used only to summarize and interpret
    information already derived from the Neo4j graph.
    """

    subdomains = analysis["infrastructure"]["subdomains"]
    ip_addresses = analysis["infrastructure"]["ip_addresses"]
    asns = analysis["infrastructure"]["asns"]
    organizations = analysis["infrastructure"]["organizations"]
    certificates = analysis["infrastructure"]["certificates"]
    observations = analysis.get("observations", [])

    prompt = f"""
You are an OSINT intelligence reporting assistant.

Your role is to transform structured graph-analysis results
into a concise analyst-readable report.

IMPORTANT:

The supplied information comes from a Neo4j graph generated
from publicly collected OSINT data.

You MUST use ONLY the information provided below.

Do NOT invent facts.
Do NOT introduce external knowledge.
Do NOT make unsupported cybersecurity conclusions.

============================================================
GRAPH ANALYSIS DATA
============================================================

Domain:

{analysis["domain"]}

Statistics:

- Observed subdomains: {analysis["statistics"]["subdomains"]}
- Observed IP addresses: {analysis["statistics"]["ip_addresses"]}
- Observed ASNs: {analysis["statistics"]["asns"]}
- Observed organizations: {analysis["statistics"]["organizations"]}
- Observed certificates: {analysis["statistics"]["certificates"]}

Graph-derived observations:

{chr(10).join("- " + x for x in observations)}

IP addresses:

{chr(10).join("- " + x for x in ip_addresses)}

ASNs:

{chr(10).join("- " + x for x in asns)}

Organizations:

{chr(10).join("- " + x for x in organizations)}

Certificates:

{chr(10).join("- " + x for x in certificates)}

First 20 observed subdomains:

{chr(10).join("- " + x for x in subdomains[:20])}

============================================================
REPORTING RULES
============================================================

1. Report observations that are directly supported by the
   supplied graph data.

2. You may provide limited interpretation of those observations,
   but clearly distinguish interpretation from fact.

3. Do NOT determine whether the domain is malicious or benign.

4. Do NOT make claims about threat level, intent, reputation,
   compromise, or suspiciousness.

5. Do NOT claim that an organization owns the domain merely
   because an observed IP address is associated with that
   organization.

6. Do NOT claim that certificates prove that a domain is secure,
   trusted, or legitimate.

7. Do NOT claim that a large number of subdomains is evidence
   of malicious activity.

8. Do NOT describe the infrastructure as "robust", "secure",
   "trusted", "malicious", or "suspicious" unless the supplied
   graph data explicitly supports such a statement.

9. Do NOT infer information that is absent from the graph.

10. If the available information is insufficient to determine
    something, explicitly state that it cannot be determined
    from the collected data.

11. Do not reproduce the complete subdomain list.
    Only discuss the supplied subdomain statistics and examples.

12. Keep the report concise and technically precise.

13. Do not introduce new section headings.

14. Do not rename the required section headings.

============================================================
REQUIRED REPORT FORMAT
============================================================

Produce EXACTLY these six sections and use EXACTLY these
section headings:

1. Domain Infrastructure

Describe the observed domain, subdomain count, IP addresses,
and IP version distribution if available.

If mentioning ASN or organization information, describe it
through the observed IP infrastructure. Do not imply a direct
Domain -> ASN or Domain -> Organization relationship unless
such a relationship explicitly exists in the graph.

2. Network Relationships

Describe the observed relationships between the domain,
IP addresses, and ASNs.

The graph relationships are directional and must not be
represented as direct relationships when they are actually
multi-hop relationships.

For example:

Domain -> RESOLVES_TO -> IPAddress
IPAddress -> BELONGS_TO_ASN -> ASN

Therefore, describe this as:

"The domain resolves to observed IP addresses, and those
IP addresses map to the observed ASN."

Do NOT state that the domain is directly associated with
the ASN unless a direct Domain -> ASN relationship is
explicitly present in the supplied graph data.

Report only relationships explicitly represented in the
supplied graph-derived data.

3. Organizational Associations

Describe organizations associated with the observed IP
infrastructure.

IMPORTANT:

Association with an IP address does not establish domain
ownership.

4. Certificate Observations

Describe the number and identifiers of certificates associated
with the domain through the observed graph relationships.

Do not infer security, validity, trustworthiness, or ownership
from certificate presence or certificate count alone.

5. Notable Patterns

Describe only patterns explicitly identified by the graph
analysis.

Examples include:

- Numeric-leading subdomains
- Hyphenated subdomains
- Multi-level subdomains
- Common subdomain prefixes
- IPv4 and IPv6 distribution
- ASN concentration
- Organization count
- Certificate count

Do not infer maliciousness, benignness, ownership, intent,
reputation, or security characteristics from these patterns.

6. Key Takeaways

Provide 3-5 concise points summarizing the most important
directly observed facts from the previous sections.

Do not introduce new information or unsupported conclusions.

After the six sections, provide a short limitation statement
explaining that the report reflects only the collected OSINT
data and does not establish ownership, maliciousness,
benignness, or security posture.

============================================================

FINAL OUTPUT REQUIREMENTS
============================================================

- Use exactly the six section headings specified above.
- Do not add additional sections.
- Do not rename any section.
- Do not include information that is not present in the
  supplied graph-analysis data.
- Clearly distinguish observations from interpretation.
- If something cannot be determined from the supplied data,
  say so explicitly.
- Return ONLY the report.
"""

    response = ollama.chat(
        model="llama3.2:3b",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response["message"]["content"]


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    domain = input("Enter domain: ").strip()

    password = input("Enter Neo4j password: ")

    print("\n[*] Generating AI-assisted analysis...\n")

    try:

        analysis = get_domain_analysis(
            domain,
            password
        )

        if analysis is None:

            print(
                f"[!] Domain not found in Neo4j: {domain}"
            )

        else:

            print("[+] Graph analysis complete.")

            print(
                "\n[*] Generating AI-assisted analysis...\n"
            )

            report = generate_ai_report(
                analysis
            )

            print(
                "[+] AI analysis complete.\n"
            )

            print("=" * 60)

            print(
                "AI-ASSISTED INTELLIGENCE SUMMARY"
            )

            print("=" * 60)

            print(report)

            print("=" * 60)

    except Exception as error:

        print(
            f"[!] AI analysis error: {error}"
        )