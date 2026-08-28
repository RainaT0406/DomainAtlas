import { useRef, useState } from "react";

import {
  Activity,
  BarChart3,
  Database,
  Globe,
  Network,
  Server,
  FileKey,
  Brain,
  Search,
  ChevronRight,
  Download,
  Radar,
  Fingerprint,
  Layers3,
  CircleDot,
  Shield,
} from "lucide-react";

import jsPDF from "jspdf";
import GraphView from "./GraphView";
import "./App.css";

function App() {
  // ============================================================
  // STATE
  // ============================================================

  const [domain, setDomain] = useState("");
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // ============================================================
  // SECTION REFERENCES
  // ============================================================

  const dashboardRef = useRef(null);
  const infrastructureRef = useRef(null);
  const graphRef = useRef(null);
  const subdomainsRef = useRef(null);
  const certificatesRef = useRef(null);
  const aiReportRef = useRef(null);

  // ============================================================
  // SCROLL NAVIGATION
  // ============================================================

  const scrollToSection = (ref) => {
    if (!ref.current) return;

    ref.current.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  };

  // ============================================================
  // ANALYZE DOMAIN
  // ============================================================

  const analyzeDomain = async () => {
    const targetDomain = domain
      .trim()
      .toLowerCase()
      .replace(/\.$/, "");

    if (!targetDomain) {
      setError("Please enter a domain.");
      return;
    }

    setLoading(true);
    setError("");
    setAnalysis(null);

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/analyze",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify({
            domain: targetDomain,
          }),
        }
      );

      let data;

      try {
        data = await response.json();
      } catch {
        throw new Error(
          "The API returned an invalid response."
        );
      }

      if (!response.ok) {
        throw new Error(
          data?.detail || "Domain analysis failed."
        );
      }

      if (!data?.success) {
        throw new Error(
          "Domain analysis was not successful."
        );
      }

      setAnalysis(data);
    } catch (err) {
      console.error("Domain analysis error:", err);

      setError(
        err?.message ||
          "Unable to connect to the DomainAtlas API."
      );
    } finally {
      setLoading(false);
    }
  };

  // ============================================================
  // ENTER KEY
  // ============================================================

  const handleKeyDown = (event) => {
    if (event.key === "Enter" && !loading) {
      analyzeDomain();
    }
  };

  // ============================================================
  // SAFE DATA EXTRACTION
  // ============================================================

  const statistics = analysis?.statistics || {};

  const infrastructure =
    analysis?.infrastructure || {};

  const ipVersion =
    analysis?.ip_version_summary || {};

  const patterns =
    analysis?.subdomain_patterns || {};

  const observations = Array.isArray(
    analysis?.observations
  )
    ? analysis.observations
    : [];

  const aiReport =
    typeof analysis?.ai_report === "string"
      ? analysis.ai_report
      : "";

  const graph = analysis?.graph || {
    nodes: [],
    edges: [],
  };

  const subdomains = Array.isArray(
    infrastructure?.subdomains
  )
    ? infrastructure.subdomains
    : [];

  const certificates = Array.isArray(
    infrastructure?.certificates
  )
    ? infrastructure.certificates
    : [];

  const ipAddresses = Array.isArray(
    infrastructure?.ip_addresses
  )
    ? infrastructure.ip_addresses
    : [];

  const asns = Array.isArray(
    infrastructure?.asns
  )
    ? infrastructure.asns
    : [];

  const organizations = Array.isArray(
    infrastructure?.organizations
  )
    ? infrastructure.organizations
    : [];

  // ============================================================
  // OBSERVATION HELPER
  // ============================================================

  const getObservation = (keyword) => {
    return observations.find(
      (observation) =>
        typeof observation === "string" &&
        observation
          .toLowerCase()
          .includes(keyword.toLowerCase())
    );
  };

  // ============================================================
  // EXTRACT VIRUSTOTAL COUNT
  // ============================================================

  const getDetectionCount = (keyword) => {
    const observation = getObservation(keyword);

    if (!observation) return "0";

    const match = observation.match(/\d+/);

    return match?.[0] || "0";
  };

  // ============================================================
  // DOWNLOAD SUBDOMAIN PDF
  // ============================================================

  const downloadSubdomainsPDF = () => {
    if (subdomains.length === 0) return;

    const pdf = new jsPDF({
      orientation: "portrait",
      unit: "mm",
      format: "a4",
    });

    const pageWidth =
      pdf.internal.pageSize.getWidth();

    const pageHeight =
      pdf.internal.pageSize.getHeight();

    const margin = 15;
    const lineHeight = 6;

    let y = 20;

    // ----------------------------------------------------------
    // TITLE
    // ----------------------------------------------------------

    pdf.setFontSize(18);
    pdf.setFont("helvetica", "bold");

    pdf.text(
      "DomainAtlas — Subdomain Inventory",
      margin,
      y
    );

    y += 9;

    // ----------------------------------------------------------
    // METADATA
    // ----------------------------------------------------------

    pdf.setFontSize(11);
    pdf.setFont("helvetica", "normal");

    pdf.text(
      `Target Domain: ${analysis?.domain || domain}`,
      margin,
      y
    );

    y += 6;

    pdf.text(
      `Total Subdomains: ${subdomains.length}`,
      margin,
      y
    );

    y += 6;

    pdf.text(
      `Generated: ${new Date().toLocaleString()}`,
      margin,
      y
    );

    y += 10;

    // ----------------------------------------------------------
    // TABLE HEADER
    // ----------------------------------------------------------

    const numberX = margin;
    const subdomainX = margin + 15;

    pdf.setFontSize(9);
    pdf.setFont("helvetica", "bold");

    pdf.text("#", numberX, y);
    pdf.text("Subdomain", subdomainX, y);

    y += 3;

    pdf.line(
      margin,
      y,
      pageWidth - margin,
      y
    );

    y += 6;

    // ----------------------------------------------------------
    // TABLE CONTENT
    // ----------------------------------------------------------

    pdf.setFont("helvetica", "normal");
    pdf.setFontSize(9);

    subdomains.forEach((subdomain, index) => {
      if (y + lineHeight > pageHeight - margin) {
        pdf.addPage();

        y = 20;

        pdf.setFont(
          "helvetica",
          "bold"
        );

        pdf.text(
          "DomainAtlas — Subdomain Inventory",
          margin,
          y
        );

        y += 8;

        pdf.setFont(
          "helvetica",
          "normal"
        );

        pdf.setFontSize(9);
      }

      const value = String(
        subdomain ?? ""
      );

      pdf.text(
        String(index + 1),
        numberX,
        y
      );

      const maxWidth =
        pageWidth -
        subdomainX -
        margin;

      const lines =
        pdf.splitTextToSize(
          value,
          maxWidth
        );

      pdf.text(
        lines,
        subdomainX,
        y
      );

      y +=
        lineHeight *
        Math.max(1, lines.length);

      pdf.setDrawColor(220);

      pdf.line(
        margin,
        y - 2,
        pageWidth - margin,
        y - 2
      );

      pdf.setDrawColor(0);

      y += 2;
    });

    // ----------------------------------------------------------
    // PAGE FOOTERS
    // ----------------------------------------------------------

    const totalPages =
      pdf.internal.getNumberOfPages();

    for (
      let page = 1;
      page <= totalPages;
      page++
    ) {
      pdf.setPage(page);

      pdf.setFontSize(8);
      pdf.setFont(
        "helvetica",
        "normal"
      );

      pdf.setTextColor(100);

      pdf.text(
        `DomainAtlas | ${
          analysis?.domain || domain
        }`,
        margin,
        pageHeight - 8
      );

      pdf.text(
        `Page ${page} of ${totalPages}`,
        pageWidth - margin,
        pageHeight - 8,
        {
          align: "right",
        }
      );

      pdf.setTextColor(0);
    }

    // ----------------------------------------------------------
    // SAVE
    // ----------------------------------------------------------

    const safeDomain =
      (analysis?.domain || domain).replace(
        /[^a-z0-9.-]/gi,
        "_"
      );

    pdf.save(
      `${safeDomain}_subdomains.pdf`
    );
  };

  // ============================================================
  // DOWNLOAD AI REPORT PDF
  // ============================================================

  const downloadAIReportPDF = () => {
    if (!aiReport) return;

    const pdf = new jsPDF({
      orientation: "portrait",
      unit: "mm",
      format: "a4",
    });

    const pageWidth =
      pdf.internal.pageSize.getWidth();

    const pageHeight =
      pdf.internal.pageSize.getHeight();

    const margin = 15;

    const contentWidth =
      pageWidth - margin * 2;

    let y = 20;

    // ----------------------------------------------------------
    // TITLE
    // ----------------------------------------------------------

    pdf.setFontSize(18);

    pdf.setFont(
      "helvetica",
      "bold"
    );

    pdf.text(
      "DomainAtlas — AI Intelligence Report",
      margin,
      y
    );

    y += 10;

    // ----------------------------------------------------------
    // METADATA
    // ----------------------------------------------------------

    pdf.setFontSize(11);

    pdf.setFont(
      "helvetica",
      "normal"
    );

    pdf.text(
      `Target Domain: ${
        analysis?.domain || domain
      }`,
      margin,
      y
    );

    y += 6;

    pdf.text(
      `Generated: ${new Date().toLocaleString()}`,
      margin,
      y
    );

    y += 10;

    pdf.setDrawColor(180);

    pdf.line(
      margin,
      y,
      pageWidth - margin,
      y
    );

    y += 8;

    // ----------------------------------------------------------
    // REPORT CONTENT
    // ----------------------------------------------------------

    const lines =
      aiReport.split("\n");

    pdf.setFontSize(10);

    lines.forEach((line) => {
      const trimmed = line.trim();

      if (!trimmed) {
        y += 4;
        return;
      }

      // --------------------------------------------------------
      // MARKDOWN HEADING
      // --------------------------------------------------------

      if (
        trimmed.startsWith("**") &&
        trimmed.endsWith("**")
      ) {
        const heading =
          trimmed.replace(
            /\*\*/g,
            ""
          );

        if (y > pageHeight - 30) {
          pdf.addPage();
          y = 20;
        }

        pdf.setFont(
          "helvetica",
          "bold"
        );

        pdf.setFontSize(12);

        const headingLines =
          pdf.splitTextToSize(
            heading,
            contentWidth
          );

        pdf.text(
          headingLines,
          margin,
          y
        );

        y +=
          6 *
            Math.max(
              1,
              headingLines.length
            ) +
          3;

        return;
      }

      // --------------------------------------------------------
      // BULLET
      // --------------------------------------------------------

      let text = trimmed;

      if (
        trimmed.startsWith("- ") ||
        trimmed.startsWith("* ")
      ) {
        text =
          "• " +
          trimmed.substring(2);
      }

      pdf.setFont(
        "helvetica",
        "normal"
      );

      pdf.setFontSize(10);

      const textLines =
        pdf.splitTextToSize(
          text,
          contentWidth
        );

      const requiredHeight =
        textLines.length * 5;

      if (
        y + requiredHeight >
        pageHeight - 20
      ) {
        pdf.addPage();
        y = 20;
      }

      pdf.text(
        textLines,
        margin,
        y
      );

      y +=
        requiredHeight + 2;
    });

    // ----------------------------------------------------------
    // ANALYTICAL LIMITATION
    // ----------------------------------------------------------

    if (
      y + 25 >
      pageHeight - 15
    ) {
      pdf.addPage();
      y = 20;
    }

    y += 5;

    pdf.setDrawColor(150);

    pdf.rect(
      margin,
      y,
      contentWidth,
      22
    );

    pdf.setFont(
      "helvetica",
      "bold"
    );

    pdf.setFontSize(9);

    pdf.text(
      "Analytical Limitation",
      margin + 5,
      y + 7
    );

    pdf.setFont(
      "helvetica",
      "normal"
    );

    pdf.setFontSize(8);

    const limitation =
      "This report reflects only the collected OSINT data and does not establish ownership, maliciousness, benignness, or security posture.";

    const limitationLines =
      pdf.splitTextToSize(
        limitation,
        contentWidth - 10
      );

    pdf.text(
      limitationLines,
      margin + 5,
      y + 13
    );

    // ----------------------------------------------------------
    // PAGE FOOTERS
    // ----------------------------------------------------------

    const totalPages =
      pdf.internal.getNumberOfPages();

    for (
      let page = 1;
      page <= totalPages;
      page++
    ) {
      pdf.setPage(page);

      pdf.setFont(
        "helvetica",
        "normal"
      );

      pdf.setFontSize(8);

      pdf.setTextColor(100);

      pdf.text(
        `DomainAtlas | ${
          analysis?.domain || domain
        }`,
        margin,
        pageHeight - 8
      );

      pdf.text(
        `Page ${page} of ${totalPages}`,
        pageWidth - margin,
        pageHeight - 8,
        {
          align: "right",
        }
      );

      pdf.setTextColor(0);
    }

    // ----------------------------------------------------------
    // SAVE
    // ----------------------------------------------------------

    const safeDomain =
      (analysis?.domain || domain).replace(
        /[^a-z0-9.-]/gi,
        "_"
      );

    pdf.save(
      `${safeDomain}_DomainAtlas_AI_Report.pdf`
    );
  };

  // ============================================================
  // RENDER
  // ============================================================

  return (
    <div className="app">

      {/* ======================================================
          SIDEBAR
      ====================================================== */}

      <aside className="sidebar">

        <div className="brand">
          <div className="brand-mark">
            <Radar size={22} />
          </div>

          <div className="brand-copy">
            <h1>
              Domain<span>Atlas</span>
            </h1>

            <p>
              DOMAIN INTELLIGENCE
            </p>
          </div>
        </div>

        <div className="sidebar-divider" />

        <nav className="navigation">

          <p className="nav-label">
            WORKSPACE
          </p>

          <button
            className="nav-item active"
            onClick={() =>
              scrollToSection(
                dashboardRef
              )
            }
          >
            <BarChart3 size={17} />
            <span>Overview</span>
          </button>

          <button
            className="nav-item"
            onClick={() =>
              scrollToSection(
                infrastructureRef
              )
            }
          >
            <Server size={17} />
            <span>Infrastructure</span>
          </button>

          <button
            className="nav-item"
            onClick={() =>
              scrollToSection(
                graphRef
              )
            }
          >
            <Network size={17} />
            <span>
              Relationship Graph
            </span>
          </button>

          <button
            className="nav-item"
            onClick={() =>
              scrollToSection(
                subdomainsRef
              )
            }
          >
            <Globe size={17} />
            <span>Subdomains</span>
          </button>

          <button
            className="nav-item"
            onClick={() =>
              scrollToSection(
                certificatesRef
              )
            }
          >
            <FileKey size={17} />
            <span>Certificates</span>
          </button>

          <p className="nav-label">
            INTELLIGENCE
          </p>

          <button
            className="nav-item"
            onClick={() =>
              scrollToSection(
                aiReportRef
              )
            }
          >
            <Brain size={17} />
            <span>AI Assessment</span>
          </button>

        </nav>

        <div className="sidebar-footer">

          <div className="system-indicator">
            <span className="status-dot" />
          </div>

          <div>
            <strong>
              SYSTEM ONLINE
            </strong>

            <span>
              Neo4j · Ollama
            </span>
          </div>

        </div>

      </aside>

      {/* ======================================================
          MAIN CONTENT
      ====================================================== */}

      <main className="main-content">

        {/* ====================================================
            TOP HEADER
        ==================================================== */}

        <header
          className="topbar"
          ref={dashboardRef}
        >

          <div className="topbar-left">

            <div className="breadcrumb">
              <span>
                DOMAIN ATLAS
              </span>

              <ChevronRight size={13} />

              <span>
                ANALYSIS
              </span>
            </div>

            <h2>
              Domain Intelligence
            </h2>

            <p>
              Automated collection, correlation
              and intelligence analysis.
            </p>

          </div>

          <div className="header-status">

            <span
              className={
                loading
                  ? "status-dot loading"
                  : "status-dot"
              }
            />

            <div>

              <strong>
                {loading
                  ? "ANALYSIS RUNNING"
                  : "SYSTEM READY"}
              </strong>

              <span>
                {loading
                  ? "Processing intelligence"
                  : "Awaiting target"}
              </span>

            </div>

          </div>

        </header>

        {/* ====================================================
            SEARCH / TARGET AREA
        ==================================================== */}

        <section className="target-section">

          <div className="target-header">

            <div>

              <p className="eyebrow">
                TARGET ACQUISITION
              </p>

              <h3>
                Analyze a Domain
              </h3>

              <p>
                Enter a domain to initiate
                automated OSINT collection.
              </p>

            </div>

            <div className="target-icon">
              <Fingerprint size={23} />
            </div>

          </div>

          <div className="search-box">

            <div className="search-icon">
              <Search size={19} />
            </div>

            <input
              type="text"
              placeholder="example.com"
              value={domain}
              onChange={(event) =>
                setDomain(
                  event.target.value
                )
              }
              onKeyDown={handleKeyDown}
              disabled={loading}
            />

            <button
              onClick={analyzeDomain}
              disabled={loading}
              className="analyze-button"
            >
              {loading
                ? "Analyzing..."
                : "Analyze Domain"}

              {!loading && (
                <ChevronRight size={17} />
              )}
            </button>

          </div>

          <div className="target-meta">

            <span>
              <CircleDot size={12} />
              DNS
            </span>

            <span>
              <CircleDot size={12} />
              Subdomain Discovery
            </span>

            <span>
              <CircleDot size={12} />
              Certificates
            </span>

            <span>
              <CircleDot size={12} />
              Graph Correlation
            </span>

            <span>
              <CircleDot size={12} />
              AI Analysis
            </span>

          </div>

          {error && (
            <div className="error-message">
              <Shield size={15} />
              <span>{error}</span>
            </div>
          )}

        </section>

        {/* ====================================================
            LOADING
        ==================================================== */}

        {loading && (
          <section className="panel loading-panel">

            <div className="analysis-loader">

              <div className="loader-icon">
                <Radar size={38} />
              </div>

              <div>

                <p className="eyebrow">
                  COLLECTION PIPELINE
                </p>

                <h3>
                  Analysis in progress
                </h3>

                <p>
                  Collecting OSINT sources,
                  normalizing entities,
                  updating the intelligence graph
                  and generating the AI assessment.
                </p>

              </div>

            </div>

          </section>
        )}

        {/* ====================================================
            RESULTS
        ==================================================== */}

        {analysis && !loading && (
          <>

            {/* ==================================================
                ANALYSIS HEADER
            ================================================== */}

            <section className="analysis-banner">

              <div>

                <p className="eyebrow">
                  ANALYSIS COMPLETE
                </p>

                <h3>
                  {analysis.domain}
                </h3>

                <p>
                  Intelligence collection and
                  graph analysis completed successfully.
                </p>

              </div>

              <div className="analysis-complete">

                <Activity size={16} />

                <span>
                  COMPLETE
                </span>

              </div>

            </section>

            {/* ==================================================
                OVERVIEW
            ================================================== */}

            <section className="results-section">

              <div className="section-heading">

                <div>

                  <p className="eyebrow">
                    01 / OVERVIEW
                  </p>

                  <h3>
                    Infrastructure Summary
                  </h3>

                </div>

                <span className="domain-badge">
                  <Globe size={14} />
                  {analysis.domain}
                </span>

              </div>

              <div className="stat-grid">

                <StatCard
                  icon={<Globe />}
                  label="Subdomains"
                  value={
                    statistics.subdomains ?? 0
                  }
                  description="Discovered"
                />

                <StatCard
                  icon={<Server />}
                  label="IP Addresses"
                  value={
                    statistics.ip_addresses ?? 0
                  }
                  description={
                    `${ipVersion.ipv4 ?? 0} IPv4 · ` +
                    `${ipVersion.ipv6 ?? 0} IPv6`
                  }
                />

                <StatCard
                  icon={<Network />}
                  label="ASNs"
                  value={
                    statistics.asns ?? 0
                  }
                  description="Identified"
                />

                <StatCard
                  icon={<Database />}
                  label="Organizations"
                  value={
                    statistics.organizations ?? 0
                  }
                  description="Associated"
                />

                <StatCard
                  icon={<FileKey />}
                  label="Certificates"
                  value={
                    statistics.certificates ?? 0
                  }
                  description="Identified"
                />

              </div>

            </section>

            {/* ==================================================
                INFRASTRUCTURE
            ================================================== */}

            <section
              ref={infrastructureRef}
              className="panel-section"
            >

              <div className="panel">

                <div className="panel-header">

                  <div>

                    <p className="eyebrow">
                      02 / NETWORK
                    </p>

                    <h3>
                      Infrastructure
                    </h3>

                    <p className="panel-description">
                      Observed network infrastructure
                      associated with the target domain.
                    </p>

                  </div>

                  <div className="panel-icon">
                    <Server size={20} />
                  </div>

                </div>

                <div className="info-list">

                  {ipAddresses
                    .slice(0, 8)
                    .map((ip) => (
                      <InfoRow
                        key={ip}
                        label={
                          ip.includes(":")
                            ? "IPv6"
                            : "IPv4"
                        }
                        value={ip}
                      />
                    ))}

                  {asns.map((asn) => (
                    <InfoRow
                      key={asn}
                      label="ASN"
                      value={asn}
                    />
                  ))}

                  {organizations.map(
                    (organization) => (
                      <InfoRow
                        key={organization}
                        label="Organization"
                        value={organization}
                      />
                    )
                  )}

                  {ipAddresses.length === 0 &&
                    asns.length === 0 &&
                    organizations.length === 0 && (
                      <div className="empty-inline">
                        No infrastructure data
                        available.
                      </div>
                    )}

                </div>

              </div>

            </section>

            {/* ==================================================
                GRAPH
            ================================================== */}

            <section
              ref={graphRef}
              className="panel-section"
            >

              <div className="panel graph-panel">

                <div className="panel-header">

                  <div>

                    <p className="eyebrow">
                      03 / CORRELATION
                    </p>

                    <h3>
                      Intelligence Graph
                    </h3>

                    <p className="panel-description">
                      Correlated entities and observed
                      relationships within the collected dataset.
                    </p>

                  </div>

                  <div className="panel-icon">
                    <Network size={20} />
                  </div>

                </div>

                <div className="graph-wrapper">
                  <GraphView graph={graph} />
                </div>

                <div className="graph-legend">

                  <span>
                    <i className="legend-domain" />
                    Domain
                  </span>

                  <span>
                    <i className="legend-ip" />
                    IP
                  </span>

                  <span>
                    <i className="legend-asn" />
                    ASN
                  </span>

                  <span>
                    <i className="legend-org" />
                    Organization
                  </span>

                  <span>
                    <i className="legend-cert" />
                    Certificate
                  </span>

                </div>

              </div>

            </section>

            {/* ==================================================
                SUBDOMAINS
            ================================================== */}

            <section
              ref={subdomainsRef}
              className="panel-section"
            >

              <div className="panel">

                <div className="panel-header">

                  <div>

                    <p className="eyebrow">
                      04 / DISCOVERY
                    </p>

                    <h3>
                      Subdomain Inventory
                    </h3>

                    <p className="panel-description">
                      Complete list of discovered
                      subdomains.
                    </p>

                  </div>

                  <button
                    className="download-button"
                    onClick={
                      downloadSubdomainsPDF
                    }
                    disabled={
                      subdomains.length === 0
                    }
                  >
                    <Download size={15} />
                    Export Inventory
                  </button>

                </div>

                <div className="subdomain-summary">

                  <div className="inventory-count">

                    <strong>
                      {subdomains.length}
                    </strong>

                    <span>
                      discovered subdomains
                    </span>

                  </div>

                  <div className="inventory-note">

                    <Layers3 size={14} />

                    Graph visualization:

                    <strong>
                      first 150
                    </strong>

                  </div>

                </div>

                {subdomains.length > 0 ? (

                  <div className="subdomain-table-wrapper">

                    <table className="subdomain-table">

                      <thead>

                        <tr>
                          <th>#</th>
                          <th>Subdomain</th>
                        </tr>

                      </thead>

                      <tbody>

                        {subdomains.map(
                          (
                            subdomain,
                            index
                          ) => (

                            <tr
                              key={`${subdomain}-${index}`}
                            >

                              <td>
                                {String(
                                  index + 1
                                ).padStart(
                                  4,
                                  "0"
                                )}
                              </td>

                              <td>
                                {subdomain}
                              </td>

                            </tr>

                          )
                        )}

                      </tbody>

                    </table>

                  </div>

                ) : (

                  <div className="empty-inline">
                    No subdomains discovered.
                  </div>

                )}

              </div>

            </section>

            {/* ==================================================
                CERTIFICATES
            ================================================== */}

            <section
              ref={certificatesRef}
              className="panel-section"
            >

              <div className="panel">

                <div className="panel-header">

                  <div>

                    <p className="eyebrow">
                      05 / TLS INTELLIGENCE
                    </p>

                    <h3>
                      Certificate Inventory
                    </h3>

                    <p className="panel-description">
                      Certificate identifiers observed
                      during OSINT collection.
                    </p>

                  </div>

                  <div className="panel-icon">
                    <FileKey size={20} />
                  </div>

                </div>

                <div className="certificate-grid">

                  {certificates.length > 0 ? (

                    certificates.map(
                      (
                        certificate,
                        index
                      ) => (

                        <div
                          className="certificate-card"
                          key={`${certificate}-${index}`}
                        >

                          <div className="certificate-index">
                            {String(
                              index + 1
                            ).padStart(
                              2,
                              "0"
                            )}
                          </div>

                          <div>

                            <span>
                              CERTIFICATE
                            </span>

                            <strong>
                              {certificate}
                            </strong>

                          </div>

                        </div>

                      )
                    )

                  ) : (

                    <div className="empty-inline">
                      No certificate data
                      available.
                    </div>

                  )}

                </div>

              </div>

            </section>

            {/* ==================================================
                PATTERNS
            ================================================== */}

            <section className="panel-section">

              <div className="panel">

                <div className="panel-header">

                  <div>

                    <p className="eyebrow">
                      06 / PATTERN ANALYSIS
                    </p>

                    <h3>
                      Subdomain Patterns
                    </h3>

                    <p className="panel-description">
                      Structural characteristics observed
                      across the discovered subdomain set.
                    </p>

                  </div>

                  <div className="panel-icon">
                    <Globe size={20} />
                  </div>

                </div>

                <div className="pattern-grid">

                  <PatternCard
                    value={
                      patterns.numeric_leading ??
                      0
                    }
                    label="Numeric-leading"
                  />

                  <PatternCard
                    value={
                      patterns.contains_hyphen ??
                      0
                    }
                    label="Contains hyphen"
                  />

                  <PatternCard
                    value={
                      patterns.multi_level ??
                      0
                    }
                    label="Multi-level"
                  />

                  <PatternCard
                    value={
                      patterns.common_prefixes?.[0]
                        ? patterns
                            .common_prefixes[0]
                            .count
                        : 0
                    }
                    label={
                      patterns.common_prefixes?.[0]
                        ? `${patterns.common_prefixes[0].prefix} prefix`
                        : "Common prefix"
                    }
                  />

                </div>

              </div>

            </section>

            {/* ==================================================
                VIRUSTOTAL
            ================================================== */}

            <section className="panel-section">

              <div className="panel">

                <div className="panel-header">

                  <div>

                    <p className="eyebrow">
                      07 / EXTERNAL INTELLIGENCE
                    </p>

                    <h3>
                      VirusTotal Observations
                    </h3>

                    <p className="panel-description">
                      External intelligence observations
                      incorporated into the analysis.
                    </p>

                  </div>

                  <div className="panel-icon">
                    <Shield size={20} />
                  </div>

                </div>

                <div className="pattern-grid">

                  <PatternCard
                    value={getDetectionCount(
                      "malicious detections"
                    )}
                    label="Malicious"
                  />

                  <PatternCard
                    value={getDetectionCount(
                      "suspicious detections"
                    )}
                    label="Suspicious"
                  />

                  <PatternCard
                    value={getDetectionCount(
                      "harmless detections"
                    )}
                    label="Harmless"
                  />

                  <PatternCard
                    value={getDetectionCount(
                      "undetected security"
                    )}
                    label="Undetected"
                  />

                </div>

              </div>

            </section>

            {/* ==================================================
                AI REPORT
            ================================================== */}

            <section
              ref={aiReportRef}
              className="panel-section"
            >

              <div className="panel ai-panel">

                <div className="panel-header">

                  <div>

                    <p className="eyebrow">
                      08 / AI-ASSISTED ANALYSIS
                    </p>

                    <h3>
                      Intelligence Assessment
                    </h3>

                    <p className="panel-description">
                      Structured interpretation of the
                      collected OSINT dataset.
                    </p>

                  </div>

                  <div className="ai-report-actions">

                    <button
                      className="download-button"
                      onClick={
                        downloadAIReportPDF
                      }
                      disabled={!aiReport}
                    >
                      <Download size={15} />
                      Export Report
                    </button>

                    <div className="ai-badge">

                      <Brain size={15} />

                      <span>
                        Ollama
                      </span>

                    </div>

                  </div>

                </div>

                <div className="report">

                  <div className="report-meta">

                    <div>

                      <span>
                        TARGET
                      </span>

                      <strong>
                        {analysis.domain}
                      </strong>

                    </div>

                    <div>

                      <span>
                        ANALYSIS ENGINE
                      </span>

                      <strong>
                        Ollama
                      </strong>

                    </div>

                    <div>

                      <span>
                        STATUS
                      </span>

                      <strong>
                        {aiReport
                          ? "Generated"
                          : "Unavailable"}
                      </strong>

                    </div>

                  </div>

                  <div className="report-content">

                    {aiReport ? (

                      aiReport
                        .split("\n")
                        .map(
                          (
                            line,
                            index
                          ) => {

                            const trimmed =
                              line.trim();

                            if (!trimmed) {
                              return (
                                <div
                                  key={index}
                                  className="report-spacer"
                                />
                              );
                            }

                            // Markdown heading
                            if (
                              trimmed.startsWith(
                                "**"
                              ) &&
                              trimmed.endsWith(
                                "**"
                              )
                            ) {
                              return (
                                <h4
                                  key={index}
                                >
                                  {trimmed.replace(
                                    /\*\*/g,
                                    ""
                                  )}
                                </h4>
                              );
                            }

                            // Markdown bullet
                            if (
                              trimmed.startsWith(
                                "- "
                              ) ||
                              trimmed.startsWith(
                                "* "
                              )
                            ) {
                              return (
                                <p
                                  key={index}
                                  className="report-bullet"
                                >
                                  <span>
                                    •
                                  </span>

                                  {trimmed.substring(
                                    2
                                  )}
                                </p>
                              );
                            }

                            return (
                              <p
                                key={index}
                              >
                                {trimmed}
                              </p>
                            );
                          }
                        )

                    ) : (

                      <p>
                        No AI report was
                        generated.
                      </p>

                    )}

                  </div>

                  <div className="limitation">

                    <Shield size={17} />

                    <div>

                      <strong>
                        Analytical Limitation
                      </strong>

                      <span>
                        This report reflects
                        only the collected OSINT
                        data and does not establish
                        ownership, maliciousness,
                        benignness, or security
                        posture.
                      </span>

                    </div>

                  </div>

                </div>

              </div>

            </section>

            {/* ==================================================
                FOOTER
            ================================================== */}

            <footer className="dashboard-footer">

              <div>

                <strong>
                  DomainAtlas
                </strong>

                <span>
                  Domain-Centric OSINT Intelligence Platform
                </span>

              </div>

              <div>

                <span>
                  Collection
                </span>

                <span>•</span>

                <span>
                  Correlation
                </span>

                <span>•</span>

                <span>
                  Graph Analysis
                </span>

                <span>•</span>

                <span>
                  AI Assessment
                </span>

              </div>

            </footer>

          </>
        )}

        {/* ====================================================
            EMPTY STATE
        ==================================================== */}

        {!analysis &&
          !loading &&
          !error && (

            <section className="empty-dashboard">

              <div className="empty-visual">

                <Radar size={46} />

                <div className="radar-ring ring-one" />

                <div className="radar-ring ring-two" />

              </div>

              <p className="eyebrow">
                DOMAINATLAS INTELLIGENCE ENGINE
              </p>

              <h3>
                Ready for reconnaissance.
              </h3>

              <p>
                Enter a target domain above to
                begin OSINT collection, entity
                correlation and graph-based analysis.
              </p>

              <div className="empty-capabilities">

                <span>
                  <Globe size={14} />
                  DNS Intelligence
                </span>

                <span>
                  <Network size={14} />
                  Entity Correlation
                </span>

                <span>
                  <Database size={14} />
                  Knowledge Graph
                </span>

                <span>
                  <Brain size={14} />
                  AI Assessment
                </span>

              </div>

            </section>

          )}

      </main>

    </div>
  );
}

// ================================================================
// STAT CARD
// ================================================================

function StatCard({
  icon,
  label,
  value,
  description,
}) {
  return (
    <div className="stat-card">

      <div className="stat-card-top">

        <div className="stat-icon">
          {icon}
        </div>

      </div>

      <div className="stat-content">

        <p>
          {label}
        </p>

        <strong>
          {value}
        </strong>

        <span>
          {description}
        </span>

      </div>

    </div>
  );
}

// ================================================================
// INFO ROW
// ================================================================

function InfoRow({
  label,
  value,
}) {
  return (
    <div className="info-row">

      <div className="info-label">

        <span className="info-marker" />

        {label}

      </div>

      <span className="info-value">
        {value}
      </span>

    </div>
  );
}

// ================================================================
// PATTERN CARD
// ================================================================

function PatternCard({
  value,
  label,
}) {
  return (
    <div className="pattern-card">

      <div className="pattern-value">
        {value}
      </div>

      <div className="pattern-label">
        {label}
      </div>

    </div>
  );
}

export default App;