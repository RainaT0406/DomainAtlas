import { useRef, useState, useEffect } from "react";

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
  CheckCircle2,
  Loader2,
  Sparkles,
  Compass,
  ArrowRight,
  Zap,
  Map,
  Target,
  Square,
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
  const [progress, setProgress] = useState([]);
  const [currentProgress, setCurrentProgress] = useState(0);
  const [showIntro, setShowIntro] = useState(true);
  const [stopRequested, setStopRequested] = useState(false);
  const [abortController, setAbortController] = useState(null);
  const [eventSource, setEventSource] = useState(null);
  const [scanId, setScanId] = useState(null);
  const [activeNav, setActiveNav] = useState("overview");
  const [isStopped, setIsStopped] = useState(false);
  const [renderError, setRenderError] = useState(null);

  // ============================================================
  // SCAN LIFECYCLE REFS
  // ============================================================

  const scanGenerationRef = useRef(0);
  const eventSourceRef = useRef(null);
  const abortControllerRef = useRef(null);
  const stopRequestedRef = useRef(false);

  // ============================================================
  // SECTION REFERENCES
  // ============================================================

  const dashboardRef = useRef(null);
  const infrastructureRef = useRef(null);
  const graphRef = useRef(null);
  const subdomainsRef = useRef(null);
  const certificatesRef = useRef(null);
  const aiReportRef = useRef(null);
  const heroRef = useRef(null);

  // ============================================================
  // SCROLL NAVIGATION WITH HIGHLIGHTING
  // ============================================================

  const scrollToSection = (ref, sectionName) => {
    if (!ref.current) return;

    setActiveNav(sectionName);

    ref.current.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  };

  // ============================================================
  // DETECT SCROLL POSITION FOR HIGHLIGHTING
  // ============================================================

  useEffect(() => {
    const handleScroll = () => {
      const scrollY = window.scrollY + 120;

      const sections = [
        { ref: dashboardRef, name: "overview" },
        { ref: infrastructureRef, name: "infrastructure" },
        { ref: graphRef, name: "graph" },
        { ref: subdomainsRef, name: "subdomains" },
        { ref: certificatesRef, name: "certificates" },
        { ref: aiReportRef, name: "ai" },
      ];

      let activeSection = "overview";

      for (const section of sections) {
        if (section.ref.current) {
          const rect = section.ref.current.getBoundingClientRect();
          const elementTop = rect.top + window.scrollY;
          const elementBottom = elementTop + rect.height;

          if (scrollY >= elementTop - 50 && scrollY < elementBottom - 50) {
            activeSection = section.name;
            break;
          }
        }
      }

      setActiveNav(activeSection);
    };

    if (analysis || loading) {
      window.addEventListener("scroll", handleScroll);
      setTimeout(handleScroll, 100);
    } else {
      window.removeEventListener("scroll", handleScroll);
    }

    return () => window.removeEventListener("scroll", handleScroll);
  }, [analysis, loading]);

  // ============================================================
  // CLEAN UP ACTIVE SCAN RESOURCES
  // ============================================================

  const cleanupScanResources = () => {
    const activeEventSource = eventSourceRef.current;

    if (activeEventSource) {
      try {
        activeEventSource.close();
      } catch (e) {
        console.warn("[!] Error closing EventSource:", e);
      }
    }

    eventSourceRef.current = null;
    setEventSource(null);

    const activeController = abortControllerRef.current;

    if (activeController) {
      try {
        activeController.abort();
      } catch (e) {
        console.warn("[!] Error aborting fetch:", e);
      }
    }

    abortControllerRef.current = null;
    setAbortController(null);
  };

  // ============================================================
  // STOP FUNCTION
  // ============================================================

  const stopAnalysis = async () => {
    console.log("[*] Stop requested");

    stopRequestedRef.current = true;

    const stoppedGeneration = scanGenerationRef.current;

    setIsStopped(true);
    setStopRequested(true);

    scanGenerationRef.current += 1;

    const activeEventSource = eventSourceRef.current;

    if (activeEventSource) {
      console.log("[*] Closing EventSource");
      try {
        activeEventSource.close();
      } catch (e) {
        console.warn("[!] Failed to close EventSource:", e);
      }
    }

    eventSourceRef.current = null;
    setEventSource(null);

    const activeController = abortControllerRef.current;

    if (activeController) {
      console.log("[*] Aborting fetch request");

      try {
        activeController.abort();
      } catch (e) {
        console.warn("[!] Failed to abort fetch:", e);
      }
    }

    abortControllerRef.current = null;
    setAbortController(null);

    const targetDomain = domain.trim().toLowerCase().replace(/\.$/, "");
    const currentScanId = scanId;

    setLoading(false);
    setProgress([]);
    setCurrentProgress(0);
    setShowIntro(true);
    setAnalysis(null);
    setScanId(null);
    setActiveNav("overview");
    setError("Scan cancelled by user.");

    try {
      const payload = {};

      if (targetDomain) payload.domain = targetDomain;
      if (currentScanId) payload.scan_id = currentScanId;

      console.log("[*] Sending stop payload:", payload);

      const response = await fetch("http://127.0.0.1:8000/analyze/stop", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();
      console.log("[*] Stop response:", data);
    } catch (e) {
      console.warn("[!] Failed to send stop signal to backend:", e);
    }

    console.log("[*] Scan stopped:", stoppedGeneration);
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

    console.log("[*] Starting new scan for:", targetDomain);

    setRenderError(null);

    const scanGeneration = scanGenerationRef.current + 1;
    scanGenerationRef.current = scanGeneration;

    const previousEventSource = eventSourceRef.current;

    if (previousEventSource) {
      console.log("[*] Closing previous EventSource");

      try {
        previousEventSource.close();
      } catch (e) {
        console.warn("[!] Failed to close previous EventSource:", e);
      }

      eventSourceRef.current = null;
      setEventSource(null);
    }

    const previousController = abortControllerRef.current;

    if (previousController) {
      console.log("[*] Aborting previous fetch");

      try {
        previousController.abort();
      } catch (e) {
        console.warn("[!] Failed to abort previous fetch:", e);
      }

      abortControllerRef.current = null;
      setAbortController(null);
    }

    stopRequestedRef.current = false;

    setIsStopped(false);
    setStopRequested(false);
    setLoading(true);
    setError("");
    setAnalysis(null);
    setProgress([]);
    setCurrentProgress(0);
    setShowIntro(false);
    setScanId(null);
    setActiveNav("overview");

    const controller = new AbortController();

    abortControllerRef.current = controller;
    setAbortController(controller);

    const es = new EventSource(
      "http://127.0.0.1:8000/analyze/progress"
    );

    eventSourceRef.current = es;
    setEventSource(es);

    let isClosed = false;

    const isCurrentScan = () => {
      return (
        scanGenerationRef.current === scanGeneration &&
        !controller.signal.aborted
      );
    };

    es.onopen = () => {
      if (!isCurrentScan()) {
        es.close();
        return;
      }

      console.log("[*] EventSource connected for scan:", scanGeneration);
    };

    es.onmessage = (event) => {
      if (!isCurrentScan()) {
        console.log(
          "[*] Ignoring stale progress event from scan:",
          scanGeneration
        );

        if (!isClosed) {
          es.close();
          isClosed = true;
        }

        return;
      }

      if (stopRequestedRef.current) {
        if (!isClosed) {
          console.log("[*] Closing EventSource because current scan was stopped");
          es.close();
          isClosed = true;
        }

        return;
      }

      try {
        const update = JSON.parse(event.data);

        console.log(
          "[*] Progress update:",
          update.step,
          update.status,
          update.progress
        );

        if (update.status === "cancelled") {
          console.log(
            "[*] Ignoring backend cancelled event"
          );
          return;
        }

        setProgress((prev) => {
          if (scanGenerationRef.current !== scanGeneration) {
            return prev;
          }

          const existing = prev.findIndex(
            (p) => p.step === update.step
          );

          if (existing >= 0) {
            const updated = [...prev];
            updated[existing] = update;
            return updated;
          }

          return [...prev, update];
        });

        if (scanGenerationRef.current === scanGeneration) {
          setCurrentProgress(update.progress || 0);
        }
      } catch (e) {
        console.error("Error parsing progress update:", e);
      }
    };

    es.onerror = (event) => {
      if (scanGenerationRef.current !== scanGeneration) {
        if (!isClosed) {
          es.close();
          isClosed = true;
        }

        return;
      }

      console.log("[*] EventSource error:", event);

      if (
        !stopRequestedRef.current &&
        !controller.signal.aborted
      ) {
        console.warn("EventSource connection closed unexpectedly.");
      }

      if (!isClosed) {
        es.close();
        isClosed = true;
      }

      if (eventSourceRef.current === es) {
        eventSourceRef.current = null;
        setEventSource(null);
      }
    };

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
          signal: controller.signal,
        }
      );

      if (
        controller.signal.aborted ||
        scanGenerationRef.current !== scanGeneration ||
        stopRequestedRef.current
      ) {
        return;
      }

      let data;

      try {
        data = await response.json();
      } catch {
        if (
          controller.signal.aborted ||
          scanGenerationRef.current !== scanGeneration
        ) {
          return;
        }

        throw new Error(
          "The API returned an invalid response."
        );
      }

      if (
        controller.signal.aborted ||
        scanGenerationRef.current !== scanGeneration ||
        stopRequestedRef.current
      ) {
        return;
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

      if (scanGenerationRef.current !== scanGeneration) {
        return;
      }

      console.log("[*] Analysis data received:", data);

      // Ensure data has all required fields with fallbacks
      const safeData = {
        ...data,
        infrastructure: data.infrastructure || { subdomains: [], ip_addresses: [], asns: [], organizations: [], certificates: [] },
        virustotal: data.virustotal || {},
        statistics: data.statistics || {},
        subdomain_patterns: data.subdomain_patterns || {},
        observations: data.observations || [],
        provenance: data.provenance || [],
        ai_report: data.ai_report || "",
        graph: data.graph || { nodes: [], edges: [], provenance: [] }
      };

      setScanId(safeData.scan_id || null);
      setAnalysis(safeData);
      setLoading(false);
      setIsStopped(false);
      setStopRequested(false);
      stopRequestedRef.current = false;

      setTimeout(() => {
        if (
          scanGenerationRef.current === scanGeneration &&
          dashboardRef.current
        ) {
          dashboardRef.current.scrollIntoView({
            behavior: "smooth",
            block: "start",
          });
        }
      }, 300);
    } catch (err) {
      if (err?.name === "AbortError") {
        console.log("[*] Fetch aborted");
        return;
      }

      if (scanGenerationRef.current !== scanGeneration) {
        console.log(
          "[*] Ignoring error from stale scan:",
          scanGeneration
        );
        return;
      }

      if (stopRequestedRef.current) {
        return;
      }

      console.error("Domain analysis error:", err);

      setLoading(false);
      setError(
        err?.message ||
        "Unable to connect to the DomainAtlas API."
      );
    } finally {
      if (scanGenerationRef.current !== scanGeneration) {
        return;
      }

      if (!isClosed) {
        try {
          es.close();
        } catch (e) {
          console.warn("[!] Failed to close EventSource:", e);
        }

        isClosed = true;
      }

      if (eventSourceRef.current === es) {
        eventSourceRef.current = null;
        setEventSource(null);
      }

      if (abortControllerRef.current === controller) {
        abortControllerRef.current = null;
        setAbortController(null);
      }
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
  // SAFE DATA EXTRACTION WITH ERROR HANDLING
  // ============================================================

  const statistics = analysis?.statistics || {};

  const infrastructure = analysis?.infrastructure || {};

  const ipVersion = analysis?.ip_version_summary || {};

  const patterns = analysis?.subdomain_patterns || {};

  const observations = Array.isArray(analysis?.observations)
    ? analysis.observations
    : [];

  const provenance = Array.isArray(analysis?.provenance)
    ? analysis.provenance
    : [];

  const aiReport = typeof analysis?.ai_report === "string"
    ? analysis.ai_report
    : "";

  const graph = analysis?.graph || {
    nodes: [],
    edges: [],
    provenance: []
  };

  const subdomains = Array.isArray(infrastructure?.subdomains)
    ? infrastructure.subdomains
    : [];

  const certificates = Array.isArray(infrastructure?.certificates)
    ? infrastructure.certificates
    : [];

  const ipAddresses = Array.isArray(infrastructure?.ip_addresses)
    ? infrastructure.ip_addresses
    : [];

  const asns = Array.isArray(infrastructure?.asns)
    ? infrastructure.asns
    : [];

  const organizations = Array.isArray(infrastructure?.organizations)
    ? infrastructure.organizations
    : [];

  // Safe VirusTotal data extraction
  const virustotal = analysis?.virustotal || {};
  const vtRiskScore = virustotal?.risk_score ?? 0;
  const vtSecuritySummary = virustotal?.security_summary || {};
  const vtVendorBreakdown = Array.isArray(virustotal?.vendor_breakdown) ? virustotal.vendor_breakdown : [];
  const vtRiskFactors = Array.isArray(virustotal?.risk_factors) ? virustotal.risk_factors : [];
  const vtWhois = virustotal?.whois_info || {};
  const vtCommunityVotes = virustotal?.community_votes || {};

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

    const pageWidth = pdf.internal.pageSize.getWidth();
    const pageHeight = pdf.internal.pageSize.getHeight();
    const margin = 15;
    const lineHeight = 6;

    let y = 20;

    pdf.setFontSize(18);
    pdf.setFont("helvetica", "bold");

    pdf.text(
      "DomainAtlas — Subdomain Inventory",
      margin,
      y
    );

    y += 9;

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

    pdf.setFont("helvetica", "normal");
    pdf.setFontSize(9);

    subdomains.forEach((subdomain, index) => {
      if (y + lineHeight > pageHeight - margin) {
        pdf.addPage();
        y = 20;

        pdf.setFont("helvetica", "bold");
        pdf.text(
          "DomainAtlas — Subdomain Inventory",
          margin,
          y
        );
        y += 8;
        pdf.setFont("helvetica", "normal");
        pdf.setFontSize(9);
      }

      const value = String(subdomain ?? "");
      pdf.text(String(index + 1), numberX, y);

      const maxWidth = pageWidth - subdomainX - margin;
      const lines = pdf.splitTextToSize(value, maxWidth);
      pdf.text(lines, subdomainX, y);

      y += lineHeight * Math.max(1, lines.length);

      pdf.setDrawColor(220);
      pdf.line(margin, y - 2, pageWidth - margin, y - 2);
      pdf.setDrawColor(0);

      y += 2;
    });

    const totalPages = pdf.internal.getNumberOfPages();

    for (let page = 1; page <= totalPages; page++) {
      pdf.setPage(page);
      pdf.setFontSize(8);
      pdf.setFont("helvetica", "normal");
      pdf.setTextColor(100);

      pdf.text(
        `DomainAtlas | ${analysis?.domain || domain}`,
        margin,
        pageHeight - 8
      );

      pdf.text(
        `Page ${page} of ${totalPages}`,
        pageWidth - margin,
        pageHeight - 8,
        { align: "right" }
      );

      pdf.setTextColor(0);
    }

    const safeDomain = (analysis?.domain || domain).replace(/[^a-z0-9.-]/gi, "_");
    pdf.save(`${safeDomain}_subdomains.pdf`);
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

    const pageWidth = pdf.internal.pageSize.getWidth();
    const pageHeight = pdf.internal.pageSize.getHeight();
    const margin = 15;
    const contentWidth = pageWidth - margin * 2;

    let y = 20;

    pdf.setFontSize(18);
    pdf.setFont("helvetica", "bold");
    pdf.text("DomainAtlas — AI Intelligence Report", margin, y);

    y += 10;

    pdf.setFontSize(11);
    pdf.setFont("helvetica", "normal");
    pdf.text(`Target Domain: ${analysis?.domain || domain}`, margin, y);

    y += 6;
    pdf.text(`Generated: ${new Date().toLocaleString()}`, margin, y);

    y += 10;

    pdf.setDrawColor(180);
    pdf.line(margin, y, pageWidth - margin, y);
    y += 8;

    const lines = aiReport.split("\n");

    pdf.setFontSize(10);

    lines.forEach((line) => {
      const trimmed = line.trim();

      if (!trimmed) {
        y += 4;
        return;
      }

      if (trimmed.startsWith("**") && trimmed.endsWith("**")) {
        const heading = trimmed.replace(/\*\*/g, "");

        if (y > pageHeight - 30) {
          pdf.addPage();
          y = 20;
        }

        pdf.setFont("helvetica", "bold");
        pdf.setFontSize(12);

        const headingLines = pdf.splitTextToSize(heading, contentWidth);
        pdf.text(headingLines, margin, y);

        y += 6 * Math.max(1, headingLines.length) + 3;
        return;
      }

      let text = trimmed;

      if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
        text = "• " + trimmed.substring(2);
      }

      pdf.setFont("helvetica", "normal");
      pdf.setFontSize(10);

      const textLines = pdf.splitTextToSize(text, contentWidth);
      const requiredHeight = textLines.length * 5;

      if (y + requiredHeight > pageHeight - 20) {
        pdf.addPage();
        y = 20;
      }

      pdf.text(textLines, margin, y);
      y += requiredHeight + 2;
    });

    if (y + 25 > pageHeight - 15) {
      pdf.addPage();
      y = 20;
    }

    y += 5;

    pdf.setDrawColor(150);
    pdf.rect(margin, y, contentWidth, 22);

    pdf.setFont("helvetica", "bold");
    pdf.setFontSize(9);
    pdf.text("Analytical Limitation", margin + 5, y + 7);

    pdf.setFont("helvetica", "normal");
    pdf.setFontSize(8);

    const limitation =
      "This report reflects only the collected OSINT data and does not establish ownership, maliciousness, benignness, or security posture.";

    const limitationLines = pdf.splitTextToSize(limitation, contentWidth - 10);
    pdf.text(limitationLines, margin + 5, y + 13);

    const totalPages = pdf.internal.getNumberOfPages();

    for (let page = 1; page <= totalPages; page++) {
      pdf.setPage(page);
      pdf.setFont("helvetica", "normal");
      pdf.setFontSize(8);
      pdf.setTextColor(100);

      pdf.text(`DomainAtlas | ${analysis?.domain || domain}`, margin, pageHeight - 8);
      pdf.text(`Page ${page} of ${totalPages}`, pageWidth - margin, pageHeight - 8, {
        align: "right",
      });

      pdf.setTextColor(0);
    }

    const safeDomain = (analysis?.domain || domain).replace(/[^a-z0-9.-]/gi, "_");
    pdf.save(`${safeDomain}_DomainAtlas_AI_Report.pdf`);
  };

  // ============================================================
  // ERROR BOUNDARY FOR RENDER
  // ============================================================

  useEffect(() => {
    if (analysis) {
      try {
        // Test render by accessing safe properties
        const testData = {
          subdomains: Array.isArray(analysis.infrastructure?.subdomains) ? analysis.infrastructure.subdomains : [],
          virustotal: analysis.virustotal || {},
          statistics: analysis.statistics || {}
        };
        console.log("[*] Analysis data is valid for rendering:", testData);
        setRenderError(null);
      } catch (e) {
        console.error("[!] Error in analysis data:", e);
        setRenderError("Error processing analysis data. Please try again.");
      }
    }
  }, [analysis]);

  // ============================================================
  // RENDER
  // ============================================================

  if (renderError) {
    return (
      <div className="app">
        <div className="error-container">
          <Shield size={48} />
          <h2>Something went wrong</h2>
          <p>{renderError}</p>
          <button onClick={() => window.location.reload()}>Refresh Page</button>
        </div>
      </div>
    );
  }

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
            className={`nav-item ${activeNav === "overview" ? "active" : ""}`}
            onClick={() =>
              scrollToSection(
                dashboardRef,
                "overview"
              )
            }
          >
            <BarChart3 size={17} />
            <span>Overview</span>
          </button>

          <button
            className={`nav-item ${activeNav === "infrastructure" ? "active" : ""}`}
            onClick={() =>
              scrollToSection(
                infrastructureRef,
                "infrastructure"
              )
            }
          >
            <Server size={17} />
            <span>Infrastructure</span>
          </button>

          <button
            className={`nav-item ${activeNav === "graph" ? "active" : ""}`}
            onClick={() =>
              scrollToSection(
                graphRef,
                "graph"
              )
            }
          >
            <Network size={17} />
            <span>
              Relationship Graph
            </span>
          </button>

          <button
            className={`nav-item ${activeNav === "subdomains" ? "active" : ""}`}
            onClick={() =>
              scrollToSection(
                subdomainsRef,
                "subdomains"
              )
            }
          >
            <Globe size={17} />
            <span>Subdomains</span>
          </button>

          <button
            className={`nav-item ${activeNav === "certificates" ? "active" : ""}`}
            onClick={() =>
              scrollToSection(
                certificatesRef,
                "certificates"
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
            className={`nav-item ${activeNav === "ai" ? "active" : ""}`}
            onClick={() =>
              scrollToSection(
                aiReportRef,
                "ai"
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
            HERO / INTRO SECTION
        ==================================================== */}

        {showIntro && !analysis && !loading && (
          <section className="hero-section" ref={heroRef}>

            <div className="hero-glow" />
            <div className="hero-grid" />

            <div className="hero-content">

              <div className="hero-badge">
                <Sparkles size={14} />
                <span>Next-Gen OSINT Platform</span>
              </div>

              <h1 className="hero-title">
                Map the Digital<br />
                <span className="hero-highlight">Frontier</span>
              </h1>

              <p className="hero-description">
                DomainAtlas combines automated OSINT collection,
                knowledge graph correlation, and AI-powered analysis
                to give you complete visibility into any domain's
                digital footprint.
              </p>

              <div className="hero-features">
                <div className="hero-feature">
                  <Compass size={16} />
                  <span>Intelligent Discovery</span>
                </div>
                <div className="hero-feature">
                  <Network size={16} />
                  <span>Graph Correlation</span>
                </div>
                <div className="hero-feature">
                  <Brain size={16} />
                  <span>AI Assessment</span>
                </div>
                <div className="hero-feature">
                  <Zap size={16} />
                  <span>Real-time Analysis</span>
                </div>
              </div>

              <div className="hero-search-wrapper">
                <div className="search-box hero-search">
                  <div className="search-icon">
                    <Search size={19} />
                  </div>
                  <input
                    type="text"
                    placeholder="Enter a domain to analyze…"
                    value={domain}
                    onChange={(event) =>
                      setDomain(
                        event.target.value
                      )
                    }
                    onKeyDown={handleKeyDown}
                    disabled={loading}
                    className="hero-input"
                  />
                  <button
                    onClick={analyzeDomain}
                    disabled={loading}
                    className="analyze-button hero-analyze-btn"
                  >
                    {loading
                      ? "Analyzing..."
                      : "Analyze Domain"}
                    {!loading && (
                      <ArrowRight size={17} />
                    )}
                  </button>
                </div>

                {error && (
                  <div className="error-message">
                    <Shield size={15} />
                    <span>{error}</span>
                  </div>
                )}

                <div className="hero-search-meta">
                  <span>
                    <Target size={12} />
                    DNS · Subdomains · Certificates · Graph · AI
                  </span>
                </div>
              </div>

            </div>
          </section>
        )}

        {/* ====================================================
            TOP HEADER (Results View)
        ==================================================== */}

        {(analysis || loading) && (
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
                    ? `Processing intelligence (${currentProgress}%)`
                    : analysis?.domain || "Awaiting target"}
                </span>

              </div>

            </div>

          </header>
        )}

        {/* ====================================================
            LOADING - PROGRESS PIPELINE WITH STOP BUTTON
        ==================================================== */}

        {loading && (
          <section className="panel loading-panel">

            <div className="pipeline-progress">

              <div className="pipeline-header">

                <div>

                  <p className="eyebrow">
                    COLLECTION PIPELINE
                  </p>

                  <h3>
                    OSINT Analysis in Progress
                  </h3>

                  <p>
                    Real-time collection and analysis
                    for <strong>{domain}</strong>
                  </p>

                </div>

                <div className="pipeline-header-right">

                  <div className="progress-percentage">
                    {currentProgress}%
                  </div>

                  <button
                    className="stop-button"
                    onClick={stopAnalysis}
                    disabled={!loading}
                  >
                    <Square size={16} />
                    Stop Scan
                  </button>

                </div>

              </div>

              <div className="progress-bar-container">

                <div
                  className="progress-bar-fill"
                  style={{
                    width: `${currentProgress}%`,
                  }}
                />

              </div>

              <div className="pipeline-steps">

                <PipelineStep
                  label="Initialization"
                  message="Pipeline started"
                  progress={5}
                  currentProgress={currentProgress}
                  status={
                    progress.find(
                      (p) => p.step === "init"
                    )?.status
                  }
                  isCancelled={stopRequested}
                />

                <PipelineStep
                  label="DNS Resolution"
                  message="Querying DNS records"
                  progress={15}
                  currentProgress={currentProgress}
                  status={
                    progress.find(
                      (p) => p.step === "dns"
                    )?.status
                  }
                  isCancelled={stopRequested}
                />

                <PipelineStep
                  label="IP Metadata"
                  message="Looking up ASN and organization"
                  progress={25}
                  currentProgress={currentProgress}
                  status={
                    progress.find(
                      (p) => p.step === "ip_metadata"
                    )?.status
                  }
                  isCancelled={stopRequested}
                />

                <PipelineStep
                  label="Subdomain Discovery"
                  message="Running subdomain enumeration"
                  progress={45}
                  currentProgress={currentProgress}
                  status={
                    progress.some(
                      (p) =>
                        (p.step === "subfinder" || p.step === "amass") &&
                        p.status === "running"
                    )
                      ? "running"
                      : progress.some(
                        (p) =>
                          (p.step === "subfinder" || p.step === "amass") &&
                          p.status === "completed"
                      )
                        ? "completed"
                        : progress.some(
                          (p) =>
                            (p.step === "subfinder" || p.step === "amass") &&
                            p.status === "cancelled"
                        )
                          ? "cancelled"
                          : undefined
                  }
                  isCancelled={stopRequested}
                />

                <PipelineStep
                  label="Certificate Intelligence"
                  message="Querying Certificate Transparency"
                  progress={65}
                  currentProgress={currentProgress}
                  status={
                    progress.find(
                      (p) => p.step === "certificates"
                    )?.status
                  }
                  isCancelled={stopRequested}
                />

                <PipelineStep
                  label="VirusTotal Intelligence"
                  message="Querying VirusTotal API"
                  progress={75}
                  currentProgress={currentProgress}
                  status={
                    progress.find(
                      (p) => p.step === "virustotal"
                    )?.status
                  }
                  isCancelled={stopRequested}
                />

                <PipelineStep
                  label="Entity Normalization"
                  message="Normalizing entities"
                  progress={80}
                  currentProgress={currentProgress}
                  status={
                    progress.find(
                      (p) => p.step === "normalization"
                    )?.status
                  }
                  isCancelled={stopRequested}
                />

                <PipelineStep
                  label="Knowledge Graph"
                  message="Loading into Neo4j"
                  progress={85}
                  currentProgress={currentProgress}
                  status={
                    progress.find(
                      (p) => p.step === "graph_loading"
                    )?.status
                  }
                  isCancelled={stopRequested}
                />

                <PipelineStep
                  label="Graph Analysis"
                  message="Analyzing knowledge graph"
                  progress={92}
                  currentProgress={currentProgress}
                  status={
                    progress.find(
                      (p) => p.step === "graph_analysis"
                    )?.status
                  }
                  isCancelled={stopRequested}
                />

                <PipelineStep
                  label="AI Intelligence Report"
                  message="Generating AI assessment"
                  progress={97}
                  currentProgress={currentProgress}
                  status={
                    progress.find(
                      (p) => p.step === "ai_report"
                    )?.status
                  }
                  isCancelled={stopRequested}
                />

              </div>

            </div>

          </section>
        )}

        {/* ====================================================
            RESULTS - Only render if analysis exists and not loading
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
                  <GraphView
                    graph={{
                      ...graph,
                      provenance: provenance
                    }}
                    domain={analysis.domain}
                    subdomainCount={statistics.subdomains || 0}
                    allSubdomains={subdomains}  // <-- Add this line
                  />
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
                      first 5
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
                VIRUSTOTAL INTELLIGENCE (ENHANCED)
            ================================================== */}

            <section className="panel-section">

              <div className="panel">

                <div className="panel-header">

                  <div>

                    <p className="eyebrow">
                      07 / EXTERNAL INTELLIGENCE
                    </p>

                    <h3>
                      VirusTotal Analysis
                    </h3>

                    <p className="panel-description">
                      Comprehensive threat intelligence from 70+ security vendors
                    </p>

                  </div>

                  <div className="panel-icon">
                    <Shield size={20} />
                  </div>

                </div>

                {/* Check if we have VirusTotal data */}
                {virustotal && typeof virustotal === 'object' && !virustotal.error ? (
                  <>
                    {/* Risk Score Card */}
                    <div className="vt-risk-section">
                      <div className={`vt-risk-score ${vtRiskScore >= 70 ? 'critical' : vtRiskScore >= 40 ? 'high' : vtRiskScore >= 20 ? 'medium' : 'low'}`}>
                        <div className="vt-risk-number">
                          {vtRiskScore}
                          <span>/100</span>
                        </div>
                        <div className="vt-risk-label">
                          Risk Score
                        </div>
                        <div className="vt-risk-level">
                          {vtRiskScore >= 70 ? 'CRITICAL' :
                            vtRiskScore >= 40 ? 'HIGH' :
                              vtRiskScore >= 20 ? 'MEDIUM' : 'LOW'}
                        </div>
                      </div>

                      <div className="vt-stats-grid">
                        <div className="vt-stat">
                          <span className="vt-stat-label">Malicious</span>
                          <span className="vt-stat-value malicious">
                            {vtSecuritySummary.malicious || 0}
                          </span>
                        </div>
                        <div className="vt-stat">
                          <span className="vt-stat-label">Suspicious</span>
                          <span className="vt-stat-value suspicious">
                            {vtSecuritySummary.suspicious || 0}
                          </span>
                        </div>
                        <div className="vt-stat">
                          <span className="vt-stat-label">Harmless</span>
                          <span className="vt-stat-value harmless">
                            {vtSecuritySummary.harmless || 0}
                          </span>
                        </div>
                        <div className="vt-stat">
                          <span className="vt-stat-label">Undetected</span>
                          <span className="vt-stat-value undetected">
                            {vtSecuritySummary.undetected || 0}
                          </span>
                        </div>
                        <div className="vt-stat">
                          <span className="vt-stat-label">Vendors</span>
                          <span className="vt-stat-value">
                            {vtSecuritySummary.total_vendors || 0}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Risk Factors */}
                    {vtRiskFactors.length > 0 && (
                      <div className="vt-risk-factors">
                        <h4>⚠️ Risk Factors</h4>
                        {vtRiskFactors.map((factor, index) => (
                          <div key={index} className={`vt-risk-factor ${factor.severity || 'low'}`}>
                            <div className="vt-factor-header">
                              <span className={`vt-factor-badge ${factor.severity || 'low'}`}>
                                {(factor.severity || 'low').toUpperCase()}
                              </span>
                              <span className="vt-factor-description">{factor.description}</span>
                            </div>
                            {factor.details && factor.details.length > 0 && (
                              <ul className="vt-factor-details">
                                {factor.details.map((detail, i) => (
                                  <li key={i}>{detail}</li>
                                ))}
                              </ul>
                            )}
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Vendor Breakdown */}
                    {vtVendorBreakdown.length > 0 && (
                      <div className="vt-vendors">
                        <h4>Security Vendor Analysis</h4>
                        <div className="vt-vendor-grid">
                          {vtVendorBreakdown
                            .filter(v => v.status === 'malicious' || v.status === 'suspicious')
                            .slice(0, 10)
                            .map((vendor, index) => (
                              <div key={index} className={`vt-vendor-item ${vendor.status}`}>
                                <span className="vt-vendor-name">{vendor.vendor}</span>
                                <span className={`vt-vendor-status ${vendor.status}`}>
                                  {vendor.status}
                                </span>
                                <span className="vt-vendor-result">{vendor.result}</span>
                              </div>
                            ))}
                        </div>
                        {vtVendorBreakdown.filter(v => v.status === 'malicious' || v.status === 'suspicious').length > 10 && (
                          <div className="vt-vendor-more">
                            +{vtVendorBreakdown.filter(v => v.status === 'malicious' || v.status === 'suspicious').length - 10} more vendors
                          </div>
                        )}
                      </div>
                    )}

                    {/* WHOIS Info */}
                    {vtWhois && (vtWhois.registrar || vtWhois.creation_date) && (
                      <div className="vt-whois">
                        <h4>WHOIS Information</h4>
                        <div className="vt-whois-grid">
                          {vtWhois.registrar && (
                            <div className="vt-whois-item">
                              <span>Registrar</span>
                              <strong>{vtWhois.registrar}</strong>
                            </div>
                          )}
                          {vtWhois.creation_date && (
                            <div className="vt-whois-item">
                              <span>Creation Date</span>
                              <strong>{vtWhois.creation_date}</strong>
                            </div>
                          )}
                          {vtWhois.expiration_date && (
                            <div className="vt-whois-item">
                              <span>Expiration Date</span>
                              <strong>{vtWhois.expiration_date}</strong>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Community Votes */}
                    {vtCommunityVotes && (vtCommunityVotes.harmless !== undefined || vtCommunityVotes.malicious !== undefined) && (
                      <div className="vt-community">
                        <h4>Community Trust</h4>
                        <div className="vt-community-bar">
                          {(() => {
                            const total = (vtCommunityVotes.harmless || 0) + (vtCommunityVotes.malicious || 0);
                            const harmlessPct = total > 0 ? (vtCommunityVotes.harmless || 0) / total * 100 : 100;
                            return (
                              <div
                                className="vt-community-fill"
                                style={{ width: `${harmlessPct}%` }}
                              />
                            );
                          })()}
                        </div>
                        <div className="vt-community-stats">
                          <span>👍 {vtCommunityVotes.harmless || 0} harmless</span>
                          <span>👎 {vtCommunityVotes.malicious || 0} malicious</span>
                        </div>
                      </div>
                    )}
                  </>
                ) : (
                  <div className="empty-inline">
                    {virustotal?.error || "No VirusTotal intelligence available."}
                  </div>
                )}

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

      </main>

    </div>
  );
}

// ================================================================
// PIPELINE STEP - IMPROVED WITH REAL-TIME STATUS
// ================================================================

function PipelineStep({
  label,
  message,
  progress,
  currentProgress,
  status,
  isCancelled,
}) {
  const isCancelledState = status === "cancelled" || isCancelled === true;
  const isComplete = status === "completed" && !isCancelledState;
  const isRunning = status === "running" && !isCancelledState;
  const isActive = currentProgress >= progress && !isComplete && !isCancelledState;

  // Show the actual progress value
  const displayProgress = isComplete ? 100 : isRunning ? currentProgress : progress;

  return (
    <div className={`pipeline-step ${isComplete ? "completed" : isRunning ? "running" : isActive ? "active" : ""} ${isCancelledState ? "cancelled" : ""}`}>
      <div className="pipeline-step-icon">
        {isComplete ? (
          <CheckCircle2 size={16} />
        ) : isRunning ? (
          <Loader2 size={16} className="spin" />
        ) : isCancelledState ? (
          <Square size={16} />
        ) : (
          <CircleDot size={16} />
        )}
      </div>

      <div className="pipeline-step-content">
        <strong>{label}</strong>
        <span>
          {isComplete ? "Complete" :
            isRunning ? message :
              isCancelledState ? "Cancelled" :
                isActive ? "Processing..." :
                  "Waiting"}
        </span>
      </div>

      <div className="pipeline-step-progress">
        {isCancelledState ? "✕" :
          isComplete ? "✓" :
            isRunning ? `${Math.round(currentProgress)}%` :
              isActive ? `${Math.round(currentProgress)}%` :
                `${progress}%`}
      </div>
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