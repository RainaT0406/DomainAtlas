import {
  useEffect,
  useRef,
  useState,
} from "react";

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
  Plug,
} from "lucide-react";

import GraphView from "./GraphView";

import PipelineStep from "./components/PipelineStep";
import PortScanResults from "./components/PortScanResults";
import StatCard from "./components/StatCard";
import InfoRow from "./components/InfoRow";
import PatternCard from "./components/PatternCard";
import AIReport from "./components/AIReport";
import ScanTimer from "./components/ScanTimer";
import History from "./components/History";
import {
  useScanTimer,
} from "./utils/useScanTimer";
import {
  normalizeAnalysisData,
} from "./utils/analysisData";

import {
  downloadSubdomainsPDF,
  downloadAIReportPDF,
} from "./utils/pdfExport";

import "./App.css";

const API_BASE =
  "http://127.0.0.1:8000";

function App() {
  // ============================================================
  // STATE
  // ============================================================

  const [domain, setDomain] = useState("");
  const [analysis, setAnalysis] = useState(null);

  const [loading, setLoading] =
    useState(false);

  const [error, setError] =
    useState("");

  const [progress, setProgress] =
    useState([]);

  const {
  elapsed: scanElapsed,
  finalTime: scanFinalTime,
} = useScanTimer(loading);

  const [showIntro, setShowIntro] =
    useState(true);

  const [stopRequested, setStopRequested] =
    useState(false);

  const [scanId, setScanId] =
    useState(null);

  const [activeNav, setActiveNav] =
    useState("overview");
  
  const [currentPage, setCurrentPage] = useState("dashboard");

  // ============================================================
  // SCAN LIFECYCLE REFS
  // ============================================================

  const scanGenerationRef =
    useRef(0);

  const eventSourceRef =
    useRef(null);
  const activeScanIdRef =
    useRef(null);

  const abortControllerRef =
    useRef(null);

  const stopRequestedRef =
    useRef(false);

  // ============================================================
  // SECTION REFS
  // ============================================================

  const dashboardRef =
    useRef(null);

  const infrastructureRef =
    useRef(null);

  const graphRef =
    useRef(null);

  const subdomainsRef =
    useRef(null);

  const certificatesRef =
    useRef(null);

  const portsRef =
    useRef(null);

  const virustotalRef =
    useRef(null);

  const aiReportRef =
    useRef(null);

  // ============================================================
  // NAVIGATION
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
// VIEW HISTORICAL SCAN
// ============================================================

const viewHistoricalScan = async (scanId) => {
  try {
    setError("");
    setLoading(true);

    const response = await fetch(
      `http://127.0.0.1:8000/history/${encodeURIComponent(scanId)}`
    );

    if (!response.ok) {
      throw new Error("Failed to load historical scan.");
    }

    const data = await response.json();
    const historicalResult = data.result;

    if (!historicalResult) {
      throw new Error(
        "Historical scan contains no result data."
      );
    }

    const rawData = historicalResult.raw_data || {};
    const graphAnalysis =
      historicalResult.graph_analysis || {};

    /*
     * Rebuild the frontend analysis structure from
     * the data stored in the history snapshot.
     */
    const rawVirusTotal =
      rawData.virustotal ||
      historicalResult.virustotal ||
      {};

    const historicalVirusTotal = {
      domain: rawVirusTotal.domain || "",
      risk_score: rawVirusTotal.risk_score ?? 0,
      reputation: rawVirusTotal.reputation ?? 0,
      security_summary:
        rawVirusTotal.security_summary || {},
      whois_info:
        rawVirusTotal.whois_info || {},
      vendor_breakdown: [],
      risk_factors: [],
      community_votes: {},
    };
    const restoredResult = {
      ...historicalResult,

      infrastructure:
        graphAnalysis.infrastructure || {
          subdomains: rawData.subdomains || [],
          ip_addresses: rawData.ips || [],
          asns: [
            ...new Set(
              (rawData.ip_metadata || [])
                .map((item) => item?.asn)
                .filter(Boolean)
            ),
          ],
          organizations: [
            ...new Set(
              (rawData.ip_metadata || [])
                .map((item) => item?.organization)
                .filter(Boolean)
            ),
          ],
          certificates: rawData.certificates || [],
          certificate_details: [],
        },

      statistics:
        graphAnalysis.statistics ||
        historicalResult.statistics ||
        {},

      ip_version_summary:
        graphAnalysis.ip_version_summary ||
        historicalResult.ip_version_summary ||
        {},

      subdomain_patterns:
        graphAnalysis.subdomain_patterns ||
        historicalResult.subdomain_patterns ||
        {},

      observations:
        graphAnalysis.observations ||
        historicalResult.observations ||
        [],

      provenance:
        historicalResult.provenance || [],

      ai_report:
        historicalResult.ai_report || "",

      graph:
        historicalResult.graph || {
          nodes: [],
          edges: [],
          provenance: [],
        },

      virustotal: historicalVirusTotal,

      port_scan:
        rawData.port_scan ||
        historicalResult.port_scan ||
        {},
    };

    const normalizedHistoricalResult =
      normalizeAnalysisData(restoredResult);

    setAnalysis(normalizedHistoricalResult);
    setScanId(data.scan_id || scanId);

    setCurrentPage("dashboard");
    setActiveNav("overview");
    setLoading(false);

    setTimeout(() => {
      window.scrollTo({
        top: 0,
        behavior: "smooth",
      });
    }, 100);

  } catch (error) {
    console.error(
      "Failed to load historical scan:",
      error
    );

    setError(
      error.message ||
      "Unable to load historical scan."
    );

    setLoading(false);
  }
};

  
  // ============================================================
  // SCROLL TRACKING
  // ============================================================

  useEffect(() => {
    if (!analysis && !loading) {
      return undefined;
    }

    const handleScroll = () => {
      const scrollY =
        window.scrollY + 120;

      const sections = [
        {
          ref: dashboardRef,
          name: "overview",
        },
        {
          ref: infrastructureRef,
          name: "infrastructure",
        },
        {
          ref: graphRef,
          name: "graph",
        },
        {
          ref: subdomainsRef,
          name: "subdomains",
        },
        {
          ref: certificatesRef,
          name: "certificates",
        },
        {
          ref: portsRef,
          name: "ports",
        },
        {
          ref: virustotalRef,
          name: "virustotal",
        },
        {
          ref: aiReportRef,
          name: "ai",
        },
      ];

      let activeSection =
        "overview";

      for (const section of sections) {
        if (!section.ref.current) {
          continue;
        }

        const rect =
          section.ref.current.getBoundingClientRect();

        const top =
          rect.top + window.scrollY;

        const bottom =
          top + rect.height;

        if (
          scrollY >= top - 50 &&
          scrollY < bottom - 50
        ) {
          activeSection =
            section.name;

          break;
        }
      }

      setActiveNav(activeSection);
    };

    window.addEventListener(
      "scroll",
      handleScroll,
      { passive: true }
    );

    const timeout =
      window.setTimeout(
        handleScroll,
        100
      );

    return () => {
      window.removeEventListener(
        "scroll",
        handleScroll
      );

      window.clearTimeout(timeout);
    };
  }, [analysis, loading]);

  // ============================================================
  // CLEANUP
  // ============================================================

  const cleanupScanResources = () => {
    const es =
      eventSourceRef.current;

    if (es) {
      try {
        es.close();
      } catch (err) {
        console.warn(
          "[!] EventSource cleanup failed:",
          err
        );
      }
    }

    eventSourceRef.current =
      null;

    const controller =
      abortControllerRef.current;

    if (controller) {
      try {
        controller.abort();
      } catch (err) {
        console.warn(
          "[!] Abort cleanup failed:",
          err
        );
      }
    }

    abortControllerRef.current =
      null;
  };

  // ============================================================
  // COMPONENT UNMOUNT CLEANUP
  // ============================================================

  useEffect(() => {
    return () => {
      scanGenerationRef.current += 1;

      stopRequestedRef.current =
        true;

      cleanupScanResources();
    };
  }, []);

  // ============================================================
  // STOP SCAN
  // ============================================================

  const stopAnalysis = async () => {
    if (!loading) {
      return;
    }

    console.log(
      "[*] User requested scan stop"
    );

    const targetDomain = domain
      .trim()
      .toLowerCase()
      .replace(/\.$/, "");

    const currentScanId =
      scanId;

    // IMPORTANT:
    // Mark the scan stale BEFORE aborting anything.
    // This prevents late SSE/fetch events from
    // modifying state after cancellation.
    stopRequestedRef.current =
      true;

    scanGenerationRef.current += 1;

    cleanupScanResources();

    setLoading(false);
    setStopRequested(true);

    setProgress([]);

    setAnalysis(null);
    setScanId(null);

    setShowIntro(true);
    setActiveNav("overview");

    setError(
      "Scan cancelled by user."
    );

    const payload = {};

    if (targetDomain) {
      payload.domain =
        targetDomain;
    }

    if (currentScanId) {
      payload.scan_id =
        currentScanId;
    }

    try {
      console.log(
        "[*] Sending backend stop request:",
        payload
      );

      const response =
        await fetch(
          `${API_BASE}/analyze/stop`,
          {
            method: "POST",
            headers: {
              "Content-Type":
                "application/json",
            },
            body: JSON.stringify(
              payload
            ),
          }
        );

      if (!response.ok) {
        console.warn(
          "[!] Backend stop request returned:",
          response.status
        );

        return;
      }

      const data =
        await response.json();

      console.log(
        "[*] Backend stop response:",
        data
      );
    } catch (err) {
      console.warn(
        "[!] Could not notify backend about stop:",
        err
      );
    }
  };

  // ============================================================
  // PROGRESS UPDATE
  // ============================================================

  const processProgressUpdate = (
    update,
    generation
  ) => {
    if (
      scanGenerationRef.current !==
      generation
    ) {
      return false;
    }

    if (
      stopRequestedRef.current
    ) {
      return false;
    }

    if (
      !update ||
      typeof update !== "object"
    ) {
      return false;
    }

    if (
      update.status ===
      "cancelled"
    ) {
      console.log(
        "[*] Ignoring backend cancellation event"
      );

      return false;
    }

    setProgress((previous) => {
      const existingIndex =
        previous.findIndex(
          (item) =>
            item.step ===
            update.step
        );

      if (
        existingIndex === -1
      ) {
        return [
          ...previous,
          update,
        ];
      }

      const next = [
        ...previous,
      ];

      next[existingIndex] =
        update;

      return next;
    });

    return true;
  };
  // ============================================================
  // SUBDOMAIN DISCOVERY STATUS
  // ============================================================

  const getCombinedDiscoveryStatus =
    () => {
      const discoverySteps =
        progress.filter(
          (item) =>
            item.step ===
              "subfinder" ||
            item.step ===
              "amass"
        );

      if (
        discoverySteps.some(
          (item) =>
            item.status ===
            "running"
        )
      ) {
        return "running";
      }

      if (
        discoverySteps.length > 0 &&
        discoverySteps.every(
          (item) =>
            item.status ===
            "completed"
        )
      ) {
        return "completed";
      }

      if (
        discoverySteps.some(
          (item) =>
            item.status ===
            "cancelled"
        )
      ) {
        return "cancelled";
      }

      return undefined;
    };
const getCurrentActivity =
  () => {
    const runningStep =
      progress.find(
        (item) =>
          item.status ===
          "running"
      );

    if (
      runningStep
    ) {
      if (
        runningStep.step ===
          "subfinder" ||
        runningStep.step ===
          "amass"
      ) {
        return {
          label:
            "Subdomain Discovery",
          message:
            "Running Subfinder and Amass...",
        };
      }

      const activityMap = {
        init: {
          label:
            "Initialization",
          message:
            runningStep.message ||
            "Starting analysis pipeline...",
        },
          collection: {
            label: "OSINT Collection",
            message:
              runningStep.message ||
              "Collecting domain intelligence...",
          },



        dns: {
          label:
            "DNS Resolution",
          message:
            runningStep.message ||
            "Querying DNS records...",
        },

        ip_metadata: {
          label:
            "IP Metadata",
          message:
            runningStep.message ||
            "Looking up ASN and organization...",
        },

        certificates: {
          label:
            "Certificate Intelligence",
          message:
            runningStep.message ||
            "Querying Certificate Transparency...",
        },

        virustotal: {
          label:
            "VirusTotal Intelligence",
          message:
            runningStep.message ||
            "Querying VirusTotal API...",
        },

        normalization: {
          label:
            "Entity Normalization",
          message:
            runningStep.message ||
            "Normalizing collected entities...",
        },

        graph_loading: {
          label:
            "Knowledge Graph",
          message:
            runningStep.message ||
            "Loading entities into Neo4j...",
        },

        graph_analysis: {
          label:
            "Graph Analysis",
          message:
            runningStep.message ||
            "Analyzing knowledge graph...",
        },

        ai_report: {
          label:
            "AI Intelligence Report",
          message:
            runningStep.message ||
            "Generating AI assessment...",
        },
      };

      return (
        activityMap[
          runningStep.step
        ] || {
          label:
            runningStep.step ||
            "Processing",
          message:
            runningStep.message ||
            "Processing intelligence...",
        }
      );
    }

    return {
      label:
        "Preparing Analysis",
      message:
        "Initializing collection pipeline...",
    };
  };
  // ============================================================
  // ANALYZE DOMAIN
  // ============================================================

  const analyzeDomain =
    async () => {
      const targetDomain =
        domain
          .trim()
          .toLowerCase()
          .replace(/\.$/, "");

      if (!targetDomain) {
        setError(
          "Please enter a domain."
        );

        return;
      }

      console.log(
        "[*] Starting scan:",
        targetDomain
      );

      // --------------------------------------------------------
      // Invalidate previous scan
      // --------------------------------------------------------

      scanGenerationRef.current += 1;

      const generation =
        scanGenerationRef.current;

      stopRequestedRef.current =
        false;

      cleanupScanResources();

      // --------------------------------------------------------
      // Reset UI
      // --------------------------------------------------------

      setLoading(true);
      setError("");
      setAnalysis(null);

      setProgress([]);

      setShowIntro(false);
      setStopRequested(false);

      setScanId(null);
      setActiveNav("overview");
      activeScanIdRef.current = null;

      // --------------------------------------------------------
      // New AbortController
      // --------------------------------------------------------

      const controller =
        new AbortController();

      abortControllerRef.current =
        controller;

      // --------------------------------------------------------
      // Create SSE connection
      // --------------------------------------------------------

      const eventSource =
        new EventSource(
          `${API_BASE}/analyze/progress`
        );

      eventSourceRef.current =
        eventSource;

      let eventSourceClosed =
        false;

      const isCurrentScan =
        () =>
          scanGenerationRef.current ===
            generation &&
          !controller.signal
            .aborted &&
          !stopRequestedRef.current;

      const closeEventSource =
        () => {
          if (
            eventSourceClosed
          ) {
            return;
          }

          eventSourceClosed =
            true;

          try {
            eventSource.close();
          } catch (err) {
            console.warn(
              "[!] EventSource close failed:",
              err
            );
          }

          if (
            eventSourceRef.current ===
            eventSource
          ) {
            eventSourceRef.current =
              null;
          }
        };

      eventSource.onopen =
        () => {
          if (
            !isCurrentScan()
          ) {
            closeEventSource();
            return;
          }

          console.log(
            "[*] Progress SSE connected"
          );
        };

eventSource.onmessage =
  (event) => {
    if (
      !isCurrentScan()
    ) {
      closeEventSource();
      return;
    }

    try {
      const update =
        JSON.parse(
          event.data
        );

      console.log(
        "[*] Progress SSE:",
        update.scan_id,
        update.step,
        update.status,
        update.progress
      );

      // Ignore progress belonging to another scan.
      // The scan ID becomes available after the POST response,
      // so allow events while scanId is not yet known.
      if (
        scanId &&
        update.scan_id &&
        update.scan_id !== scanId
      ) {
        return;
      }

      processProgressUpdate(
        update,
        generation
      );
    } catch (err) {
      console.error(
        "[!] Invalid SSE message:",
        err,
        event.data
      );
    }
  };

  eventSource.onerror =
  (event) => {
    if (
      !isCurrentScan()
    ) {
      closeEventSource();
      return;
    }

    console.warn(
      "[!] Progress SSE connection error; EventSource will retry.",
      event
    );
  };

      // --------------------------------------------------------
      // Start backend analysis
      // --------------------------------------------------------

      try {
        const response =
          await fetch(
            `${API_BASE}/analyze`,
            {
              method: "POST",
              headers: {
                "Content-Type":
                  "application/json",
                Accept:
                  "application/json",
              },
              body: JSON.stringify({
                domain:
                  targetDomain,
              }),
              signal:
                controller.signal,
            }
          );

        // ------------------------------------------------------
        // Ignore stale result
        // ------------------------------------------------------

        if (
          !isCurrentScan()
        ) {
          return;
        }

        let data;

        try {
          data =
            await response.json();
        } catch {
          throw new Error(
            "The API returned an invalid response."
          );
        }

        if (
          !response.ok
        ) {
          throw new Error(
            data?.detail ||
              "Domain analysis failed."
          );
        }

        if (
          !data?.success
        ) {
          throw new Error(
            "Domain analysis was not successful."
          );
        }

        if (
          !isCurrentScan()
        ) {
          return;
        }

        console.log(
          "[*] Analysis completed:",
          data
        );

        // ------------------------------------------------------
        // Normalize data once
        // ------------------------------------------------------
          console.log(
            "DOMAINATLAS ANALYSIS RESPONSE:",
            data
          );

const safeData =
  normalizeAnalysisData(
    data
  );

// Preserve certificate metadata returned by the backend.
// normalizeAnalysisData may normalize the analysis object
// without retaining certificate_details.
if (
  Array.isArray(
    data?.graph_analysis?.infrastructure?.certificate_details
  )
) {
  safeData.infrastructure = {
    ...(safeData.infrastructure || {}),
    certificate_details:
      data.graph_analysis.infrastructure
        .certificate_details,
  };
}

const completedScanId =
  safeData.scan_id ||
  null;

          activeScanIdRef.current =
            completedScanId;

          setScanId(
            completedScanId
          );

        setAnalysis(
          safeData
        );

        setLoading(false);
        setStopRequested(
          false
        );

        stopRequestedRef.current =
          false;

        // ------------------------------------------------------
        // Close SSE after successful completion
        // ------------------------------------------------------

        closeEventSource();

        setTimeout(() => {
          if (
            scanGenerationRef.current ===
              generation &&
            dashboardRef.current
          ) {
            dashboardRef.current.scrollIntoView(
              {
                behavior:
                  "smooth",
                block: "start",
              }
            );
          }
        }, 300);
      } catch (err) {
        if (
          err?.name ===
          "AbortError"
        ) {
          console.log(
            "[*] Analysis fetch aborted"
          );

          return;
        }

        if (
          !isCurrentScan()
        ) {
          console.log(
            "[*] Ignoring stale scan error"
          );

          return;
        }

        console.error(
          "[!] Domain analysis error:",
          err
        );

        setLoading(false);

        setError(
          err?.message ||
            "Unable to connect to the DomainAtlas API."
        );

        closeEventSource();
      } finally {
        if (
          scanGenerationRef.current !==
          generation
        ) {
          return;
        }

        closeEventSource();

        if (
          abortControllerRef.current ===
          controller
        ) {
          abortControllerRef.current =
            null;
        }
      }
    };

  // ============================================================
  // ENTER KEY
  // ============================================================

  const handleKeyDown =
    (event) => {
      if (
        event.key === "Enter" &&
        !loading
      ) {
        analyzeDomain();
      }
    };

  // ============================================================
  // SAFE DATA
  // ============================================================

  const statistics =
    analysis?.statistics || {};

  const infrastructure =
    analysis?.infrastructure || {};

  const ipVersion =
    analysis?.ip_version_summary ||
    {};

  const patterns =
    analysis?.subdomain_patterns ||
    {};

  const observations =
    Array.isArray(
      analysis?.observations
    )
      ? analysis.observations
      : [];

  const provenance =
    Array.isArray(
      analysis?.provenance
    )
      ? analysis.provenance
      : [];

  const aiReport =
    typeof analysis?.ai_report ===
    "string"
      ? analysis.ai_report
      : "";

  const graph =
    analysis?.graph || {
      nodes: [],
      edges: [],
      provenance: [],
    };

  const subdomains =
    Array.isArray(
      infrastructure.subdomains
    )
      ? infrastructure.subdomains
      : [];
    console.log(
      "[App] infrastructure.subdomains sample:",
      infrastructure.subdomains?.[0]
    );

    console.log(
      "[App] subdomains sample:",
      subdomains[0]
    );

  const certificates =
    Array.isArray(
      infrastructure.certificates
    )
      ? infrastructure.certificates
      : [];

  const certificateDetails =
    Array.isArray(
      infrastructure.certificate_details
    )
      ? infrastructure.certificate_details
      : [];

  const ipAddresses =
    Array.isArray(
      infrastructure.ip_addresses
    )
      ? infrastructure.ip_addresses
      : [];

  const asns =
    Array.isArray(
      infrastructure.asns
    )
      ? infrastructure.asns
      : [];

  const organizations =
    Array.isArray(
      infrastructure.organizations
    )
      ? infrastructure.organizations
      : [];

  const virustotal =
    analysis?.virustotal || {};

  // ============================================================
  // VIRUSTOTAL DATA NORMALIZATION
  // ============================================================
  // The backend currently returns VirusTotal detection counts as
  // flat properties. The UI historically expected a nested
  // security_summary object, so normalize both shapes here.

  const vtMalicious =
    Number(
      virustotal?.security_summary?.malicious ??
        virustotal?.malicious
    ) || 0;

  const vtSuspicious =
    Number(
      virustotal?.security_summary?.suspicious ??
        virustotal?.suspicious
    ) || 0;

  const vtHarmless =
    Number(
      virustotal?.security_summary?.harmless ??
        virustotal?.harmless
    ) || 0;

  const vtUndetected =
    Number(
      virustotal?.security_summary?.undetected ??
        virustotal?.undetected
    ) || 0;

  const vtTimeout =
    Number(
      virustotal?.security_summary?.timeout ??
        virustotal?.timeout
    ) || 0;

  const calculatedVendorTotal =
    vtMalicious +
    vtSuspicious +
    vtHarmless +
    vtUndetected +
    vtTimeout;

  const vtTotalVendors =
    Number(
      virustotal?.security_summary?.total_vendors ??
        virustotal?.total_vendors
    ) || calculatedVendorTotal;

  const vtRiskScore =
    Number(
      virustotal?.risk_score
    ) || 0;

  const vtSecuritySummary = {
    malicious: vtMalicious,
    suspicious: vtSuspicious,
    harmless: vtHarmless,
    undetected: vtUndetected,
    timeout: vtTimeout,
    total_vendors: vtTotalVendors,
  };

  const vtVendorBreakdown =
    Array.isArray(
      virustotal?.vendor_breakdown
    )
      ? virustotal.vendor_breakdown
      : [];

  const vtRiskFactors =
    Array.isArray(
      virustotal?.risk_factors
    )
      ? virustotal.risk_factors
      : [];

  const vtWhois = {
    ...(virustotal?.whois_info || {}),
    registrar:
      virustotal?.whois_info?.registrar ||
      virustotal?.registrar ||
      "",
    creation_date:
      virustotal?.whois_info?.creation_date ||
      virustotal?.creation_date ||
      "",
    expiration_date:
      virustotal?.whois_info?.expiration_date ||
      virustotal?.expiration_date ||
      "",
    last_modification_date:
      virustotal?.whois_info?.last_modification_date ||
      virustotal?.last_modification_date ||
      "",
  };

  const vtCommunityVotes =
    virustotal?.community_votes ||
    {};

  const portScanData =
    analysis?.port_scan || {
      scanned_ips: 0,
      open_ports_total: 0,
      results: [],
    };

  // ============================================================
  // OBSERVATION HELPER
  // ============================================================

  const getObservation =
    (keyword) =>
      observations.find(
        (observation) =>
          typeof observation ===
            "string" &&
          observation
            .toLowerCase()
            .includes(
              keyword.toLowerCase()
            )
      );

  const getDetectionCount =
    (keyword) => {
      const observation =
        getObservation(
          keyword
        );

      if (!observation) {
        return "0";
      }

      const match =
        observation.match(
          /\d+/
        );

      return (
        match?.[0] || "0"
      );
    };

  // ============================================================
  // PDF HANDLERS
  // ============================================================

  const handleDownloadSubdomains =
    () => {
      downloadSubdomainsPDF({
        domain:
          analysis?.domain ||
          domain,
        subdomains,
      });
    };

  const handleDownloadAIReport =
    () => {
      downloadAIReportPDF({
        domain:
          analysis?.domain ||
          domain,
        aiReport,
      });
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

          <NavButton
              active={
                currentPage === "dashboard" &&
                activeNav === "overview"
              }
            icon={
              <BarChart3
                size={17}
              />
            }
            label="Overview"
            onClick={() => {
              setCurrentPage("dashboard");
              scrollToSection(
                dashboardRef,
                "overview"
              );
            }}
          />

        <NavButton
          active={
            currentPage === "dashboard" &&
            activeNav === "infrastructure"
          }
          icon={
            <Server
              size={17}
            />
          }
          label="Infrastructure"
          onClick={() => {
            setCurrentPage("dashboard");
            scrollToSection(
              infrastructureRef,
              "infrastructure"
            );
          }}
        />

        <NavButton
          active={
            currentPage === "dashboard" &&
            activeNav === "graph"
          }
          icon={
            <Network
              size={17}
            />
          }
          label="Relationship Graph"
          onClick={() => {
            setCurrentPage("dashboard");
            scrollToSection(
              graphRef,
              "graph"
            );
          }}
        />

        <NavButton
          active={
            currentPage === "dashboard" &&
            activeNav === "subdomains"
          }
          icon={
            <Globe
              size={17}
            />
          }
          label="Subdomains"
          onClick={() => {
            setCurrentPage("dashboard");
            scrollToSection(
              subdomainsRef,
              "subdomains"
            );
          }}
        />

        <NavButton
          active={
            currentPage === "dashboard" &&
            activeNav === "certificates"
          }
          icon={
            <FileKey
              size={17}
            />
          }
          label="Certificates"
          onClick={() => {
            setCurrentPage("dashboard");
            scrollToSection(
              certificatesRef,
              "certificates"
            );
          }}
        />

        <NavButton
          active={
            currentPage === "dashboard" &&
            activeNav === "ports"
          }
          icon={
            <Plug
              size={17}
            />
          }
          label="Port Scan"
          onClick={() => {
            setCurrentPage("dashboard");
            scrollToSection(
              portsRef,
              "ports"
            );
          }}
        />

        <p className="nav-label">
          INTELLIGENCE
        </p>

        <NavButton
          active={
            currentPage === "dashboard" &&
            activeNav === "virustotal"
          }
          icon={
            <Shield
              size={17}
            />
          }
          label="VirusTotal"
          onClick={() => {
            setCurrentPage("dashboard");
            scrollToSection(
              virustotalRef,
              "virustotal"
            );
          }}
        />

        <NavButton
          active={
            currentPage === "dashboard" &&
            activeNav === "ai"
          }
          icon={
            <Brain
              size={17}
            />
          }
          label="AI Assessment"
          onClick={() => {
            setCurrentPage("dashboard");
            scrollToSection(
              aiReportRef,
              "ai"
            );
          }}
        />
                {/* ======================================================
              HISTORY
          ====================================================== */}

          <div className="sidebar-history-divider" />

          <NavButton
            active={
              currentPage === "history"
            }
            icon={
              <Database
                size={17}
              />
            }
            label="Scan History"
            onClick={() => {
              setCurrentPage("history");
              setActiveNav("history");
              window.scrollTo({
                top: 0,
                behavior: "smooth",
              });
            }}
          />
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

      {currentPage === "history" ? (
        <History
          onViewScan={viewHistoricalScan}
        />
      ) : (
          <>
        {/* ====================================================
            HERO
        ==================================================== */}

        {showIntro &&
          !analysis &&
          !loading && (
            <section className="hero-section">

              <div className="hero-glow" />
              <div className="hero-grid" />

              <div className="hero-content">

                <div className="hero-badge">
                  <Sparkles
                    size={14}
                  />
                  <span>
                    Next-Gen OSINT
                    Platform
                  </span>
                </div>

                <h1 className="hero-title">
                  Map the Digital
                  <br />
                  <span className="hero-highlight">
                    Frontier
                  </span>
                </h1>

                <p className="hero-description">
                  DomainAtlas combines
                  automated OSINT
                  collection, knowledge
                  graph correlation, and
                  AI-powered analysis to
                  give you complete
                  visibility into any
                  domain's digital
                  footprint.
                </p>

                <div className="hero-features">

                  <div className="hero-feature">
                    <Compass
                      size={16}
                    />
                    <span>
                      Intelligent
                      Discovery
                    </span>
                  </div>

                  <div className="hero-feature">
                    <Network
                      size={16}
                    />
                    <span>
                      Graph Correlation
                    </span>
                  </div>

                  <div className="hero-feature">
                    <Brain
                      size={16}
                    />
                    <span>
                      AI Assessment
                    </span>
                  </div>

                  <div className="hero-feature">
                    <Zap
                      size={16}
                    />
                    <span>
                      Real-time Analysis
                    </span>
                  </div>

                </div>

                <div className="hero-search-wrapper">

                  <div className="search-box hero-search">

                    <div className="search-icon">
                      <Search
                        size={19}
                      />
                    </div>

                    <input
                      type="text"
                      placeholder="Enter a domain to analyze…"
                      value={domain}
                      onChange={(event) =>
                        setDomain(
                          event.target
                            .value
                        )
                      }
                      onKeyDown={
                        handleKeyDown
                      }
                      disabled={loading}
                      className="hero-input"
                    />

                    <button
                      onClick={
                        analyzeDomain
                      }
                      disabled={loading}
                      className="analyze-button hero-analyze-btn"
                    >
                      {loading
                        ? "Analyzing..."
                        : "Analyze Domain"}

                      {!loading && (
                        <ArrowRight
                          size={17}
                        />
                      )}
                    </button>

                  </div>

                  {error && (
                    <div className="error-message">
                      <Shield
                        size={15}
                      />
                      <span>
                        {error}
                      </span>
                    </div>
                  )}

                  <div className="hero-search-meta">
                    <span>
                      <Target
                        size={12}
                      />
                      DNS · Subdomains ·
                      Certificates · Ports ·
                      Graph · AI
                    </span>
                  </div>

                </div>

              </div>
            </section>
          )}

        {/* ====================================================
            TOP HEADER
        ==================================================== */}

        {(analysis ||
          loading) && (
          <header
            className="topbar"
            ref={dashboardRef}
          >

            <div className="topbar-left">

              <div className="breadcrumb">
                <span>
                  DOMAIN ATLAS
                </span>

                <ChevronRight
                  size={13}
                />

                <span>
                  ANALYSIS
                </span>
              </div>

              <h2>
                Domain Intelligence
              </h2>

              <p>
                Automated collection,
                correlation and
                intelligence analysis.
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
                    ? `Collecting intelligence for ${domain}`
                    : analysis?.domain ||
                      "Awaiting target"}
                </span>
              </div>

            </div>

          </header>
        )}

        {/* ====================================================
            LOADING PIPELINE
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
                    OSINT Analysis in
                    Progress
                  </h3>

                  <p>
                    Real-time collection
                    and analysis for{" "}
                    <strong>
                      {domain}
                    </strong>
                  </p>
                </div>

                <div className="pipeline-header-right">
                    <ScanTimer
                        running={loading}
                        elapsed={scanElapsed}
                      />
                  <button
                    className="stop-button"
                    onClick={
                      stopAnalysis
                    }
                    disabled={!loading}
                  >
                    <Square
                      size={16}
                    />
                    Stop Scan
                  </button>

                </div>

              </div>

         <div className="current-activity">

          <div className="current-activity-header">
            <span className="current-activity-indicator">
              <Loader2
                size={15}
                className="spin"
              />
            </span>

            <span>
              CURRENT ACTIVITY
            </span>
          </div>

          <div className="current-activity-content">

            <strong>
              {getCurrentActivity().label}
            </strong>

            <span>
              {getCurrentActivity().message}
            </span>

          </div>

        </div>

        <div className="pipeline-section-label">
          COLLECTION PIPELINE
        </div>
      

              <div className="pipeline-steps">

                <PipelineStep
                  label="Initialization"
                  message="Pipeline started"
                
                  status={
                    progress.find(
                      (p) =>
                        p.step ===
                        "init"
                    )?.status
                  }
                  isCancelled={
                    stopRequested
                  }
                />

                <PipelineStep
                  label="DNS Resolution"
                  message="Querying DNS records"
               
                  status={
                    progress.find(
                      (p) =>
                        p.step ===
                        "dns"
                    )?.status
                  }
                  isCancelled={
                    stopRequested
                  }
                />

                <PipelineStep
                  label="IP Metadata"
                  message="Looking up ASN and organization"
               
                  status={
                    progress.find(
                      (p) =>
                        p.step ===
                        "ip_metadata"
                    )?.status
                  }
                  isCancelled={
                    stopRequested
                  }
                />

                <PipelineStep
                  label="Subdomain Discovery"
                  message="Running subdomain enumeration"
               
                  status={getCombinedDiscoveryStatus()}
                  isCancelled={
                    stopRequested
                  }
                />

                <PipelineStep
                  label="Certificate Intelligence"
                  message="Querying Certificate Transparency"
                
                  status={
                    progress.find(
                      (p) =>
                        p.step ===
                        "certificates"
                    )?.status
                  }
                  isCancelled={
                    stopRequested
                  }
                />

                <PipelineStep
                  label="VirusTotal Intelligence"
                  message="Querying VirusTotal API"
                
                  status={
                    progress.find(
                      (p) =>
                        p.step ===
                        "virustotal"
                    )?.status
                  }
                  isCancelled={
                    stopRequested
                  }
                />

                <PipelineStep
                  label="Entity Normalization"
                  message="Normalizing entities"
               
                  status={
                    progress.find(
                      (p) =>
                        p.step ===
                        "normalization"
                    )?.status
                  }
                  isCancelled={
                    stopRequested
                  }
                />

                <PipelineStep
                  label="Knowledge Graph"
                  message="Loading into Neo4j"
               
                  status={
                    progress.find(
                      (p) =>
                        p.step ===
                        "graph_loading"
                    )?.status
                  }
                  isCancelled={
                    stopRequested
                  }
                />

                <PipelineStep
                  label="Graph Analysis"
                  message="Analyzing knowledge graph"
                
                  status={
                    progress.find(
                      (p) =>
                        p.step ===
                        "graph_analysis"
                    )?.status
                  }
                  isCancelled={
                    stopRequested
                  }
                />

                <PipelineStep
                  label="AI Intelligence Report"
                  message="Generating AI assessment"
              
                  status={
                    progress.find(
                      (p) =>
                        p.step ===
                        "ai_report"
                    )?.status
                  }
                  isCancelled={
                    stopRequested
                  }
                />

              </div>
            </div>
          </section>
        )}

        {/* ====================================================
            RESULTS
        ==================================================== */}

        {analysis &&
          !loading && (
            <>

              {/* ==============================================
                  COMPLETE BANNER
              ============================================== */}

              <section className="analysis-banner">

                <div>
                  <p className="eyebrow">
                    ANALYSIS COMPLETE
                  </p>

                  <h3>
                    {analysis.domain}
                  </h3>

                  <p>
                    Intelligence collection
                    and graph analysis
                    completed successfully.
                  </p>
                </div>

                  <ScanTimer
                    completed={!loading && !!analysis}
                    finalTime={scanFinalTime}
                  />

              </section>

              {/* ==============================================
                  OVERVIEW
              ============================================== */}

              <section className="results-section">

                <div className="section-heading">

                  <div>
                    <p className="eyebrow">
                      01 / OVERVIEW
                    </p>

                    <h3>
                      Infrastructure
                      Summary
                    </h3>
                  </div>

                  <span className="domain-badge">
                    <Globe
                      size={14}
                    />
                    {analysis.domain}
                  </span>

                </div>

                <div className="stat-grid">

                  <StatCard
                    icon={<Globe />}
                    label="Subdomains"
                    value={
                      statistics.subdomains ??
                      0
                    }
                    description="Discovered"
                  />

                  <StatCard
                    icon={<Server />}
                    label="IP Addresses"
                    value={
                      statistics.ip_addresses ??
                      0
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
                      statistics.asns ??
                      0
                    }
                    description="Identified"
                  />

                  <StatCard
                    icon={<Database />}
                    label="Organizations"
                    value={
                      statistics.organizations ??
                      0
                    }
                    description="Associated"
                  />

                  <StatCard
                    icon={<FileKey />}
                    label="Certificates"
                    value={
                      statistics.certificates ??
                      0
                    }
                    description="Identified"
                  />

                  <StatCard
                    icon={<Plug />}
                    label="Open Ports"
                    value={
                      portScanData.open_ports_total ||
                      0
                    }
                    description={`${portScanData.scanned_ips || 0} IPs scanned`}
                  />

                </div>

              </section>

              {/* ==============================================
                  INFRASTRUCTURE
              ============================================== */}

              <section
                ref={
                  infrastructureRef
                }
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
                        Observed network
                        infrastructure
                        associated with the
                        target domain.
                      </p>
                    </div>

                    <div className="panel-icon">
                      <Server
                        size={20}
                      />
                    </div>

                  </div>

                  <div className="info-list">

                    {ipAddresses
                      .slice(0, 8)
                      .map((ip) => (
                        <InfoRow
                          key={ip}
                          label={
                            ip.includes(
                              ":"
                            )
                              ? "IPv6"
                              : "IPv4"
                          }
                          value={ip}
                        />
                      ))}

                    {asns.map(
                      (asn) => (
                        <InfoRow
                          key={asn}
                          label="ASN"
                          value={asn}
                        />
                      )
                    )}

                    {organizations.map(
                      (organization) => (
                        <InfoRow
                          key={
                            organization
                          }
                          label="Organization"
                          value={
                            organization
                          }
                        />
                      )
                    )}

                    {ipAddresses.length ===
                      0 &&
                      asns.length ===
                        0 &&
                      organizations.length ===
                        0 && (
                        <div className="empty-inline">
                          No infrastructure
                          data available.
                        </div>
                      )}

                  </div>

                </div>

              </section>

              {/* ==============================================
                  GRAPH
              ============================================== */}

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
                        Correlated entities
                        and observed
                        relationships within
                        the collected dataset.
                      </p>
                    </div>

                    <div className="panel-icon">
                      <Network
                        size={20}
                      />
                    </div>

                  </div>

                  <div className="graph-wrapper">

                    <GraphView
                      graph={{
                        ...graph,
                        provenance:
                          provenance,
                      }}
                      domain={
                        analysis.domain
                      }
                      subdomainCount={
                        statistics.subdomains ||
                        0
                      }
                      allSubdomains={
                        subdomains
                      }
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

              {/* ==============================================
                  SUBDOMAINS
              ============================================== */}

              <section
                ref={
                  subdomainsRef
                }
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
                        Complete list of
                        discovered
                        subdomains.
                      </p>
                    </div>

                    <button
                      className="download-button"
                      onClick={
                        handleDownloadSubdomains
                      }
                      disabled={
                        subdomains.length ===
                        0
                      }
                    >
                      <Download
                        size={15}
                      />
                      Export Inventory
                    </button>

                  </div>

                  <div className="subdomain-summary">

                    <div className="inventory-count">
                      <strong>
                        {subdomains.length}
                      </strong>

                      <span>
                        discovered
                        subdomains
                      </span>
                    </div>

                    <div className="inventory-note">
                      <Layers3
                        size={14}
                      />

                      Graph visualization:

                      <strong>
                        first 5
                      </strong>
                    </div>

                  </div>

                  {subdomains.length >
                  0 ? (
                    <div className="subdomain-table-wrapper">

                      <table className="subdomain-table">

                        <thead>
                          <tr>
                            <th>#</th>
                            <th>
                              Subdomain
                            </th>
                          </tr>
                        </thead>

                        <tbody>

                          {subdomains.map(
                            (
                              subdomainData,
                              index
                            ) => {
                              const subdomain =
                                typeof subdomainData === "string"
                                  ? subdomainData
                                  : subdomainData?.subdomain || "";

                              const active =
                                typeof subdomainData === "object" &&
                                subdomainData?.active === true;

                              return (
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
                              );
                            }
                          )}

                        </tbody>

                      </table>

                    </div>
                  ) : (
                    <div className="empty-inline">
                      No subdomains
                      discovered.
                    </div>
                  )}

                </div>

              </section>

{/* ==============================================
    CERTIFICATES
============================================== */}

<section
  ref={
    certificatesRef
  }
  className="panel-section"
>

  <div className="panel">

    <div className="panel-header">

      <div>
        <p className="eyebrow">
          05 / TLS
          INTELLIGENCE
        </p>

        <h3>
          Certificate
          Inventory
        </h3>

        <p className="panel-description">
          Certificate identifiers, cryptographic fingerprints,
          validity periods, and revocation status observed
          during OSINT collection.
        </p>
      </div>

      <div className="panel-icon">
        <FileKey
          size={20}
        />
      </div>

    </div>

<div className="certificate-scroll">
  <div className="certificate-grid">
  {certificateDetails.length > 0 ? (
    certificateDetails.map(
      (certificate, index) => {
        const revoked =
          certificate?.revoked === true;

        return (
          <details
            className="certificate-item"
            key={`${certificate?.id || "certificate"}-${index}`}
          >

            <summary className="certificate-summary">

              <div className="certificate-index">
                {String(
                  index + 1
                ).padStart(2, "0")}
              </div>

              <div className="certificate-content">

                <div className="certificate-header">

                  <div>
                    <span>
                      CERTIFICATE
                    </span>

                    <strong>
                      {certificate?.id || "Unknown"}
                    </strong>
                  </div>

                  <span
                    className={`certificate-status ${
                      revoked
                        ? "revoked"
                        : "active"
                    }`}
                  >
                    {revoked
                      ? "REVOKED"
                      : "ACTIVE"}
                  </span>

                </div>

              </div>

              <span
                className="certificate-toggle"
                aria-hidden="true"
              >
                +
              </span>

            </summary>

            <div className="certificate-details">

              <div className="certificate-detail">
                <span>
                  Certificate SHA-256
                </span>

                <strong>
                  {certificate?.certificate_sha256 ||
                    "Not available"}
                </strong>
              </div>

              <div className="certificate-detail">
                <span>
                  Public Key SHA-256
                </span>

                <strong>
                  {certificate?.public_key_sha256 ||
                    "Not available"}
                </strong>
              </div>

              <div className="certificate-detail">
                <span>
                  Valid From
                </span>

                <strong>
                  {certificate?.not_before ||
                    "Not available"}
                </strong>
              </div>

              <div className="certificate-detail">
                <span>
                  Valid Until
                </span>

                <strong>
                  {certificate?.not_after ||
                    "Not available"}
                </strong>
              </div>

            </div>

          </details>
        );
      }
    )
  ) : certificates.length > 0 ? (

    certificates.map(
      (
        certificate,
        index
      ) => (

        <details
          className="certificate-item"
          key={`${certificate}-${index}`}
        >

          <summary className="certificate-summary">

            <div className="certificate-index">
              {String(
                index + 1
              ).padStart(2, "0")}
            </div>

            <div className="certificate-content">

              <div className="certificate-header">

                <div>
                  <span>
                    CERTIFICATE
                  </span>

                  <strong>
                    {certificate}
                  </strong>
                </div>

              </div>

            </div>

            <span
              className="certificate-toggle"
              aria-hidden="true"
            >
              +
            </span>

          </summary>

          <div className="certificate-details">

            <div className="certificate-detail">
              <span>
                Certificate Metadata
              </span>

              <strong>
                Detailed certificate metadata
                was not returned by the analysis
                endpoint.
              </strong>
            </div>

          </div>

        </details>

      )
    )

  ) : (

    <div className="empty-inline">
      No certificate data available.
    </div>

  )}

</div>
</div>

  </div>

</section>

              {/* ==============================================
                  PORT SCAN
              ============================================== */}

              <section
                ref={portsRef}
                className="panel-section"
              >

                <div className="panel port-scan-panel">

                  <div className="panel-header">

                    <div>
                      <p className="eyebrow">
                        06 / NETWORK
                        SCAN
                      </p>

                      <h3>
                        Port Scan Results
                      </h3>

                      <p className="panel-description">
                        TCP port scanning
                        results for
                        discovered IP
                        addresses with
                        service detection.
                      </p>
                    </div>

                    <div className="panel-icon">
                      <Plug
                        size={20}
                      />
                    </div>

                  </div>

                  <PortScanResults
                    portScanData={
                      portScanData
                    }
                  />

                </div>

              </section>

              {/* ==============================================
                  PATTERNS
              ============================================== */}

              <section className="panel-section">

                <div className="panel">

                  <div className="panel-header">

                    <div>
                      <p className="eyebrow">
                        07 / PATTERN
                        ANALYSIS
                      </p>

                      <h3>
                        Subdomain
                        Patterns
                      </h3>

                      <p className="panel-description">
                        Structural
                        characteristics
                        observed across
                        the discovered
                        subdomain set.
                      </p>
                    </div>

                    <div className="panel-icon">
                      <Globe
                        size={20}
                      />
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
                        patterns
                          .common_prefixes?.[0]
                          ?.count || 0
                      }
                      label={
                        patterns
                          .common_prefixes?.[0]
                          ? `${patterns.common_prefixes[0].prefix} prefix`
                          : "Common prefix"
                      }
                    />

                  </div>

                </div>

              </section>

              {/* ==============================================
                  VIRUSTOTAL
              ============================================== */}

              <section
                ref={
                  virustotalRef
                }
                className="panel-section"
              >

                <div className="panel">

                  <div className="panel-header">

                    <div>
                      <p className="eyebrow">
                        08 / EXTERNAL
                        INTELLIGENCE
                      </p>

                      <h3>
                        VirusTotal
                        Analysis
                      </h3>

                      <p className="panel-description">
                        Comprehensive
                        threat intelligence
                        from VirusTotal.
                      </p>
                    </div>

                    <div className="panel-icon">
                      <Shield
                        size={20}
                      />
                    </div>

                  </div>

                  {virustotal &&
                  typeof virustotal ===
                    "object" &&
                  !virustotal.error ? (
                    <>

                      <div className="vt-risk-section">

                        <div
                          className={`vt-risk-score ${
                            vtRiskScore >=
                            70
                              ? "critical"
                              : vtRiskScore >=
                                40
                              ? "high"
                              : vtRiskScore >=
                                20
                              ? "medium"
                              : "low"
                          }`}
                        >

                          <div className="vt-risk-number">
                            {
                              vtRiskScore
                            }
                            <span>
                              /100
                            </span>
                          </div>

                          <div className="vt-risk-label">
                            Risk Score
                          </div>

                          <div className="vt-risk-level">
                            {vtRiskScore >=
                            70
                              ? "CRITICAL"
                              : vtRiskScore >=
                                40
                              ? "HIGH"
                              : vtRiskScore >=
                                20
                              ? "MEDIUM"
                              : "LOW"}
                          </div>

                        </div>

                        <div className="vt-stats-grid">

                          <VTStat
                            label="Malicious"
                            value={
                              vtSecuritySummary.malicious ||
                              0
                            }
                            className="malicious"
                          />

                          <VTStat
                            label="Suspicious"
                            value={
                              vtSecuritySummary.suspicious ||
                              0
                            }
                            className="suspicious"
                          />

                          <VTStat
                            label="Harmless"
                            value={
                              vtSecuritySummary.harmless ||
                              0
                            }
                            className="harmless"
                          />

                          <VTStat
                            label="Undetected"
                            value={
                              vtSecuritySummary.undetected ||
                              0
                            }
                            className="undetected"
                          />

                          <VTStat
                            label="Vendors"
                            value={
                              vtSecuritySummary.total_vendors ||
                              0
                            }
                          />

                        </div>

                      </div>

                      {vtVendorBreakdown.length > 0 &&
                        vtVendorBreakdown.filter(
                          (v) =>
                            v?.status === "malicious" ||
                            v?.status === "suspicious"
                        ).length === 0 && (
                          <div className="vt-all-clean">
                            <div className="vt-all-clean-icon">
                              <CheckCircle2 size={22} />
                            </div>
                            <div>
                              <strong>
                                No malicious detections
                              </strong>
                              <span>
                                All {vtVendorBreakdown.length} security
                                vendors flagged this domain as harmless
                                or undetected.
                              </span>
                            </div>
                          </div>
                        )}

                      {vtRiskFactors.length >
                        0 && (
                        <div className="vt-risk-factors">

                          <h4>
                            ⚠️ Risk Factors
                          </h4>

                          {vtRiskFactors.map(
                            (
                              factor,
                              index
                            ) => {
                              const severity =
                                factor?.severity ||
                                "low";

                              return (
                                <div
                                  key={
                                    index
                                  }
                                  className={`vt-risk-factor ${severity}`}
                                >

                                  <div className="vt-factor-header">

                                    <span
                                      className={`vt-factor-badge ${severity}`}
                                    >
                                      {severity.toUpperCase()}
                                    </span>

                                    <span className="vt-factor-description">
                                      {
                                        factor?.description
                                      }
                                    </span>

                                  </div>

                                  {Array.isArray(
                                    factor?.details
                                  ) &&
                                    factor.details
                                      .length >
                                      0 && (
                                      <ul className="vt-factor-details">

                                        {factor.details.map(
                                          (
                                            detail,
                                            i
                                          ) => (
                                            <li
                                              key={
                                                i
                                              }
                                            >
                                              {
                                                detail
                                              }
                                            </li>
                                          )
                                        )}

                                      </ul>
                                    )}

                                </div>
                              );
                            }
                          )}

                        </div>
                      )}

                      {vtVendorBreakdown.length > 0 &&
                        (() => {
                          const statusRank = {
                            malicious: 0,
                            suspicious: 1,
                            undetected: 2,
                            harmless: 3,
                          };
                          const sorted = [
                            ...vtVendorBreakdown,
                          ].sort(
                            (a, b) =>
                              (statusRank[a?.status] ??
                                99) -
                              (statusRank[b?.status] ?? 99)
                          );
                          const MAX_SHOWN = 30;
                          const visible =
                            sorted.slice(0, MAX_SHOWN);
                          const remaining =
                            sorted.length - visible.length;

                          return (
                            <div className="vt-vendors">
                              <h4>
                                Security Vendor Analysis
                                <span className="vt-vendors-count">
                                  {
                                    vtVendorBreakdown.length
                                  }{" "}
                                  vendors
                                </span>
                              </h4>

                              <div className="vt-vendor-grid">
                                {visible.map(
                                  (vendor, index) => (
                                    <div
                                      key={`${vendor.vendor}-${index}`}
                                      className={`vt-vendor-item ${vendor.status}`}
                                    >
                                      <span className="vt-vendor-name">
                                        {vendor.vendor}
                                      </span>
                                      <span
                                        className={`vt-vendor-status ${vendor.status}`}
                                      >
                                        {vendor.status}
                                      </span>
                                      <span className="vt-vendor-result">
                                        {vendor.result ||
                                          "—"}
                                      </span>
                                    </div>
                                  )
                                )}
                              </div>

                              {remaining > 0 && (
                                <div className="vt-vendor-more">
                                  +{remaining} more
                                  vendors not shown
                                </div>
                              )}
                            </div>
                          );
                        })()}

                      {vtWhois &&
                        (vtWhois.registrar ||
                          vtWhois.creation_date) && (
                          <div className="vt-whois">

                            <h4>
                              WHOIS Information
                            </h4>

                            <div className="vt-whois-grid">

                              {vtWhois.registrar && (
                                <div className="vt-whois-item">
                                  <span>
                                    Registrar
                                  </span>

                                  <strong>
                                    {
                                      vtWhois.registrar
                                    }
                                  </strong>
                                </div>
                              )}

                              {vtWhois.creation_date && (
                                <div className="vt-whois-item">
                                  <span>
                                    Creation Date
                                  </span>

                                  <strong>
                                    {
                                      vtWhois.creation_date
                                    }
                                  </strong>
                                </div>
                              )}

                              {vtWhois.expiration_date && (
                                <div className="vt-whois-item">
                                  <span>
                                    Expiration Date
                                  </span>

                                  <strong>
                                    {
                                      vtWhois.expiration_date
                                    }
                                  </strong>
                                </div>
                              )}

                            </div>

                          </div>
                        )}

                      {vtCommunityVotes &&
                        (vtCommunityVotes.harmless !==
                          undefined ||
                          vtCommunityVotes.malicious !==
                            undefined) && (
                          <div className="vt-community">

                            <h4>
                              Community Trust
                            </h4>

                            {(() => {
                              const harmless =
                                Number(
                                  vtCommunityVotes.harmless
                                ) ||
                                0;

                              const malicious =
                                Number(
                                  vtCommunityVotes.malicious
                                ) ||
                                0;

                              const total =
                                harmless +
                                malicious;

                              const harmlessPct =
                                total >
                                0
                                  ? (harmless /
                                      total) *
                                    100
                                  : 100;

                              return (
                                <>
                                  <div className="vt-community-bar">
                                    <div
                                      className="vt-community-fill"
                                      style={{
                                        width: `${harmlessPct}%`,
                                      }}
                                    />
                                  </div>

                                  <div className="vt-community-stats">
                                    <span>
                                      👍{" "}
                                      {
                                        harmless
                                      }{" "}
                                      harmless
                                    </span>

                                    <span>
                                      👎{" "}
                                      {
                                        malicious
                                      }{" "}
                                      malicious
                                    </span>
                                  </div>
                                </>
                              );
                            })()}

                          </div>
                        )}

                    </>
                  ) : (
                    <div className="empty-inline">
                      {virustotal?.error ||
                        "No VirusTotal intelligence available."}
                    </div>
                  )}

                </div>

              </section>

              {/* ==============================================
                  AI REPORT
              ============================================== */}


              <section
                ref={aiReportRef}
                className="panel-section"
              >
                <div className="panel ai-panel">
                  <AIReport
                    report={aiReport}
                    domain={analysis.domain}
                    engine="Ollama"
                    onDownload={
                      handleDownloadAIReport
                    }
                    canDownload={
                      aiReport.trim().length > 0
                    }
                  />
                </div>
              </section>



              {/* ==============================================
                  FOOTER
              ============================================== */}

              <footer className="dashboard-footer">

                <div>
                  <strong>
                    DomainAtlas
                  </strong>

                  <span>
                    Domain-Centric OSINT
                    Intelligence Platform
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

    
    </>
  )}

</main>
    </div>
  );
}

// ================================================================
// NAV BUTTON
// ================================================================

function NavButton({
  active,
  icon,
  label,
  onClick,
}) {
  return (
    <button
      className={`nav-item ${
        active ? "active" : ""
      }`}
      onClick={onClick}
    >
      {icon}
      <span>{label}</span>
    </button>
  );
}

// ================================================================
// VIRUSTOTAL STAT
// ================================================================

function VTStat({
  label,
  value,
  className = "",
}) {
  return (
    <div className="vt-stat">
      <span className="vt-stat-label">
        {label}
      </span>

      <span
        className={`vt-stat-value ${className}`}
      >
        {value}
      </span>
    </div>
  );
}

export default App;