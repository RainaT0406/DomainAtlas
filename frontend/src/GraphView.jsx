import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";

function GraphView({ graph, domain, subdomainCount = 0 }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [downloading, setDownloading] = useState(false);

  // --------------------------------------------------------------
  // GRAPH DISPLAY LIMIT
  //
  // IMPORTANT:
  // This only limits what Cytoscape displays.
  // It does NOT delete subdomains from the collected dataset,
  // Neo4j, reports, or PDF generation.
  // --------------------------------------------------------------
  const MAX_SUBDOMAINS = 50;

  useEffect(() => {
    const container = containerRef.current;

    if (!container) {
      return;
    }

    // ------------------------------------------------------------
    // DESTROY PREVIOUS CYTOSCAPE INSTANCE
    // ------------------------------------------------------------

    if (cyRef.current) {
      cyRef.current.destroy();
      cyRef.current = null;
    }

    // ------------------------------------------------------------
    // GET GRAPH DATA
    // ------------------------------------------------------------

    const allNodes = Array.isArray(graph?.nodes)
      ? graph.nodes
      : [];

    const allEdges = Array.isArray(graph?.edges)
      ? graph.edges
      : [];

    if (allNodes.length === 0) {
      return;
    }

    // ------------------------------------------------------------
    // SEPARATE NODE TYPES
    // ------------------------------------------------------------

    const domainNodes = allNodes.filter(
      (node) => node.data?.type === "Domain"
    );

    const ipNodes = allNodes.filter(
      (node) => node.data?.type === "IPAddress"
    );

    const asnNodes = allNodes.filter(
      (node) => node.data?.type === "ASN"
    );

    const organizationNodes = allNodes.filter(
      (node) => node.data?.type === "Organization"
    );

    const certificateNodes = allNodes.filter(
      (node) => node.data?.type === "Certificate"
    );

    const allSubdomainNodes = allNodes.filter(
      (node) => node.data?.type === "Subdomain"
    );

    // ------------------------------------------------------------
    // LIMIT ONLY SUBDOMAINS FOR VISUALIZATION
    // ------------------------------------------------------------

    const subdomainNodes = allSubdomainNodes.slice(
      0,
      MAX_SUBDOMAINS
    );

    // ------------------------------------------------------------
    // BUILD VISIBLE NODE SET
    // ------------------------------------------------------------

    const visibleNodes = [
      ...domainNodes,
      ...ipNodes,
      ...asnNodes,
      ...organizationNodes,
      ...certificateNodes,
      ...subdomainNodes,
    ];

    // ------------------------------------------------------------
    // CREATE SET OF VISIBLE NODE IDS
    // ------------------------------------------------------------

    const visibleNodeIds = new Set(
      visibleNodes.map((node) => String(node.data.id))
    );

    // ------------------------------------------------------------
    // ONLY SHOW EDGES BETWEEN VISIBLE NODES
    // ------------------------------------------------------------

    const visibleEdges = allEdges.filter((edge) => {
      const source = String(edge.data?.source);
      const target = String(edge.data?.target);

      return (
        visibleNodeIds.has(source) &&
        visibleNodeIds.has(target)
      );
    });

    // ------------------------------------------------------------
    // CREATE CYTOSCAPE
    // ------------------------------------------------------------

    const cy = cytoscape({
      container,

      elements: [
        ...visibleNodes,
        ...visibleEdges,
      ],

      // ==========================================================
      // STYLING
      // ==========================================================

      style: [
        // --------------------------------------------------------
        // DEFAULT NODE
        // --------------------------------------------------------

        {
          selector: "node",

          style: {
            "background-color": "#172033",
            "border-color": "#334155",
            "border-width": 1,

            label: "data(label)",

            color: "#cbd5e1",

            "font-size": 10,

            "text-valign": "center",
            "text-halign": "center",

            "text-wrap": "wrap",
            "text-max-width": 100,

            width: 50,
            height: 50,

            "overlay-opacity": 0,
          },
        },

        // --------------------------------------------------------
        // DOMAIN
        // --------------------------------------------------------

        {
          selector: 'node[type="Domain"]',

          style: {
            "background-color": "#1d4ed8",
            "border-color": "#60a5fa",
            "border-width": 3,

            width: 85,
            height: 85,

            "font-size": 13,
            "font-weight": "bold",

            color: "#ffffff",

            "text-max-width": 120,
          },
        },

        // --------------------------------------------------------
        // SUBDOMAIN
        // --------------------------------------------------------

        {
          selector: 'node[type="Subdomain"]',

          style: {
            "background-color": "#72316a",
            "border-color": "#22d3ee",
            "border-width": 1,

            width: 38,
            height: 38,

            "font-size": 7,

            color: "#cbd5e1",

            "text-max-width": 80,
          },
        },

        // --------------------------------------------------------
        // IP ADDRESS
        // --------------------------------------------------------

        {
          selector: 'node[type="IPAddress"]',

          style: {
            "background-color": "#172554",
            "border-color": "#60a5fa",
            "border-width": 2,

            width: 58,
            height: 58,

            "font-size": 9,
          },
        },

        // --------------------------------------------------------
        // ASN
        // --------------------------------------------------------

        {
          selector: 'node[type="ASN"]',

          style: {
            "background-color": "#312e81",
            "border-color": "#818cf8",
            "border-width": 2,

            width: 62,
            height: 62,

            "font-size": 9,
          },
        },

        // --------------------------------------------------------
        // ORGANIZATION
        // --------------------------------------------------------

        {
          selector: 'node[type="Organization"]',

          style: {
            "background-color": "#365314",
            "border-color": "#84cc16",
            "border-width": 2,

            width: 68,
            height: 68,

            "font-size": 9,
          },
        },

        // --------------------------------------------------------
        // CERTIFICATE
        // --------------------------------------------------------

        {
          selector: 'node[type="Certificate"]',

          style: {
            "background-color": "#713f12",
            "border-color": "#facc15",
            "border-width": 2,

            width: 55,
            height: 55,

            "font-size": 8,
          },
        },

        // --------------------------------------------------------
        // EDGES
        // --------------------------------------------------------

        {
          selector: "edge",

          style: {
            width: 1,

            "line-color": "#334155",

            "target-arrow-color": "#475569",

            "target-arrow-shape": "triangle",

            "curve-style": "bezier",

            // Hide edge labels by default.
            // This significantly reduces visual clutter.
            label: "",

            color: "#64748b",

            "font-size": 7,

            "text-background-color": "#0c121c",

            "text-background-opacity": 1,

            "text-background-padding": 2,

            "text-rotation": "autorotate",

            opacity: 0.65,
          },
        },

        // --------------------------------------------------------
        // SELECTED NODE
        // --------------------------------------------------------

        {
          selector: "node:selected",

          style: {
            "border-color": "#ffffff",

            "border-width": 3,

            "shadow-blur": 15,

            "shadow-color": "#60a5fa",

            "shadow-opacity": 0.7,
          },
        },

        // --------------------------------------------------------
        // SELECTED EDGE
        // --------------------------------------------------------

        {
          selector: "edge:selected",

          style: {
            "line-color": "#60a5fa",

            "target-arrow-color": "#60a5fa",

            width: 2,

            opacity: 1,
          },
        },
      ],

      // ==========================================================
      // GRAPH LAYOUT
      // ==========================================================

      layout: {
        name: "concentric",

        animate: false,

        fit: true,

        padding: 60,

        // --------------------------------------------------------
        // Central node
        // --------------------------------------------------------

        concentric: (node) => {
          const type = node.data("type");

          if (type === "Domain") {
            return 5;
          }

          if (type === "IPAddress") {
            return 4;
          }

          if (type === "ASN") {
            return 3;
          }

          if (type === "Organization") {
            return 2;
          }

          if (type === "Certificate") {
            return 2;
          }

          if (type === "Subdomain") {
            return 1;
          }

          return 0;
        },

        // --------------------------------------------------------
        // Distance between layers
        // --------------------------------------------------------

        levelWidth: () => {
          return 1;
        },

        // --------------------------------------------------------
        // Prevent nodes from being too close
        // --------------------------------------------------------

        minNodeSpacing: 55,

        avoidOverlap: true,

        // --------------------------------------------------------
        // Keep the domain in the middle
        // --------------------------------------------------------

        clockwise: true,

        startAngle: (3 * Math.PI) / 2,

        sweep: 2 * Math.PI,

        equidistant: false,

        spacingFactor: 1.15,
      },

      // ==========================================================
      // ZOOM
      // ==========================================================

      minZoom: 0.2,
      maxZoom: 3,
    });

    cyRef.current = cy;

    // ------------------------------------------------------------
    // FORCE CORRECT SIZE / FIT
    // ------------------------------------------------------------

    const fitGraph = () => {
      if (!cyRef.current) {
        return;
      }

      cyRef.current.resize();

      if (cyRef.current.nodes().length > 0) {
        cyRef.current.fit(
          cyRef.current.elements(),
          60
        );
      }
    };

    // Initial sizing
    requestAnimationFrame(() => {
      fitGraph();

      requestAnimationFrame(() => {
        fitGraph();
      });
    });

    // ------------------------------------------------------------
    // HANDLE CONTAINER RESIZING
    // ------------------------------------------------------------

    const resizeObserver = new ResizeObserver(() => {
      fitGraph();
    });

    resizeObserver.observe(container);

    // ------------------------------------------------------------
    // NODE HOVER
    // ------------------------------------------------------------

    cy.on(
      "mouseover",
      "node",
      (event) => {
        event.target.style(
          "border-width",
          3
        );
      }
    );

    cy.on(
      "mouseout",
      "node",
      (event) => {
        if (!event.target.selected()) {
          event.target.style(
            "border-width",
            event.target.data("type") === "Domain"
              ? 3
              : event.target.data("type") === "Subdomain"
              ? 1
              : 2
          );
        }
      }
    );

    // ------------------------------------------------------------
    // CLEANUP
    // ------------------------------------------------------------

    return () => {
      resizeObserver.disconnect();

      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [graph]);

  // ==============================================================
  // DOWNLOAD COMPLETE SUBDOMAIN PDF
  // ==============================================================

  const downloadSubdomainsPDF = async () => {
    if (!domain) {
      alert("Domain information is unavailable.");
      return;
    }

    try {
      setDownloading(true);

      const response = await fetch(
        `http://localhost:8000/subdomains/pdf?domain=${encodeURIComponent(
          domain
        )}`
      );

      if (!response.ok) {
        let message =
          "Failed to generate the PDF.";

        try {
          const errorData =
            await response.json();

          if (errorData.detail) {
            message = errorData.detail;
          }
        } catch {
          // Ignore JSON parsing failure.
        }

        throw new Error(message);
      }

      const blob =
        await response.blob();

      const url =
        window.URL.createObjectURL(blob);

      const link =
        document.createElement("a");

      link.href = url;

      link.download =
        `${domain}-subdomains.pdf`;

      document.body.appendChild(link);

      link.click();

      link.remove();

      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error(
        "PDF download failed:",
        error
      );

      alert(
        error.message ||
          "Unable to download subdomain PDF."
      );
    } finally {
      setDownloading(false);
    }
  };

  // ==============================================================
  // EMPTY STATE
  // ==============================================================

  const hasNodes =
    Array.isArray(graph?.nodes) &&
    graph.nodes.length > 0;

  const displayedSubdomains =
    Math.min(
      MAX_SUBDOMAINS,
      subdomainCount
    );

  // ==============================================================
  // RENDER
  // ==============================================================

  return (
    <div className="graph-section">

      {/* ========================================================
          GRAPH HEADER
      ======================================================== */}

      <div className="graph-header">

        <div>
          <h3>
            Entity Relationships
          </h3>

          <p>
            Visual representation of
            correlated infrastructure entities.
          </p>
        </div>

        <div className="graph-actions">

          {subdomainCount > 0 && (
            <span className="graph-limit-info">
              Showing{" "}
              <strong>
                {displayedSubdomains}
              </strong>{" "}
              of{" "}
              <strong>
                {subdomainCount}
              </strong>{" "}
              subdomains
            </span>
          )}

          {subdomainCount > 0 && (
            <button
              type="button"
              className="download-subdomains-btn"
              onClick={downloadSubdomainsPDF}
              disabled={downloading}
            >
              {downloading
                ? "Generating PDF..."
                : "Download All Subdomains (PDF)"}
            </button>
          )}

        </div>
      </div>

      {/* ========================================================
          CYTOSCAPE CONTAINER
      ======================================================== */}

      <div
        ref={containerRef}
        className="cytoscape-container"
      >

        {!hasNodes && (
          <div className="graph-empty">
            No graph entities available.
          </div>
        )}

      </div>

    </div>
  );
}

export default GraphView;