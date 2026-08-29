import { useState } from "react";
import HierarchicalGraph from "./HierarchicalGraph";

function GraphView({
  graph,
  domain,
  subdomainCount = 0,
}) {
  const [downloading, setDownloading] = useState(false);

  // --------------------------------------------------------------
  // GRAPH DISPLAY LIMIT
  // --------------------------------------------------------------

  const MAX_SUBDOMAINS = 50;

  // --------------------------------------------------------------
  // DOWNLOAD COMPLETE SUBDOMAIN PDF
  // --------------------------------------------------------------

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
        let message = "Failed to generate the PDF.";

        try {
          const errorData = await response.json();
          if (errorData.detail) {
            message = errorData.detail;
          }
        } catch {
          // Ignore JSON parsing failure.
        }

        throw new Error(message);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${domain}-subdomains.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error("PDF download failed:", error);
      alert(error.message || "Unable to download subdomain PDF.");
    } finally {
      setDownloading(false);
    }
  };

  // --------------------------------------------------------------
  // GRAPH STATE
  // --------------------------------------------------------------

  const hasNodes = Array.isArray(graph?.nodes) && graph.nodes.length > 0;
  const displayedSubdomains = Math.min(MAX_SUBDOMAINS, subdomainCount);

  // --------------------------------------------------------------
  // RENDER
  // --------------------------------------------------------------

  return (
    <div className="graph-section">
      {/* ========================================================
          GRAPH HEADER
      ======================================================== */}

      <div className="graph-header">
        <div>
          <h3>Domain Infrastructure Relationship Graph</h3>
          <p>
            Hierarchical view of infrastructure discovered from the target domain.
          </p>
        </div>

        <div className="graph-actions">
          {subdomainCount > 0 && (
            <span className="graph-limit-info">
              Showing <strong>{displayedSubdomains}</strong> of{" "}
              <strong>{subdomainCount}</strong> subdomains
            </span>
          )}

          {subdomainCount > 0 && (
            <button
              type="button"
              className="download-subdomains-btn"
              onClick={downloadSubdomainsPDF}
              disabled={downloading}
            >
              {downloading ? "Generating PDF..." : "Download All Subdomains (PDF)"}
            </button>
          )}
        </div>
      </div>

      {/* ========================================================
          GRAPH
      ======================================================== */}

      <div className="graph-container-wrapper">
        {!hasNodes ? (
          <div className="graph-empty">No graph entities available.</div>
        ) : (
          <HierarchicalGraph
            graph={graph}
            onNodeSelect={(node) => {
              // Handle node selection if needed
              console.log("Node selected:", node);
            }}
          />
        )}
      </div>
    </div>
  );
}

export default GraphView;