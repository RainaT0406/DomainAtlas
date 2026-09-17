import { useEffect, useState } from "react";

function History({ onViewScan }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch("http://127.0.0.1:8000/history")
      .then((response) => {
        if (!response.ok) {
          throw new Error("Failed to load scan history.");
        }

        return response.json();
      })
      .then((data) => {
        setHistory(data.history || []);
      })
      .catch((err) => {
        console.error(err);
        setError("Unable to load scan history.");
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  const formatDate = (timestamp) => {
    if (!timestamp) return "Unknown";

    return new Date(timestamp).toLocaleString();
  };

  const formatDuration = (seconds) => {
    if (seconds === null || seconds === undefined) {
      return "—";
    }

    if (seconds < 60) {
      return `${Math.round(seconds)}s`;
    }

    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = Math.round(seconds % 60);

    return `${minutes}m ${remainingSeconds}s`;
  };

  const downloadScan = (scanId) => {
    window.open(
      `http://127.0.0.1:8000/history/${encodeURIComponent(
        scanId
      )}/download`,
      "_blank"
    );
  };

  if (loading) {
    return (
      <section className="history-section">
        <div className="section-header">
          <span className="section-number">07</span>
          <div>
            <h2>Scan History</h2>
            <p>Previous DomainAtlas scans</p>
          </div>
        </div>

        <div className="history-empty">
          Loading scan history...
        </div>
      </section>
    );
  }

  if (error) {
    return (
      <section className="history-section">
        <div className="section-header">
          <span className="section-number">07</span>
          <div>
            <h2>Scan History</h2>
            <p>Previous DomainAtlas scans</p>
          </div>
        </div>

        <div className="history-empty history-error">
          {error}
        </div>
      </section>
    );
  }

  return (
    <section className="history-section">
      <div className="section-header">
        <span className="section-number">07</span>
        <div>
          <h2>Scan History</h2>
          <p>Previous DomainAtlas scans</p>
        </div>
      </div>

      {history.length === 0 ? (
        <div className="history-empty">
          No previous scans available.
        </div>
      ) : (
        <div className="history-list">
          {history.map((scan) => (
            <div
              className="history-card"
              key={scan.scan_id}
            >
              <div className="history-card-main">
                <div>
                  <h3>{scan.domain}</h3>

                  <p className="history-date">
                    {formatDate(scan.completed_at)}
                  </p>

                  <p className="history-id">
                    Scan ID: {scan.scan_id}
                  </p>
                </div>

                <div className="history-actions">
                  <button
                    className="history-view-button"
                    onClick={() => onViewScan(scan.scan_id)}
                  >
                    View
                  </button>

                  <button
                    className="history-download-button"
                    onClick={() =>
                      downloadScan(scan.scan_id)
                    }
                  >
                    JSON
                  </button>
                </div>
              </div>

              <div className="history-stats">
                <div>
                  <strong>{scan.subdomains}</strong>
                  <span>Subdomains</span>
                </div>

                <div>
                  <strong>{scan.ip_addresses}</strong>
                  <span>IPs</span>
                </div>

                <div>
                  <strong>{scan.asns}</strong>
                  <span>ASNs</span>
                </div>

                <div>
                  <strong>{scan.certificates}</strong>
                  <span>Certificates</span>
                </div>

                <div>
                  <strong>{scan.open_ports}</strong>
                  <span>Open Ports</span>
                </div>

                <div>
                  <strong>
                    {formatDuration(
                      scan.duration_seconds
                    )}
                  </strong>
                  <span>Duration</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

export default History;