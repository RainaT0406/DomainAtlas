import {
  CheckCircle2,
  Globe,
  Network,
  Plug,
  Server,
  Wifi,
} from "lucide-react";

import "./PortScanResults.css";

function PortScanResults({ portScanData }) {
  // ============================================================
  // NO DATA
  // ============================================================

  if (!portScanData) {
    return (
      <div className="empty-inline">
        No port scan data available.
      </div>
    );
  }

  // ============================================================
  // NORMALIZE TOP-LEVEL DATA
  // ============================================================

  const scannedIps = Number(portScanData.scanned_ips) || 0;

  const openPortsTotal =
    Number(portScanData.open_ports_total) || 0;

  const results = Array.isArray(portScanData.results)
    ? portScanData.results
    : [];

  // ============================================================
  // NO RESULTS
  // ============================================================

  if (results.length === 0) {
    return (
      <div className="port-scan-empty">
        <div className="port-scan-empty-icon">
          <Wifi size={32} />
        </div>

        <h4>No Open Ports Detected</h4>

        <p>
          Port scanning completed on {scannedIps} IP
          address(es). No open ports were found in the
          common ports list.
        </p>

        <div className="port-scan-common-ports">
          <span>Common ports scanned:</span>

          <div className="common-ports-tags">
            {[
              21,
              22,
              23,
              25,
              53,
              80,
              110,
              143,
              443,
              445,
              3306,
              3389,
              5432,
              8080,
              8443,
            ].map((port) => (
              <span
                key={port}
                className="port-tag"
              >
                {port}
              </span>
            ))}
          </div>
        </div>
      </div>
    );
  }

  // ============================================================
  // NORMALIZE RESULTS
  // ============================================================

  const normalizedResults = results.map((result) => {
    const openPorts = Array.isArray(result?.open_ports)
      ? result.open_ports
      : [];

    return {
      ...result,
      ip: result?.ip || "Unknown",
      open_ports: openPorts,
    };
  });

  // Only display IPs that actually have open ports
  const ipsWithPorts = normalizedResults.filter(
    (result) => result.open_ports.length > 0
  );

  // ============================================================
  // MAIN UI
  // ============================================================

  return (
    <div className="port-scan-results">

      {/* ======================================================
          SUMMARY
          ====================================================== */}

      <div className="port-scan-summary">

        {/* IPs Scanned */}
        <div className="port-stat-card">
          <div className="port-stat-icon">
            <Server size={18} />
          </div>

          <div>
            <span className="port-stat-label">
              IPs Scanned
            </span>

            <span className="port-stat-value">
              {scannedIps}
            </span>
          </div>
        </div>

        {/* Open Ports */}
        <div className="port-stat-card">
          <div className="port-stat-icon">
            <Plug size={18} />
          </div>

          <div>
            <span className="port-stat-label">
              Open Ports
            </span>

            <span className="port-stat-value">
              {openPortsTotal}
            </span>
          </div>
        </div>

        {/* IPs With Ports */}
        <div className="port-stat-card">
          <div className="port-stat-icon">
            <Network size={18} />
          </div>

          <div>
            <span className="port-stat-label">
              IPs with Ports
            </span>

            <span className="port-stat-value">
              {ipsWithPorts.length}
            </span>
          </div>
        </div>

      </div>

      {/* ======================================================
          PORT DETAILS
          ====================================================== */}

      {ipsWithPorts.length > 0 ? (
        <div className="port-scan-details">

          <h4>Open Ports by IP Address</h4>

          {ipsWithPorts.map((ipResult) => {
            const ip = ipResult.ip;
            const ports = ipResult.open_ports;

            return (
              <div
                key={ip}
                className="ip-port-group"
              >

                {/* ==================================================
                    IP HEADER
                    ================================================== */}

                <div className="ip-port-header">

                  <div className="ip-address">
                    <Globe size={14} />

                    <span>{ip}</span>
                  </div>

                  <div className="ip-port-count">
                    <span className="port-badge">
                      {ports.length} open ports
                    </span>
                  </div>

                </div>

                {/* ==================================================
                    PORT LIST
                    ================================================== */}

                <div className="port-list">

                  {ports.map((portInfo, index) => {
                    const portNum =
                      portInfo?.port ?? "Unknown";

                    const service =
                      portInfo?.service || "unknown";

                    const protocol =
                      portInfo?.protocol || "tcp";

                    const banner =
                      portInfo?.banner || null;

                    const hasBanner =
                      Boolean(
                        portInfo?.banner_available &&
                        banner
                      );

                    return (
                      <div
                        key={`${ip}-${portNum}-${index}`}
                        className="port-item"
                      >

                        {/* ==================================================
                            PORT NUMBER + PROTOCOL
                            ================================================== */}

                        <div className="port-number">

                          <span className="port-num">
                            {portNum}
                          </span>

                          <span className="port-protocol">
                            {protocol}
                          </span>

                        </div>

                        {/* ==================================================
                            SERVICE + BANNER
                            ================================================== */}

                        <div className="port-service">

                          <span className="service-name">
                            {service}
                          </span>

                          {hasBanner && (
                            <div className="port-banner-full">

                              <span className="banner-label">
                                Banner:
                              </span>

                              <code>
                                {banner}
                              </code>

                            </div>
                          )}

                        </div>

                      </div>
                    );
                  })}

                </div>
              </div>
            );
          })}

        </div>
      ) : (

        /* ======================================================
           NO OPEN PORTS
           ====================================================== */

        <div className="port-scan-empty">

          <div className="port-scan-empty-icon">
            <CheckCircle2 size={32} />
          </div>

          <h4>No Open Ports Found</h4>

          <p>
            All {scannedIps} scanned IPs have no open
            ports in the common ports list.
          </p>

        </div>
      )}

    </div>
  );
}

export default PortScanResults;