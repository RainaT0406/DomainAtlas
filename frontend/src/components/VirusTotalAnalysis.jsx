import { forwardRef } from "react";

import {
  Shield,
  CheckCircle2,
} from "lucide-react";


const VirusTotalAnalysis = forwardRef(
  function VirusTotalAnalysis(
    { virustotal },
    ref
  ) {

    // ============================================================
    // VIRUSTOTAL DATA NORMALIZATION
    // ============================================================

    const data =
      virustotal &&
      typeof virustotal === "object"
        ? virustotal
        : {};


    // ------------------------------------------------------------
    // Security statistics
    //
    // Current DomainAtlas structure:
    //
    // security_summary: {
    //     malicious,
    //     suspicious,
    //     harmless,
    //     undetected,
    //     timeout,
    //     total_vendors
    // }
    //
    // Flat properties are retained as a fallback.
    // ------------------------------------------------------------

    const vtMalicious =
      Number(
        data?.security_summary?.malicious ??
        data?.malicious
      ) || 0;


    const vtSuspicious =
      Number(
        data?.security_summary?.suspicious ??
        data?.suspicious
      ) || 0;


    const vtHarmless =
      Number(
        data?.security_summary?.harmless ??
        data?.harmless
      ) || 0;


    const vtUndetected =
      Number(
        data?.security_summary?.undetected ??
        data?.undetected
      ) || 0;


    const vtTimeout =
      Number(
        data?.security_summary?.timeout ??
        data?.timeout
      ) || 0;


    const calculatedVendorTotal =
      vtMalicious +
      vtSuspicious +
      vtHarmless +
      vtUndetected +
      vtTimeout;


    const vtTotalVendors =
      Number(
        data?.security_summary?.total_vendors ??
        data?.total_vendors
      ) || calculatedVendorTotal;


    // ------------------------------------------------------------
    // Risk score
    //
    // Do NOT use `|| 0` here because a legitimate score of 0
    // must remain distinguishable from missing data.
    // ------------------------------------------------------------

    const parsedRiskScore =
      Number(data?.risk_score);


    const hasRiskScore =
      Number.isFinite(parsedRiskScore);


    const vtRiskScore =
      hasRiskScore
        ? parsedRiskScore
        : null;


    // ------------------------------------------------------------
    // Security summary
    // ------------------------------------------------------------

    const vtSecuritySummary = {
      malicious: vtMalicious,
      suspicious: vtSuspicious,
      harmless: vtHarmless,
      undetected: vtUndetected,
      timeout: vtTimeout,
      total_vendors: vtTotalVendors,
    };


    // ------------------------------------------------------------
    // Vendor breakdown
    // ------------------------------------------------------------

    const vtVendorBreakdown =
      Array.isArray(
        data?.vendor_breakdown
      )
        ? data.vendor_breakdown
        : [];


    // ------------------------------------------------------------
    // Risk factors
    // ------------------------------------------------------------

    const vtRiskFactors =
      Array.isArray(
        data?.risk_factors
      )
        ? data.risk_factors
        : [];


    // ------------------------------------------------------------
    // WHOIS
    // ------------------------------------------------------------

    const vtWhois = {
      ...(data?.whois_info || {}),

      registrar:
        data?.whois_info?.registrar ||
        data?.registrar ||
        "",

      creation_date:
        data?.whois_info?.creation_date ||
        data?.creation_date ||
        "",

      expiration_date:
        data?.whois_info?.expiration_date ||
        data?.expiration_date ||
        "",

      last_modification_date:
        data?.whois_info?.last_modification_date ||
        data?.last_modification_date ||
        "",
    };


    // ------------------------------------------------------------
    // Community votes
    // ------------------------------------------------------------

    const vtCommunityVotes =
      data?.community_votes &&
      typeof data.community_votes === "object"
        ? data.community_votes
        : {};


    // ============================================================
    // RISK LEVEL
    // ============================================================

    let riskLevel = "LOW";

    let riskClass = "low";


    if (hasRiskScore) {

      if (vtRiskScore >= 70) {

        riskLevel = "CRITICAL";
        riskClass = "critical";

      } else if (vtRiskScore >= 40) {

        riskLevel = "HIGH";
        riskClass = "high";

      } else if (vtRiskScore >= 20) {

        riskLevel = "MEDIUM";
        riskClass = "medium";

      } else {

        riskLevel = "LOW";
        riskClass = "low";
      }
    }


    // ============================================================
    // NO MALICIOUS / SUSPICIOUS DETECTIONS
    // ============================================================

    const hasNoDetections =
      vtMalicious === 0 &&
      vtSuspicious === 0;


    // ============================================================
    // RETURN COMPONENT
    // ============================================================

    return (
      <section
        ref={ref}
        className="panel-section"
      >

        <div className="panel">

          {/* ======================================================
              HEADER
          ====================================================== */}

          <div className="panel-header">

            <div>

              <p className="eyebrow">
                08 / EXTERNAL INTELLIGENCE
              </p>

              <h3>
                VirusTotal Analysis
              </h3>

              <p className="panel-description">
                Comprehensive threat intelligence
                from VirusTotal.
              </p>

            </div>


            <div className="panel-icon">

              <Shield size={20} />

            </div>

          </div>


          {/* ======================================================
              DATA AVAILABLE
          ====================================================== */}

          {virustotal &&
          typeof virustotal === "object" &&
          !virustotal.error ? (

            <>

              {/* ==================================================
                  RISK SCORE + STATISTICS
              ================================================== */}

              <div className="vt-risk-section">

                <div
                  className={`vt-risk-score ${riskClass}`}
                >

                  <div className="vt-risk-number">

                    {hasRiskScore
                      ? vtRiskScore
                      : "N/A"}

                    {hasRiskScore && (
                      <span>
                        /100
                      </span>
                    )}

                  </div>


                  <div className="vt-risk-label">
                    Risk Score
                  </div>


                  <div className="vt-risk-level">
                    {riskLevel}
                  </div>

                </div>


                {/* =================================================
                    SECURITY STATISTICS
                ================================================= */}

                <div className="vt-stats-grid">

                  <VTStat
                    label="Malicious"
                    value={
                      vtSecuritySummary.malicious
                    }
                    className="malicious"
                  />


                  <VTStat
                    label="Suspicious"
                    value={
                      vtSecuritySummary.suspicious
                    }
                    className="suspicious"
                  />


                  <VTStat
                    label="Harmless"
                    value={
                      vtSecuritySummary.harmless
                    }
                    className="harmless"
                  />


                  <VTStat
                    label="Undetected"
                    value={
                      vtSecuritySummary.undetected
                    }
                    className="undetected"
                  />


                  <VTStat
                    label="Vendors"
                    value={
                      vtSecuritySummary.total_vendors
                    }
                  />

                </div>

              </div>


              {/* ==================================================
                  NO DETECTIONS
              ================================================== */}

              {hasNoDetections && (
                <div className="vt-all-clean">

                  <div className="vt-all-clean-icon">

                    <CheckCircle2 size={22} />

                  </div>


                  <div>

                    <strong>
                      No malicious or suspicious detections
                    </strong>

                    <span>
                      VirusTotal reported no malicious
                      or suspicious vendor detections
                      for this domain.
                    </span>

                  </div>

                </div>
              )}


              {/* ==================================================
                  RISK FACTORS
              ================================================== */}

              {vtRiskFactors.length > 0 && (

                <div className="vt-risk-factors">

                  <h4>
                    ⚠️ Risk Factors
                  </h4>


                  {vtRiskFactors.map(
                    (factor, index) => {

                      const severity =
                        factor?.severity ||
                        "low";


                      return (
                        <div
                          key={index}
                          className={
                            `vt-risk-factor ${severity}`
                          }
                        >

                          <div className="vt-factor-header">

                            <span
                              className={
                                `vt-factor-badge ${severity}`
                              }
                            >
                              {severity.toUpperCase()}
                            </span>


                            <span className="vt-factor-description">
                              {
                                factor?.description ||
                                "No description available."
                              }
                            </span>

                          </div>


                          {Array.isArray(
                            factor?.details
                          ) &&
                          factor.details.length > 0 && (

                            <ul className="vt-factor-details">

                              {factor.details.map(
                                (detail, i) => (

                                  <li key={i}>
                                    {detail}
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


              {/* ==================================================
                  SECURITY VENDOR ANALYSIS
              ================================================== */}

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
                      (
                        statusRank[a?.status] ?? 99
                      ) -
                      (
                        statusRank[b?.status] ?? 99
                      )
                  );


                  const MAX_SHOWN = 30;


                  const visible =
                    sorted.slice(
                      0,
                      MAX_SHOWN
                    );


                  const remaining =
                    sorted.length -
                    visible.length;


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
                          (vendor, index) => {

                            const status =
                              vendor?.status ||
                              "unknown";


                            return (
                              <div
                                key={
                                  `${vendor?.vendor || "vendor"}-${index}`
                                }
                                className={
                                  `vt-vendor-item ${status}`
                                }
                              >

                                <span className="vt-vendor-name">

                                  {
                                    vendor?.vendor ||
                                    "Unknown vendor"
                                  }

                                </span>


                                <span
                                  className={
                                    `vt-vendor-status ${status}`
                                  }
                                >

                                  {status}

                                </span>


                                <span className="vt-vendor-result">

                                  {
                                    vendor?.result ||
                                    "—"
                                  }

                                </span>

                              </div>
                            );
                          }
                        )}

                      </div>


                      {remaining > 0 && (

                        <div className="vt-vendor-more">

                          +{remaining} more vendors not shown

                        </div>

                      )}

                    </div>
                  );

                })()}


              {/* ==================================================
                  WHOIS INFORMATION
              ================================================== */}

              {(
                vtWhois.registrar ||
                vtWhois.creation_date ||
                vtWhois.expiration_date ||
                vtWhois.last_modification_date
              ) && (

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


                    {vtWhois.last_modification_date && (

                      <div className="vt-whois-item">

                        <span>
                          Last Modification
                        </span>

                        <strong>
                          {
                            vtWhois.last_modification_date
                          }
                        </strong>

                      </div>

                    )}

                  </div>

                </div>

              )}


              {/* ==================================================
                  COMMUNITY TRUST
              ================================================== */}

              {(
                vtCommunityVotes.harmless !==
                  undefined ||
                vtCommunityVotes.malicious !==
                  undefined
              ) && (

                <div className="vt-community">

                  <h4>
                    Community Trust
                  </h4>


                  {(() => {

                    const harmless =
                      Number(
                        vtCommunityVotes.harmless
                      ) || 0;


                    const malicious =
                      Number(
                        vtCommunityVotes.malicious
                      ) || 0;


                    const total =
                      harmless +
                      malicious;


                    const harmlessPct =
                      total > 0
                        ? (
                            harmless /
                            total
                          ) * 100
                        : 100;


                    return (
                      <>

                        <div className="vt-community-bar">

                          <div
                            className="vt-community-fill"
                            style={{
                              width:
                                `${harmlessPct}%`,
                            }}
                          />

                        </div>


                        <div className="vt-community-stats">

                          <span>
                            👍{" "}
                            {harmless}{" "}
                            harmless
                          </span>


                          <span>
                            👎{" "}
                            {malicious}{" "}
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

            /* ====================================================
               EMPTY / ERROR STATE
            ==================================================== */

            <div className="empty-inline">

              {
                virustotal?.error ||
                "No VirusTotal intelligence available."
              }

            </div>

          )}

        </div>

      </section>
    );
  }
);


// ============================================================
// VT STAT COMPONENT
// ============================================================

function VTStat({
  label,
  value,
  className = "",
}) {

  return (
    <div
      className={
        `vt-stat ${className}`
      }
    >

      <span className="vt-stat-label">
        {label}
      </span>


      <strong className="vt-stat-value">
        {value}
      </strong>

    </div>
  );
}


export default VirusTotalAnalysis;