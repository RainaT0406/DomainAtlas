
import { useMemo, useState } from "react";

import {
  Fingerprint,
  Search,
  ChevronDown,
  X,
  ExternalLink,
} from "lucide-react";

import "./Provenance.css";

function Provenance({ provenance = [] }) {
  const [entityFilter, setEntityFilter] = useState("All");
  const [sourceFilter, setSourceFilter] = useState("All");
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedRecord, setSelectedRecord] = useState(null);

  // ============================================================
  // NORMALIZE PROVENANCE CONTAINER
  //
  // Supports:
  //   provenance: []
  //   provenance: { records: [] }
  //   provenance: { provenance: [] }
  //   provenance: { observations: [] }
  // ============================================================

  const records = useMemo(() => {
    if (Array.isArray(provenance)) {
      return provenance.filter(Boolean);
    }

    if (
      provenance &&
      Array.isArray(provenance.records)
    ) {
      return provenance.records.filter(Boolean);
    }

    if (
      provenance &&
      Array.isArray(provenance.provenance)
    ) {
      return provenance.provenance.filter(Boolean);
    }

    if (
      provenance &&
      Array.isArray(provenance.observations)
    ) {
      return provenance.observations.filter(Boolean);
    }

    return [];
  }, [provenance]);

  // ============================================================
  // NORMALIZE INDIVIDUAL RECORD
  // ============================================================

  const normalizeRecord = (record, index) => {
    const entityType =
      record?.entity_type ??
      record?.entityType ??
      record?.type ??
      record?.entity ??
      "Unknown";

    const entityValue =
      record?.entity_value ??
      record?.entityValue ??
      record?.value ??
      record?.observed_value ??
      record?.observedValue ??
      "Unknown";

    const source =
      record?.source ??
      record?.source_name ??
      record?.sourceName ??
      "Unknown";

    const method =
      record?.method ??
      record?.collection_method ??
      record?.collectionMethod ??
      "Unknown";

    const recordedAt =
      record?.recorded_at ??
      record?.recordedAt ??
      record?.timestamp ??
      record?.collected_at ??
      record?.collectedAt ??
      null;

    const relationship =
      record?.relationship ??
      record?.relationship_type ??
      record?.relationshipType ??
      null;

    const sourceUrl =
      record?.source_url ??
      record?.sourceUrl ??
      record?.source_uri ??
      record?.sourceUri ??
      record?.url ??
      null;

    const recordId =
      record?.provenance_id ??
      record?.provenanceId ??
      record?.id ??
      null;

    return {
      ...record,

      _index: index,
      _id: recordId,

      _entityType: String(entityType),
      _entityValue: String(entityValue),
      _source: String(source),
      _method: String(method),

      _recordedAt: recordedAt,

      _relationship: relationship
        ? String(relationship)
        : null,

      _sourceUrl: sourceUrl
        ? String(sourceUrl)
        : null,
    };
  };

  const normalizedRecords = useMemo(
    () =>
      records.map((record, index) =>
        normalizeRecord(record, index)
      ),
    [records]
  );

  // ============================================================
  // ENTITY TYPES
  // ============================================================

  const entityTypes = useMemo(() => {
    const types = new Set();

    normalizedRecords.forEach((record) => {
      if (
        record._entityType &&
        record._entityType !== "Unknown"
      ) {
        types.add(record._entityType);
      }
    });

    return ["All", ...Array.from(types).sort()];
  }, [normalizedRecords]);

  // ============================================================
  // SOURCES
  // ============================================================

  const sources = useMemo(() => {
    const sourceSet = new Set();

    normalizedRecords.forEach((record) => {
      if (
        record._source &&
        record._source !== "Unknown"
      ) {
        sourceSet.add(record._source);
      }
    });

    return ["All", ...Array.from(sourceSet).sort()];
  }, [normalizedRecords]);

  // ============================================================
  // FILTER RECORDS
  // ============================================================

  const filteredRecords = useMemo(() => {
    const search = searchTerm
      .trim()
      .toLowerCase();

    return normalizedRecords.filter((record) => {
      const entityType =
        record._entityType.toLowerCase();

      const entityValue =
        record._entityValue.toLowerCase();

      const source =
        record._source.toLowerCase();

      const method =
        record._method.toLowerCase();

      const relationship =
        (record._relationship || "").toLowerCase();

      const sourceUrl =
        (record._sourceUrl || "").toLowerCase();

      const recordedAt =
        record._recordedAt
          ? String(record._recordedAt).toLowerCase()
          : "";

      const matchesEntity =
        entityFilter === "All" ||
        entityType === entityFilter.toLowerCase();

      const matchesSource =
        sourceFilter === "All" ||
        source === sourceFilter.toLowerCase();

      const matchesSearch =
        !search ||
        entityValue.includes(search) ||
        entityType.includes(search) ||
        source.includes(search) ||
        method.includes(search) ||
        relationship.includes(search) ||
        sourceUrl.includes(search) ||
        recordedAt.includes(search);

      return (
        matchesEntity &&
        matchesSource &&
        matchesSearch
      );
    });
  }, [
    normalizedRecords,
    entityFilter,
    sourceFilter,
    searchTerm,
  ]);

  // ============================================================
  // SOURCE DISTRIBUTION
  // ============================================================

  const sourceDistribution = useMemo(() => {
    const counts = {};

    normalizedRecords.forEach((record) => {
      const source =
        record._source || "Unknown";

      counts[source] =
        (counts[source] || 0) + 1;
    });

    return Object.entries(counts).sort(
      (a, b) => b[1] - a[1]
    );
  }, [normalizedRecords]);

  // ============================================================
  // ENTITY DISTRIBUTION
  // ============================================================

  const entityDistribution = useMemo(() => {
    const counts = {};

    normalizedRecords.forEach((record) => {
      const type =
        record._entityType || "Unknown";

      counts[type] =
        (counts[type] || 0) + 1;
    });

    return Object.entries(counts).sort(
      (a, b) => b[1] - a[1]
    );
  }, [normalizedRecords]);

  // ============================================================
  // FORMAT DATE
  // ============================================================

  const formatDate = (value) => {
    if (!value) {
      return "Unknown time";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return String(value);
    }

    return date.toLocaleString();
  };

  // ============================================================
  // CLEAR FILTERS
  // ============================================================

  const clearFilters = () => {
    setEntityFilter("All");
    setSourceFilter("All");
    setSearchTerm("");
  };

  const filtersActive =
    entityFilter !== "All" ||
    sourceFilter !== "All" ||
    searchTerm.trim() !== "";

  // ============================================================
  // OPEN RECORD
  // ============================================================

  const openRecord = (record) => {
    setSelectedRecord(record);
  };

  // ============================================================
  // EMPTY STATE
  // ============================================================

  if (normalizedRecords.length === 0) {
    return (
      <div className="provenance-container">
        <div className="empty-inline">
          <Fingerprint size={18} />

          <span>
            No provenance data available for
            this analysis.
          </span>
        </div>
      </div>
    );
  }

  // ============================================================
  // RENDER
  // ============================================================

  return (
    <div className="provenance-container">

      {/* ======================================================
          SUMMARY
      ====================================================== */}

      <div className="provenance-summary">

        <div className="provenance-summary-main">

          <div className="provenance-summary-icon">
            <Fingerprint size={22} />
          </div>

          <div>
            <span className="provenance-summary-label">
              TOTAL OBSERVATIONS
            </span>

            <strong className="provenance-summary-number">
              {normalizedRecords.length}
            </strong>

            <p>
              Evidence records collected across{" "}
              {sourceDistribution.length}{" "}
              source
              {sourceDistribution.length !== 1
                ? "s"
                : ""}.
            </p>
          </div>

        </div>

        <div className="provenance-summary-stats">

          <div>
            <span>ENTITY TYPES</span>

            <strong>
              {entityDistribution.length}
            </strong>
          </div>

          <div>
            <span>SOURCES</span>

            <strong>
              {sourceDistribution.length}
            </strong>
          </div>

          <div>
            <span>VISIBLE</span>

            <strong>
              {filteredRecords.length}
            </strong>
          </div>

        </div>

      </div>

      {/* ======================================================
          SOURCE DISTRIBUTION
      ====================================================== */}

      <div className="provenance-distribution">

        <div className="distribution-header">

          <div>
            <span className="provenance-mini-label">
              SOURCE DISTRIBUTION
            </span>

            <h4>
              Collection footprint
            </h4>
          </div>

          <span className="distribution-total">
            {normalizedRecords.length} observations
          </span>

        </div>

        <div className="source-bars">

          {sourceDistribution.map(
            ([source, count]) => {
              const percentage =
                normalizedRecords.length > 0
                  ? (count /
                      normalizedRecords.length) *
                    100
                  : 0;

              const isActive =
                sourceFilter === source;

              return (
                <button
                  key={source}
                  type="button"
                  className={`source-bar-row ${
                    isActive ? "active" : ""
                  }`}
                  onClick={() =>
                    setSourceFilter(
                      isActive
                        ? "All"
                        : source
                    )
                  }
                  title={`Filter by ${source}`}
                >

                  <div className="source-bar-label">
                    <span>{source}</span>

                    <strong>
                      {count}
                    </strong>
                  </div>

                  <div className="source-bar-track">

                    <div
                      className="source-bar-fill"
                      style={{
                        width: `${percentage}%`,
                      }}
                    />

                  </div>

                </button>
              );
            }
          )}

        </div>

      </div>

      {/* ======================================================
          FILTER CONTROLS
      ====================================================== */}

      <div className="provenance-controls">

        <div className="provenance-search">

          <Search size={16} />

          <input
            type="text"
            placeholder="Search evidence, entity, source, method..."
            value={searchTerm}
            onChange={(event) =>
              setSearchTerm(
                event.target.value
              )
            }
          />

          {searchTerm && (
            <button
              type="button"
              className="clear-search"
              onClick={() =>
                setSearchTerm("")
              }
              aria-label="Clear search"
            >
              <X size={14} />
            </button>
          )}

        </div>

        <div className="provenance-filter">

          <span>ENTITY</span>

          <div className="select-wrapper">

            <select
              value={entityFilter}
              onChange={(event) =>
                setEntityFilter(
                  event.target.value
                )
              }
            >
              {entityTypes.map((type) => (
                <option
                  key={type}
                  value={type}
                >
                  {type}
                </option>
              ))}
            </select>

            <ChevronDown size={14} />

          </div>

        </div>

        <div className="provenance-filter">

          <span>SOURCE</span>

          <div className="select-wrapper">

            <select
              value={sourceFilter}
              onChange={(event) =>
                setSourceFilter(
                  event.target.value
                )
              }
            >
              {sources.map((source) => (
                <option
                  key={source}
                  value={source}
                >
                  {source}
                </option>
              ))}
            </select>

            <ChevronDown size={14} />

          </div>

        </div>

        {filtersActive && (
          <button
            type="button"
            className="clear-filters-button"
            onClick={clearFilters}
          >
            <X size={14} />
            Clear
          </button>
        )}

      </div>

      {/* ======================================================
          FILTER STATUS
      ====================================================== */}

      <div className="provenance-result-status">

        <span>
          Showing{" "}
          <strong>
            {filteredRecords.length}
          </strong>{" "}
          of{" "}
          <strong>
            {normalizedRecords.length}
          </strong>{" "}
          observations
        </span>

        {filtersActive && (
          <span className="filter-active">
            Filters active
          </span>
        )}

      </div>

      {/* ======================================================
          EVIDENCE TABLE
      ====================================================== */}

      {filteredRecords.length > 0 ? (

        <div className="provenance-table-wrapper">

          <table className="provenance-table">

            <thead>
              <tr>
                <th>#</th>
                <th>ENTITY TYPE</th>
                <th>OBSERVED VALUE</th>
                <th>SOURCE</th>
                <th>METHOD</th>
                <th>RECORDED</th>
              </tr>
            </thead>

            <tbody>

              {filteredRecords.map(
                (record, index) => {

                  const recordKey =
                    record._id ??
                    `${record._entityType}-${record._entityValue}-${record._source}-${record._index}`;

                  return (
                    <tr
                      key={recordKey}
                      className="provenance-table-row"
                      onClick={() =>
                        openRecord(record)
                      }
                      onKeyDown={(event) => {
                        if (
                          event.key === "Enter" ||
                          event.key === " "
                        ) {
                          event.preventDefault();
                          openRecord(record);
                        }
                      }}
                      tabIndex={0}
                      role="button"
                      aria-label={`View provenance record for ${record._entityValue}`}
                    >

                      <td className="provenance-number">
                        {String(
                          index + 1
                        ).padStart(4, "0")}
                      </td>

                      <td>
                        <span className="entity-type-badge">
                          {record._entityType}
                        </span>
                      </td>

                      <td className="evidence-value">
                        {record._entityValue}
                      </td>

                      <td>
                        <span className="source-badge">
                          {record._source}
                        </span>
                      </td>

                      <td className="method-value">
                        {record._method}
                      </td>

                      <td className="time-value">
                        {formatDate(
                          record._recordedAt
                        )}
                      </td>

                    </tr>
                  );
                }
              )}

            </tbody>

          </table>

        </div>

      ) : (

        <div className="provenance-no-results">

          <Search size={20} />

          <strong>
            No matching evidence
          </strong>

          <span>
            Try changing the search term
            or filters.
          </span>

          <button
            type="button"
            onClick={clearFilters}
          >
            Clear filters
          </button>

        </div>

      )}

      {/* ======================================================
          DETAIL MODAL
      ====================================================== */}

      {selectedRecord && (

        <div
          className="provenance-modal-overlay"
          onClick={() =>
            setSelectedRecord(null)
          }
        >

          <div
            className="provenance-modal"
            onClick={(event) =>
              event.stopPropagation()
            }
          >

            {/* HEADER */}

            <div className="provenance-modal-header">

              <div>

                <span className="provenance-mini-label">
                  EVIDENCE DETAIL
                </span>

                <h4>
                  Provenance Record
                </h4>

              </div>

              <button
                type="button"
                className="modal-close"
                onClick={() =>
                  setSelectedRecord(null)
                }
                aria-label="Close provenance detail"
              >
                <X size={18} />
              </button>

            </div>

            {/* DETAILS */}

            <div className="provenance-detail-grid">

              <div className="detail-field">

                <span>
                  ENTITY TYPE
                </span>

                <strong>
                  {selectedRecord._entityType}
                </strong>

              </div>

              <div className="detail-field">

                <span>
                  SOURCE
                </span>

                <strong>
                  {selectedRecord._source}
                </strong>

              </div>

              <div className="detail-field detail-field-wide">

                <span>
                  OBSERVED VALUE
                </span>

                <strong className="detail-value-break">
                  {selectedRecord._entityValue}
                </strong>

              </div>

              {selectedRecord._relationship && (
                <div className="detail-field detail-field-wide">

                  <span>
                    RELATIONSHIP
                  </span>

                  <strong>
                    {selectedRecord._relationship}
                  </strong>

                </div>
              )}

              <div className="detail-field">

                <span>
                  METHOD
                </span>

                <strong>
                  {selectedRecord._method}
                </strong>

              </div>

              <div className="detail-field">

                <span>
                  RECORDED AT
                </span>

                <strong>
                  {formatDate(
                    selectedRecord._recordedAt
                  )}
                </strong>

              </div>

              {selectedRecord._sourceUrl && (
                <div className="detail-field detail-field-wide">

                  <span>
                    SOURCE URL
                  </span>

                  <a
                    href={
                      selectedRecord._sourceUrl
                    }
                    target="_blank"
                    rel="noopener noreferrer"
                    className="provenance-source-link"
                    onClick={(event) =>
                      event.stopPropagation()
                    }
                  >
                    <span className="detail-value-break">
                      {selectedRecord._sourceUrl}
                    </span>

                    <ExternalLink size={13} />
                  </a>

                </div>
              )}

              {selectedRecord._id && (
                <div className="detail-field detail-field-wide">

                  <span>
                    PROVENANCE ID
                  </span>

                  <strong className="detail-value-break">
                    {selectedRecord._id}
                  </strong>

                </div>
              )}

            </div>

            {/* PROVENANCE EXPLANATION */}

            <div className="provenance-academic-note">

              <Fingerprint size={16} />

              <div>

                <strong>
                  Evidence provenance
                </strong>

                <span>
                  This record preserves the
                  observed value together with
                  its source, collection method,
                  and observation timestamp.
                  These provenance attributes
                  allow the analyst to trace how
                  the corresponding OSINT entity
                  was collected and correlated.
                </span>

              </div>

            </div>

          </div>

        </div>

      )}

    </div>
  );
}

export default Provenance;

