export function normalizeAnalysisData(data) {
  return {
    ...data,

    infrastructure: {
      subdomains:
        Array.isArray(data?.infrastructure?.subdomains)
          ? data.infrastructure.subdomains
          : [],

      ip_addresses:
        Array.isArray(data?.infrastructure?.ip_addresses)
          ? data.infrastructure.ip_addresses
          : [],

      asns:
        Array.isArray(data?.infrastructure?.asns)
          ? data.infrastructure.asns
          : [],

      organizations:
        Array.isArray(
          data?.infrastructure?.organizations
        )
          ? data.infrastructure.organizations
          : [],

      certificates:
        Array.isArray(
          data?.infrastructure?.certificates
        )
          ? data.infrastructure.certificates
          : [],
    },

    statistics: data?.statistics || {},

    ip_version_summary:
      data?.ip_version_summary || {},

    subdomain_patterns:
      data?.subdomain_patterns || {},

    observations:
      Array.isArray(data?.observations)
        ? data.observations
        : [],

    provenance:
      Array.isArray(data?.provenance)
        ? data.provenance
        : [],

    ai_report:
      typeof data?.ai_report === "string"
        ? data.ai_report
        : "",

    graph: {
      nodes: Array.isArray(data?.graph?.nodes)
        ? data.graph.nodes
        : [],

      edges: Array.isArray(data?.graph?.edges)
        ? data.graph.edges
        : [],

      provenance: Array.isArray(
        data?.graph?.provenance
      )
        ? data.graph.provenance
        : [],
    },

    raw_data: data?.raw_data || {},

    virustotal: data?.virustotal || {},

    port_scan: normalizePortScanData(
      data?.raw_data?.port_scan ||
        data?.port_scan ||
        {}
    ),
  };
}

export function normalizePortScanData(data) {
  const results = Array.isArray(data?.results)
    ? data.results.map((result) => {
        const openPorts = Array.isArray(
          result?.open_ports
        )
          ? result.open_ports
          : [];

        return {
          ...result,
          open_ports: openPorts,
          open_count:
            result?.open_count ??
            openPorts.length,
        };
      })
    : [];

  const calculatedOpenPorts = results.reduce(
    (total, result) =>
      total + result.open_ports.length,
    0
  );

  return {
    scanned_ips:
      Number(data?.scanned_ips) ||
      results.length,

    open_ports_total:
      Number(data?.open_ports_total) ||
      calculatedOpenPorts,

    results,
  };
}