import { useEffect, useRef, useState, useMemo, useCallback } from "react";
import cytoscape from "cytoscape";
import {
  getPriorityActiveSubdomains,
  getPrioritizedSubdomains
} from "./utils/subdomainPriority";

function HierarchicalGraph({
  graph,
  onNodeSelect,
  searchTerms: externalSearchTerms,
  onSearchChange,
}) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const animRef = useRef(null); // track in-flight camera animation

  // ============================================================
  // STATE
  // ============================================================

  const [expandedGroups, setExpandedGroups] = useState({
    Subdomain: false,
    IPAddress: false,
    Certificate: false,
  });

  const [internalSearchTerms, setInternalSearchTerms] = useState({
    Subdomain: "",
    IPAddress: "",
    Certificate: "",
  });

  const searchTerms = externalSearchTerms || internalSearchTerms;
  const setSearchTerms = onSearchChange || setInternalSearchTerms;

  const [selectedNode, setSelectedNode] = useState(null);
  const [isReady, setIsReady] = useState(false);

  const [focusedNodes, setFocusedNodes] = useState({
    Subdomain: null,
    IPAddress: null,
    Certificate: null,
  });

  // ============================================================
  // CONSTANTS
  // ============================================================

  const MAX_VISIBLE_ENTITIES = 5;
  const MAX_SEARCH_RESULTS = 100;
  const CAMERA_DURATION = 500;
  const ELEMENT_FADE_MS = 220;

  // ============================================================
  // HELPERS
  // ============================================================

  const getType = useCallback((node) => String(node?.data?.type ?? ""), []);

  const getNodeId = useCallback(
    (node) => String(node?.data?.id ?? node?.id ?? node?.data?.value ?? ""),
    []
  );

  const getValue = useCallback(
    (node) =>
      String(
        node?.data?.value ??
          node?.data?.label ??
          node?.data?.name ??
          node?.data?.id ??
          ""
      ),
    []
  );

  const getLabel = useCallback(
    (node) => {
      const value = getValue(node);
      if (getType(node) === "IPAddress" && value.length > 30) {
        return `${value.substring(0, 27)}...`;
      }
      return value;
    },
    [getValue, getType]
  );

  const getRelationship = useCallback(
    (edge) =>
      String(
        edge?.data?.label ?? edge?.data?.relationship ?? edge?.label ?? ""
      ),
    []
  );

  const getEdgeSource = useCallback(
    (edge) => String(edge?.data?.source ?? ""),
    []
  );

  const getEdgeTarget = useCallback(
    (edge) => String(edge?.data?.target ?? ""),
    []
  );

  const uniqueId = useCallback(
    (prefix, id) => `${prefix}_${String(id).replace(/[^a-zA-Z0-9_-]/g, "_")}`,
    []
  );

  const isOrganizationType = useCallback((type) => {
    const t = String(type);
    return t === "Organization" || t === "ORG" || t === "Organisation";
  }, []);

  // ============================================================
  // GRAPH DATA
  // ============================================================

  const allNodes = useMemo(
    () => (Array.isArray(graph?.nodes) ? graph.nodes : []),
    [graph]
  );
  const allEdges = useMemo(
    () => (Array.isArray(graph?.edges) ? graph.edges : []),
    [graph]
  );
  const provenance = useMemo(
    () => (Array.isArray(graph?.provenance) ? graph.provenance : []),
    [graph]
  );

  const domainNodes = useMemo(
    () => allNodes.filter((n) => getType(n) === "Domain"),
    [allNodes, getType]
  );
const subdomainNodes = useMemo(
  () => allNodes.filter((n) => getType(n) === "Subdomain"),
  [allNodes, getType]
);

const activeSubdomainNodes = useMemo(
  () =>
    subdomainNodes.filter(
      (node) =>
        node.data?.active === true ||
        node.data?.properties?.active === true
    ),
  [subdomainNodes]
);

const priorityActiveSubdomains = useMemo(
  () => getPriorityActiveSubdomains(subdomainNodes, 5),
  [subdomainNodes]
);

const prioritizedSubdomainNodes = useMemo(
  () => getPrioritizedSubdomains(subdomainNodes),
  [subdomainNodes]
);
  const ipNodes = useMemo(
    () => allNodes.filter((n) => getType(n) === "IPAddress"),
    [allNodes, getType]
  );
  const asnNodes = useMemo(
    () => allNodes.filter((n) => getType(n) === "ASN"),
    [allNodes, getType]
  );
  const organizationNodes = useMemo(
    () =>
      allNodes.filter((n) => {
        const t = getType(n);
        return t === "Organization" || t === "ORG" || t === "Organisation";
      }),
    [allNodes, getType]
  );
  const certificateNodes = useMemo(
    () => allNodes.filter((n) => getType(n) === "Certificate"),
    [allNodes, getType]
  );

  const findNodeById = useCallback(
    (id) => {
      const wanted = String(id);
      return allNodes.find((node) => getNodeId(node) === wanted);
    },
    [allNodes, getNodeId]
  );

  // ============================================================
  // PROVENANCE
  // ============================================================

  const getProvenanceForNode = useCallback(
    (nodeId) => {
      if (!provenance || provenance.length === 0) return [];

      const node = findNodeById(nodeId);
      const nodeValue = (node ? getValue(node) : "").trim().toLowerCase();
      if (!nodeValue) return [];

      const matched = provenance.filter((record) => {
        const entityValue = String(record.entity_value || "")
          .trim()
          .toLowerCase();
        return entityValue === nodeValue;
      });

      const groups = new Map();
      for (const record of matched) {
        const key = `${record.source || "Unknown"}|${record.method || ""}`;
        if (!groups.has(key)) {
          groups.set(key, {
            source: record.source || "Unknown Source",
            method: record.method || "N/A",
            count: 0,
            first_seen: record.recorded_at,
            last_seen: record.recorded_at,
            details: record.details,
          });
        }
        const g = groups.get(key);
        g.count += 1;

        const t = record.recorded_at ? new Date(record.recorded_at).getTime() : 0;
        const first = g.first_seen ? new Date(g.first_seen).getTime() : 0;
        const last = g.last_seen ? new Date(g.last_seen).getTime() : 0;
        if (t && (!first || t < first)) g.first_seen = record.recorded_at;
        if (t && (!last || t > last)) g.last_seen = record.recorded_at;
      }

      return Array.from(groups.values()).sort((a, b) => {
        const ta = a.last_seen ? new Date(a.last_seen).getTime() : 0;
        const tb = b.last_seen ? new Date(b.last_seen).getTime() : 0;
        return tb - ta;
      });
    },
    [provenance, findNodeById, getValue]
  );

  // ============================================================
  // SIDEBAR LIST FILTER
  // ============================================================

  const getSearchResults = useCallback(
    (nodes, type) => {
      if (!expandedGroups[type]) return [];
      const search = searchTerms[type]?.trim() || "";
      if (!search) return nodes.slice(0, MAX_VISIBLE_ENTITIES);
      const searchLower = search.toLowerCase();
      return nodes
        .filter((node) => getValue(node).toLowerCase().includes(searchLower))
        .slice(0, MAX_SEARCH_RESULTS);
    },
    [expandedGroups, searchTerms, getValue]
  );

 const subdomainResults = getSearchResults(
  prioritizedSubdomainNodes,
  "Subdomain"
);
  const ipResults = getSearchResults(ipNodes, "IPAddress");
  const certificateResults = getSearchResults(certificateNodes, "Certificate");

  const activeFocuses = useMemo(
    () => Object.values(focusedNodes).filter(Boolean),
    [focusedNodes]
  );
  const hasFocus = activeFocuses.length > 0;

  // ============================================================
  // BUILD DESIRED ELEMENTS
  // ============================================================

  const buildDesiredState = useCallback(() => {
    if (domainNodes.length === 0) {
      return { elements: [], focusCytoscapeIds: [] };
    }

    const domain = domainNodes[0];
    const domainId = getNodeId(domain);
    if (!domainId) return { elements: [], focusCytoscapeIds: [] };

    const pickVisible = (nodes, groupType) => {
      const focus = focusedNodes[groupType];
      if (focus) return nodes.filter((n) => getNodeId(n) === focus.id);
      return nodes.slice(0, MAX_VISIBLE_ENTITIES);
    };

    const visibleSubdomains = expandedGroups.Subdomain
      ? focusedNodes.Subdomain
        ? activeSubdomainNodes.filter(
            (node) => getNodeId(node) === focusedNodes.Subdomain.id
          )
        : priorityActiveSubdomains
      : [];
    const visibleIPs = expandedGroups.IPAddress
      ? pickVisible(ipNodes, "IPAddress")
      : [];
    const visibleCertificates = expandedGroups.Certificate
      ? pickVisible(certificateNodes, "Certificate")
      : [];

    const connectedASNIds = new Set();
    const connectedOrganizationIds = new Set();

    if (expandedGroups.IPAddress && visibleIPs.length > 0) {
      const visibleIpIds = new Set(visibleIPs.map(getNodeId));

      allEdges.forEach((edge) => {
        const source = getEdgeSource(edge);
        const target = getEdgeTarget(edge);
        const rel = getRelationship(edge);
        if (rel !== "BELONGS_TO_ASN") return;
        if (visibleIpIds.has(source)) connectedASNIds.add(target);
        if (visibleIpIds.has(target)) connectedASNIds.add(source);
      });

      allEdges.forEach((edge) => {
        const source = getEdgeSource(edge);
        const target = getEdgeTarget(edge);
        const rel = getRelationship(edge);
        if (rel !== "ASSOCIATED_WITH") return;
        if (connectedASNIds.has(source)) connectedOrganizationIds.add(target);
        if (connectedASNIds.has(target)) connectedOrganizationIds.add(source);
      });

      allEdges.forEach((edge) => {
        const source = getEdgeSource(edge);
        const target = getEdgeTarget(edge);
        const rel = getRelationship(edge);
        if (rel !== "ASSOCIATED_WITH") return;

        const sourceNode = findNodeById(source);
        const targetNode = findNodeById(target);

        if (
          visibleIpIds.has(source) &&
          targetNode &&
          isOrganizationType(getType(targetNode))
        ) {
          connectedOrganizationIds.add(target);
        }
        if (
          visibleIpIds.has(target) &&
          sourceNode &&
          isOrganizationType(getType(sourceNode))
        ) {
          connectedOrganizationIds.add(source);
        }
      });
    }

    const connectedASNs = asnNodes.filter((n) =>
      connectedASNIds.has(getNodeId(n))
    );
    const connectedOrganizations = organizationNodes.filter((n) =>
      connectedOrganizationIds.has(getNodeId(n))
    );

    const computeRowPositions = (nodes, centerX, y, spacing) => {
      if (!nodes.length) return [];
      const totalWidth = (nodes.length - 1) * spacing;
      const startX = centerX - totalWidth / 2;
      return nodes.map((node, i) => ({
        id: uniqueId("node", getNodeId(node)),
        x: startX + i * spacing,
        y,
      }));
    };

    const positions = [
      { id: uniqueId("node", domainId), x: 0, y: 0 },
      { id: "__group_subdomains", x: -400, y: 220 },
      { id: "__group_ips", x: 0, y: 220 },
      { id: "__group_certificates", x: 400, y: 220 },
      ...computeRowPositions(visibleSubdomains, -400, 430, 155),
      ...computeRowPositions(visibleIPs, 0, 430, 155),
      ...computeRowPositions(visibleCertificates, 400, 430, 155),
      ...(expandedGroups.IPAddress
        ? [
            ...computeRowPositions(connectedASNs, 0, 650, 180),
            ...computeRowPositions(connectedOrganizations, 0, 850, 220),
          ]
        : []),
    ];
    const posMap = new Map(positions.map((p) => [p.id, p]));

    const elements = [];
    const addedNodeIds = new Set();

    const addRealNode = (node) => {
      if (!node) return null;
      const originalId = getNodeId(node);
      if (!originalId) return null;
      const cytoscapeId = uniqueId("node", originalId);
      if (addedNodeIds.has(cytoscapeId)) return cytoscapeId;
      addedNodeIds.add(cytoscapeId);

      const pos = posMap.get(cytoscapeId);
      const el = {
        group: "nodes",
        data: {
          ...node.data,
          id: cytoscapeId,
          originalId,
          label: getLabel(node),
          type: getType(node),
        },
      };
      if (pos) el.position = { x: pos.x, y: pos.y };
      elements.push(el);
      return cytoscapeId;
    };

    const groupLabel = (type, totalCount) => {
      if (focusedNodes[type]) return `${type.toUpperCase()}\n1 focused`;
      return `${type.toUpperCase()}\n${totalCount} total`;
    };

    const addGroupNode = (id, groupType, count) => {
      const label = groupLabel(groupType, count);
      const pos = posMap.get(id);
      const el = {
        group: "nodes",
        data: { id, type: "Group", groupType, label, count },
      };
      if (pos) el.position = { x: pos.x, y: pos.y };
      elements.push(el);
    };

    addRealNode(domain);
    addGroupNode("__group_subdomains", "Subdomain", subdomainNodes.length);
    addGroupNode("__group_ips", "IPAddress", ipNodes.length);
    addGroupNode("__group_certificates", "Certificate", certificateNodes.length);

    elements.push(
      {
        group: "edges",
        data: {
          id: "__struct_domain_subdomains",
          source: uniqueId("node", domainId),
          target: "__group_subdomains",
          label: "HAS_SUBDOMAIN",
        },
      },
      {
        group: "edges",
        data: {
          id: "__struct_domain_ips",
          source: uniqueId("node", domainId),
          target: "__group_ips",
          label: "RESOLVES_TO",
        },
      },
      {
        group: "edges",
        data: {
          id: "__struct_domain_certificates",
          source: uniqueId("node", domainId),
          target: "__group_certificates",
          label: "HAS_CERTIFICATE",
        },
      }
    );

    const addGroupEntityEdge = (groupId, node, index, prefix) => {
      const originalId = getNodeId(node);
      if (!originalId) return;
      elements.push({
        group: "edges",
        data: {
          id: uniqueId(prefix, `${originalId}_${index}`),
          source: groupId,
          target: uniqueId("node", originalId),
          label: "",
        },
      });
    };

    visibleSubdomains.forEach((node, i) => {
      addRealNode(node);
      addGroupEntityEdge("__group_subdomains", node, i, "subdomain_group_edge");
    });
    visibleIPs.forEach((node, i) => {
      addRealNode(node);
      addGroupEntityEdge("__group_ips", node, i, "ip_group_edge");
    });
    visibleCertificates.forEach((node, i) => {
      addRealNode(node);
      addGroupEntityEdge("__group_certificates", node, i, "certificate_group_edge");
    });

    if (expandedGroups.IPAddress && visibleIPs.length > 0) {
      connectedASNs.forEach((n) => addRealNode(n));
      connectedOrganizations.forEach((n) => addRealNode(n));

      const visibleOriginalIds = new Set([
        ...visibleIPs.map(getNodeId),
        ...connectedASNs.map(getNodeId),
        ...connectedOrganizations.map(getNodeId),
      ]);

      const addedRelIds = new Set();
      allEdges.forEach((edge, index) => {
        const source = getEdgeSource(edge);
        const target = getEdgeTarget(edge);
        const rel = getRelationship(edge);

        if (rel !== "BELONGS_TO_ASN" && rel !== "ASSOCIATED_WITH") return;
        if (!visibleOriginalIds.has(source) || !visibleOriginalIds.has(target))
          return;

        const edgeId = uniqueId(
          "relationship",
          edge?.data?.id ?? `${source}_${rel}_${target}_${index}`
        );
        if (addedRelIds.has(edgeId)) return;
        addedRelIds.add(edgeId);

        elements.push({
          group: "edges",
          data: {
            ...edge.data,
            id: edgeId,
            source: uniqueId("node", source),
            target: uniqueId("node", target),
            label: rel,
          },
        });
      });
    }

    const focusCytoscapeIds = Object.values(focusedNodes)
      .filter(Boolean)
      .map((f) => uniqueId("node", f.id));

    return { elements, focusCytoscapeIds };
  }, [
    domainNodes,
    subdomainNodes,
    ipNodes,
    asnNodes,
    organizationNodes,
    certificateNodes,
    allEdges,
    expandedGroups,
    focusedNodes,
    getNodeId,
    getType,
    getLabel,
    getValue,
    getRelationship,
    getEdgeSource,
    getEdgeTarget,
    uniqueId,
    findNodeById,
    isOrganizationType,
  ]);

  // ============================================================
  // CYTOSCAPE INIT
  // ============================================================

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    if (domainNodes.length === 0) return;

    setIsReady(false);

    const cy = cytoscape({
      container,
      elements: [],

      style: [
        {
          selector: "node",
          style: {
            "background-color": "#ffffff",
            "border-color": "#8aca9a",
            "border-width": 2,
            label: "data(label)",
            color: "#0a2e1a",
            "font-size": 10,
            "font-weight": "600",
            "text-valign": "center",
            "text-halign": "center",
            "text-wrap": "wrap",
            "text-max-width": 130,
            "line-height": 1.3,
            "text-outline-color": "#ffffff",
            "text-outline-width": 2,
            width: 85,
            height: 65,
            shape: "round-rectangle",
            "overlay-opacity": 0,
          },
        },
        {
          selector: 'node[type="Domain"]',
          style: {
            "background-color": "#0a2e1a",
            "border-color": "#2a6a3a",
            "border-width": 4,
            width: 140,
            height: 90,
            shape: "round-rectangle",
            "font-size": 16,
            "font-weight": "bold",
            color: "#ffffff",
            "text-max-width": 160,
            "text-outline-width": 0,
          },
        },
        {
          selector: 'node[type="Group"]',
          style: {
            "background-color": "#f0f3ee",
            "background-opacity": 1,
            "border-color": "#3a8a4a",
            "border-width": 2,
            "border-style": "dashed",
            width: 170,
            height: 90,
            shape: "round-rectangle",
            "font-size": 12,
            "font-weight": "700",
            color: "#0a2e1a",
            "text-max-width": 150,
            "text-wrap": "wrap",
            "text-valign": "center",
            "text-halign": "center",
            "text-outline-width": 0,
            "line-height": 1.3,
          },
        },
        {
          selector: 'node[type="Subdomain"]',
          style: {
            "background-color": "#d0e8d8",
            "border-color": "#3a8a4a",
            "border-width": 2,
            width: 125,
            height: 65,
            "font-size": 10,
            color: "#0a2e1a",
            "text-max-width": 115,
            shape: "round-rectangle",
          },
        },
        {
          selector: 'node[type="IPAddress"]',
          style: {
            "background-color": "#2a6a3a",
            "border-color": "#1a4a2a",
            "border-width": 2,
            width: 135,
            height: 65,
            "font-size": 10,
            color: "#ffffff",
            "text-max-width": 125,
            shape: "round-rectangle",
            "text-outline-width": 0,
          },
        },
        {
          selector: 'node[type="ASN"]',
          style: {
            "background-color": "#5aaa6a",
            "border-color": "#2a6a3a",
            "border-width": 2,
            width: 120,
            height: 65,
            "font-size": 11,
            color: "#0a2e1a",
            shape: "round-rectangle",
          },
        },
        {
          selector:
            'node[type="Organization"], node[type="ORG"], node[type="Organisation"]',
          style: {
            "background-color": "#1a4a2a",
            "border-color": "#0a2e1a",
            "border-width": 2,
            width: 155,
            height: 70,
            "font-size": 10,
            color: "#ffffff",
            "text-max-width": 145,
            shape: "round-rectangle",
            "text-outline-width": 0,
          },
        },
        {
          selector: 'node[type="Certificate"]',
          style: {
            "background-color": "#8aca9a",
            "border-color": "#3a8a4a",
            "border-width": 2,
            width: 135,
            height: 65,
            "font-size": 10,
            color: "#0a2e1a",
            "text-max-width": 125,
            shape: "round-rectangle",
          },
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "line-color": "#8aca9a",
            "target-arrow-color": "#3a8a4a",
            "target-arrow-shape": "triangle",
            "source-arrow-shape": "none",
            "curve-style": "bezier",
            label: "data(label)",
            color: "#1a4a2a",
            "font-size": 8,
            "font-weight": "600",
            "text-background-color": "#ffffff",
            "text-background-opacity": 0.95,
            "text-background-padding": 3,
            "text-rotation": "autorotate",
            opacity: 0.85,
          },
        },
        {
          selector: 'edge[label="HAS_SUBDOMAIN"]',
          style: {
            "line-color": "#5aaa6a",
            "target-arrow-color": "#3a8a4a",
            width: 2.5,
            color: "#2a6a3a",
          },
        },
        {
          selector: 'edge[label="RESOLVES_TO"]',
          style: {
            "line-color": "#3a8a4a",
            "target-arrow-color": "#2a6a3a",
            width: 2.5,
            color: "#1a4a2a",
          },
        },
        {
          selector: 'edge[label="BELONGS_TO_ASN"]',
          style: {
            "line-color": "#2a6a3a",
            "target-arrow-color": "#1a4a2a",
            width: 2.5,
            color: "#1a4a2a",
          },
        },
        {
          selector: 'edge[label="ASSOCIATED_WITH"]',
          style: {
            "line-color": "#0a2e1a",
            "target-arrow-color": "#0a2e1a",
            width: 2.5,
            color: "#0a2e1a",
          },
        },
        {
          selector: 'edge[label="HAS_CERTIFICATE"]',
          style: {
            "line-color": "#8aca9a",
            "target-arrow-color": "#5aaa6a",
            width: 2.5,
            color: "#2a6a3a",
          },
        },
        {
          selector: "node:selected",
          style: {
            "border-color": "#0a2e1a",
            "border-width": 4,
            "overlay-opacity": 0,
          },
        },
        {
          selector: "edge:selected",
          style: {
            "line-color": "#0a2e1a",
            "target-arrow-color": "#0a2e1a",
            width: 3.5,
            opacity: 1,
          },
        },
      ],

      layout: { name: "preset" },
      minZoom: 0.15,
      maxZoom: 3,
      wheelSensitivity: 0.25,
    });

    cyRef.current = cy;

    cy.on("tap", 'node[type="Group"]', (event) => {
      const group = event.target;
      const groupType = group.data("groupType");
      setFocusedNodes((prev) => ({ ...prev, [groupType]: null }));
      setSelectedNode(null);
      if (typeof onNodeSelect === "function") onNodeSelect(null);
      setExpandedGroups((prev) => ({
        ...prev,
        [groupType]: !prev[groupType],
      }));
    });

    cy.on("tap", 'node[type!="Group"]', (event) => {
      const node = event.target;
      const type = String(node.data("type"));

      if (type === "Domain") {
        node.unselect();
        setSelectedNode(null);
        setFocusedNodes({
          Subdomain: null,
          IPAddress: null,
          Certificate: null,
        });
        if (typeof onNodeSelect === "function") onNodeSelect(null);
        return;
      }

      const originalId = String(node.data("originalId"));
      const originalNode = findNodeById(originalId);
      if (!originalNode) return;

      setFocusedNodes((prev) => ({
        ...prev,
        [type]: { type, id: originalId },
      }));

      const connectedEdges = allEdges.filter((edge) => {
        const s = getEdgeSource(edge);
        const t = getEdgeTarget(edge);
        return s === originalId || t === originalId;
      });

      const connectedNodes = connectedEdges
        .map((edge) => {
          const s = getEdgeSource(edge);
          const t = getEdgeTarget(edge);
          const other = s === originalId ? t : s;
          return findNodeById(other);
        })
        .filter(Boolean);

      const nodeProvenance = getProvenanceForNode(originalId);

      const selection = {
        ...originalNode.data,
        id: originalId,
        type: getType(originalNode),
        value: getValue(originalNode),
        label: getLabel(originalNode),
        original: originalNode,
        connectedNodes,
        connectedEdges,
        provenance: nodeProvenance,
      };

      setSelectedNode(selection);
      if (typeof onNodeSelect === "function") onNodeSelect(selection);
    });

    cy.on("mouseover", "node", (event) => {
      event.target.style("border-width", 4);
    });

    cy.on("mouseout", "node", (event) => {
      const node = event.target;
      if (!node.selected()) {
        const type = node.data("type");
        node.style("border-width", type === "Domain" ? 4 : 2);
      }
    });

    let resizeTimer;
    const resizeObserver = new ResizeObserver(() => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        if (!cyRef.current) return;
        cyRef.current.resize();
      }, 120);
    });
    resizeObserver.observe(container);

    return () => {
      clearTimeout(resizeTimer);
      resizeObserver.disconnect();
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph]);

  // ============================================================
  // SYNC EFFECT — smooth add/remove via opacity fade
  // ============================================================

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    const { elements: desiredElements, focusCytoscapeIds } =
      buildDesiredState();

    // Stop any in-flight camera animation so it doesn't fight the new one
    if (animRef.current) {
      animRef.current.stop();
      animRef.current = null;
    }

    const desiredNodeIds = new Set();
    const desiredEdgeIds = new Set();
    for (const el of desiredElements) {
      if (el.group === "nodes") desiredNodeIds.add(el.data.id);
      else desiredEdgeIds.add(el.data.id);
    }

    // ---- 1. FADE OUT + REMOVE STALE ELEMENTS ----
    const staleEdges = cy
      .edges()
      .filter((e) => !desiredEdgeIds.has(e.id()));
    const staleNodes = cy
      .nodes()
      .filter((n) => !desiredNodeIds.has(n.id()));

    if (staleEdges.length > 0 || staleNodes.length > 0) {
      const stale = staleEdges.union(staleNodes);
      stale.animate(
        {
          style: {
            opacity: 0,
            "border-opacity": 0,
            "background-opacity": 0,
            "text-opacity": 0,
            "line-opacity": 0,
          },
        },
        {
          duration: ELEMENT_FADE_MS,
          complete: () => {
            stale.remove();
          },
        }
      );
    }

    // ---- 2. ADD NEW ELEMENTS WITH opacity: 0 ----
    const toAdd = [];
    for (const el of desiredElements) {
      const existing = cy.getElementById(el.data.id);
      if (existing.empty()) {
        toAdd.push({ ...el, style: { opacity: 0 } });
      }
    }

    const addedEls = toAdd.length > 0 ? cy.add(toAdd) : cy.collection();

    // ---- 3. UPDATE EXISTING ELEMENTS (data + position) ----
    for (const el of desiredElements) {
      const existing = cy.getElementById(el.data.id);
      if (existing.empty()) continue;
      existing.data(el.data);
      if (el.position) existing.position(el.position);
      // Ensure opacity is 1 (in case it was fading)
      existing.style("opacity", 1);
    }

    // ---- 4. FADE IN NEWLY ADDED ----
    if (addedEls.length > 0) {
      addedEls.animate(
        { style: { opacity: 1 } },
        { duration: ELEMENT_FADE_MS, easing: "ease-out" }
      );
    }

    // ---- 5. Hide empty groups ----
    const hideIfEmpty = (groupId, edgeId, isEmpty) => {
      const g = cy.getElementById(groupId);
      const e = cy.getElementById(edgeId);
      if (!g.empty()) g.style("display", isEmpty ? "none" : "element");
      if (!e.empty()) e.style("display", isEmpty ? "none" : "element");
    };
    hideIfEmpty(
      "__group_subdomains",
      "__struct_domain_subdomains",
      subdomainNodes.length === 0
    );
    hideIfEmpty(
      "__group_ips",
      "__struct_domain_ips",
      ipNodes.length === 0
    );
    hideIfEmpty(
      "__group_certificates",
      "__struct_domain_certificates",
      certificateNodes.length === 0
    );

    // ---- 6. Update selection ----
    cy.nodes().unselect();
    focusCytoscapeIds.forEach((id) => {
      const el = cy.getElementById(id);
      if (!el.empty()) el.select();
    });

    // ---- 7. SMOOTH CAMERA TRANSITION ----
    // Wait a tick so newly-added elements have their positions applied
    const rafId = requestAnimationFrame(() => {
      const cyNow = cyRef.current;
      if (!cyNow) return;

      let targetZoom;
      let targetPan;

      if (focusCytoscapeIds.length > 0) {
        const focusEls = focusCytoscapeIds
          .map((id) => cyNow.getElementById(id))
          .filter((el) => !el.empty());

        if (focusEls.length > 0) {
          const collection = cyNow.collection(
            focusEls.flatMap((el) => [el, ...el.connectedEdges()])
          );
          const bb = collection.boundingBox();
          const padding = 160;
          const containerW = cyNow.width();
          const containerH = cyNow.height();
          const bbW = bb.w + padding * 2;
          const bbH = bb.h + padding * 2;
          targetZoom = Math.min(
            cyNow.maxZoom(),
            Math.max(
              cyNow.minZoom(),
              Math.min(containerW / bbW, containerH / bbH)
            )
          );
          targetPan = {
            x: containerW / 2 - ((bb.x1 + bb.x2) / 2) * targetZoom,
            y: containerH / 2 - ((bb.y1 + bb.y2) / 2) * targetZoom,
          };
        }
      }

      if (targetZoom === undefined) {
        // Fit all visible
        const visible = cyNow.elements(":visible");
        if (visible.length > 0) {
          const bb = visible.boundingBox();
          const padding = 80;
          const containerW = cyNow.width();
          const containerH = cyNow.height();
          const bbW = bb.w + padding * 2;
          const bbH = bb.h + padding * 2;
          targetZoom = Math.min(
            cyNow.maxZoom(),
            Math.max(
              cyNow.minZoom(),
              Math.min(containerW / bbW, containerH / bbH)
            )
          );
          targetPan = {
            x: containerW / 2 - ((bb.x1 + bb.x2) / 2) * targetZoom,
            y: containerH / 2 - ((bb.y1 + bb.y2) / 2) * targetZoom,
          };
        }
      }

      if (targetZoom !== undefined && targetPan !== undefined) {
        // Skip animation if we're already essentially there
        const currentZoom = cyNow.zoom();
        const currentPan = cyNow.pan();
        const zoomDelta = Math.abs(currentZoom - targetZoom);
        const panDelta =
          Math.abs(currentPan.x - targetPan.x) +
          Math.abs(currentPan.y - targetPan.y);

        if (zoomDelta < 0.01 && panDelta < 2) {
          // Nothing to animate
          if (!isReady) setIsReady(true);
          return;
        }

        const anim = cyNow.animate(
          { zoom: targetZoom, pan: targetPan },
          {
            duration: CAMERA_DURATION,
            easing: "ease-out-cubic",
            complete: () => {
              animRef.current = null;
            },
          }
        );
        animRef.current = anim;
      }

      if (!isReady) setIsReady(true);
    });

    return () => {
      cancelAnimationFrame(rafId);
    };
  }, [
    buildDesiredState,
    subdomainNodes.length,
    ipNodes.length,
    certificateNodes.length,
    isReady,
  ]);

  // ============================================================
  // ACTIONS
  // ============================================================

  const closeSelection = () => {
    setSelectedNode(null);
    if (typeof onNodeSelect === "function") onNodeSelect(null);
    if (cyRef.current) cyRef.current.nodes().unselect();
  };

  const handleSearch = (type, value) => {
    setSearchTerms((prev) => ({ ...prev, [type]: value }));
  };

  const handleEntityClick = (type, node) => {
    setExpandedGroups((prev) => ({ ...prev, [type]: true }));
    setFocusedNodes((prev) => ({
      ...prev,
      [type]: { type, id: getNodeId(node) },
    }));
    setSelectedNode(null);
    if (typeof onNodeSelect === "function") onNodeSelect(null);
  };

  const clearFocus = (type) => {
    if (type) {
      setFocusedNodes((prev) => ({ ...prev, [type]: null }));
    } else {
      setFocusedNodes({
        Subdomain: null,
        IPAddress: null,
        Certificate: null,
      });
    }
    setSelectedNode(null);
  };

  // ============================================================
  // RENDER
  // ============================================================

  return (
    <div style={{ width: "100%", position: "relative" }}>
      <div
        ref={containerRef}
        className="cytoscape-container hierarchical-graph-container"
        style={{
          width: "100%",
          height: "700px",
          minHeight: "700px",
          position: "relative",
          borderRadius: "12px",
          overflow: "hidden",
          border: "1px solid #d0e8d8",
          background: `
            radial-gradient(circle at 20% 30%, rgba(58, 138, 74, 0.06) 0%, transparent 55%),
            radial-gradient(circle at 80% 70%, rgba(42, 106, 58, 0.05) 0%, transparent 55%),
            linear-gradient(rgba(10, 46, 26, 0.035) 1px, transparent 1px),
            linear-gradient(90deg, rgba(10, 46, 26, 0.035) 1px, transparent 1px),
            #ffffff
          `,
          backgroundSize: `100% 100%, 100% 100%, 30px 30px, 30px 30px`,
          opacity: isReady ? 1 : 0,
          transition: "opacity 0.4s ease-out",
          boxShadow: "0 1px 3px rgba(10, 46, 26, 0.04)",
        }}
      />

      {hasFocus && (
        <div
          style={{
            position: "absolute",
            top: "12px",
            right: "12px",
            padding: "8px 12px",
            background: "#0a2e1a",
            color: "#ffffff",
            borderRadius: "20px",
            fontSize: "11px",
            fontWeight: "600",
            display: "flex",
            alignItems: "center",
            gap: "8px",
            zIndex: 10,
            boxShadow: "0 2px 8px rgba(10,46,26,0.2)",
            maxWidth: "70%",
            flexWrap: "wrap",
          }}
        >
          {activeFocuses.map((f) => (
            <span
              key={f.type}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                background: "rgba(255,255,255,0.12)",
                padding: "3px 8px",
                borderRadius: "12px",
                maxWidth: "220px",
              }}
            >
              <span
                style={{
                  color: "#8aca9a",
                  fontSize: "10px",
                  textTransform: "uppercase",
                  letterSpacing: "0.3px",
                  fontWeight: "700",
                }}
              >
                {f.type}
              </span>
              <span
                style={{
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {f.id}
              </span>
              <button
                type="button"
                onClick={() => clearFocus(f.type)}
                title={`Clear ${f.type} focus`}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "#ffffff",
                  cursor: "pointer",
                  fontSize: "13px",
                  lineHeight: 1,
                  padding: 0,
                  marginLeft: "2px",
                }}
              >
                ×
              </button>
            </span>
          ))}
          <button
            type="button"
            onClick={() => clearFocus(null)}
            title="Show all nodes"
            style={{
              background: "rgba(255,255,255,0.15)",
              border: "none",
              color: "#ffffff",
              cursor: "pointer",
              padding: "3px 10px",
              borderRadius: "10px",
              fontSize: "10px",
              fontWeight: "700",
              lineHeight: 1,
              whiteSpace: "nowrap",
            }}
          >
            Show all ×
          </button>
        </div>
      )}

      {(subdomainNodes.length > 0 ||
        ipNodes.length > 0 ||
        certificateNodes.length > 0) && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
            gap: "12px",
            marginTop: "14px",
          }}
        >
          {expandedGroups.Subdomain && subdomainNodes.length > 0 && (
            <div
              style={{
                background: "#ffffff",
                border: "1px solid #d0e8d8",
                borderRadius: "10px",
                padding: "12px",
                boxShadow: "0 1px 3px rgba(10,46,26,0.04)",
              }}
            >
              <div
                style={{
                  fontWeight: "700",
                  color: "#0a2e1a",
                  marginBottom: "8px",
                  fontSize: "13px",
                }}
              >
                Subdomains ({subdomainNodes.length})
              </div>
              <input
                type="text"
                placeholder="Search subdomains..."
                value={searchTerms.Subdomain}
                onChange={(e) => handleSearch("Subdomain", e.target.value)}
                style={{
                  width: "100%",
                  boxSizing: "border-box",
                  padding: "6px 10px",
                  borderRadius: "6px",
                  border: "1px solid #d0e8d8",
                  background: "#f8faf7",
                  color: "#0a2e1a",
                  outline: "none",
                  marginBottom: "8px",
                  fontSize: "12px",
                }}
              />
              <div style={{ maxHeight: "150px", overflowY: "auto" }}>
                {subdomainResults.map((node) => (
                  <button
                    type="button"
                    key={getNodeId(node)}
                    onClick={() => handleEntityClick("Subdomain", node)}
                    style={{
                      display: "block",
                      width: "100%",
                      textAlign: "left",
                      padding: "5px 8px",
                      marginBottom: "3px",
                      borderRadius: "4px",
                      border: "none",
                      cursor: "pointer",
                      background: "#f0f3ee",
                      color: "#0a2e1a",
                      fontSize: "11px",
                      wordBreak: "break-word",
                      transition: "background 0.2s",
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = "#d0e8d8";
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = "#f0f3ee";
                    }}
                  >
                    {getValue(node)}
                  </button>
                ))}
              </div>
              {subdomainNodes.length > MAX_VISIBLE_ENTITIES &&
                !searchTerms.Subdomain.trim() && (
                  <div
                    style={{
                      marginTop: "6px",
                      color: "#5aaa6a",
                      fontSize: "10px",
                    }}
                  >
                    Showing first{" "}
                    {Math.min(subdomainNodes.length, MAX_VISIBLE_ENTITIES)} of{" "}
                    {subdomainNodes.length}. Search to find more.
                  </div>
                )}
            </div>
          )}

          {expandedGroups.IPAddress && ipNodes.length > 0 && (
            <div
              style={{
                background: "#ffffff",
                border: "1px solid #d0e8d8",
                borderRadius: "10px",
                padding: "12px",
                boxShadow: "0 1px 3px rgba(10,46,26,0.04)",
              }}
            >
              <div
                style={{
                  fontWeight: "700",
                  color: "#0a2e1a",
                  marginBottom: "8px",
                  fontSize: "13px",
                }}
              >
                IP Addresses ({ipNodes.length})
              </div>
              <input
                type="text"
                placeholder="Search IP addresses..."
                value={searchTerms.IPAddress}
                onChange={(e) => handleSearch("IPAddress", e.target.value)}
                style={{
                  width: "100%",
                  boxSizing: "border-box",
                  padding: "6px 10px",
                  borderRadius: "6px",
                  border: "1px solid #d0e8d8",
                  background: "#f8faf7",
                  color: "#0a2e1a",
                  outline: "none",
                  marginBottom: "8px",
                  fontSize: "12px",
                }}
              />
              <div style={{ maxHeight: "150px", overflowY: "auto" }}>
                {ipResults.map((node) => (
                  <button
                    type="button"
                    key={getNodeId(node)}
                    onClick={() => handleEntityClick("IPAddress", node)}
                    style={{
                      display: "block",
                      width: "100%",
                      textAlign: "left",
                      padding: "5px 8px",
                      marginBottom: "3px",
                      borderRadius: "4px",
                      border: "none",
                      cursor: "pointer",
                      background: "#f0f3ee",
                      color: "#0a2e1a",
                      fontSize: "11px",
                      wordBreak: "break-word",
                      transition: "background 0.2s",
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = "#d0e8d8";
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = "#f0f3ee";
                    }}
                  >
                    {getValue(node)}
                  </button>
                ))}
              </div>
            </div>
          )}

          {expandedGroups.Certificate && certificateNodes.length > 0 && (
            <div
              style={{
                background: "#ffffff",
                border: "1px solid #d0e8d8",
                borderRadius: "10px",
                padding: "12px",
                boxShadow: "0 1px 3px rgba(10,46,26,0.04)",
              }}
            >
              <div
                style={{
                  fontWeight: "700",
                  color: "#0a2e1a",
                  marginBottom: "8px",
                  fontSize: "13px",
                }}
              >
                Certificates ({certificateNodes.length})
              </div>
              <input
                type="text"
                placeholder="Search certificates..."
                value={searchTerms.Certificate}
                onChange={(e) => handleSearch("Certificate", e.target.value)}
                style={{
                  width: "100%",
                  boxSizing: "border-box",
                  padding: "6px 10px",
                  borderRadius: "6px",
                  border: "1px solid #d0e8d8",
                  background: "#f8faf7",
                  color: "#0a2e1a",
                  outline: "none",
                  marginBottom: "8px",
                  fontSize: "12px",
                }}
              />
              <div style={{ maxHeight: "150px", overflowY: "auto" }}>
                {certificateResults.map((node) => (
                  <button
                    type="button"
                    key={getNodeId(node)}
                    onClick={() => handleEntityClick("Certificate", node)}
                    style={{
                      display: "block",
                      width: "100%",
                      textAlign: "left",
                      padding: "5px 8px",
                      marginBottom: "3px",
                      borderRadius: "4px",
                      border: "none",
                      cursor: "pointer",
                      background: "#f0f3ee",
                      color: "#0a2e1a",
                      fontSize: "11px",
                      wordBreak: "break-word",
                      transition: "background 0.2s",
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = "#d0e8d8";
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = "#f0f3ee";
                    }}
                  >
                    {getValue(node)}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {selectedNode && (
        <div
          style={{
            marginTop: "16px",
            width: "100%",
            boxSizing: "border-box",
            padding: "20px",
            borderRadius: "12px",
            background: "#ffffff",
            border: "1px solid #d0e8d8",
            color: "#0a2e1a",
            boxShadow: "0 4px 20px rgba(10,46,26,0.06)",
            maxHeight: "500px",
            overflowY: "auto",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "16px",
              borderBottom: "1px solid #d0e8d8",
              paddingBottom: "12px",
            }}
          >
            <div>
              <span
                style={{
                  fontSize: "11px",
                  color: "#2a6a3a",
                  textTransform: "uppercase",
                  fontWeight: "600",
                  letterSpacing: "0.5px",
                }}
              >
                Node Details
              </span>
              <div
                style={{
                  fontSize: "18px",
                  fontWeight: "700",
                  color: "#0a2e1a",
                  marginTop: "2px",
                }}
              >
                {selectedNode.value}
              </div>
            </div>
            <button
              type="button"
              onClick={closeSelection}
              style={{
                background: "#f0f3ee",
                border: "none",
                color: "#2a6a3a",
                cursor: "pointer",
                fontSize: "20px",
                width: "32px",
                height: "32px",
                borderRadius: "6px",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                transition: "background 0.2s",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = "#d0e8d8";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = "#f0f3ee";
              }}
            >
              ×
            </button>
          </div>

          <div
            style={{
              display: "inline-block",
              padding: "4px 12px",
              borderRadius: "20px",
              fontSize: "11px",
              fontWeight: "600",
              marginBottom: "16px",
              background: (() => {
                const type = selectedNode.type;
                if (type === "IPAddress") return "rgba(42,106,58,0.15)";
                if (type === "Subdomain") return "rgba(208,232,216,0.6)";
                if (type === "ASN") return "rgba(90,170,106,0.2)";
                if (isOrganizationType(type)) return "rgba(26,74,42,0.15)";
                if (type === "Certificate") return "rgba(138,202,154,0.25)";
                return "rgba(10,46,26,0.08)";
              })(),
              color: "#0a2e1a",
            }}
          >
            {selectedNode.type}
          </div>

          {selectedNode.provenance && selectedNode.provenance.length > 0 && (
            <div style={{ marginBottom: "20px" }}>
              <div
                style={{
                  color: "#2a6a3a",
                  fontSize: "11px",
                  fontWeight: "700",
                  marginBottom: "10px",
                  textTransform: "uppercase",
                  letterSpacing: "0.5px",
                }}
              >
                📋 Provenance & Evidence
              </div>
              <div
                style={{
                  display: "grid",
                  gap: "8px",
                  maxHeight: "240px",
                  overflowY: "auto",
                }}
              >
                {selectedNode.provenance.map((record, index) => (
                  <div
                    key={index}
                    style={{
                      padding: "10px 14px",
                      borderRadius: "8px",
                      background: "#f8faf7",
                      border: "1px solid #d0e8d8",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        marginBottom: "4px",
                        gap: "8px",
                      }}
                    >
                      <span
                        style={{
                          fontWeight: "600",
                          fontSize: "12px",
                          color: "#2a6a3a",
                          display: "flex",
                          alignItems: "center",
                          gap: "6px",
                          flexWrap: "wrap",
                        }}
                      >
                        {record.source}
                        {record.count > 1 && (
                          <span
                            style={{
                              padding: "1px 7px",
                              borderRadius: "10px",
                              background: "#d0e8d8",
                              color: "#0a2e1a",
                              fontSize: "10px",
                              fontWeight: "700",
                            }}
                          >
                            ×{record.count}
                          </span>
                        )}
                      </span>
                      <span
                        style={{
                          fontSize: "10px",
                          color: "#5aaa6a",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {record.last_seen
                          ? new Date(record.last_seen).toLocaleDateString()
                          : "N/A"}
                      </span>
                    </div>
                    <div style={{ fontSize: "11px", color: "#1a4a2a" }}>
                      <strong>Method:</strong> {record.method}
                    </div>
                    {record.first_seen &&
                      record.last_seen &&
                      record.first_seen !== record.last_seen && (
                        <div
                          style={{
                            fontSize: "10px",
                            color: "#5aaa6a",
                            marginTop: "3px",
                          }}
                        >
                          First seen{" "}
                          {new Date(record.first_seen).toLocaleDateString()},
                          last seen{" "}
                          {new Date(record.last_seen).toLocaleDateString()}
                        </div>
                      )}
                    {record.details && (
                      <div
                        style={{
                          fontSize: "10px",
                          color: "#5aaa6a",
                          marginTop: "4px",
                          wordBreak: "break-word",
                          fontStyle: "italic",
                        }}
                      >
                        {typeof record.details === "string"
                          ? record.details
                          : JSON.stringify(record.details)}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {Array.isArray(selectedNode.connectedEdges) &&
            selectedNode.connectedEdges.length > 0 && (
              <div>
                <div
                  style={{
                    color: "#2a6a3a",
                    fontSize: "11px",
                    fontWeight: "700",
                    marginBottom: "10px",
                    textTransform: "uppercase",
                    letterSpacing: "0.5px",
                  }}
                >
                  Relationships
                </div>
                <div style={{ display: "grid", gap: "6px" }}>
                  {selectedNode.connectedEdges.map((edge, index) => {
                    const source = getEdgeSource(edge);
                    const target = getEdgeTarget(edge);
                    const relationship = getRelationship(edge);
                    const sourceNode = findNodeById(source);
                    const targetNode = findNodeById(target);
                    return (
                      <div
                        key={edge?.data?.id ?? index}
                        style={{
                          padding: "8px 12px",
                          borderRadius: "6px",
                          background: "#f8faf7",
                          border: "1px solid #d0e8d8",
                          display: "flex",
                          alignItems: "center",
                          gap: "8px",
                          flexWrap: "wrap",
                          fontSize: "12px",
                        }}
                      >
                        <span
                          style={{
                            fontWeight: "600",
                            fontSize: "10px",
                            color: "#2a6a3a",
                            textTransform: "uppercase",
                            letterSpacing: "0.3px",
                          }}
                        >
                          {relationship}
                        </span>
                        <span style={{ color: "#5aaa6a" }}>·</span>
                        <span style={{ color: "#1a4a2a" }}>
                          {sourceNode ? getValue(sourceNode) : source}
                        </span>
                        <span style={{ color: "#3a8a4a", fontWeight: "700" }}>
                          →
                        </span>
                        <span style={{ color: "#1a4a2a" }}>
                          {targetNode ? getValue(targetNode) : target}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

          {(!Array.isArray(selectedNode.connectedEdges) ||
            selectedNode.connectedEdges.length === 0) && (
            <div
              style={{ color: "#5aaa6a", fontSize: "12px", padding: "8px 0" }}
            >
              No relationships available for this node.
            </div>
          )}
        </div>
      )}

      <div
        style={{
          marginTop: "12px",
          textAlign: "center",
          fontSize: "11px",
          color: "#5aaa6a",
          padding: "8px",
        }}
      >
        Click a category to expand it. Click an entity to focus on it (you can
        focus one of each type at once). Click the group header or "Show all" to
        see all nodes.
      </div>
    </div>
  );
}

export default HierarchicalGraph;