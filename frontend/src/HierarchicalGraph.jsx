import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";

function HierarchicalGraph({ 
  graph, 
  onNodeSelect,
  searchTerms: externalSearchTerms,
  onSearchChange
}) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);

  // ============================================================
  // STATE
  // ============================================================

  const [expandedGroups, setExpandedGroups] = useState({
    Subdomain: false,
    IPAddress: false,
    Certificate: false,
  });

  // Internal search state (used when external is not provided)
  const [internalSearchTerms, setInternalSearchTerms] = useState({
    Subdomain: "",
    IPAddress: "",
    Certificate: "",
  });

  // Use external search terms if provided, fallback to internal
  const searchTerms = externalSearchTerms || internalSearchTerms;
  const setSearchTerms = onSearchChange || setInternalSearchTerms;

  const [selectedNode, setSelectedNode] = useState(null);

  // ============================================================
  // LIMIT
  // ============================================================

  const MAX_VISIBLE_ENTITIES = 5;
  const MAX_SEARCH_RESULTS = 100;

  // ============================================================
  // GRAPH DATA
  // ============================================================

  const allNodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const allEdges = Array.isArray(graph?.edges) ? graph.edges : [];
  const provenance = Array.isArray(graph?.provenance) ? graph.provenance : [];

  // ============================================================
  // HELPERS
  // ============================================================

  const getType = (node) => {
    return String(node?.data?.type ?? "");
  };

  const getNodeId = (node) => {
    return String(
      node?.data?.id ??
        node?.id ??
        node?.data?.value ??
        ""
    );
  };

  const getValue = (node) => {
    return String(
      node?.data?.value ??
        node?.data?.label ??
        node?.data?.name ??
        node?.data?.id ??
        ""
    );
  };

  const getLabel = (node) => {
    const value = getValue(node);

    if (
      getType(node) === "IPAddress" &&
      value.length > 30
    ) {
      return `${value.substring(0, 27)}...`;
    }

    return value;
  };

  const getRelationship = (edge) => {
    return String(
      edge?.data?.label ??
        edge?.data?.relationship ??
        edge?.label ??
        ""
    );
  };

  const getEdgeSource = (edge) => {
    return String(edge?.data?.source ?? "");
  };

  const getEdgeTarget = (edge) => {
    return String(edge?.data?.target ?? "");
  };

  const findNodeById = (id) => {
    const wanted = String(id);

    return allNodes.find(
      (node) => getNodeId(node) === wanted
    );
  };

  const uniqueId = (prefix, id) => {
    return `${prefix}_${String(id).replace(
      /[^a-zA-Z0-9_-]/g,
      "_"
    )}`;
  };

  // ============================================================
  // GET PROVENANCE FOR NODE
  // ============================================================

  const getProvenanceForNode = (nodeId) => {
    if (!provenance || provenance.length === 0) return [];
    
    return provenance.filter(record => {
      const entityValue = record.entity_value || "";
      const nodeValue = getValue(findNodeById(nodeId)) || "";
      return entityValue === nodeValue || 
             entityValue.includes(nodeValue) ||
             nodeValue.includes(entityValue);
    });
  };

  // ============================================================
  // NODE GROUPS
  // ============================================================

  const domainNodes = allNodes.filter(
    (node) => getType(node) === "Domain"
  );

  const subdomainNodes = allNodes.filter(
    (node) => getType(node) === "Subdomain"
  );

  const ipNodes = allNodes.filter(
    (node) => getType(node) === "IPAddress"
  );

  const asnNodes = allNodes.filter(
    (node) => getType(node) === "ASN"
  );

  const organizationNodes = allNodes.filter(
    (node) => getType(node) === "Organization"
  );

  const certificateNodes = allNodes.filter(
    (node) => getType(node) === "Certificate"
  );

  // ============================================================
  // SEARCH - Get filtered nodes (ALL matches, not just visible)
  // ============================================================

  const getFilteredNodes = (nodes, type) => {
    const search = String(
      searchTerms[type] ?? ""
    )
      .trim()
      .toLowerCase();

    if (!search) {
      // When no search, return the first N nodes (for display)
      return nodes.slice(0, MAX_VISIBLE_ENTITIES);
    }

    // When searching, return ALL matches (up to 100 to prevent performance issues)
    return nodes
      .filter((node) =>
        getValue(node)
          .toLowerCase()
          .includes(search)
      )
      .slice(0, MAX_SEARCH_RESULTS);
  };

  // ============================================================
  // GET DISPLAY INFO FOR GROUP NODE
  // ============================================================

  const getGroupLabel = (type, totalCount) => {
    const search = String(searchTerms[type] ?? "").trim().toLowerCase();
    const hasSearch = search.length > 0;
    
    let nodes;
    if (type === "Subdomain") nodes = subdomainNodes;
    else if (type === "IPAddress") nodes = ipNodes;
    else if (type === "Certificate") nodes = certificateNodes;
    else return `${type.toUpperCase()}\n${totalCount} discovered`;
    
    const filteredNodes = getFilteredNodes(nodes, type);
    const displayCount = filteredNodes.length;
    
    let label = `${type.toUpperCase()}\n${totalCount} discovered`;
    
    if (hasSearch) {
      if (displayCount === 0) {
        label += `\nNo matches found`;
      } else if (displayCount === 1) {
        label += `\n1 match found`;
      } else {
        label += `\n${displayCount} matches found`;
      }
    } else {
      if (totalCount > MAX_VISIBLE_ENTITIES) {
        label += `\nShowing first ${MAX_VISIBLE_ENTITIES}`;
      } else if (totalCount > 0) {
        label += `\nShowing all ${totalCount}`;
      }
    }
    
    return label;
  };

  // ============================================================
  // SEARCH RESULTS - For the list display
  // ============================================================

  const getSearchResults = (nodes, type) => {
    if (!expandedGroups[type]) {
      return [];
    }

    const search = searchTerms[type]?.trim() || '';

    if (!search) {
      // When no search, show first 5
      return nodes.slice(0, MAX_VISIBLE_ENTITIES);
    }

    const searchLower = search.toLowerCase();

    // Search through ALL nodes
    const matches = nodes.filter((node) => {
      const value = getValue(node).toLowerCase();
      return value.includes(searchLower);
    });

    // Return ALL matches (up to 100)
    return matches.slice(0, MAX_SEARCH_RESULTS);
  };

  const subdomainResults = getSearchResults(subdomainNodes, "Subdomain");
  const ipResults = getSearchResults(ipNodes, "IPAddress");
  const certificateResults = getSearchResults(certificateNodes, "Certificate");

  // ============================================================
  // CYTOSCAPE
  // ============================================================

  useEffect(() => {
    const container = containerRef.current;

    if (!container) {
      return;
    }

    if (cyRef.current) {
      cyRef.current.destroy();
      cyRef.current = null;
    }

    if (domainNodes.length === 0) {
      return;
    }

    const domain = domainNodes[0];
    const domainId = getNodeId(domain);

    if (!domainId) {
      return;
    }

    const elements = [];
    const addedNodeIds = new Set();

    const addRealNode = (node) => {
      if (!node) {
        return null;
      }

      const originalId = getNodeId(node);

      if (!originalId) {
        return null;
      }

      const cytoscapeId = uniqueId(
        "node",
        originalId
      );

      if (addedNodeIds.has(cytoscapeId)) {
        return cytoscapeId;
      }

      addedNodeIds.add(cytoscapeId);

      elements.push({
        group: "nodes",
        data: {
          ...node.data,
          id: cytoscapeId,
          originalId,
          label: getLabel(node),
          type: getType(node),
        },
      });

      return cytoscapeId;
    };

    const addGroupNode = (
      id,
      groupType,
      count
    ) => {
      const label = getGroupLabel(groupType, count);
      elements.push({
        group: "nodes",
        data: {
          id,
          type: "Group",
          groupType,
          label: label,
          count,
        },
      });
    };

    addRealNode(domain);

    addGroupNode(
      "__group_subdomains",
      "Subdomain",
      subdomainNodes.length
    );

    addGroupNode(
      "__group_ips",
      "IPAddress",
      ipNodes.length
    );

    addGroupNode(
      "__group_certificates",
      "Certificate",
      certificateNodes.length
    );

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

    const visibleSubdomains =
      expandedGroups.Subdomain
        ? getFilteredNodes(
            subdomainNodes,
            "Subdomain"
          )
        : [];

    const visibleIPs =
      expandedGroups.IPAddress
        ? getFilteredNodes(
            ipNodes,
            "IPAddress"
          )
        : [];

    const visibleCertificates =
      expandedGroups.Certificate
        ? getFilteredNodes(
            certificateNodes,
            "Certificate"
          )
        : [];

    const addGroupEntityEdge = (
      groupId,
      node,
      index,
      prefix
    ) => {
      const originalId = getNodeId(node);

      if (!originalId) {
        return;
      }

      const nodeCyId = uniqueId(
        "node",
        originalId
      );

      elements.push({
        group: "edges",
        data: {
          id: uniqueId(
            prefix,
            `${originalId}_${index}`
          ),
          source: groupId,
          target: nodeCyId,
          label: "",
        },
      });
    };

    visibleSubdomains.forEach(
      (node, index) => {
        addRealNode(node);

        addGroupEntityEdge(
          "__group_subdomains",
          node,
          index,
          "subdomain_group_edge"
        );
      }
    );

    visibleIPs.forEach(
      (node, index) => {
        addRealNode(node);

        addGroupEntityEdge(
          "__group_ips",
          node,
          index,
          "ip_group_edge"
        );
      }
    );

    visibleCertificates.forEach(
      (node, index) => {
        addRealNode(node);

        addGroupEntityEdge(
          "__group_certificates",
          node,
          index,
          "certificate_group_edge"
        );
      }
    );

    const visibleOriginalIds = new Set();

    visibleOriginalIds.add(domainId);

    visibleSubdomains.forEach((node) => {
      visibleOriginalIds.add(getNodeId(node));
    });

    visibleIPs.forEach((node) => {
      visibleOriginalIds.add(getNodeId(node));
    });

    visibleCertificates.forEach((node) => {
      visibleOriginalIds.add(getNodeId(node));
    });

    const connectedASNIds = new Set();
    const connectedOrganizationIds = new Set();

    if (expandedGroups.IPAddress) {
      visibleIPs.forEach((ip) => {
        const ipId = getNodeId(ip);

        allEdges.forEach((edge) => {
          const source = getEdgeSource(edge);
          const target = getEdgeTarget(edge);
          const relationship =
            getRelationship(edge);

          if (
            relationship !==
            "BELONGS_TO_ASN"
          ) {
            return;
          }

          if (source === ipId) {
            connectedASNIds.add(target);
          }

          if (target === ipId) {
            connectedASNIds.add(source);
          }
        });
      });

      allEdges.forEach((edge) => {
        const source = getEdgeSource(edge);
        const target = getEdgeTarget(edge);
        const relationship =
          getRelationship(edge);

        if (
          relationship !==
          "ASSOCIATED_WITH"
        ) {
          return;
        }

        if (connectedASNIds.has(source)) {
          connectedOrganizationIds.add(
            target
          );
        }

        if (connectedASNIds.has(target)) {
          connectedOrganizationIds.add(
            source
          );
        }

        if (
          visibleOriginalIds.has(source)
        ) {
          const targetNode =
            findNodeById(target);

          if (
            targetNode &&
            getType(targetNode) ===
              "Organization"
          ) {
            connectedOrganizationIds.add(
              target
            );
          }
        }

        if (
          visibleOriginalIds.has(target)
        ) {
          const sourceNode =
            findNodeById(source);

          if (
            sourceNode &&
            getType(sourceNode) ===
              "Organization"
          ) {
            connectedOrganizationIds.add(
              source
            );
          }
        }
      });

      const connectedASNs =
        asnNodes.filter((node) =>
          connectedASNIds.has(
            getNodeId(node)
          )
        );

      connectedASNs.forEach((node) => {
        addRealNode(node);

        visibleOriginalIds.add(
          getNodeId(node)
        );
      });

      const connectedOrganizations =
        organizationNodes.filter((node) =>
          connectedOrganizationIds.has(
            getNodeId(node)
          )
        );

      connectedOrganizations.forEach(
        (node) => {
          addRealNode(node);

          visibleOriginalIds.add(
            getNodeId(node)
          );
        }
      );

      const addedRelationshipIds =
        new Set();

      allEdges.forEach(
        (edge, index) => {
          const source =
            getEdgeSource(edge);

          const target =
            getEdgeTarget(edge);

          const relationship =
            getRelationship(edge);

          const isInfrastructureRelationship =
            relationship ===
              "BELONGS_TO_ASN" ||
            relationship ===
              "ASSOCIATED_WITH";

          if (
            !isInfrastructureRelationship
          ) {
            return;
          }

          if (
            !visibleOriginalIds.has(
              source
            ) ||
            !visibleOriginalIds.has(
              target
            )
          ) {
            return;
          }

          const edgeId = uniqueId(
            "relationship",
            edge?.data?.id ??
              `${source}_${relationship}_${target}_${index}`
          );

          if (
            addedRelationshipIds.has(
              edgeId
            )
          ) {
            return;
          }

          addedRelationshipIds.add(
            edgeId
          );

          elements.push({
            group: "edges",
            data: {
              ...edge.data,
              id: edgeId,
              source: uniqueId(
                "node",
                source
              ),
              target: uniqueId(
                "node",
                target
              ),
              label: relationship,
            },
          });
        }
      );
    }

    const cy = cytoscape({
      container,
      elements,

      style: [
        {
          selector: "node",
          style: {
            "background-color": "#172033",
            "border-color": "#475569",
            "border-width": 2,
            label: "data(label)",
            color: "#e2e8f0",
            "font-size": 10,
            "font-weight": "600",
            "text-valign": "center",
            "text-halign": "center",
            "text-wrap": "wrap",
            "text-max-width": 130,
            width: 85,
            height: 65,
            shape: "round-rectangle",
            "overlay-opacity": 0,
          },
        },
        {
          selector: 'node[type="Domain"]',
          style: {
            "background-color": "#f97316",
            "border-color": "#ffffff",
            "border-width": 4,
            width: 140,
            height: 90,
            shape: "round-rectangle",
            "font-size": 16,
            "font-weight": "bold",
            color: "#ffffff",
            "text-max-width": 160,
          },
        },
        {
          selector: 'node[type="Group"]',
          style: {
            "background-color": "#111827",
            "border-color": "#64748b",
            "border-width": 3,
            width: 190,
            height: 115,
            shape: "round-rectangle",
            "font-size": 11,
            "font-weight": "bold",
            color: "#f8fafc",
            "text-max-width": 170,
            "text-wrap": "wrap",
            "text-valign": "center",
            "text-halign": "center",
          },
        },
        {
          selector: 'node[type="Subdomain"]',
          style: {
            "background-color": "#9333ea",
            "border-color": "#e9d5ff",
            "border-width": 3,
            width: 125,
            height: 65,
            "font-size": 10,
            color: "#ffffff",
            "text-max-width": 115,
            shape: "round-rectangle",
          },
        },
        {
          selector: 'node[type="IPAddress"]',
          style: {
            "background-color": "#dc2626",
            "border-color": "#fecaca",
            "border-width": 3,
            width: 135,
            height: 65,
            "font-size": 10,
            color: "#ffffff",
            "text-max-width": 125,
            shape: "round-rectangle",
          },
        },
        {
          selector: 'node[type="ASN"]',
          style: {
            "background-color": "#4f46e5",
            "border-color": "#c7d2fe",
            "border-width": 3,
            width: 120,
            height: 65,
            "font-size": 11,
            color: "#ffffff",
            shape: "round-rectangle",
          },
        },
        {
          selector:
            'node[type="Organization"]',
          style: {
            "background-color": "#65a30d",
            "border-color": "#d9f99d",
            "border-width": 3,
            width: 155,
            height: 70,
            "font-size": 10,
            color: "#ffffff",
            "text-max-width": 145,
            shape: "round-rectangle",
          },
        },
        {
          selector:
            'node[type="Certificate"]',
          style: {
            "background-color": "#0f766e",
            "border-color": "#99f6e4",
            "border-width": 3,
            width: 135,
            height: 65,
            "font-size": 10,
            color: "#ffffff",
            "text-max-width": 125,
            shape: "round-rectangle",
          },
        },
        {
          selector: "edge",
          style: {
            width: 2.5,
            "line-color": "#64748b",
            "target-arrow-color": "#94a3b8",
            "target-arrow-shape": "triangle",
            "source-arrow-shape": "none",
            "curve-style": "bezier",
            label: "data(label)",
            color: "#cbd5e1",
            "font-size": 8,
            "font-weight": "600",
            "text-background-color": "#0c121c",
            "text-background-opacity": 0.9,
            "text-background-padding": 3,
            "text-rotation": "autorotate",
            opacity: 0.9,
          },
        },
        {
          selector:
            'edge[label="HAS_SUBDOMAIN"]',
          style: {
            "line-color": "#a855f7",
            "target-arrow-color": "#a855f7",
            width: 3,
            color: "#d8b4fe",
          },
        },
        {
          selector:
            'edge[label="RESOLVES_TO"]',
          style: {
            "line-color": "#ef4444",
            "target-arrow-color": "#ef4444",
            width: 3,
            color: "#fca5a5",
          },
        },
        {
          selector:
            'edge[label="BELONGS_TO_ASN"]',
          style: {
            "line-color": "#6366f1",
            "target-arrow-color": "#6366f1",
            width: 3,
            color: "#c7d2fe",
          },
        },
        {
          selector:
            'edge[label="ASSOCIATED_WITH"]',
          style: {
            "line-color": "#84cc16",
            "target-arrow-color": "#84cc16",
            width: 3,
            color: "#bef264",
          },
        },
        {
          selector:
            'edge[label="HAS_CERTIFICATE"]',
          style: {
            "line-color": "#14b8a6",
            "target-arrow-color": "#14b8a6",
            width: 3,
            color: "#5eead4",
          },
        },
        {
          selector: "node:selected",
          style: {
            "border-color": "#ffffff",
            "border-width": 5,
            "overlay-opacity": 0,
          },
        },
        {
          selector: "edge:selected",
          style: {
            "line-color": "#60a5fa",
            "target-arrow-color": "#60a5fa",
            width: 4,
            opacity: 1,
          },
        },
      ],

      layout: {
        name: "preset",
        fit: false,
      },

      minZoom: 0.15,
      maxZoom: 3,
      wheelSensitivity: 0.25,
    });

    cyRef.current = cy;

    const domainCyId = uniqueId(
      "node",
      domainId
    );

    cy.getElementById(domainCyId).position({
      x: 0,
      y: 0,
    });

    cy.getElementById(
      "__group_subdomains"
    ).position({
      x: -400,
      y: 220,
    });

    cy.getElementById(
      "__group_ips"
    ).position({
      x: 0,
      y: 220,
    });

    cy.getElementById(
      "__group_certificates"
    ).position({
      x: 400,
      y: 220,
    });

    const positionHorizontal = (
      nodes,
      centerX,
      y,
      spacing
    ) => {
      if (!nodes.length) {
        return;
      }

      const totalWidth =
        (nodes.length - 1) * spacing;

      const startX =
        centerX - totalWidth / 2;

      nodes.forEach((node, index) => {
        const id = uniqueId(
          "node",
          getNodeId(node)
        );

        const cyNode =
          cy.getElementById(id);

        if (cyNode.empty()) {
          return;
        }

        cyNode.position({
          x: startX + index * spacing,
          y,
        });
      });
    };

    positionHorizontal(
      visibleSubdomains,
      -400,
      430,
      155
    );

    positionHorizontal(
      visibleIPs,
      0,
      430,
      155
    );

    positionHorizontal(
      visibleCertificates,
      400,
      430,
      155
    );

    if (expandedGroups.IPAddress) {
      const connectedASNs =
        asnNodes.filter((node) =>
          connectedASNIds.has(
            getNodeId(node)
          )
        );

      positionHorizontal(
        connectedASNs,
        0,
        650,
        180
      );

      const connectedOrganizations =
        organizationNodes.filter(
          (node) =>
            connectedOrganizationIds.has(
              getNodeId(node)
            )
        );

      positionHorizontal(
        connectedOrganizations,
        0,
        850,
        220
      );
    }

    if (subdomainNodes.length === 0) {
      cy.getElementById(
        "__group_subdomains"
      ).style("display", "none");

      cy.edges(
        "#__struct_domain_subdomains"
      ).style("display", "none");
    }

    if (ipNodes.length === 0) {
      cy.getElementById(
        "__group_ips"
      ).style("display", "none");

      cy.edges(
        "#__struct_domain_ips"
      ).style("display", "none");
    }

    if (certificateNodes.length === 0) {
      cy.getElementById(
        "__group_certificates"
      ).style("display", "none");

      cy.edges(
        "#__struct_domain_certificates"
      ).style("display", "none");
    }

    const fitGraph = () => {
      if (!cyRef.current) {
        return;
      }

      cyRef.current.resize();

      if (
        cyRef.current.nodes().length > 0
      ) {
        cyRef.current.fit(
          cyRef.current.elements(),
          70
        );
      }
    };

    requestAnimationFrame(() => {
      fitGraph();

      requestAnimationFrame(() => {
        fitGraph();
      });
    });

    cy.on(
      "tap",
      'node[type="Group"]',
      (event) => {
        const group =
          event.target;

        const groupType =
          group.data("groupType");

        setExpandedGroups(
          (previous) => ({
            ...previous,
            [groupType]:
              !previous[groupType],
          })
        );
      }
    );

    cy.on(
      "tap",
      'node[type!="Group"]',
      (event) => {
        const node =
          event.target;

        const type =
          String(node.data("type"));

        if (type === "Domain") {
          node.unselect();
          setSelectedNode(null);

          if (
            typeof onNodeSelect ===
            "function"
          ) {
            onNodeSelect(null);
          }

          return;
        }

        const originalId =
          String(
            node.data("originalId")
          );

        const originalNode =
          findNodeById(originalId);

        if (!originalNode) {
          return;
        }

        const connectedEdges =
          allEdges.filter(
            (edge) => {
              const source =
                getEdgeSource(edge);

              const target =
                getEdgeTarget(edge);

              return (
                source === originalId ||
                target === originalId
              );
            }
          );

        const connectedNodes =
          connectedEdges
            .map((edge) => {
              const source =
                getEdgeSource(edge);

              const target =
                getEdgeTarget(edge);

              const other =
                source === originalId
                  ? target
                  : source;

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

        if (
          typeof onNodeSelect ===
          "function"
        ) {
          onNodeSelect(selection);
        }
      }
    );

    cy.on(
      "mouseover",
      "node",
      (event) => {
        event.target.style(
          "border-width",
          5
        );
      }
    );

    cy.on(
      "mouseout",
      "node",
      (event) => {
        const node =
          event.target;

        if (!node.selected()) {
          const type =
            node.data("type");

          if (type === "Domain") {
            node.style(
              "border-width",
              4
            );
          } else {
            node.style(
              "border-width",
              3
            );
          }
        }
      }
    );

    const resizeObserver =
      new ResizeObserver(() => {
        fitGraph();
      });

    resizeObserver.observe(container);

    return () => {
      resizeObserver.disconnect();

      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [
    graph,
    expandedGroups,
    searchTerms,
    onNodeSelect,
  ]);

  // ============================================================
  // CLOSE SELECTION
  // ============================================================

  const closeSelection = () => {
    setSelectedNode(null);

    if (
      typeof onNodeSelect ===
      "function"
    ) {
      onNodeSelect(null);
    }

    if (cyRef.current) {
      cyRef.current
        .nodes()
        .unselect();
    }
  };

  // ============================================================
  // SEARCH HANDLER
  // ============================================================

  const handleSearch = (
    type,
    value
  ) => {
    setSearchTerms(
      (previous) => ({
        ...previous,
        [type]: value,
      })
    );
  };

  // ============================================================
  // LIST ITEM CLICK
  // ============================================================

  const handleEntityClick = (
    type,
    node
  ) => {
    const value = getValue(node);

    setExpandedGroups(
      (previous) => ({
        ...previous,
        [type]: true,
      })
    );

    setSearchTerms(
      (previous) => ({
        ...previous,
        [type]: value,
      })
    );

    setSelectedNode(null);

    if (
      typeof onNodeSelect ===
      "function"
    ) {
      onNodeSelect(null);
    }
  };

  // ============================================================
  // RENDER
  // ============================================================

  return (
    <div
      style={{
        width: "100%",
        position: "relative",
      }}
    >
      {/* Graph Container */}
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
          border: "1px solid rgba(148,163,184,0.15)",
          background: `
            radial-gradient(circle at 20% 50%, rgba(99, 102, 241, 0.05) 0%, transparent 50%),
            radial-gradient(circle at 80% 50%, rgba(168, 85, 247, 0.05) 0%, transparent 50%),
            linear-gradient(rgba(148, 163, 184, 0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(148, 163, 184, 0.03) 1px, transparent 1px),
            #0a0f1a
          `,
          backgroundSize: `100% 100%, 100% 100%, 30px 30px, 30px 30px`,
        }}
      />

      {/* Search & Lists */}
      {(subdomainNodes.length > 0 || ipNodes.length > 0 || certificateNodes.length > 0) && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
            gap: "12px",
            marginTop: "14px",
          }}
        >
          {/* Subdomains */}
          {expandedGroups.Subdomain && subdomainNodes.length > 0 && (
            <div
              style={{
                background: "rgba(15,23,42,0.96)",
                border: "1px solid rgba(168,85,247,0.35)",
                borderRadius: "10px",
                padding: "12px",
              }}
            >
              <div
                style={{
                  fontWeight: "700",
                  color: "#e9d5ff",
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
                onChange={(event) =>
                  handleSearch(
                    "Subdomain",
                    event.target.value
                  )
                }
                style={{
                  width: "100%",
                  boxSizing: "border-box",
                  padding: "6px 10px",
                  borderRadius: "6px",
                  border: "1px solid #475569",
                  background: "#0f172a",
                  color: "#e2e8f0",
                  outline: "none",
                  marginBottom: "8px",
                  fontSize: "12px",
                }}
              />

              <div
                style={{
                  maxHeight: "150px",
                  overflowY: "auto",
                }}
              >
                {subdomainResults.map((node) => (
                  <button
                    type="button"
                    key={getNodeId(node)}
                    onClick={() =>
                      handleEntityClick(
                        "Subdomain",
                        node
                      )
                    }
                    style={{
                      display: "block",
                      width: "100%",
                      textAlign: "left",
                      padding: "5px 8px",
                      marginBottom: "3px",
                      borderRadius: "4px",
                      border: "none",
                      cursor: "pointer",
                      background: "rgba(147,51,234,0.12)",
                      color: "#e9d5ff",
                      fontSize: "11px",
                      wordBreak: "break-word",
                      transition: "background 0.2s",
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = "rgba(147,51,234,0.25)";
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = "rgba(147,51,234,0.12)";
                    }}
                  >
                    {getValue(node)}
                  </button>
                ))}

                {subdomainResults.length === 0 && searchTerms.Subdomain.trim() && (
                  <div
                    style={{
                      color: "#94a3b8",
                      fontSize: "11px",
                      padding: "8px 0",
                    }}
                  >
                    No matching subdomains found.
                  </div>
                )}

                {subdomainResults.length === 0 && !searchTerms.Subdomain.trim() && (
                  <div
                    style={{
                      color: "#94a3b8",
                      fontSize: "11px",
                      padding: "8px 0",
                    }}
                  >
                    Click the SUBDOMAINS group to show results.
                  </div>
                )}
              </div>

              {subdomainNodes.length > MAX_VISIBLE_ENTITIES && !searchTerms.Subdomain.trim() && (
                <div
                  style={{
                    marginTop: "6px",
                    color: "#94a3b8",
                    fontSize: "10px",
                  }}
                >
                  Showing first {Math.min(subdomainNodes.length, MAX_VISIBLE_ENTITIES)} of {subdomainNodes.length}. Search to find more.
                </div>
              )}

              {searchTerms.Subdomain.trim() && subdomainResults.length > 0 && (
                <div
                  style={{
                    marginTop: "6px",
                    color: "#60a5fa",
                    fontSize: "10px",
                  }}
                >
                  Found {subdomainResults.length} matching subdomain{subdomainResults.length > 1 ? 's' : ''}
                </div>
              )}
            </div>
          )}

          {/* IP Addresses */}
          {expandedGroups.IPAddress && ipNodes.length > 0 && (
            <div
              style={{
                background: "rgba(15,23,42,0.96)",
                border: "1px solid rgba(239,68,68,0.35)",
                borderRadius: "10px",
                padding: "12px",
              }}
            >
              <div
                style={{
                  fontWeight: "700",
                  color: "#fecaca",
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
                onChange={(event) =>
                  handleSearch(
                    "IPAddress",
                    event.target.value
                  )
                }
                style={{
                  width: "100%",
                  boxSizing: "border-box",
                  padding: "6px 10px",
                  borderRadius: "6px",
                  border: "1px solid #475569",
                  background: "#0f172a",
                  color: "#e2e8f0",
                  outline: "none",
                  marginBottom: "8px",
                  fontSize: "12px",
                }}
              />

              <div
                style={{
                  maxHeight: "150px",
                  overflowY: "auto",
                }}
              >
                {ipResults.map((node) => (
                  <button
                    type="button"
                    key={getNodeId(node)}
                    onClick={() =>
                      handleEntityClick(
                        "IPAddress",
                        node
                      )
                    }
                    style={{
                      display: "block",
                      width: "100%",
                      textAlign: "left",
                      padding: "5px 8px",
                      marginBottom: "3px",
                      borderRadius: "4px",
                      border: "none",
                      cursor: "pointer",
                      background: "rgba(220,38,38,0.12)",
                      color: "#fecaca",
                      fontSize: "11px",
                      wordBreak: "break-word",
                      transition: "background 0.2s",
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = "rgba(220,38,38,0.25)";
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = "rgba(220,38,38,0.12)";
                    }}
                  >
                    {getValue(node)}
                  </button>
                ))}

                {ipResults.length === 0 && searchTerms.IPAddress.trim() && (
                  <div
                    style={{
                      color: "#94a3b8",
                      fontSize: "11px",
                      padding: "8px 0",
                    }}
                  >
                    No matching IP addresses found.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Certificates */}
          {expandedGroups.Certificate && certificateNodes.length > 0 && (
            <div
              style={{
                background: "rgba(15,23,42,0.96)",
                border: "1px solid rgba(20,184,166,0.35)",
                borderRadius: "10px",
                padding: "12px",
              }}
            >
              <div
                style={{
                  fontWeight: "700",
                  color: "#99f6e4",
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
                onChange={(event) =>
                  handleSearch(
                    "Certificate",
                    event.target.value
                  )
                }
                style={{
                  width: "100%",
                  boxSizing: "border-box",
                  padding: "6px 10px",
                  borderRadius: "6px",
                  border: "1px solid #475569",
                  background: "#0f172a",
                  color: "#e2e8f0",
                  outline: "none",
                  marginBottom: "8px",
                  fontSize: "12px",
                }}
              />

              <div
                style={{
                  maxHeight: "150px",
                  overflowY: "auto",
                }}
              >
                {certificateResults.map((node) => (
                  <button
                    type="button"
                    key={getNodeId(node)}
                    onClick={() =>
                      handleEntityClick(
                        "Certificate",
                        node
                      )
                    }
                    style={{
                      display: "block",
                      width: "100%",
                      textAlign: "left",
                      padding: "5px 8px",
                      marginBottom: "3px",
                      borderRadius: "4px",
                      border: "none",
                      cursor: "pointer",
                      background: "rgba(15,118,110,0.12)",
                      color: "#99f6e4",
                      fontSize: "11px",
                      wordBreak: "break-word",
                      transition: "background 0.2s",
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = "rgba(15,118,110,0.25)";
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = "rgba(15,118,110,0.12)";
                    }}
                  >
                    {getValue(node)}
                  </button>
                ))}

                {certificateResults.length === 0 && searchTerms.Certificate.trim() && (
                  <div
                    style={{
                      color: "#94a3b8",
                      fontSize: "11px",
                      padding: "8px 0",
                    }}
                  >
                    No matching certificates found.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Node Details Panel */}
      {selectedNode && (
        <div
          style={{
            marginTop: "16px",
            width: "100%",
            boxSizing: "border-box",
            padding: "20px",
            borderRadius: "12px",
            background: "rgba(15,23,42,0.98)",
            border: "1px solid rgba(148,163,184,0.2)",
            color: "#e2e8f0",
            boxShadow: "0 10px 40px rgba(0,0,0,0.3)",
            maxHeight: "500px",
            overflowY: "auto",
          }}
        >
          {/* Header */}
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "16px",
              borderBottom: "1px solid rgba(148,163,184,0.1)",
              paddingBottom: "12px",
            }}
          >
            <div>
              <span
                style={{
                  fontSize: "11px",
                  color: "#94a3b8",
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
                  color: "#f8fafc",
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
                background: "rgba(148,163,184,0.1)",
                border: "none",
                color: "#94a3b8",
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
                e.currentTarget.style.background = "rgba(148,163,184,0.2)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = "rgba(148,163,184,0.1)";
              }}
            >
              ×
            </button>
          </div>

          {/* Type Badge */}
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
                if (type === "IPAddress") return "rgba(220,38,38,0.2)";
                if (type === "Subdomain") return "rgba(147,51,234,0.2)";
                if (type === "ASN") return "rgba(79,70,229,0.2)";
                if (type === "Organization") return "rgba(101,163,13,0.2)";
                if (type === "Certificate") return "rgba(15,118,110,0.2)";
                return "rgba(148,163,184,0.2)";
              })(),
              color: (() => {
                const type = selectedNode.type;
                if (type === "IPAddress") return "#fecaca";
                if (type === "Subdomain") return "#e9d5ff";
                if (type === "ASN") return "#c7d2fe";
                if (type === "Organization") return "#d9f99d";
                if (type === "Certificate") return "#99f6e4";
                return "#e2e8f0";
              })(),
            }}
          >
            {selectedNode.type}
          </div>

          {/* Provenance Section */}
          {selectedNode.provenance && selectedNode.provenance.length > 0 && (
            <div style={{ marginBottom: "20px" }}>
              <div
                style={{
                  color: "#94a3b8",
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
                  maxHeight: "200px",
                  overflowY: "auto",
                }}
              >
                {selectedNode.provenance.map((record, index) => (
                  <div
                    key={index}
                    style={{
                      padding: "10px 14px",
                      borderRadius: "8px",
                      background: "rgba(30,41,59,0.6)",
                      border: "1px solid rgba(71,85,105,0.3)",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        marginBottom: "4px",
                      }}
                    >
                      <span
                        style={{
                          fontWeight: "600",
                          fontSize: "12px",
                          color: "#60a5fa",
                        }}
                      >
                        {record.source || "Unknown Source"}
                      </span>
                      <span
                        style={{
                          fontSize: "10px",
                          color: "#94a3b8",
                        }}
                      >
                        {record.recorded_at ? new Date(record.recorded_at).toLocaleDateString() : "N/A"}
                      </span>
                    </div>
                    
                    <div
                      style={{
                        fontSize: "11px",
                        color: "#cbd5e1",
                      }}
                    >
                      <strong>Method:</strong> {record.method || "N/A"}
                    </div>
                    
                    {record.entity_value && record.entity_value !== selectedNode.value && (
                      <div
                        style={{
                          fontSize: "11px",
                          color: "#94a3b8",
                          marginTop: "3px",
                        }}
                      >
                        <strong>Entity:</strong> {record.entity_value}
                      </div>
                    )}
                    
                    {record.details && (
                      <div
                        style={{
                          fontSize: "10px",
                          color: "#64748b",
                          marginTop: "4px",
                          wordBreak: "break-word",
                          fontStyle: "italic",
                        }}
                      >
                        {typeof record.details === 'string' ? record.details : JSON.stringify(record.details)}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Relationships */}
          {Array.isArray(selectedNode.connectedEdges) && selectedNode.connectedEdges.length > 0 && (
            <div>
              <div
                style={{
                  color: "#94a3b8",
                  fontSize: "11px",
                  fontWeight: "700",
                  marginBottom: "10px",
                  textTransform: "uppercase",
                  letterSpacing: "0.5px",
                }}
              >
                Relationships
              </div>

              <div
                style={{
                  display: "grid",
                  gap: "6px",
                }}
              >
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
                        background: "rgba(30,41,59,0.6)",
                        border: "1px solid rgba(71,85,105,0.2)",
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
                          color: "#60a5fa",
                          textTransform: "uppercase",
                          letterSpacing: "0.3px",
                        }}
                      >
                        {relationship}
                      </span>
                      <span style={{ color: "#94a3b8" }}>·</span>
                      <span style={{ color: "#cbd5e1" }}>
                        {sourceNode ? getValue(sourceNode) : source}
                      </span>
                      <span style={{ color: "#60a5fa", fontWeight: "700" }}>→</span>
                      <span style={{ color: "#cbd5e1" }}>
                        {targetNode ? getValue(targetNode) : target}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {(!Array.isArray(selectedNode.connectedEdges) || selectedNode.connectedEdges.length === 0) && (
            <div
              style={{
                color: "#94a3b8",
                fontSize: "12px",
                padding: "8px 0",
              }}
            >
              No relationships available for this node.
            </div>
          )}
        </div>
      )}

      {/* Instructions */}
      <div
        style={{
          marginTop: "12px",
          textAlign: "center",
          fontSize: "11px",
          color: "#64748b",
          padding: "8px",
        }}
      >
        Click a category to expand it. Click an entity to inspect relationships and provenance.
      </div>
    </div>
  );
}

export default HierarchicalGraph;