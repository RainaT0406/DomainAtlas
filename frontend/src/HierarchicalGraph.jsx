import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";

function HierarchicalGraph({ graph, onNodeSelect }) {
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

  const [searchTerms, setSearchTerms] = useState({
    Subdomain: "",
    IPAddress: "",
    Certificate: "",
  });

  const [selectedNode, setSelectedNode] = useState(null);

  // ============================================================
  // LIMIT
  // ============================================================

  // Never render thousands of nodes in Cytoscape.
  // Search can still locate a specific entity.
  const MAX_VISIBLE_ENTITIES = 5;

  // ============================================================
  // GRAPH DATA
  // ============================================================

  const allNodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const allEdges = Array.isArray(graph?.edges) ? graph.edges : [];

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
  // SEARCH
  // ============================================================

  const getFilteredNodes = (nodes, type) => {
    const search = String(
      searchTerms[type] ?? ""
    )
      .trim()
      .toLowerCase();

    if (!search) {
      return nodes.slice(0, MAX_VISIBLE_ENTITIES);
    }

    return nodes
      .filter((node) =>
        getValue(node)
          .toLowerCase()
          .includes(search)
      )
      .slice(0, MAX_VISIBLE_ENTITIES);
  };

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

    // ==========================================================
    // ELEMENTS
    // ==========================================================

    const elements = [];
    const addedNodeIds = new Set();

    // ==========================================================
    // ADD REAL NODE
    // ==========================================================

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

    // ==========================================================
    // ADD GROUP NODE
    // ==========================================================

    const addGroupNode = (
      id,
      groupType,
      label,
      count
    ) => {
      elements.push({
        group: "nodes",
        data: {
          id,
          type: "Group",
          groupType,
          label: `${label}\n${count} discovered`,
          count,
        },
      });
    };

    // ==========================================================
    // DOMAIN
    // ==========================================================

    addRealNode(domain);

    // ==========================================================
    // GROUPS
    // ==========================================================

    addGroupNode(
      "__group_subdomains",
      "Subdomain",
      "SUBDOMAINS",
      subdomainNodes.length
    );

    addGroupNode(
      "__group_ips",
      "IPAddress",
      "IP ADDRESSES",
      ipNodes.length
    );

    addGroupNode(
      "__group_certificates",
      "Certificate",
      "CERTIFICATES",
      certificateNodes.length
    );

    // ==========================================================
    // DOMAIN -> GROUP EDGES
    // ==========================================================

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

    // ==========================================================
    // VISIBLE CONTENT
    // ==========================================================

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

    // ==========================================================
    // GROUP -> ENTITY EDGE
    // ==========================================================

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

    // ==========================================================
    // SUBDOMAINS
    // ==========================================================

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

    // ==========================================================
    // IP ADDRESSES
    // ==========================================================

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

    // ==========================================================
    // CERTIFICATES
    // ==========================================================

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

    // ==========================================================
    // VISIBLE ORIGINAL IDS
    // ==========================================================

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

    // ==========================================================
    // INFRASTRUCTURE
    //
    // IP -> ASN -> ORGANIZATION
    // ==========================================================

    const connectedASNIds = new Set();
    const connectedOrganizationIds = new Set();

    if (expandedGroups.IPAddress) {
      // --------------------------------------------------------
      // FIND ASN CONNECTED TO VISIBLE IPS
      // --------------------------------------------------------

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

      // --------------------------------------------------------
      // FIND ORGANIZATIONS
      // --------------------------------------------------------

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

        // Direct IP -> Organization
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

      // --------------------------------------------------------
      // ADD ASN NODES
      // --------------------------------------------------------

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

      // --------------------------------------------------------
      // ADD ORGANIZATION NODES
      // --------------------------------------------------------

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

      // --------------------------------------------------------
      // ACTUAL INFRASTRUCTURE EDGES
      // --------------------------------------------------------

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

    // ==========================================================
    // CREATE CYTOSCAPE
    // ==========================================================

    const cy = cytoscape({
      container,
      elements,

      style: [
        // ------------------------------------------------------
        // DEFAULT NODE
        // ------------------------------------------------------

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

        // ------------------------------------------------------
        // DOMAIN
        // ------------------------------------------------------

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

        // ------------------------------------------------------
        // GROUP
        // ------------------------------------------------------

        {
          selector: 'node[type="Group"]',
          style: {
            "background-color": "#111827",
            "border-color": "#64748b",
            "border-width": 3,
            width: 190,
            height: 105,
            shape: "round-rectangle",
            "font-size": 12,
            "font-weight": "bold",
            color: "#f8fafc",
            "text-max-width": 170,
            "text-wrap": "wrap",
            "text-valign": "center",
            "text-halign": "center",
          },
        },

        // ------------------------------------------------------
        // SUBDOMAIN
        // ------------------------------------------------------

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

        // ------------------------------------------------------
        // IP
        // ------------------------------------------------------

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

        // ------------------------------------------------------
        // ASN
        // ------------------------------------------------------

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

        // ------------------------------------------------------
        // ORGANIZATION
        // ------------------------------------------------------

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

        // ------------------------------------------------------
        // CERTIFICATE
        // ------------------------------------------------------

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

        // ------------------------------------------------------
        // EDGES
        // ------------------------------------------------------

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

        // ------------------------------------------------------
        // RELATIONSHIP COLORS
        // ------------------------------------------------------

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

        // ------------------------------------------------------
        // SELECTED
        // ------------------------------------------------------

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

    // ==========================================================
    // POSITIONING
    // ==========================================================

    const domainCyId = uniqueId(
      "node",
      domainId
    );

    cy.getElementById(domainCyId).position({
      x: 0,
      y: 0,
    });

    // Groups
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

    // ==========================================================
    // HORIZONTAL POSITIONING
    // ==========================================================

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

    // Subdomains
    positionHorizontal(
      visibleSubdomains,
      -400,
      430,
      155
    );

    // IPs
    positionHorizontal(
      visibleIPs,
      0,
      430,
      155
    );

    // Certificates
    positionHorizontal(
      visibleCertificates,
      400,
      430,
      155
    );

    // ==========================================================
    // ASN / ORGANIZATION POSITIONING
    // ==========================================================

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

    // ==========================================================
    // HIDE EMPTY GROUPS
    // ==========================================================

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

    // ==========================================================
    // FIT
    // ==========================================================

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

    // ==========================================================
    // GROUP CLICK
    // ==========================================================

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

    // ==========================================================
    // REAL NODE CLICK
    //
    // IMPORTANT:
    // Domain is intentionally ignored.
    // We do NOT show Node Details for Domain.
    // ==========================================================

    cy.on(
      "tap",
      'node[type!="Group"]',
      (event) => {
        const node =
          event.target;

        const type =
          String(node.data("type"));

        // ------------------------------------------------------
        // DO NOTHING FOR DOMAIN
        // ------------------------------------------------------

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

        // ------------------------------------------------------
        // OTHER REAL NODES
        // ------------------------------------------------------

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

        const selection = {
          ...originalNode.data,
          id: originalId,
          type: getType(originalNode),
          value: getValue(originalNode),
          label: getLabel(originalNode),
          original: originalNode,
          connectedNodes,
          connectedEdges,
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

    // ==========================================================
    // HOVER
    // ==========================================================

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

    // ==========================================================
    // RESIZE
    // ==========================================================

    const resizeObserver =
      new ResizeObserver(() => {
        fitGraph();
      });

    resizeObserver.observe(container);

    // ==========================================================
    // CLEANUP
    // ==========================================================

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
  //
  // Clicking a result:
  // 1. puts the value in search
  // 2. keeps the group expanded
  // 3. Cytoscape re-renders that matching node
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

    // Close any currently open details.
    setSelectedNode(null);

    if (
      typeof onNodeSelect ===
      "function"
    ) {
      onNodeSelect(null);
    }
  };

  // ============================================================
  // SEARCH RESULTS
  // ============================================================

  const getSearchResults = (
    nodes,
    type
  ) => {
    if (!expandedGroups[type]) {
      return [];
    }

    const search =
      searchTerms[type]
        .trim()
        .toLowerCase();

    if (!search) {
      return nodes.slice(
        0,
        MAX_VISIBLE_ENTITIES
      );
    }

    return nodes
      .filter((node) =>
        getValue(node)
          .toLowerCase()
          .includes(search)
      )
      .slice(
        0,
        MAX_VISIBLE_ENTITIES
      );
  };

  const subdomainResults =
    getSearchResults(
      subdomainNodes,
      "Subdomain"
    );

  const ipResults =
    getSearchResults(
      ipNodes,
      "IPAddress"
    );

  const certificateResults =
    getSearchResults(
      certificateNodes,
      "Certificate"
    );

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
      {/* ======================================================
          GRAPH
      ====================================================== */}

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
          border:
            "1px solid rgba(148,163,184,0.15)",
        }}
      />

      {/* ======================================================
          LISTS / SEARCH
      ====================================================== */}

      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "repeat(3, minmax(0, 1fr))",
          gap: "12px",
          marginTop: "14px",
        }}
      >
        {/* ====================================================
            SUBDOMAINS
        ==================================================== */}

        {expandedGroups.Subdomain &&
          subdomainNodes.length > 0 && (
            <div
              style={{
                background:
                  "rgba(15,23,42,0.96)",
                border:
                  "1px solid rgba(168,85,247,0.35)",
                borderRadius: "10px",
                padding: "12px",
              }}
            >
              <div
                style={{
                  fontWeight: "700",
                  color: "#e9d5ff",
                  marginBottom: "8px",
                }}
              >
                Subdomains (
                {subdomainNodes.length}
                )
              </div>

              <input
                type="text"
                placeholder="Search subdomains..."
                value={
                  searchTerms.Subdomain
                }
                onChange={(event) =>
                  handleSearch(
                    "Subdomain",
                    event.target.value
                  )
                }
                style={{
                  width: "100%",
                  boxSizing: "border-box",
                  padding: "8px 10px",
                  borderRadius: "7px",
                  border:
                    "1px solid #475569",
                  background: "#0f172a",
                  color: "#e2e8f0",
                  outline: "none",
                  marginBottom: "8px",
                }}
              />

              <div
                style={{
                  maxHeight: "180px",
                  overflowY: "auto",
                }}
              >
                {subdomainResults.map(
                  (node) => (
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
                        padding:
                          "7px 8px",
                        marginBottom: "4px",
                        borderRadius: "6px",
                        border: "none",
                        cursor: "pointer",
                        background:
                          "rgba(147,51,234,0.12)",
                        color: "#e9d5ff",
                        fontSize: "11px",
                        wordBreak:
                          "break-word",
                      }}
                    >
                      {getValue(node)}
                    </button>
                  )
                )}

                {subdomainResults.length ===
                  0 && (
                  <div
                    style={{
                      color: "#94a3b8",
                      fontSize: "11px",
                    }}
                  >
                    No matching
                    subdomains.
                  </div>
                )}
              </div>

              {subdomainNodes.length >
                MAX_VISIBLE_ENTITIES && (
                <div
                  style={{
                    marginTop: "8px",
                    color: "#94a3b8",
                    fontSize: "10px",
                  }}
                >
                  Showing first{" "}
                  {MAX_VISIBLE_ENTITIES}{" "}
                  results. Use search
                  to find a specific
                  subdomain.
                </div>
              )}
            </div>
          )}

        {/* ====================================================
            IP ADDRESSES
        ==================================================== */}

        {expandedGroups.IPAddress &&
          ipNodes.length > 0 && (
            <div
              style={{
                background:
                  "rgba(15,23,42,0.96)",
                border:
                  "1px solid rgba(239,68,68,0.35)",
                borderRadius: "10px",
                padding: "12px",
              }}
            >
              <div
                style={{
                  fontWeight: "700",
                  color: "#fecaca",
                  marginBottom: "8px",
                }}
              >
                IP Addresses (
                {ipNodes.length}
                )
              </div>

              <input
                type="text"
                placeholder="Search IP addresses..."
                value={
                  searchTerms.IPAddress
                }
                onChange={(event) =>
                  handleSearch(
                    "IPAddress",
                    event.target.value
                  )
                }
                style={{
                  width: "100%",
                  boxSizing: "border-box",
                  padding: "8px 10px",
                  borderRadius: "7px",
                  border:
                    "1px solid #475569",
                  background: "#0f172a",
                  color: "#e2e8f0",
                  outline: "none",
                  marginBottom: "8px",
                }}
              />

              <div
                style={{
                  maxHeight: "180px",
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
                      padding: "7px 8px",
                      marginBottom: "4px",
                      borderRadius: "6px",
                      border: "none",
                      cursor: "pointer",
                      background:
                        "rgba(220,38,38,0.12)",
                      color: "#fecaca",
                      fontSize: "11px",
                      wordBreak:
                        "break-word",
                    }}
                  >
                    {getValue(node)}
                  </button>
                ))}

                {ipResults.length ===
                  0 && (
                  <div
                    style={{
                      color: "#94a3b8",
                      fontSize: "11px",
                    }}
                  >
                    No matching IP
                    addresses.
                  </div>
                )}
              </div>
            </div>
          )}

        {/* ====================================================
            CERTIFICATES
        ==================================================== */}

        {expandedGroups.Certificate &&
          certificateNodes.length > 0 && (
            <div
              style={{
                background:
                  "rgba(15,23,42,0.96)",
                border:
                  "1px solid rgba(20,184,166,0.35)",
                borderRadius: "10px",
                padding: "12px",
              }}
            >
              <div
                style={{
                  fontWeight: "700",
                  color: "#99f6e4",
                  marginBottom: "8px",
                }}
              >
                Certificates (
                {certificateNodes.length}
                )
              </div>

              <input
                type="text"
                placeholder="Search certificates..."
                value={
                  searchTerms.Certificate
                }
                onChange={(event) =>
                  handleSearch(
                    "Certificate",
                    event.target.value
                  )
                }
                style={{
                  width: "100%",
                  boxSizing: "border-box",
                  padding: "8px 10px",
                  borderRadius: "7px",
                  border:
                    "1px solid #475569",
                  background: "#0f172a",
                  color: "#e2e8f0",
                  outline: "none",
                  marginBottom: "8px",
                }}
              />

              <div
                style={{
                  maxHeight: "180px",
                  overflowY: "auto",
                }}
              >
                {certificateResults.map(
                  (node) => (
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
                        padding:
                          "7px 8px",
                        marginBottom: "4px",
                        borderRadius: "6px",
                        border: "none",
                        cursor: "pointer",
                        background:
                          "rgba(15,118,110,0.12)",
                        color: "#99f6e4",
                        fontSize: "11px",
                        wordBreak:
                          "break-word",
                      }}
                    >
                      {getValue(node)}
                    </button>
                  )
                )}

                {certificateResults.length ===
                  0 && (
                  <div
                    style={{
                      color: "#94a3b8",
                      fontSize: "11px",
                    }}
                  >
                    No matching
                    certificates.
                  </div>
                )}
              </div>
            </div>
          )}
      </div>

      {/* ======================================================
          NODE DETAILS
          Domain intentionally never opens this panel.
      ====================================================== */}

      {selectedNode && (
        <div
          style={{
            marginTop: "14px",
            width: "100%",
            boxSizing: "border-box",
            padding: "18px",
            borderRadius: "12px",
            background:
              "rgba(15,23,42,0.98)",
            border:
              "1px solid rgba(148,163,184,0.25)",
            color: "#e2e8f0",
            boxShadow:
              "0 10px 30px rgba(0,0,0,0.25)",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent:
                "space-between",
              alignItems: "center",
              marginBottom: "15px",
            }}
          >
            <strong
              style={{
                fontSize: "16px",
              }}
            >
              Node Details
            </strong>

            <button
              type="button"
              onClick={closeSelection}
              style={{
                background: "transparent",
                border: "none",
                color: "#94a3b8",
                cursor: "pointer",
                fontSize: "22px",
              }}
            >
              ×
            </button>
          </div>

          {/* TYPE */}

          <div
            style={{
              display: "grid",
              gridTemplateColumns:
                "120px 1fr",
              gap: "8px",
              marginBottom: "8px",
            }}
          >
            <span
              style={{
                color: "#94a3b8",
                fontSize: "12px",
              }}
            >
              TYPE
            </span>

            <strong>
              {selectedNode.type}
            </strong>
          </div>

          {/* VALUE */}

          <div
            style={{
              display: "grid",
              gridTemplateColumns:
                "120px 1fr",
              gap: "8px",
              marginBottom: "15px",
            }}
          >
            <span
              style={{
                color: "#94a3b8",
                fontSize: "12px",
              }}
            >
              VALUE
            </span>

            <strong
              style={{
                wordBreak: "break-word",
              }}
            >
              {selectedNode.value}
            </strong>
          </div>

          {/* RELATIONSHIPS */}

          {Array.isArray(
            selectedNode.connectedEdges
          ) &&
            selectedNode.connectedEdges
              .length > 0 && (
              <div>
                <div
                  style={{
                    color: "#94a3b8",
                    fontSize: "11px",
                    fontWeight: "700",
                    marginBottom: "8px",
                    textTransform:
                      "uppercase",
                  }}
                >
                  Relationships
                </div>

                <div
                  style={{
                    display: "grid",
                    gap: "7px",
                  }}
                >
                  {selectedNode.connectedEdges.map(
                    (
                      edge,
                      index
                    ) => {
                      const source =
                        getEdgeSource(
                          edge
                        );

                      const target =
                        getEdgeTarget(
                          edge
                        );

                      const relationship =
                        getRelationship(
                          edge
                        );

                      const sourceNode =
                        findNodeById(
                          source
                        );

                      const targetNode =
                        findNodeById(
                          target
                        );

                      return (
                        <div
                          key={
                            edge?.data
                              ?.id ??
                            index
                          }
                          style={{
                            padding:
                              "10px 12px",
                            borderRadius:
                              "8px",
                            background:
                              "rgba(30,41,59,0.8)",
                            border:
                              "1px solid rgba(71,85,105,0.4)",
                          }}
                        >
                          <div
                            style={{
                              fontWeight:
                                "700",
                              fontSize:
                                "11px",
                              marginBottom:
                                "5px",
                            }}
                          >
                            {
                              relationship
                            }
                          </div>

                          <div
                            style={{
                              display:
                                "flex",
                              alignItems:
                                "center",
                              gap: "8px",
                              flexWrap:
                                "wrap",
                              fontSize:
                                "11px",
                              color:
                                "#cbd5e1",
                            }}
                          >
                            <span>
                              {sourceNode
                                ? getValue(
                                    sourceNode
                                  )
                                : source}
                            </span>

                            <span
                              style={{
                                color:
                                  "#60a5fa",
                                fontWeight:
                                  "700",
                              }}
                            >
                              →
                            </span>

                            <span>
                              {targetNode
                                ? getValue(
                                    targetNode
                                  )
                                : target}
                            </span>
                          </div>
                        </div>
                      );
                    }
                  )}
                </div>
              </div>
            )}

          {/* NO RELATIONSHIPS */}

          {(!Array.isArray(
            selectedNode.connectedEdges
          ) ||
            selectedNode.connectedEdges
              .length === 0) && (
            <div
              style={{
                color: "#94a3b8",
                fontSize: "12px",
              }}
            >
              No relationships
              available for this
              node.
            </div>
          )}
        </div>
      )}

      {/* ======================================================
          INSTRUCTIONS
      ====================================================== */}

      <div
        style={{
          marginTop: "12px",
          textAlign: "center",
          fontSize: "12px",
          color: "#94a3b8",
        }}
      >
        Click a category to
        expand it. Search large
        result sets instead of
        rendering thousands of
        nodes. Click a list item
        to search and display it
        in the graph. Click an
        entity node to inspect
        its relationships.
      </div>
    </div>
  );
}

export default HierarchicalGraph;