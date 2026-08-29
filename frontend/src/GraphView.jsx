import { useState } from "react";
import HierarchicalGraph from "./HierarchicalGraph";

function GraphView({
  graph,
  domain,
  subdomainCount = 0,
  allSubdomains = [],
}) {
  const [downloading, setDownloading] = useState(false);
  
  // ============================================================
  // GRAPH SEARCH STATE - This syncs with HierarchicalGraph
  // ============================================================
  
  const [graphSearchTerms, setGraphSearchTerms] = useState({
    Subdomain: "",
    IPAddress: "",
    Certificate: "",
  });

  // ============================================================
  // ENHANCE GRAPH WITH ALL SUBDOMAINS
  // ============================================================
  
  const enhanceGraphWithAllSubdomains = (baseGraph, subdomains, domainName) => {
    if (!baseGraph) baseGraph = { nodes: [], edges: [], provenance: [] };
    if (!subdomains || subdomains.length === 0) return baseGraph;
    
    const nodes = [...(baseGraph.nodes || [])];
    const edges = [...(baseGraph.edges || [])];
    const existingNodeIds = new Set();
    const existingSubdomains = new Set();
    
    // Track existing node IDs and subdomains
    nodes.forEach(n => {
      const id = n?.data?.id || n?.id || '';
      if (id) existingNodeIds.add(id);
      if (n?.data?.type === 'Subdomain') {
        const value = n?.data?.value || n?.data?.label || '';
        if (value) existingSubdomains.add(value);
      }
    });
    
    // Find domain node
    let domainNodeId = null;
    const domainNode = nodes.find(n => n?.data?.type === 'Domain');
    if (domainNode) {
      domainNodeId = domainNode?.data?.id || domainNode?.id;
    } else if (domainName) {
      // Create domain node if it doesn't exist
      const domainId = domainName;
      if (!existingNodeIds.has(domainId)) {
        nodes.push({
          data: {
            id: domainId,
            type: 'Domain',
            value: domainName,
            label: domainName
          }
        });
        existingNodeIds.add(domainId);
        domainNodeId = domainId;
      } else {
        domainNodeId = domainId;
      }
    }
    
    // Add all subdomains as nodes
    let addedCount = 0;
    subdomains.forEach(subdomain => {
      if (!subdomain) return;
      
      // Skip if already exists
      if (existingSubdomains.has(subdomain)) return;
      
      const nodeId = subdomain;
      if (!existingNodeIds.has(nodeId)) {
        nodes.push({
          data: {
            id: nodeId,
            type: 'Subdomain',
            value: subdomain,
            label: subdomain
          }
        });
        existingNodeIds.add(nodeId);
        existingSubdomains.add(subdomain);
        addedCount++;
        
        // Add edge from domain to subdomain if domain exists
        if (domainNodeId) {
          const edgeId = `domain_to_${subdomain.replace(/[^a-zA-Z0-9_-]/g, '_')}`;
          // Check if edge already exists
          const edgeExists = edges.some(e => 
            (e?.data?.id === edgeId) || 
            (e?.data?.source === domainNodeId && e?.data?.target === nodeId)
          );
          if (!edgeExists) {
            edges.push({
              data: {
                id: edgeId,
                source: domainNodeId,
                target: nodeId,
                label: 'HAS_SUBDOMAIN',
                relationship: 'HAS_SUBDOMAIN'
              }
            });
          }
        }
      }
    });
    
    console.log(`[GraphView] Added ${addedCount} subdomain nodes to graph`);
    console.log(`[GraphView] Total subdomain nodes: ${nodes.filter(n => n?.data?.type === 'Subdomain').length}`);
    
    return {
      ...baseGraph,
      nodes: nodes,
      edges: edges,
      provenance: baseGraph.provenance || []
    };
  };

  // Enhance the graph with all subdomains
  const enhancedGraph = enhanceGraphWithAllSubdomains(graph, allSubdomains, domain);

  // --------------------------------------------------------------
  // GRAPH STATE
  // --------------------------------------------------------------

  const hasNodes = Array.isArray(enhancedGraph?.nodes) && enhancedGraph.nodes.length > 0;

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
          <p>Hierarchical view of infrastructure discovered from the target domain.</p>
        </div>

        <div className="graph-actions">
          {/* Download button removed from here - it's in Subdomains section */}
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
            graph={enhancedGraph}
            searchTerms={graphSearchTerms}
            onSearchChange={setGraphSearchTerms}
          />
        )}

      </div>

    </div>
  );
}

export default GraphView;