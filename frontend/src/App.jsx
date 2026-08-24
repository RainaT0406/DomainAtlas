import {
  Activity,
  BarChart3,
  Database,
  Globe,
  Network,
  Shield,
  Server,
  FileKey,
  Brain,
  Search,
  ChevronRight,
} from "lucide-react";
import "./App.css";

function App() {
  return (
    <div className="app">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="logo">
          <div className="logo-icon">
            <Network size={22} />
          </div>
          <div>
            <h1>OSINT<span>Graph</span></h1>
            <p>Domain Intelligence</p>
          </div>
        </div>

        <nav className="navigation">
          <p className="nav-label">ANALYSIS</p>

          <a className="nav-item active">
            <BarChart3 size={18} />
            Dashboard
          </a>

          <a className="nav-item">
            <Network size={18} />
            Infrastructure
          </a>

          <a className="nav-item">
            <Globe size={18} />
            Subdomains
          </a>

          <a className="nav-item">
            <FileKey size={18} />
            Certificates
          </a>

          <p className="nav-label">INTELLIGENCE</p>

          <a className="nav-item">
            <Brain size={18} />
            AI Report
          </a>

          <a className="nav-item">
            <Database size={18} />
            Graph Data
          </a>
        </nav>

        <div className="sidebar-footer">
          <div className="status-dot"></div>
          <div>
            <strong>System Online</strong>
            <span>Neo4j connected</span>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        {/* Header */}
        <header className="topbar">
          <div>
            <p className="eyebrow">DOMAIN INTELLIGENCE</p>
            <h2>OSINT Analysis Dashboard</h2>
          </div>

          <div className="header-status">
            <Activity size={16} />
            Analysis Ready
          </div>
        </header>

        {/* Search */}
        <section className="search-section">
          <div className="search-box">
            <Search size={20} />
            <input
              type="text"
              placeholder="Enter a domain to analyze..."
              defaultValue="example.com"
            />
            <button>
              Analyze Domain
              <ChevronRight size={17} />
            </button>
          </div>
          <p>
            Enter a domain to collect and correlate publicly available
            intelligence.
          </p>
        </section>

        {/* Overview */}
        <section>
          <div className="section-heading">
            <div>
              <p className="eyebrow">OVERVIEW</p>
              <h3>Domain Infrastructure</h3>
            </div>
            <span className="domain-badge">
              <Globe size={15} />
              example.com
            </span>
          </div>

          <div className="stat-grid">
            <StatCard
              icon={<Globe />}
              label="Subdomains"
              value="40,139"
              description="Observed"
            />

            <StatCard
              icon={<Server />}
              label="IP Addresses"
              value="4"
              description="2 IPv4 · 2 IPv6"
            />

            <StatCard
              icon={<Network />}
              label="ASNs"
              value="1"
              description="Observed"
            />

            <StatCard
              icon={<Database />}
              label="Organizations"
              value="1"
              description="Associated"
            />

            <StatCard
              icon={<FileKey />}
              label="Certificates"
              value="9"
              description="Observed"
            />
          </div>
        </section>

        {/* Infrastructure */}
        <section className="content-grid">
          <div className="panel">
            <div className="panel-header">
              <div>
                <p className="eyebrow">NETWORK</p>
                <h3>Infrastructure</h3>
              </div>
              <Server size={20} />
            </div>

            <div className="info-list">
              <InfoRow
                label="IPv4"
                value="104.20.23.154"
              />

              <InfoRow
                label="IPv4"
                value="172.66.147.243"
              />

              <InfoRow
                label="IPv6"
                value="2606:4700:10::6814:179a"
              />

              <InfoRow
                label="IPv6"
                value="2606:4700:10::ac42:93f3"
              />

              <InfoRow
                label="ASN"
                value="13335"
              />

              <InfoRow
                label="Organization"
                value="Cloudflare, Inc."
              />
            </div>
          </div>

          {/* Graph Preview */}
          <div className="panel graph-panel">
            <div className="panel-header">
              <div>
                <p className="eyebrow">CORRELATION</p>
                <h3>Entity Relationships</h3>
              </div>
              <Network size={20} />
            </div>

            <div className="graph-preview">
              <div className="graph-node domain-node">
                <Globe size={18} />
                <span>example.com</span>
              </div>

              <div className="graph-line line-one"></div>
              <div className="graph-line line-two"></div>

              <div className="graph-node ip-node">
                <Server size={16} />
                <span>IP Addresses</span>
              </div>

              <div className="graph-node asn-node">
                <Network size={16} />
                <span>ASN 13335</span>
              </div>

              <div className="graph-node org-node">
                <Database size={16} />
                <span>Cloudflare</span>
              </div>
            </div>
          </div>
        </section>

        {/* Subdomain Patterns */}
        <section className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">PATTERN ANALYSIS</p>
              <h3>Subdomain Patterns</h3>
            </div>
            <Globe size={20} />
          </div>

          <div className="pattern-grid">
            <PatternCard
              value="2,586"
              label="Numeric-leading"
            />

            <PatternCard
              value="2,711"
              label="Contains hyphen"
            />

            <PatternCard
              value="6,426"
              label="Multi-level"
            />

            <PatternCard
              value="71"
              label="www prefix"
            />
          </div>
        </section>

        {/* AI Report */}
        <section className="panel ai-panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">AI-ASSISTED ANALYSIS</p>
              <h3>Intelligence Summary</h3>
            </div>

            <div className="ai-badge">
              <Brain size={16} />
              Llama 3.2
            </div>
          </div>

          <div className="report">
            <h4>Domain Infrastructure</h4>
            <p>
              The domain example.com resolves to four observed IP addresses.
              The observed infrastructure maps to a single ASN, 13335, and is
              associated with one observed organization, Cloudflare, Inc.
            </p>

            <h4>Network Relationships</h4>
            <p>
              The domain resolves to observed IP addresses, and those IP
              addresses map to the observed ASN. The available graph data does
              not establish a direct domain-to-ASN relationship.
            </p>

            <h4>Certificate Observations</h4>
            <p>
              Nine certificates are associated with the domain through the
              observed graph relationships. Certificate presence does not by
              itself establish security, validity, trustworthiness, or
              ownership.
            </p>

            <div className="limitation">
              <Shield size={17} />
              <span>
                This report reflects only the collected OSINT data and does not
                establish ownership, maliciousness, benignness, or security
                posture.
              </span>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}

function StatCard({ icon, label, value, description }) {
  return (
    <div className="stat-card">
      <div className="stat-icon">{icon}</div>
      <div>
        <p>{label}</p>
        <strong>{value}</strong>
        <span>{description}</span>
      </div>
    </div>
  );
}

function InfoRow({ label, value }) {
  return (
    <div className="info-row">
      <span className="info-label">{label}</span>
      <span className="info-value">{value}</span>
    </div>
  );
}

function PatternCard({ value, label }) {
  return (
    <div className="pattern-card">
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

export default App;