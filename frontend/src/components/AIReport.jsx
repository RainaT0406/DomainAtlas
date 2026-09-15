import {
  Brain,
  Download,
  Shield,
  Target,
  Cpu,
  CheckCircle2,
} from "lucide-react";

import "./AIReport.css";

/**
 * Renders the DomainAtlas AI-Assisted Intelligence Report.
 *
 * The report comes from the backend as Markdown-ish text:
 *   - "## Heading"          -> section heading
 *   - "### Heading"         -> sub-heading
 *   - "- item" / "* item"   -> bullet
 *   - "1. item"             -> ordered item
 *   - "**bold**" inline     -> bold
 *   - blank line            -> paragraph break
 *
 * It is rendered as styled HTML, never as raw Markdown.
 */
function AIReport({
  report,
  domain,
  engine = "Ollama",
  onDownload,
  canDownload = true,
}) {
  const hasReport =
    typeof report === "string" && report.trim().length > 0;

  return (
    <div className="ai-report">
      <header className="ai-report-header">
        <div className="ai-report-header-left">
          <div className="ai-report-emblem">
            <Brain size={20} />
          </div>

          <div>
            <p className="ai-report-eyebrow">
              AI-ASSISTED INTELLIGENCE
            </p>

            <h3 className="ai-report-title">
              Intelligence Assessment
            </h3>

            <p className="ai-report-subtitle">
              Structured interpretation of the collected OSINT dataset.
            </p>
          </div>
        </div>

        <div className="ai-report-header-right">
          <button
            type="button"
            className="download-button"
            onClick={onDownload}
            disabled={!canDownload || !hasReport}
          >
            <Download size={15} />
            Export Report
          </button>

          <span className="ai-engine-badge">
            <Cpu size={14} />
            {engine}
          </span>
        </div>
      </header>

      <div className="ai-report-meta">
        <MetaItem
          icon={<Target size={14} />}
          label="Target"
          value={domain || "Unknown"}
        />
        <MetaItem
          icon={<Cpu size={14} />}
          label="Engine"
          value={engine}
        />
        <MetaItem
          icon={<CheckCircle2 size={14} />}
          label="Status"
          value={hasReport ? "Generated" : "Unavailable"}
        />
      </div>

      <article className="ai-report-body">
        {hasReport ? (
          <ReportContent text={report} />
        ) : (
          <p className="ai-report-empty">
            No AI report was generated for this analysis.
          </p>
        )}
      </article>

      <footer className="ai-report-limitation">
        <Shield size={17} />
        <div>
          <strong>Analytical Limitation</strong>
          <span>
            This report reflects only the collected OSINT data and does
            not establish ownership, maliciousness, benignness, or
            security posture.
          </span>
        </div>
      </footer>
    </div>
  );
}

/* ================================================================
   META ITEM
   ================================================================ */

function MetaItem({ icon, label, value }) {
  return (
    <div className="ai-report-meta-item">
      <span className="ai-report-meta-label">
        {icon}
        {label}
      </span>
      <span className="ai-report-meta-value">{value}</span>
    </div>
  );
}

/* ================================================================
   CONTENT RENDERER
   ================================================================ */

function ReportContent({ text }) {
  const blocks = parseBlocks(text);

  return (
    <>
      {blocks.map((block, index) => {
        switch (block.type) {
          case "h2":
            return (
              <h3 key={index} className="ai-report-heading">
                {block.text}
              </h3>
            );

          case "h3":
            return (
              <h4 key={index} className="ai-report-subheading">
                {block.text}
              </h4>
            );

          case "ul":
            return (
              <ul key={index} className="ai-report-list">
                {block.items.map((item, i) => (
                  <li key={i}>
                    <Inline text={item} />
                  </li>
                ))}
              </ul>
            );

          case "ol":
            return (
              <ol key={index} className="ai-report-ordered">
                {block.items.map((item, i) => (
                  <li key={i}>
                    <Inline text={item} />
                  </li>
                ))}
              </ol>
            );

          case "code":
            return (
              <pre key={index} className="ai-report-code">
                <code>{block.text}</code>
              </pre>
            );

          case "p":
            return (
              <p key={index} className="ai-report-paragraph">
                <Inline text={block.text} />
              </p>
            );

          default:
            return null;
        }
      })}
    </>
  );
}

/* ================================================================
   INLINE FORMATTING (**bold** and `code`)
   ================================================================ */

function Inline({ text }) {
  if (!text) return null;

  // Split on **bold** and `code` in one pass.
  const parts = [];
  const regex = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let lastIndex = 0;
  let match;

  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push({
        type: "text",
        value: text.slice(lastIndex, match.index),
      });
    }

    const token = match[0];

    if (token.startsWith("**")) {
      parts.push({
        type: "bold",
        value: token.slice(2, -2),
      });
    } else if (token.startsWith("`")) {
      parts.push({
        type: "code",
        value: token.slice(1, -1),
      });
    }

    lastIndex = match.index + token.length;
  }

  if (lastIndex < text.length) {
    parts.push({
      type: "text",
      value: text.slice(lastIndex),
    });
  }

  return (
    <>
      {parts.map((part, index) => {
        if (part.type === "bold") {
          return <strong key={index}>{part.value}</strong>;
        }
        if (part.type === "code") {
          return (
            <code key={index} className="ai-report-inline-code">
              {part.value}
            </code>
          );
        }
        return <span key={index}>{part.value}</span>;
      })}
    </>
  );
}

/* ================================================================
   PARSER
   ================================================================ */

function parseBlocks(text) {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const blocks = [];

  let i = 0;

  while (i < lines.length) {
    const raw = lines[i];
    const line = raw.trim();

    // Blank line
    if (!line) {
      i += 1;
      continue;
    }

    // Code fence
    if (line.startsWith("```")) {
      const codeLines = [];
      i += 1;

      while (i < lines.length && !lines[i].trim().startsWith("```")) {
        codeLines.push(lines[i]);
        i += 1;
      }

      // Skip closing fence
      i += 1;

      blocks.push({
        type: "code",
        text: codeLines.join("\n"),
      });

      continue;
    }

    // Heading
    const headingMatch = line.match(/^(#{1,6})\s+(.*)$/);
    if (headingMatch) {
      const level = headingMatch[1].length;
      const headingText = headingMatch[2].trim();

      // Normalize: treat #, ##, ### as section headings; ####+ as sub.
      if (level <= 2 || level === 3) {
        // "Analytical Limitation" is handled by the footer, skip it.
        if (/^analytical\s+limitation$/i.test(headingText)) {
          i += 1;
          continue;
        }

        blocks.push({
          type: level <= 2 ? "h2" : "h3",
          text: headingText,
        });
      } else {
        blocks.push({
          type: "h3",
          text: headingText,
        });
      }

      i += 1;
      continue;
    }

    // Unordered list
    if (/^[-*+]\s+/.test(line)) {
      const items = [];

      while (i < lines.length && /^[-*+]\s+/.test(lines[i].trim())) {
        items.push(lines[i].trim().replace(/^[-*+]\s+/, ""));
        i += 1;
      }

      blocks.push({ type: "ul", items });
      continue;
    }

    // Ordered list
    if (/^\d+\.\s+/.test(line)) {
      const items = [];

      while (i < lines.length && /^\d+\.\s+/.test(lines[i].trim())) {
        items.push(lines[i].trim().replace(/^\d+\.\s+/, ""));
        i += 1;
      }

      blocks.push({ type: "ol", items });
      continue;
    }

    // Paragraph — collect consecutive non-special lines
    const paragraphLines = [line];
    i += 1;

    while (
      i < lines.length &&
      lines[i].trim() &&
      !/^(#{1,6})\s+/.test(lines[i].trim()) &&
      !/^[-*+]\s+/.test(lines[i].trim()) &&
      !/^\d+\.\s+/.test(lines[i].trim()) &&
      !lines[i].trim().startsWith("```")
    ) {
      paragraphLines.push(lines[i].trim());
      i += 1;
    }

    blocks.push({
      type: "p",
      text: paragraphLines.join(" "),
    });
  }

  return blocks;
}

export default AIReport;