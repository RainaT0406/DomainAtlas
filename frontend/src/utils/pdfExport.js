import jsPDF from "jspdf";

function safeDomain(domain) {
  return String(domain || "domain")
    .replace(/[^a-z0-9.-]/gi, "_");
}

function addFooter(pdf, domain) {
  const pageWidth =
    pdf.internal.pageSize.getWidth();

  const pageHeight =
    pdf.internal.pageSize.getHeight();

  const margin = 15;

  const totalPages =
    pdf.internal.getNumberOfPages();

  for (
    let page = 1;
    page <= totalPages;
    page++
  ) {
    pdf.setPage(page);

    pdf.setFont("helvetica", "normal");
    pdf.setFontSize(8);
    pdf.setTextColor(100);

    pdf.text(
      `DomainAtlas | ${domain}`,
      margin,
      pageHeight - 8
    );

    pdf.text(
      `Page ${page} of ${totalPages}`,
      pageWidth - margin,
      pageHeight - 8,
      {
        align: "right",
      }
    );

    pdf.setTextColor(0);
  }
}

export function downloadSubdomainsPDF({
  domain,
  subdomains,
}) {
  if (!Array.isArray(subdomains) || !subdomains.length) {
    return;
  }

  const pdf = new jsPDF({
    orientation: "portrait",
    unit: "mm",
    format: "a4",
  });

  const pageWidth =
    pdf.internal.pageSize.getWidth();

  const pageHeight =
    pdf.internal.pageSize.getHeight();

  const margin = 15;
  const lineHeight = 6;

  let y = 20;

  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(18);

  pdf.text(
    "DomainAtlas — Subdomain Inventory",
    margin,
    y
  );

  y += 9;

  pdf.setFont("helvetica", "normal");
  pdf.setFontSize(11);

  pdf.text(
    `Target Domain: ${domain}`,
    margin,
    y
  );

  y += 6;

  pdf.text(
    `Total Subdomains: ${subdomains.length}`,
    margin,
    y
  );

  y += 6;

  pdf.text(
    `Generated: ${new Date().toLocaleString()}`,
    margin,
    y
  );

  y += 10;

  const numberX = margin;
  const subdomainX = margin + 15;

  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(9);

  pdf.text("#", numberX, y);
  pdf.text("Subdomain", subdomainX, y);

  y += 3;

  pdf.line(
    margin,
    y,
    pageWidth - margin,
    y
  );

  y += 6;

  pdf.setFont("helvetica", "normal");

  subdomains.forEach((subdomain, index) => {
    if (y + lineHeight > pageHeight - margin) {
      pdf.addPage();
      y = 20;

      pdf.setFont("helvetica", "bold");
      pdf.setFontSize(12);

      pdf.text(
        "DomainAtlas — Subdomain Inventory",
        margin,
        y
      );

      y += 10;

      pdf.setFont("helvetica", "normal");
      pdf.setFontSize(9);
    }

    const value = String(subdomain ?? "");

    pdf.text(
      String(index + 1),
      numberX,
      y
    );

    const maxWidth =
      pageWidth - subdomainX - margin;

    const lines =
      pdf.splitTextToSize(
        value,
        maxWidth
      );

    pdf.text(
      lines,
      subdomainX,
      y
    );

    y +=
      lineHeight *
      Math.max(1, lines.length);

    pdf.setDrawColor(220);

    pdf.line(
      margin,
      y - 2,
      pageWidth - margin,
      y - 2
    );

    pdf.setDrawColor(0);

    y += 2;
  });

  addFooter(pdf, domain);

  pdf.save(
    `${safeDomain(domain)}_subdomains.pdf`
  );
}

export function downloadAIReportPDF({
  domain,
  aiReport,
}) {
  if (!aiReport) return;

  const pdf = new jsPDF({
    orientation: "portrait",
    unit: "mm",
    format: "a4",
  });

  const pageWidth =
    pdf.internal.pageSize.getWidth();

  const pageHeight =
    pdf.internal.pageSize.getHeight();

  const margin = 15;

  const contentWidth =
    pageWidth - margin * 2;

  let y = 20;

  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(18);

  pdf.text(
    "DomainAtlas — AI Intelligence Report",
    margin,
    y
  );

  y += 10;

  pdf.setFont("helvetica", "normal");
  pdf.setFontSize(11);

  pdf.text(
    `Target Domain: ${domain}`,
    margin,
    y
  );

  y += 6;

  pdf.text(
    `Generated: ${new Date().toLocaleString()}`,
    margin,
    y
  );

  y += 10;

  pdf.setDrawColor(180);

  pdf.line(
    margin,
    y,
    pageWidth - margin,
    y
  );

  y += 8;

  const lines = aiReport.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();

    if (!trimmed) {
      y += 4;
      continue;
    }

    if (
      trimmed.startsWith("**") &&
      trimmed.endsWith("**")
    ) {
      const heading =
        trimmed.replace(/\*\*/g, "");

      if (y > pageHeight - 30) {
        pdf.addPage();
        y = 20;
      }

      pdf.setFont("helvetica", "bold");
      pdf.setFontSize(12);

      const headingLines =
        pdf.splitTextToSize(
          heading,
          contentWidth
        );

      pdf.text(
        headingLines,
        margin,
        y
      );

      y +=
        6 *
          Math.max(
            1,
            headingLines.length
          ) +
        3;

      continue;
    }

    let text = trimmed;

    if (
      trimmed.startsWith("- ") ||
      trimmed.startsWith("* ")
    ) {
      text =
        "• " +
        trimmed.substring(2);
    }

    pdf.setFont("helvetica", "normal");
    pdf.setFontSize(10);

    const textLines =
      pdf.splitTextToSize(
        text,
        contentWidth
      );

    const requiredHeight =
      textLines.length * 5;

    if (
      y + requiredHeight >
      pageHeight - 20
    ) {
      pdf.addPage();
      y = 20;
    }

    pdf.text(
      textLines,
      margin,
      y
    );

    y += requiredHeight + 2;
  }

  if (y + 25 > pageHeight - 15) {
    pdf.addPage();
    y = 20;
  }

  y += 5;

  pdf.setDrawColor(150);

  pdf.rect(
    margin,
    y,
    contentWidth,
    22
  );

  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(9);

  pdf.text(
    "Analytical Limitation",
    margin + 5,
    y + 7
  );

  pdf.setFont("helvetica", "normal");
  pdf.setFontSize(8);

  const limitation =
    "This report reflects only the collected OSINT data and does not establish ownership, maliciousness, benignness, or security posture.";

  const limitationLines =
    pdf.splitTextToSize(
      limitation,
      contentWidth - 10
    );

  pdf.text(
    limitationLines,
    margin + 5,
    y + 13
  );

  addFooter(pdf, domain);

  pdf.save(
    `${safeDomain(domain)}_DomainAtlas_AI_Report.pdf`
  );
}