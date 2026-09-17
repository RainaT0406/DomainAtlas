/**
 * DomainAtlas
 * Subdomain Priority Utility
 *
 * Purpose:
 * Select a small, useful set of active subdomains for graph visualization.
 *
 * This does NOT alphabetically sort subdomains.
 * Discovery order is preserved when priority scores are equal.
 */

const ROLE_PRIORITIES = {
  // Primary/public application infrastructure
  www: 100,
  api: 100,
  app: 95,
  web: 90,

  // Authentication / access
  auth: 90,
  login: 90,
  sso: 90,
  account: 85,
  accounts: 85,

  // Common services
  mail: 85,
  email: 85,
  smtp: 80,
  imap: 80,
  ftp: 75,

  // User-facing portals
  portal: 85,
  dashboard: 85,
  admin: 80,
  manage: 75,

  // Network / remote access
  vpn: 90,
  remote: 80,
  gateway: 80,

  // Development / testing infrastructure
  staging: 70,
  stage: 70,
  dev: 65,
  development: 65,
  test: 60,
  testing: 60,
  uat: 60,
  beta: 60,

  // Other commonly useful infrastructure
  docs: 55,
  status: 55,
  support: 50,
  help: 50,
  blog: 45,
  shop: 45,
  store: 45
};

/**
 * Safely obtain a subdomain's hostname/value.
 */
function getSubdomainValue(node) {
  return String(
    node?.data?.value ??
    node?.data?.label ??
    node?.data?.name ??
    node?.data?.id ??
    ""
  ).trim().toLowerCase();
}

/**
 * Determine whether the subdomain is active.
 */
function isActiveSubdomain(node) {
  return (
    node?.data?.active === true ||
    node?.data?.properties?.active === true
  );
}

/**
 * Calculate a priority score for a subdomain.
 *
 * Higher score = higher visualization priority.
 *
 * The score is based on recognizable infrastructure roles.
 * No alphabetical sorting is performed.
 */
function getSubdomainPriority(node) {
  const hostname = getSubdomainValue(node);

  if (!hostname) {
    return 0;
  }

  // Remove the final domain labels and inspect the left-most
  // meaningful subdomain component.
  const parts = hostname.split(".").filter(Boolean);

  if (parts.length === 0) {
    return 0;
  }

  const role = parts[0];

  let score = ROLE_PRIORITIES[role] || 20;

  /*
   * Additional role indicators.
   *
   * These are deliberately small bonuses so that an explicitly
   * recognized role remains more important than a random name.
   */
  const keywordBonuses = [
    ["api", 20],
    ["auth", 20],
    ["login", 20],
    ["admin", 15],
    ["portal", 15],
    ["vpn", 15],
    ["mail", 15],
    ["app", 15],
    ["dashboard", 15],
    ["www", 15]
  ];

  for (const [keyword, bonus] of keywordBonuses) {
    if (hostname.includes(keyword)) {
      score += bonus;
      break;
    }
  }

  /*
   * Prefer infrastructure-like names over obviously
   * low-value generated/random-looking names.
   */
  if (/^[0-9]+$/.test(role)) {
    score -= 10;
  }

  if (/^[a-f0-9]{8,}$/i.test(role)) {
    score -= 15;
  }

  return score;
}

/**
 * Return active subdomains ordered by visualization priority.
 *
 * Important:
 * - Only active subdomains are returned.
 * - No alphabetical sorting.
 * - Equal-priority subdomains retain their original discovery order.
 */
export function getPriorityActiveSubdomains(nodes = [], limit = 5) {
  if (!Array.isArray(nodes) || nodes.length === 0) {
    return [];
  }

  return nodes
    .map((node, index) => ({
      node,
      index,
      active: isActiveSubdomain(node),
      priority: getSubdomainPriority(node)
    }))
    .filter(item => item.active)
    .sort((a, b) => {
      // Higher priority first.
      if (b.priority !== a.priority) {
        return b.priority - a.priority;
      }

      // Stable tie-breaker:
      // preserve the original discovery order.
      return a.index - b.index;
    })
    .slice(0, limit)
    .map(item => item.node);
}

/**
 * Return all subdomains with active/high-priority subdomains first.
 *
 * This is useful for the sidebar/search list.
 */
export function getPrioritizedSubdomains(nodes = []) {
  if (!Array.isArray(nodes) || nodes.length === 0) {
    return [];
  }

  return nodes
    .map((node, index) => ({
      node,
      index,
      active: isActiveSubdomain(node),
      priority: getSubdomainPriority(node)
    }))
    .sort((a, b) => {
      // Active subdomains always come before inactive ones.
      if (a.active !== b.active) {
        return a.active ? -1 : 1;
      }

      // Within active/inactive groups, use priority.
      if (b.priority !== a.priority) {
        return b.priority - a.priority;
      }

      // Preserve original discovery order.
      return a.index - b.index;
    })
    .map(item => item.node);
}

export { getSubdomainPriority, isActiveSubdomain };