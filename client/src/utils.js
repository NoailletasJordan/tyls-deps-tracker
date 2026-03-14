const IMAGE_LABELS = {
  "registry.gitlab.com/uxiaagency/tyls-backend/strapi": "Strapi",
  "registry.gitlab.com/uxiaagency/comptacom/frontend": "Frontend",
};

export function getImageLabel(dirNameOrUrl) {
  const normalized = (dirNameOrUrl || "").replace(/_/g, "/").replace(/:.*$/, "");
  for (const [pattern, label] of Object.entries(IMAGE_LABELS)) {
    if (
      normalized.includes(pattern) ||
      pattern.replace(/\//g, "_").includes(dirNameOrUrl.replace(/:.*$/, ""))
    ) {
      return label;
    }
  }
  return normalized.split("/").pop() || dirNameOrUrl;
}

export function formatDate(str) {
  if (!str) return "Unknown";
  try {
    return new Date(str).toLocaleString();
  } catch {
    return str;
  }
}

export function formatDateShort(str) {
  if (!str) return "";
  try {
    const d = new Date(str);
    return (
      d.toLocaleDateString() +
      " " +
      d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    );
  } catch {
    return str;
  }
}

export function extractVulns(raw) {
  const vulns = [];
  for (const target of raw?.Results || []) {
    for (const v of target.Vulnerabilities || []) {
      vulns.push({
        id: v.VulnerabilityID,
        pkg: v.PkgName,
        installed: v.InstalledVersion,
        fixed: v.FixedVersion || "\u2014",
        severity: v.Severity,
        target: target.Target,
      });
    }
  }
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 };
  vulns.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
  return vulns;
}
