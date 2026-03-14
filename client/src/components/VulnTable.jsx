import { useState } from "react";

export default function VulnTable({ vulns }) {
  const [expanded, setExpanded] = useState(false);

  if (vulns.length === 0) {
    return <p style={{ color: "#4ade80", marginTop: "1rem" }}>No vulnerabilities found!</p>;
  }

  const shown = expanded ? vulns : vulns.slice(0, 10);

  return (
    <>
      <table className="vuln-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Package</th>
            <th>Installed</th>
            <th>Fix</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody>
          {shown.map((v, i) => (
            <tr key={`${v.id}-${v.pkg}-${i}`}>
              <td>{v.id}</td>
              <td>{v.pkg}</td>
              <td>{v.installed}</td>
              <td>{v.fixed}</td>
              <td>
                <span className={`badge badge-${v.severity}`}>{v.severity}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {vulns.length > 10 && (
        <button className="toggle-btn" onClick={() => setExpanded(!expanded)}>
          {expanded ? "Show top 10 only" : `Show all ${vulns.length} vulnerabilities`}
        </button>
      )}
    </>
  );
}
