import { useState } from "react";
import SeverityGrid from "./SeverityGrid";
import VulnTable from "./VulnTable";
import { getImageLabel, formatDate, extractVulns } from "../utils";

export default function ScanCard({ result }) {
  const [activeTab, setActiveTab] = useState("table");

  if (result.error) {
    return (
      <div className="card">
        <h2>{getImageLabel(result.image)}</h2>
        <p className="error">{result.error}</p>
      </div>
    );
  }

  const label = getImageLabel(result.image);
  const s = result.summary;
  const total = s.CRITICAL + s.HIGH + s.MEDIUM;
  const vulns = extractVulns(result.raw);

  return (
    <div className="card">
      <h2>{label}</h2>
      <p style={{ fontSize: "0.7rem", color: "#64748b", marginTop: "-0.75rem", marginBottom: "0.75rem" }}>
        {result.image}
      </p>
      {result.timestamp && (
        <p style={{ fontSize: "0.75rem", color: "#94a3b8", marginBottom: "1rem" }}>
          {formatDate(result.timestamp)}
        </p>
      )}
      <SeverityGrid summary={s} />
      <p style={{ fontSize: "0.85rem", color: "#94a3b8", marginBottom: "0.5rem" }}>
        {total} total vulnerabilities
      </p>
      <div className="tabs">
        <button
          className={`tab ${activeTab === "table" ? "active" : ""}`}
          onClick={() => setActiveTab("table")}
        >
          Table
        </button>
        <button
          className={`tab ${activeTab === "raw" ? "active" : ""}`}
          onClick={() => setActiveTab("raw")}
        >
          Raw JSON
        </button>
      </div>
      {activeTab === "table" ? (
        <VulnTable vulns={vulns} />
      ) : (
        <div className="raw-json">{JSON.stringify(result.raw, null, 2)}</div>
      )}
    </div>
  );
}
