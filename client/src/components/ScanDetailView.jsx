import { useState, useEffect } from "react";
import { fetchDetail } from "../api";
import { getImageLabel, formatDate, extractVulns } from "../utils";
import SeverityGrid from "./SeverityGrid";
import VulnTable from "./VulnTable";

export default function ScanDetailView({ image, file, onBack }) {
  const [data, setData] = useState(null);
  const [activeTab, setActiveTab] = useState("table");

  useEffect(() => {
    setActiveTab("table");
    fetchDetail(image, file).then((d) => {
      if (d.ok) setData(d);
      else setData({ error: d.error });
    });
  }, [image, file]);

  if (!data) return <div className="empty">Loading...</div>;
  if (data.error) return <div className="empty error">{data.error}</div>;

  const label = getImageLabel(data.image || image);
  const s = data.summary;
  const vulns = extractVulns(data.raw);

  return (
    <>
      <span className="back-link" onClick={onBack}>
        Back to Dashboard
      </span>
      <div className="card" style={{ marginTop: "0.5rem" }}>
        <h2>{label}</h2>
        <p style={{ fontSize: "0.7rem", color: "#64748b", marginTop: "-0.75rem", marginBottom: "0.75rem" }}>
          {data.image || image}
        </p>
        <p style={{ fontSize: "0.75rem", color: "#94a3b8", marginBottom: "1rem" }}>
          {formatDate(data.timestamp)}
        </p>
        <SeverityGrid summary={s} />
        <p style={{ fontSize: "0.85rem", color: "#94a3b8", marginBottom: "0.5rem" }}>
          {s.CRITICAL + s.HIGH + s.MEDIUM} total vulnerabilities
        </p>
        <div className="tabs">
          <button className={`tab ${activeTab === "table" ? "active" : ""}`} onClick={() => setActiveTab("table")}>
            Table
          </button>
          <button className={`tab ${activeTab === "raw" ? "active" : ""}`} onClick={() => setActiveTab("raw")}>
            Raw JSON
          </button>
        </div>
        {activeTab === "table" ? (
          <VulnTable vulns={vulns} />
        ) : (
          <div className="raw-json">{JSON.stringify(data.raw, null, 2)}</div>
        )}
      </div>
    </>
  );
}
