import { useState, useEffect } from "react";
import { fetchResults } from "../api";
import ScanCard from "./ScanCard";

export default function Dashboard() {
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchResults()
      .then((data) => {
        if (data.ok) setResults(data.results);
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="empty">Loading...</div>;

  if (results.length === 0) {
    return (
      <>
        <h2 style={{ marginBottom: "1rem" }}>Dashboard</h2>
        <div className="empty">No scan results yet. Click "Run Scan Now" to start.</div>
      </>
    );
  }

  return (
    <>
      <div className="controls">
        <h2>Latest Results</h2>
        <span className="status">{results.length} image(s)</span>
      </div>
      <div className="cards">
        {results.map((r, i) => (
          <ScanCard key={i} result={r} />
        ))}
      </div>
    </>
  );
}
