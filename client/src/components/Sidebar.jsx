import { useState, useEffect, useCallback } from "react";
import { fetchImages, fetchHistory, fetchStatus, triggerScan as apiTriggerScan } from "../api";
import { getImageLabel, formatDateShort } from "../utils";

export default function Sidebar({ activeView, onNavigate, refreshKey }) {
  const [imageGroups, setImageGroups] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [statusText, setStatusText] = useState("");

  const loadSidebar = useCallback(async () => {
    try {
      const imagesData = await fetchImages();
      if (!imagesData.ok || imagesData.images.length === 0) {
        setImageGroups([]);
        return;
      }

      const groups = await Promise.all(
        imagesData.images.map(async (img) => {
          const histData = await fetchHistory(img);
          return { img, history: histData.history || [] };
        })
      );
      setImageGroups(groups);
    } catch {}
  }, []);

  useEffect(() => {
    loadSidebar();
  }, [loadSidebar, refreshKey]);

  // Check if scan is already running on mount
  useEffect(() => {
    fetchStatus().then((data) => {
      if (data.running) startPolling();
    });
  }, []);

  function startPolling() {
    setScanning(true);
    setStatusText("Running now");
    const timer = setInterval(async () => {
      try {
        const data = await fetchStatus();
        if (!data.running) {
          clearInterval(timer);
          setScanning(false);
          setStatusText("Scan complete");
          loadSidebar();
          onNavigate({ type: "dashboard" });
          setTimeout(() => setStatusText(""), 5000);
        }
      } catch {}
    }, 3000);
  }

  async function handleScan() {
    try {
      const data = await apiTriggerScan();
      if (data.ok) {
        startPolling();
      }
    } catch {}
  }

  const isActive = (type, id) => {
    if (activeView.type === type && activeView.id === id) return "active";
    return "";
  };

  return (
    <nav className="sidebar">
      <h1>Deps Tracker</h1>
      <p className="subtitle">Vulnerability Scanner</p>

      <div className="nav-section">
        <h3>Views</h3>
        <button
          className={`nav-item ${isActive("dashboard")}`}
          onClick={() => onNavigate({ type: "dashboard" })}
        >
          Dashboard
        </button>
      </div>

      <div className="nav-section">
        <h3>Images</h3>
        {imageGroups.length === 0 ? (
          <span style={{ color: "#64748b", fontSize: "0.8rem", padding: "0.5rem" }}>
            No scans yet
          </span>
        ) : (
          imageGroups.map(({ img, history }) => (
            <div className="nav-image-group" key={img}>
              <div className="nav-image-label">{getImageLabel(img)}</div>
              {history.length === 0 ? (
                <div style={{ color: "#64748b", fontSize: "0.7rem", paddingLeft: "1.25rem" }}>
                  No scans yet
                </div>
              ) : (
                history.slice(0, 10).map((scan) => {
                  const s = scan.summary || {};
                  return (
                    <button
                      key={scan.file}
                      className={`nav-scan-item ${isActive("detail", scan.file)}`}
                      onClick={() =>
                        onNavigate({ type: "detail", image: img, file: scan.file, id: scan.file })
                      }
                    >
                      <span>{formatDateShort(scan.timestamp || scan.date)}</span>
                      <span className="nav-scan-counts">
                        <span className="c">{s.CRITICAL || 0}C</span>
                        <span className="h">{s.HIGH || 0}H</span>
                        <span className="m">{s.MEDIUM || 0}M</span>
                      </span>
                    </button>
                  );
                })
              )}
            </div>
          ))
        )}
      </div>

      <div className="scan-section">
        <button
          className={`scan-btn ${scanning ? "running" : ""}`}
          disabled={scanning}
          onClick={handleScan}
        >
          {scanning ? "Scanning..." : "Run Scan Now"}
        </button>
        {statusText && (
          <div className={`scan-status ${scanning ? "running" : ""}`}>{statusText}</div>
        )}
      </div>
    </nav>
  );
}
