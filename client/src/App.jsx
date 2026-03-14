import { useState, useCallback, useEffect } from "react";
import Sidebar from "./components/Sidebar";
import Dashboard from "./components/Dashboard";
import ScanDetailView from "./components/ScanDetailView";
import Login from "./components/Login";
import { isLoggedIn, logout } from "./api";

export default function App() {
  const [authed, setAuthed] = useState(isLoggedIn());
  const [view, setView] = useState({ type: "dashboard" });
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    const onLogout = () => setAuthed(false);
    window.addEventListener("auth:logout", onLogout);
    return () => window.removeEventListener("auth:logout", onLogout);
  }, []);

  const handleNavigate = useCallback((newView) => {
    setView(newView);
    if (newView.type === "dashboard") {
      setRefreshKey((k) => k + 1);
    }
  }, []);

  if (!authed) {
    return <Login onLogin={() => setAuthed(true)} />;
  }

  return (
    <div className="layout">
      <Sidebar activeView={view} onNavigate={handleNavigate} refreshKey={refreshKey} />
      <div className="main">
        {view.type === "dashboard" && <Dashboard key={refreshKey} />}
        {view.type === "detail" && (
          <ScanDetailView
            image={view.image}
            file={view.file}
            onBack={() => handleNavigate({ type: "dashboard" })}
          />
        )}
      </div>
    </div>
  );
}
