export default function SeverityGrid({ summary }) {
  return (
    <div className="severity-grid">
      <div className="severity-box sev-CRITICAL">
        <span className="count">{summary.CRITICAL}</span>Critical
      </div>
      <div className="severity-box sev-HIGH">
        <span className="count">{summary.HIGH}</span>High
      </div>
      <div className="severity-box sev-MEDIUM">
        <span className="count">{summary.MEDIUM}</span>Medium
      </div>
    </div>
  );
}
