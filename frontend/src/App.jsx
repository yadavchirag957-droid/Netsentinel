import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bell,
  ChevronRight,
  CircleDot,
  CheckCircle2,
  FileSearch,
  LayoutDashboard,
  Network,
  RefreshCw,
  Shield,
  ShieldAlert,
  Wifi,
  Loader2,
  UploadCloud,
} from "lucide-react";

import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import "./index.css";

const API_BASE = "http://127.0.0.1:8000";

function App() {
  const [statistics, setStatistics] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activePage, setActivePage] = useState("Overview");
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [traffic, setTraffic] = useState(null);
  const [liveTraffic, setLiveTraffic] = useState(null);
  const [alertFilter, setAlertFilter] = useState("ALL");
  const [pcapFile, setPcapFile] = useState(null);
  const [pcapLoading, setPcapLoading] = useState(false);
  const [pcapError, setPcapError] = useState(null);
  const [pcapResult, setPcapResult] = useState(null);
  const fetchDashboard = async () => {
    try {
      setError(null);

    const [statsRes, alertsRes, eventsRes, trafficRes, liveTrafficRes] = await Promise.all([
     fetch(`${API_BASE}/statistics`),
     fetch(`${API_BASE}/alerts?limit=100`),
     fetch(`${API_BASE}/events?limit=20`),
     fetch(`${API_BASE}/traffic`),
     fetch(`${API_BASE}/traffic/live`),
    ]);
      if (!statsRes.ok || !alertsRes.ok || !eventsRes.ok || !trafficRes.ok || !liveTrafficRes.ok) {
        throw new Error("NetSentinel API is unavailable");
      }

      const stats = await statsRes.json();
      const alertsData = await alertsRes.json();
      const eventsData = await eventsRes.json();
      const trafficData = await trafficRes.json();
      const liveTrafficData = await liveTrafficRes.json();

      setStatistics(stats);
      setAlerts(alertsData.alerts || []);
      setEvents(eventsData.events || []);
      setTraffic(trafficData);
      setLiveTraffic(liveTrafficData);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

    const analyzePcap = async () => {
  if (!pcapFile) {
    setPcapError("Please select a .pcap file first.");
    return;
  }

  setPcapLoading(true);
  setPcapError(null);
  setPcapResult(null);

  try {
    const formData = new FormData();
    formData.append("file", pcapFile);

    const response = await fetch(
      `${API_BASE}/analyze-pcap`,
      {
        method: "POST",
        body: formData,
      }
    );

    const data = await response.json();

    if (!response.ok) {
      throw new Error(
        data.detail || "PCAP analysis failed."
      );
    }

    setPcapResult(data);

    // Refresh dashboard data because
    // PCAP analysis may generate new alerts.
    await fetchDashboard();

  } catch (error) {
    setPcapError(
      error.message || "Unable to analyze PCAP."
    );
  } finally {
    setPcapLoading(false);
  }
};


  useEffect(() => {
    fetchDashboard();

    const interval = setInterval(fetchDashboard, 5000);

    return () => clearInterval(interval);
  }, []);

  const severity = statistics?.severity || {};
const filteredAlerts = useMemo(() => {
  if (alertFilter === "ALL") {
    return alerts;
  }

  return alerts.filter(
    (alert) =>
      (alert.severity || "").toUpperCase() === alertFilter
  );
}, [alerts, alertFilter]);
  const totalAlerts = statistics?.total_alerts || 0;
  const critical = severity.CRITICAL || 0;
  const high = severity.HIGH || 0;
  const medium = severity.MEDIUM || 0;
  const low = severity.LOW || 0;
  const chartData = useMemo(() => {
    const buckets = {};

    alerts.forEach((alert) => {
      if (!alert.timestamp) return;

      const time = new Date(alert.timestamp).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      });

      buckets[time] = (buckets[time] || 0) + 1;
    });

    return Object.entries(buckets)
      .map(([time, count]) => ({ time, count }))
      .slice(-12);
  }, [alerts]);

  const navigation = [
    ["Overview", LayoutDashboard],
    ["Alerts", ShieldAlert],
    ["Events", Activity],
    ["Traffic", Network],
    ["PCAP Analysis", FileSearch],
  ];

  return (
    <div className="app-shell">
      <aside className="sidebar">

        <div className="brand">
          <div className="brand-icon">
            <Shield size={22} />
          </div>

          <div>
            <div className="brand-name">NetSentinel</div>
            <div className="brand-subtitle">
              Security Operations
            </div>
          </div>
        </div>

        <div className="nav-section">
          <div className="nav-title">MONITOR</div>

          {navigation.map(([label, Icon]) => (
            <button
              key={label}
              className={
                activePage === label
                  ? "nav-item active"
                  : "nav-item"
              }
              onClick={() => setActivePage(label)}
            >
              <Icon size={18} />
              <span>{label}</span>

              {activePage === label && (
                <ChevronRight
                  size={15}
                  className="nav-arrow"
                />
              )}
            </button>
          ))}
        </div>

        <div className="sidebar-bottom">
          <div className="sensor-status">
            <span className="status-dot"></span>

            <div>
              <strong>Sensor Online</strong>
              <span>eth0 · Network Sensor</span>
            </div>
          </div>

          <div className="version">
            NetSentinel v1.0
          </div>
        </div>

      </aside>

      <main className="main-content">

        <header className="topbar">
          <div>
            <div className="breadcrumb">
              SECURITY OPERATIONS
            </div>

            <h1>{activePage}</h1>
          </div>

          <div className="topbar-actions">

            <div className="live-status">
              <span className="pulse"></span>
              SYSTEM ONLINE
            </div>

            <button
              className="refresh-button"
              onClick={fetchDashboard}
            >
              <RefreshCw size={17} />
            </button>

            <div className="notification">
              <Bell size={19} />

              {totalAlerts > 0 && (
                <span className="notification-count">
                  {totalAlerts > 99 ? "99+" : totalAlerts}
                </span>
              )}
            </div>

          </div>
        </header>

        {error && (
          <div className="api-error">
            <AlertTriangle size={18} />

            <span>{error}</span>

            <button onClick={fetchDashboard}>
              Retry
            </button>
          </div>
        )}

        {activePage === "Overview" ? (

          <section className="dashboard">

            <div className="welcome-row">
              <div>
                <h2>Security Overview</h2>

                <p>
                  Real-time visibility into network
                  security activity.
                </p>
              </div>

              <div className="updated">
                <CircleDot size={13} />
                Live monitoring
              </div>
            </div>

            <div className="stat-grid">

              <StatCard
                icon={<ShieldAlert />}
                label="Total Alerts"
                value={totalAlerts}
                description="Security events detected"
              />
              <StatCard
                icon={<Activity />}
                label="Live Traffic"
                value={liveTraffic?.count || 0}
                description="Events received"   
              />      
              <StatCard
                icon={<AlertTriangle />}
                label="Critical"
                value={critical}
                description="Immediate attention"
                danger
              />

              <StatCard
                icon={<Wifi />}
                label="High Severity"
                value={high}
                description="Requires investigation"
              />

              <StatCard
                icon={<BarChart3 />}
                label="Medium / Low"
                value={medium + low}
                description="Monitored events"
              />

            </div>

            <div className="content-grid">

              <div className="panel threat-panel">

                <div className="panel-header">

                  <div>
                    <h3>Threat Activity</h3>
                    <span>
                      Recent detected events
                    </span>
                  </div>

                  <div className="panel-badge">
                    LIVE
                  </div>

                </div>

                <div className="chart-container">

                  {chartData.length > 0 ? (

                    <ResponsiveContainer
                      width="100%"
                      height="100%"
                    >
                      <AreaChart data={chartData}>

                        <CartesianGrid
                          strokeDasharray="3 3"
                          vertical={false}
                        />

                        <XAxis
                          dataKey="time"
                          tickLine={false}
                          axisLine={false}
                        />

                        <YAxis
                          allowDecimals={false}
                          tickLine={false}
                          axisLine={false}
                        />

                        <Tooltip />

                        <Area
                          type="monotone"
                          dataKey="count"
                          strokeWidth={2}
                          fillOpacity={0.15}
                        />

                      </AreaChart>
                    </ResponsiveContainer>

                  ) : (

                    <EmptyState
                      icon={<Activity size={25} />}
                      title="No threat activity"
                      description="Detected events will appear here."
                    />

                  )}

                </div>

              </div>

              <div className="panel severity-panel">

                <div className="panel-header">

                  <div>
                    <h3>Severity</h3>

                    <span>
                      Alert distribution
                    </span>
                  </div>

                </div>

                <SeverityBar
                  label="Critical"
                  value={critical}
                  total={totalAlerts}
                />

                <SeverityBar
                  label="High"
                  value={high}
                  total={totalAlerts}
                />

                <SeverityBar
                  label="Medium"
                  value={medium}
                  total={totalAlerts}
                />

                <SeverityBar
                  label="Low"
                  value={low}
                  total={totalAlerts}
                />

              </div>

            </div>

            <div className="panel events-panel">

              <div className="panel-header">

                <div>
                  <h3>Recent Security Events</h3>

                  <span>
                    Latest detections from NetSentinel
                  </span>
                </div>

                <button
                  className="view-all"
                  onClick={() => setActivePage("Alerts")}
                >
                  View all
                  <ChevronRight size={15} />
                </button>

              </div>

              <AlertTable
                alerts={events.length ? events : alerts}
                loading={loading}
                onSelectAlert={setSelectedAlert}
              />

            </div>

          </section>


) : activePage === "Alerts" ? (

  <section className="dashboard">

    <div className="welcome-row">
      <div>
        <h2>Security Alerts</h2>

        <p>
          Review and investigate detected network threats.
        </p>
      </div>

      <div className="updated">
        <CircleDot size={13} />
        Live monitoring
      </div>
    </div>


    <div className="alert-toolbar">

      <div className="alert-filters">

        {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(
          (filter) => (

            <button
              key={filter}
              className={
                alertFilter === filter
                  ? "filter-button active"
                  : "filter-button"
              }
              onClick={() => setAlertFilter(filter)}
            >
              {filter}
            </button>

          )
        )}

      </div>

      <div className="alert-count">
        {filteredAlerts.length} alert
        {filteredAlerts.length !== 1 ? "s" : ""}
      </div>

    </div>


    <div className="panel events-panel">

      <div className="panel-header">

        <div>
          <h3>Detection Queue</h3>

          <span>
            Alerts generated by the NetSentinel detection engine
          </span>
        </div>

        <div className="panel-badge">
          {alertFilter}
        </div>

      </div>


      <AlertTable
        alerts={filteredAlerts}
        loading={loading}
        onSelectAlert={setSelectedAlert}
      />

    </div>

  </section>

) : activePage === "Events" ? (

  <section className="dashboard">

    <div className="welcome-row">

      <div>
        <h2>Security Events</h2>

        <p>
          Monitor recent detection activity across the network.
        </p>
      </div>

      <div className="updated">
        <CircleDot size={13} />
        Live monitoring
      </div>

    </div>


    <div className="panel events-panel">

      <div className="panel-header">

        <div>
          <h3>Event Stream</h3>

          <span>
            Recent security events detected by NetSentinel
          </span>
        </div>

        <div className="panel-badge">
          {events.length} EVENTS
        </div>

      </div>


      <AlertTable
        alerts={events}
        loading={loading}
        onSelectAlert={setSelectedAlert}
      />

    </div>

  </section>

) : activePage === "Traffic" ? (

  <section className="dashboard">

    <div className="welcome-row">

      <div>
        <h2>Network Traffic</h2>

        <p>
          Analyze traffic patterns associated with detected security activity.
        </p>
      </div>

      <div className="updated">
        <CircleDot size={13} />
        Live monitoring
      </div>

    </div>


    <div className="traffic-grid">

      <div className="stat-card">
        <div className="stat-icon">
          <Activity size={20} />
        </div>

        <div>
          <span className="stat-label">
            Security Events
          </span>

          <strong className="stat-value">
            {traffic?.total_security_events ?? 0}
          </strong>
        </div>
      </div>


      <div className="stat-card">
        <div className="stat-icon">
          <Network size={20} />
        </div>

        <div>
          <span className="stat-label">
            Top Source
          </span>

          <strong className="stat-value ip-value">
            {Object.keys(traffic?.top_sources || {})[0] || "N/A"}
          </strong>

          <small>
            {Object.values(traffic?.top_sources || {})[0] || 0} event
            {(Object.values(traffic?.top_sources || {})[0] || 0) !== 1
              ? "s"
              : ""}
          </small>
        </div>
      </div>


      <div className="stat-card">
        <div className="stat-icon">
          <Network size={20} />
        </div>

        <div>
          <span className="stat-label">
            Top Destination
          </span>

          <strong className="stat-value ip-value">
            {Object.keys(traffic?.top_destinations || {})[0] || "N/A"}
          </strong>

          <small>
            {Object.values(traffic?.top_destinations || {})[0] || 0} event
            {(Object.values(traffic?.top_destinations || {})[0] || 0) !== 1
              ? "s"
              : ""}
          </small>
        </div>
      </div>


      <div className="stat-card">
        <div className="stat-icon">
          <ShieldAlert size={20} />
        </div>

        <div>
          <span className="stat-label">
            Primary Protocol
          </span>

          <strong className="stat-value">
            {Object.keys(liveTraffic?.statistics?.protocols || {})[0] || "N/A"}
          </strong>

          <small>
            {Object.values(liveTraffic?.statistics?.protocols || {})[0] || 0} event
            {(Object.values(liveTraffic?.statistics?.protocols || {})[0] || 0) !== 1
              ? "s"
              : ""}
          </small>
        </div>
      </div>

    </div>


    <div className="panel events-panel">

      <div className="panel-header">

        <div>
          <h3>Protocol Distribution</h3>

          <span>
            Protocols observed in security events
          </span>
        </div>

        <div className="panel-badge">
          {Object.keys(liveTraffic?.statistics?.protocols || {}).length} PROTOCOL
          {Object.keys(liveTraffic?.statistics?.protocols || {}).length !== 1 ? "S" : ""}
        </div>

      </div>


      <div className="traffic-list">

        {Object.entries(liveTraffic?.statistics?.protocols || {}).length ? (

          Object.entries(liveTraffic.statistics.protocols).map(
            ([protocol, count]) => (

              <div className="traffic-row" key={protocol}>

                <div className="traffic-row-label">
                  <span>{protocol}</span>
                  <strong>{count}</strong>
                </div>

                <div className="traffic-bar">
                  <div
                    className="traffic-bar-fill"
                    style={{
                      width: `${Math.max(
                        8,
                        (count /
                          Math.max(
                            ...Object.values(liveTraffic.statistics.protocols)
                          )) *
                          100
                      )}%`,
                    }}
                  />
                </div>

              </div>

            )
          )

        ) : (

          <div className="empty-state">
            No traffic data available.
          </div>

        )}

      </div>

    </div>

  </section>

) : activePage === "PCAP Analysis" ? (

  <section className="dashboard">

    <div className="welcome-row">

      <div>
        <h2>PCAP Investigation</h2>

        <p>
          Analyze previously captured network
          traffic for suspicious behavior.
        </p>
      </div>

      <div className="updated">
        <FileSearch size={13} />
        Offline analysis
      </div>

    </div>

    <div className="panel pcap-upload-panel">

      <div className="panel-header">

        <div>
          <h3>Analyze Network Capture</h3>

          <span>
            Upload a PCAP file to run NetSentinel
            detection rules.
          </span>
        </div>

        <div className="panel-badge">
          PCAP
        </div>

      </div>

      <div className="pcap-upload-body">

        <label
          className={
            pcapFile
              ? "pcap-dropzone selected"
              : "pcap-dropzone"
          }
        >

          <input
            type="file"
            accept=".pcap"
            hidden
            onChange={(event) => {
              const selectedFile =
                event.target.files?.[0];

              setPcapError(null);
              setPcapResult(null);

              if (!selectedFile) {
                setPcapFile(null);
                return;
              }

              if (
                !selectedFile.name
                  .toLowerCase()
                  .endsWith(".pcap")
              ) {
                setPcapFile(null);
                setPcapError(
                  "Only .pcap files are supported."
                );
                return;
              }

              setPcapFile(selectedFile);
            }}
          />

          <div className="pcap-upload-icon">
            <UploadCloud size={28} />
          </div>

          {pcapFile ? (
            <>
              <strong>
                {pcapFile.name}
              </strong>

              <span>
                PCAP file selected and ready
                for analysis.
              </span>
            </>
          ) : (
            <>
              <strong>
                Select a PCAP file
              </strong>

              <span>
                Click here to choose a
                .pcap network capture.
              </span>
            </>
          )}

        </label>

        <div className="pcap-actions">

          <button
            className="pcap-analyze-button"
            onClick={analyzePcap}
            disabled={
              !pcapFile || pcapLoading
            }
          >

            {pcapLoading ? (
              <>
                <Loader2
                  size={17}
                  className="spin"
                />
                Analyzing PCAP...
              </>
            ) : (
              <>
                <FileSearch size={17} />
                Analyze PCAP
              </>
            )}

          </button>

          {pcapFile && !pcapLoading && (
            <button
              className="pcap-clear-button"
              onClick={() => {
                setPcapFile(null);
                setPcapResult(null);
                setPcapError(null);
              }}
            >
              Clear
            </button>
          )}

        </div>

        {pcapError && (
          <div className="pcap-error">
            <AlertTriangle size={16} />
            {pcapError}
          </div>
        )}

      </div>

    </div>
    
    {pcapResult && (
  <>

    <div className="pcap-summary-grid">

      <div className="stat-card">
        <div className="stat-icon">
          <Activity size={20} />
        </div>

        <div className="stat-info">
          <span className="stat-label">
            Detections
          </span>

          <strong className="stat-value">
            {pcapResult.detections}
          </strong>

          <span className="stat-description">
            Suspicious behaviors observed
          </span>
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-icon">
          <ShieldAlert size={20} />
        </div>

        <div className="stat-info">
          <span className="stat-label">
            Alerts Generated
          </span>

          <strong className="stat-value">
            {pcapResult.alerts?.length || 0}
          </strong>

          <span className="stat-description">
            Deduplicated security alerts
          </span>
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-icon">
          <AlertTriangle size={20} />
        </div>

        <div className="stat-info">
          <span className="stat-label">
            Highest Severity
          </span>

          <strong className="stat-value">
            {pcapResult.alerts?.length
              ? pcapResult.alerts.reduce(
                  (highest, alert) => {
                    const order = {
                      CRITICAL: 4,
                      HIGH: 3,
                      MEDIUM: 2,
                      LOW: 1,
                    };

                    return (
                      (order[
                        alert.severity?.toUpperCase()
                      ] || 0) >
                      (order[
                        highest?.toUpperCase()
                      ] || 0)
                        ? alert.severity
                        : highest
                    );
                  },
                  "LOW"
                )
              : "NONE"}
          </strong>

          <span className="stat-description">
            Highest detected severity
          </span>
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-icon">
          <BarChart3 size={20} />
        </div>

        <div className="stat-info">
          <span className="stat-label">
            Risk Score
          </span>

          <strong className="stat-value">
            {pcapResult.alerts?.length
              ? Math.max(
                  ...pcapResult.alerts.map(
                    (alert) =>
                      Number(
                        alert.risk_score || 0
                      )
                  )
                )
              : 0}
          </strong>

          <span className="stat-description">
            Highest generated risk
          </span>
        </div>
      </div>

    </div>

    <div className="panel events-panel">

      <div className="panel-header">

        <div>
          <h3>
            Detection Results
          </h3>

          <span>
            Raw detections identified from{" "}
            {pcapResult.filename}
          </span>
        </div>

        <div className="panel-badge">
          {pcapResult.detections} DETECTIONS
        </div>

      </div>

      <div className="pcap-results">

        {pcapResult.results?.map(
          (result, index) => {

            const detection =
              result.detection || {};

            const features =
              result.features || {};

            return (
              <div
                className="pcap-result-card"
                key={index}
              >

                <div className="pcap-result-header">

                  <div className="pcap-detection-title">

                    <span className="event-indicator"></span>

                    <strong>
                      {detection.detection ||
                        "Security Detection"}
                    </strong>

                  </div>

                  <SeverityBadge
                    severity={
                      detection.severity ||
                      "Unknown"
                    }
                  />

                </div>

                <div className="pcap-detail-grid">

                  <div className="pcap-detail">
                    <span>Source IP</span>
                    <strong>
                      {detection.source_ip || "—"}
                    </strong>
                  </div>

                  <div className="pcap-detail">
                    <span>Destination IP</span>
                    <strong>
                      {detection.destination_ip || "—"}
                    </strong>
                  </div>

                  <div className="pcap-detail">
                    <span>Unique Ports</span>
                    <strong>
                      {detection.unique_ports ??
                        features.unique_destination_ports ??
                        "—"}
                    </strong>
                  </div>

                  <div className="pcap-detail">
                    <span>SYN Count</span>
                    <strong>
                      {detection.syn_count ??
                        features.syn_count ??
                        "—"}
                    </strong>
                  </div>

                  <div className="pcap-detail">
                    <span>Total Packets</span>
                    <strong>
                      {features.total_packets ??
                        "—"}
                    </strong>
                  </div>

                  <div className="pcap-detail">
                    <span>Time Window</span>
                    <strong>
                      {features.window_seconds
                        ? `${features.window_seconds} sec`
                        : "—"}
                    </strong>
                  </div>

                </div>

                <div className="pcap-evidence">

                  <span>
                    Detection Evidence
                  </span>

                  <div>

                    {detection.unique_ports && (
                      <div className="pcap-evidence-item">
                        <CheckCircle2 size={14} />
                        Multiple destination ports
                        observed:{" "}
                        {detection.unique_ports}
                      </div>
                    )}

                    {detection.syn_count && (
                      <div className="pcap-evidence-item">
                        <CheckCircle2 size={14} />
                        TCP SYN requests observed:{" "}
                        {detection.syn_count}
                      </div>
                    )}

                    {features.window_seconds && (
                      <div className="pcap-evidence-item">
                        <CheckCircle2 size={14} />
                        Activity evaluated over{" "}
                        {features.window_seconds}
                        {" "}seconds
                      </div>
                    )}

                  </div>

                </div>

              </div>
            );
          }
        )}

      </div>

    </div>

    {pcapResult.alerts?.length > 0 && (

      <div className="panel events-panel">

        <div className="panel-header">

          <div>
            <h3>
              Generated Security Alerts
            </h3>

            <span>
              Deduplicated alerts created from
              this PCAP
            </span>
          </div>

          <div className="panel-badge">
            {pcapResult.alerts.length} ALERT
            {pcapResult.alerts.length !== 1
              ? "S"
              : ""}
          </div>

        </div>

        <AlertTable
          alerts={pcapResult.alerts}
          loading={false}
          onSelectAlert={setSelectedAlert}
        />

      </div>

    )}

  </>
)}

  </section>

) : (

  <section className="placeholder-page">

    <div className="placeholder-icon">
      <Activity size={32} />
    </div>

    <h2>{activePage}</h2>

    <p>
      {activePage} module is connected to the
      NetSentinel dashboard architecture.
    </p>

  </section>

)}
         {selectedAlert && (
          <InvestigationPanel
            alert={selectedAlert}
            onClose={() => setSelectedAlert(null)}
          />
        )}



      </main>
    </div>
  );
}


function StatCard({
  icon,
  label,
  value,
  description,
  danger = false,
}) {
  return (
    <div className="stat-card">

      <div
        className={
          danger
            ? "stat-icon danger"
            : "stat-icon"
        }
      >
        {icon}
      </div>

      <div className="stat-info">

        <span className="stat-label">
          {label}
        </span>

        <strong className="stat-value">
          {value}
        </strong>

        <span className="stat-description">
          {description}
        </span>

      </div>

    </div>
  );
}


function SeverityBar({
  label,
  value,
  total,
}) {
  const percentage =
    total > 0
      ? Math.round((value / total) * 100)
      : 0;

  return (
    <div className="severity-row">

      <div className="severity-info">
        <span>{label}</span>
      </div>

      <div className="severity-track">
        <div
          className={`severity-fill ${label.toLowerCase()}`}
          style={{
            width: `${percentage}%`,
          }}
        />
      </div>

      <span className="severity-percent">
        {percentage}%
      </span>

    </div>
  );
}


function AlertTable({
  alerts,
  loading,
  onSelectAlert,
}) {
  if (loading) {
    return (
      <div className="table-empty">
        Loading security events...
      </div>
    );
  }

  if (!alerts.length) {
    return (
      <div className="table-empty">
        <Shield size={24} />

        <span>
          No security events detected yet.
        </span>
      </div>
    );
  }

  return (
    <div className="table-wrapper">

      <table>

        <thead>
          <tr>
            <th>TIME</th>
            <th>DETECTION</th>
            <th>SOURCE</th>
            <th>DESTINATION</th>
            <th>SEVERITY</th>
            <th>RISK</th>
          </tr>
        </thead>

        <tbody>

          {alerts.map((event, index) => (

            <tr
              key={
               event.id ||
                `${event.timestamp}-${index}`
             }
             className="alert-row"
             onClick={() => onSelectAlert(event)}
            >

              <td className="time-cell">
                {event.timestamp
                  ? new Date(
                      event.timestamp
                    ).toLocaleTimeString()
                  : "—"}
              </td>

              <td>
                <div className="detection-name">

                  <span className="event-indicator"></span>

                  {event.detection ||
                    event.event_type ||
                    "Security Event"}

                </div>
              </td>

              <td className="mono">
                {event.source_ip ||
                  event.src_ip ||
                  "—"}
              </td>

              <td className="mono">
                {event.destination_ip ||
                  event.dst_ip ||
                  "—"}
              </td>

              <td>
                <SeverityBadge
                  severity={
                    event.severity ||
                    "Unknown"
                  }
                />
              </td>

              <td>
                <span className="risk-score">
                  {event.risk_score ?? "—"}
                </span>
              </td>

            </tr>

          ))}

        </tbody>

      </table>

    </div>
  );
}


function SeverityBadge({
  severity,
}) {
  return (
    <span
      className={`severity-badge ${severity.toLowerCase()}`}
    >
      {severity}
    </span>
  );
}


function EmptyState({
  icon,
  title,
  description,
}) {
  return (
    <div className="empty-chart">

      <div className="empty-icon">
        {icon}
      </div>

      <strong>{title}</strong>

      <span>{description}</span>

    </div>
  );
}

function InvestigationPanel({
  alert,
  onClose,
}) {
  const reasons = alert.reasons || [];

  const risk =
    alert.risk_score ??
    alert.confidence ??
    0;

  return (
    <div className="investigation-overlay">

      <div className="investigation-panel">

        <div className="investigation-header">

          <div>
            <div className="investigation-label">
              SECURITY INVESTIGATION
            </div>

            <h2>
              {alert.detection ||
                alert.event_type ||
                "Security Event"}
            </h2>
          </div>

          <button
            className="close-investigation"
            onClick={onClose}
          >
            ×
          </button>

        </div>


        <div className="investigation-content">

          <div className="investigation-summary">

            <div className="investigation-risk">

              <span>RISK SCORE</span>

              <strong>
                {risk}
              </strong>

              <small>
                / 100
              </small>

            </div>

            <SeverityBadge
              severity={
                alert.severity ||
                "Unknown"
              }
            />

          </div>


          <section className="investigation-section">

            <div className="section-title">
              EVENT DETAILS
            </div>

            <div className="detail-grid">

              <Detail
                label="Source IP"
                value={
                  alert.source_ip ||
                  alert.src_ip ||
                  "—"
                }
              />

              <Detail
                label="Destination IP"
                value={
                  alert.destination_ip ||
                  alert.dst_ip ||
                  "—"
                }
              />

              <Detail
                label="Protocol"
                value={
                  alert.protocol ||
                  "TCP"
                }
              />

              <Detail
                label="Timestamp"
                value={
                  alert.timestamp
                    ? new Date(
                        alert.timestamp
                      ).toLocaleString()
                    : "—"
                }
              />

              <Detail
                label="Ports Contacted"
                value={
                  alert.unique_ports ??
                  alert.ports_contacted ??
                  "—"
                }
              />

              <Detail
                label="SYN Requests"
                value={
                  alert.syn_count ??
                  alert.syn_requests ??
                  "—"
                }
              />

              <Detail
                label="Detection Window"
                value={
                  alert.window_seconds
                    ? `${alert.window_seconds}s`
                    : "—"
                }
              />

            </div>

          </section>


          <section className="investigation-section">

            <div className="section-title">
              WHY WAS THIS ALERT GENERATED?
            </div>

            {reasons.length > 0 ? (

              <div className="reason-list">

                {reasons.map(
                  (reason, index) => (

                    <div
                      className="reason-item"
                      key={index}
                    >

                      <span className="reason-check">
                        ✓
                      </span>

                      <span>
                        {reason}
                      </span>

                    </div>

                  )
                )}

              </div>

            ) : (

              <div className="no-evidence">
                Detection evidence is not
                available for this alert.
              </div>

            )}

          </section>


          <section className="investigation-section">

            <div className="section-title">
              INVESTIGATION TIMELINE
            </div>

            <div className="timeline">

              <TimelineItem
                title="Network Activity Observed"
                description="Traffic matching monitored behaviour was observed."
                active
              />

              <TimelineItem
                title="Detection Triggered"
                description={
                  alert.detection ||
                  "Security detection rule matched."
                }
                active
              />

              <TimelineItem
                title="Risk Assessment"
                description={`Risk engine assigned a score of ${risk}/100.`}
                active
              />

              <TimelineItem
                title="Security Alert Generated"
                description="Event was passed to the alert pipeline."
                active
              />

            </div>

          </section>

        </div>

      </div>

    </div>
  );
}


function Detail({
  label,
  value,
}) {
  return (
    <div className="detail-item">

      <span>
        {label}
      </span>

      <strong>
        {value}
      </strong>

    </div>
  );
}


function TimelineItem({
  title,
  description,
  active,
}) {
  return (
    <div className="timeline-item">

      <div
        className={
          active
            ? "timeline-dot active"
            : "timeline-dot"
        }
      />

      <div>

        <strong>
          {title}
        </strong>

        <span>
          {description}
        </span>

      </div>

    </div>
  );
}

export default App;

