// DHCP Management Page
// Features: Lease search, last 10 leases from DB, pool stats, release actions
import { useState, useEffect, useCallback } from "react";
import "./DHCPManagement.css";

const API_BASE = "http://localhost:8081/api";

function DHCPManagement() {
  const [leases, setLeases] = useState([]);
  const [stats, setStats] = useState(null);
  const [pools, setPools] = useState([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [notification, setNotification] = useState(null);

  // Fetch initial data
  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [leasesRes, statsRes, poolsRes] = await Promise.all([
        fetch(`${API_BASE}/dhcp/leases?limit=10`),
        fetch(`${API_BASE}/dhcp/stats`),
        fetch(`${API_BASE}/dhcp/pools`),
      ]);

      if (leasesRes.ok) {
        const data = await leasesRes.json();
        setLeases(data.leases || []);
      }
      if (statsRes.ok) {
        const data = await statsRes.json();
        setStats(data);
      }
      if (poolsRes.ok) {
        const data = await poolsRes.json();
        setPools(data.pools || []);
      }
      setError(null);
    } catch (err) {
      setError("Failed to connect to DHCP API");
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = useCallback(async (query) => {
    if (query.length < 2) {
      setSearchResults(null);
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/dhcp/leases/search?q=${encodeURIComponent(query)}`);
      if (res.ok) {
        const data = await res.json();
        setSearchResults(data.results || []);
      }
    } catch (err) {
      console.error("Search error:", err);
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => handleSearch(searchQuery), 300);
    return () => clearTimeout(timer);
  }, [searchQuery, handleSearch]);

  const releaseLease = async (mac) => {
    try {
      const res = await fetch(`${API_BASE}/dhcp/leases/${mac}/release`, {
        method: "POST",
      });
      if (res.ok) {
        showNotification(`Released lease for ${mac}`);
        fetchData();
      }
    } catch (err) {
      showNotification("Failed to release lease", "error");
    }
  };

  const showNotification = (message, type = "success") => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 3000);
  };

  const formatTime = (dateStr) => {
    const date = new Date(dateStr);
    return date.toLocaleTimeString();
  };

  const formatTimeRemaining = (endDateStr) => {
    const end = new Date(endDateStr);
    const now = new Date();
    const diff = end - now;
    
    if (diff <= 0) return "Expired";
    
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const mins = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    return `${hours}h ${mins}m`;
  };

  if (loading) {
    return (
      <div className="dhcp-loading">
        <div className="dhcp-spinner"></div>
        <p>Loading DHCP data...</p>
      </div>
    );
  }

  const displayLeases = searchResults !== null ? searchResults : leases;

  return (
    <div className="dhcp-management">
      {notification && (
        <div className={`dhcp-notification ${notification.type}`}>
          {notification.type === "success" ? "✅" : "❌"} {notification.message}
        </div>
      )}

      {/* Header */}
      <div className="dhcp-header">
        <div className="dhcp-header-left">
          <h1>📡 DHCP Management</h1>
          <p className="dhcp-subtitle">
            Manage IP address leases • {stats?.activeLeases || 0} active
          </p>
        </div>
        <button className="dhcp-refresh-btn" onClick={fetchData}>
          🔄 Refresh
        </button>
      </div>

      {error && <div className="dhcp-error-banner">⚠️ {error}</div>}

      {/* Stats Cards */}
      <div className="dhcp-stats-grid">
        <div className="dhcp-stat-card">
          <div className="stat-icon">📊</div>
          <div className="stat-content">
            <div className="stat-value">{stats?.activeLeases || 0}</div>
            <div className="stat-label">Active Leases</div>
          </div>
        </div>
        <div className="dhcp-stat-card">
          <div className="stat-icon">⏰</div>
          <div className="stat-content">
            <div className="stat-value">{stats?.expiredLeases || 0}</div>
            <div className="stat-label">Expired</div>
          </div>
        </div>
        <div className="dhcp-stat-card">
          <div className="stat-icon">🎯</div>
          <div className="stat-content">
            <div className="stat-value">{pools[0]?.utilization?.toFixed(1) || 0}%</div>
            <div className="stat-label">Pool Usage</div>
          </div>
        </div>
        <div className="dhcp-stat-card">
          <div className="stat-icon">🕐</div>
          <div className="stat-content">
            <div className="stat-value">{stats?.uptime || "N/A"}</div>
            <div className="stat-label">Uptime</div>
          </div>
        </div>
      </div>

      {/* Pool Info */}
      {pools.length > 0 && (
        <div className="dhcp-pool-info">
          <h3>Pool: {pools[0].name}</h3>
          <div className="pool-details">
            <span>{pools[0].startIP} - {pools[0].endIP}</span>
            <span>Gateway: {pools[0].gateway}</span>
            <span>DNS: {pools[0].dns}</span>
          </div>
          <div className="pool-bar">
            <div 
              className="pool-bar-fill"
              style={{ width: `${pools[0].utilization}%` }}
            />
          </div>
          <div className="pool-stats">
            {pools[0].usedIPs} / {pools[0].totalIPs} IPs used
          </div>
        </div>
      )}

      {/* Search Bar */}
      <div className="dhcp-search-container">
        <input
          type="text"
          className="dhcp-search-input"
          placeholder="🔍 Search by MAC, IP, or hostname..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
        {searchQuery && (
          <button 
            className="dhcp-search-clear"
            onClick={() => setSearchQuery("")}
          >
            ×
          </button>
        )}
      </div>

      {/* Leases Table */}
      <div className="dhcp-table-container">
        <table className="dhcp-table">
          <thead>
            <tr>
              <th>MAC Address</th>
              <th>IP Address</th>
              <th>Hostname</th>
              <th>State</th>
              <th>Expires In</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {displayLeases.length === 0 ? (
              <tr>
                <td colSpan="6" className="dhcp-no-results">
                  {searchQuery ? "No matching leases found" : "No active leases"}
                </td>
              </tr>
            ) : (
              displayLeases.map((lease) => (
                <tr key={lease.mac} className={lease.state.toLowerCase()}>
                  <td className="mac-cell">{lease.mac}</td>
                  <td className="ip-cell">{lease.ip}</td>
                  <td className="hostname-cell">{lease.hostname}</td>
                  <td>
                    <span className={`state-badge ${lease.state.toLowerCase()}`}>
                      {lease.state}
                    </span>
                  </td>
                  <td className="expires-cell">
                    {formatTimeRemaining(lease.leaseEnd)}
                  </td>
                  <td>
                    <button
                      className="dhcp-release-btn"
                      onClick={() => releaseLease(lease.mac)}
                      disabled={lease.state !== "ACTIVE"}
                    >
                      Release
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {searchResults === null && (
        <div className="dhcp-table-footer">
          Showing last 10 leases • Total: {stats?.totalLeases || 0}
        </div>
      )}
    </div>
  );
}

export default DHCPManagement;
