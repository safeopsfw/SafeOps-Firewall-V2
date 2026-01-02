// NIC Management Page - Premium Network Interface Management
// Features: Real-time detection, rename, status monitoring, type classification

import { useState, useEffect, useCallback, useRef } from "react";
import { useNavigate } from "react-router-dom";
import "./NICManagement.css";
import PacketEnginePanel from "../components/PacketEnginePanel";

const NIC_API_BASE = "http://localhost:8081/api";
const NIC_SSE_URL = "http://localhost:8081/api/nics/events";

// Interface type icons
const TYPE_ICONS = {
  WAN: "🌍",
  LAN: "💻",
  VIRTUAL: "☁️",
  LOOPBACK: "🔄",
  UNKNOWN: "❓",
};

// Status colors
const STATUS_COLORS = {
  UP: "#10b981",
  DOWN: "#ef4444",
  TESTING: "#f59e0b",
  UNKNOWN: "#6b7280",
};

function NICManagement() {
  const navigate = useNavigate();
  const [nics, setNics] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [editingNic, setEditingNic] = useState(null);
  const [newAlias, setNewAlias] = useState("");
  const [saving, setSaving] = useState(false);
  const [notification, setNotification] = useState(null);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [isLive, setIsLive] = useState(false);
  const eventSourceRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const hasDataRef = useRef(false);

  // Hotspot state
  const [hotspotStatus, setHotspotStatus] = useState(null);
  const [hotspotLoading, setHotspotLoading] = useState(false);

  // Show notification toast
  const showNotification = useCallback((message, type = "success") => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 3000);
  }, []);

  // Fallback fetch (used when SSE fails or for manual refresh)
  const fetchNICs = async () => {
    try {
      console.log("Fetching NICs from REST API...");
      const res = await fetch(`${NIC_API_BASE}/nics`);
      if (!res.ok) throw new Error("Failed to fetch NICs");
      const data = await res.json();
      setNics(data.interfaces || []);
      setLastRefresh(new Date());
      setError(null);
      hasDataRef.current = true;
      console.log(`✅ Loaded ${data.interfaces?.length || 0} network interfaces from REST API`);
    } catch (err) {
      console.error("❌ Failed to fetch NICs:", err);
      setError("Unable to connect to NIC API server on port 8081. Please ensure the API is running.");
    } finally {
      setLoading(false);
    }
  };

  // Handle SSE messages
  const handleSSEMessage = useCallback((data) => {
    setLastRefresh(new Date());
    setLoading(false);
    hasDataRef.current = true;

    switch (data.type) {
      case "full_update":
        setNics(data.interfaces || []);
        break;

      case "nic_added":
        setNics(prev => [...prev, data.interface]);
        showNotification(`🔌 ${data.interface.alias || data.interface.name} connected`);
        break;

      case "nic_removed":
        setNics(prev => prev.filter(n => n.index !== data.interface.index));
        showNotification(`⚡ ${data.interface.alias || data.interface.name} disconnected`, "warning");
        break;

      case "nic_status_changed":
        setNics(prev => prev.map(n =>
          n.index === data.interface.index ? { ...n, status: data.newValue } : n
        ));
        showNotification(`${data.interface.alias || data.interface.name} is now ${data.newValue}`);
        break;

      case "nic_ip_changed":
        setNics(prev => prev.map(n =>
          n.index === data.interface.index ? { ...n, ipv4: data.interface.ipv4 } : n
        ));
        break;

      case "nic_primary_changed":
        setNics(prev => prev.map(n => ({
          ...n,
          isPrimary: n.index === data.interface.index
        })));
        break;

      case "speed_update":
        setNics(prev => prev.map(n => {
          const speed = data.interfaces?.find(s => s.index === n.index);
          if (speed) {
            return { ...n, rxBps: speed.rxBps, txBps: speed.txBps };
          }
          return n;
        }));
        break;

      default:
        break;
    }
  }, [showNotification]);

  // Connect to SSE for real-time updates
  useEffect(() => {
    let sseTimeout = null;

    const connectSSE = () => {
      console.log("🔌 Attempting SSE connection to", NIC_SSE_URL);
      eventSourceRef.current = new EventSource(NIC_SSE_URL);

      // Fallback: if SSE doesn't connect in 5 seconds, try REST API
      sseTimeout = setTimeout(() => {
        if (!hasDataRef.current) {
          console.log("⏱️  SSE connection timeout - falling back to REST API");
          fetchNICs();
        }
      }, 5000);

      eventSourceRef.current.onopen = () => {
        setIsLive(true);
        setError(null);
        if (sseTimeout) clearTimeout(sseTimeout);
        console.log("✅ SSE connected - real-time updates enabled");
      };

      eventSourceRef.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          handleSSEMessage(data);
        } catch (e) {
          console.error("SSE parse error:", e);
        }
      };

      eventSourceRef.current.onerror = (err) => {
        console.log("⚠️  SSE connection error, will retry in 3 seconds");
        setIsLive(false);
        eventSourceRef.current?.close();

        // Try fallback fetch on first error if we have no data
        if (!hasDataRef.current) {
          fetchNICs();
        }

        // Reconnect after 3 seconds
        if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = setTimeout(connectSSE, 3000);
      };
    };

    connectSSE();

    return () => {
      if (sseTimeout) clearTimeout(sseTimeout);
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      eventSourceRef.current?.close();
    };
  }, [handleSSEMessage]);

  // Fetch hotspot status periodically
  useEffect(() => {
    fetchHotspotStatus();
    const interval = setInterval(fetchHotspotStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  // Navigate to NIC detail page
  const handleCardClick = (nic) => {
    navigate(`/network/${nic.index}`);
  };

  const handleRename = (nic) => {
    setEditingNic(nic);
    setNewAlias(nic.alias || nic.name);
  };

  const saveRename = async () => {
    if (!newAlias.trim() || !editingNic) return;

    setSaving(true);
    try {
      const res = await fetch(`${NIC_API_BASE}/nics/${editingNic.index}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alias: newAlias.trim() }),
      });

      if (!res.ok) throw new Error("Failed to save");

      // Update local state
      setNics((prev) =>
        prev.map((n) =>
          n.index === editingNic.index ? { ...n, alias: newAlias.trim() } : n
        )
      );

      showNotification(`Renamed to "${newAlias.trim()}"`);
      setEditingNic(null);
    } catch (err) {
      // Still update locally even if API fails
      setNics((prev) =>
        prev.map((n) =>
          n.index === editingNic.index ? { ...n, alias: newAlias.trim() } : n
        )
      );
      showNotification(
        `Renamed to "${newAlias.trim()}" (offline mode)`,
        "warning"
      );
      setEditingNic(null);
    } finally {
      setSaving(false);
    }
  };

  const changeType = async (nic, newType) => {
    try {
      await fetch(`${NIC_API_BASE}/nics/${nic.index}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: newType }),
      });
    } catch (err) {
      // Continue anyway
    }

    setNics((prev) =>
      prev.map((n) => (n.index === nic.index ? { ...n, type: newType } : n))
    );
    showNotification(`Changed type to ${newType}`);
  };

  // WiFi/NIC toggle handler
  const handleNICToggle = async (nic, enable) => {
    const action = enable ? "enable" : "disable";

    try {
      const res = await fetch(`${NIC_API_BASE}/nics/${nic.index}/control`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      });

      const data = await res.json();

      if (data.success) {
        showNotification(`${nic.alias || nic.name} ${enable ? "enabled" : "disabled"}`);
        // Wait a moment for the system to update
        setTimeout(fetchNICs, 1000);
      } else {
        showNotification(data.message || `Failed to ${action} interface`, "warning");
      }
    } catch (err) {
      showNotification(`Failed to ${action} interface - ${err.message}`, "warning");
    }
  };

  // Hotspot management functions
  const fetchHotspotStatus = async () => {
    try {
      const res = await fetch(`${NIC_API_BASE}/hotspot/status`);
      if (res.ok) {
        const data = await res.json();
        setHotspotStatus(data);
      }
    } catch (err) {
      console.error('Failed to fetch hotspot status:', err);
    }
  };

  const toggleHotspot = async () => {
    setHotspotLoading(true);
    try {
      const endpoint = hotspotStatus?.enabled ? '/hotspot/stop' : '/hotspot/start';
      const res = await fetch(`${NIC_API_BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // Don't send config - use Windows native hotspot settings
        body: JSON.stringify({}),
      });

      const data = await res.json();
      if (data.success) {
        await fetchHotspotStatus();
        showNotification(
          hotspotStatus?.enabled ? 'Hotspot stopped' : 'Hotspot started',
          'success'
        );
      } else {
        // Show a shorter, friendlier error message
        let errorMsg = 'Failed to toggle hotspot';
        if (data.error) {
          if (data.error.includes('not ready') || data.error.includes('not in the correct state')) {
            errorMsg = 'Hotspot unavailable. Try enabling Mobile Hotspot in Windows Settings.';
          } else if (data.error.includes('does not support')) {
            errorMsg = 'WiFi adapter does not support hosted networks.';
          } else if (data.error.includes('radio')) {
            errorMsg = 'WiFi is turned off. Please enable WiFi first.';
          } else {
            // Truncate long error messages
            errorMsg = data.error.length > 80 ? data.error.substring(0, 80) + '...' : data.error;
          }
        }
        showNotification(errorMsg, 'warning');
      }
    } catch (err) {
      showNotification('Network error: ' + err.message, 'warning');
    } finally {
      setHotspotLoading(false);
    }
  };

  const formatSpeed = (bps) => {
    if (!bps) return "-";
    if (bps >= 1000000000) return `${(bps / 1000000000).toFixed(0)} Gbps`;
    if (bps >= 1000000) return `${(bps / 1000000).toFixed(0)} Mbps`;
    return `${(bps / 1000).toFixed(0)} Kbps`;
  };

  // Format bandwidth speed (bytes per second)
  const formatBps = (bps) => {
    if (!bps || bps === 0) return "0 B/s";
    if (bps >= 1073741824) return `${(bps / 1073741824).toFixed(1)} GB/s`;
    if (bps >= 1048576) return `${(bps / 1048576).toFixed(1)} MB/s`;
    if (bps >= 1024) return `${(bps / 1024).toFixed(1)} KB/s`;
    return `${bps} B/s`;
  };

  const formatIP = (ipList) => {
    if (!ipList || ipList.length === 0) return "-";
    return ipList[0].split("/")[0];
  };

  // Group NICs by type
  const wanNics = nics.filter((n) => n.type === "WAN");
  const lanNics = nics.filter((n) => n.type === "LAN");
  const virtualNics = nics.filter(
    (n) => n.type === "VIRTUAL" || n.type === "LOOPBACK"
  );

  if (loading) {
    return (
      <div className="nic-loading">
        <div className="nic-spinner"></div>
        <p>Detecting network interfaces...</p>
      </div>
    );
  }

  return (
    <div className="nic-management">
      {/* Notification Toast */}
      {notification && (
        <div className={`nic-notification ${notification.type}`}>
          {notification.type === "success" ? "✅" : "⚠️"} {notification.message}
        </div>
      )}

      {/* Header */}
      <div className="nic-header">
        <div className="nic-header-left">
          <h1>🌐 Network Interfaces</h1>
          <p className="nic-subtitle">
            Manage your network adapters • {nics.length} detected
            {isLive && <span className="nic-live-badge">● LIVE</span>}
          </p>
        </div>
        <div className="nic-header-right">
          <span className="nic-last-refresh">
            {isLive ? "Real-time" : `Last updated: ${lastRefresh?.toLocaleTimeString() || "-"}`}
          </span>
          <button className="nic-refresh-btn" onClick={fetchNICs}>
            🔄 Refresh
          </button>
        </div>
      </div>

      {error && <div className="nic-error-banner">⚠️ {error}</div>}

      {/* Packet Engine Status Panel */}
      <PacketEnginePanel />

      {/* Mobile Hotspot Control */}
      {hotspotStatus && (
        <div className="hotspot-section">
          <div className="hotspot-card">
            <div className="hotspot-header">
              <div className="hotspot-title">
                <span className="hotspot-icon">📡</span>
                <h3>Mobile Hotspot</h3>
              </div>
              <div className="hotspot-status">
                <span className={`status-dot ${hotspotStatus.enabled ? 'active' : 'inactive'}`}></span>
                <span className="status-text">{hotspotStatus.enabled ? 'Active' : 'Inactive'}</span>
              </div>
            </div>

            {hotspotStatus.enabled && hotspotStatus.ssid && (
              <div className="hotspot-info">
                <div className="info-item">
                  <span className="info-label">Network Name:</span>
                  <span className="info-value">{hotspotStatus.ssid}</span>
                </div>
                {hotspotStatus.clientCount !== undefined && (
                  <div className="info-item">
                    <span className="info-label">Connected Devices:</span>
                    <span className="info-value">{hotspotStatus.clientCount}</span>
                  </div>
                )}
              </div>
            )}

            <div className="hotspot-actions">
              <button
                className={`hotspot-btn ${hotspotStatus.enabled ? 'stop' : 'start'}`}
                onClick={toggleHotspot}
                disabled={hotspotLoading}
              >
                {hotspotLoading ? '⏳ Processing...' : (
                  hotspotStatus.enabled ? '🔴 Stop Hotspot' : '🟢 Start Hotspot'
                )}
              </button>
              {!hotspotStatus.enabled && (
                <p className="hotspot-hint">
                  Will use Windows configured hotspot settings
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* WAN Interfaces */}
      {wanNics.length > 0 && (
        <section className="nic-section">
          <h2 className="nic-section-title">
            🌍 WAN Interfaces{" "}
            <span className="nic-count">{wanNics.length}</span>
          </h2>
          <div className="nic-grid">
            {wanNics.map((nic, idx) => (
              <NICCard
                key={nic.index}
                nic={nic}
                priority={idx + 1}
                onRename={handleRename}
                onTypeChange={changeType}
                onToggle={handleNICToggle}
                onCardClick={handleCardClick}
                formatSpeed={formatSpeed}
                formatIP={formatIP}
                formatBps={formatBps}
              />
            ))}
          </div>
        </section>
      )}

      {/* LAN Interfaces */}
      {lanNics.length > 0 && (
        <section className="nic-section">
          <h2 className="nic-section-title">
            💻 LAN Interfaces{" "}
            <span className="nic-count">{lanNics.length}</span>
          </h2>
          <div className="nic-grid">
            {lanNics.map((nic) => (
              <NICCard
                key={nic.index}
                nic={nic}
                onRename={handleRename}
                onTypeChange={changeType}
                onToggle={handleNICToggle}
                onCardClick={handleCardClick}
                formatSpeed={formatSpeed}
                formatIP={formatIP}
                formatBps={formatBps}
              />
            ))}
          </div>
        </section>
      )}

      {/* Virtual Interfaces */}
      {virtualNics.length > 0 && (
        <section className="nic-section">
          <h2 className="nic-section-title">
            ☁️ Virtual Interfaces{" "}
            <span className="nic-count">{virtualNics.length}</span>
          </h2>
          <div className="nic-grid">
            {virtualNics.map((nic) => (
              <NICCard
                key={nic.index}
                nic={nic}
                onRename={handleRename}
                onTypeChange={changeType}
                onToggle={handleNICToggle}
                onCardClick={handleCardClick}
                formatSpeed={formatSpeed}
                formatIP={formatIP}
                formatBps={formatBps}
              />
            ))}
          </div>
        </section>
      )}

      {/* Rename Modal */}
      {editingNic && (
        <div className="nic-modal-overlay" onClick={() => setEditingNic(null)}>
          <div className="nic-modal" onClick={(e) => e.stopPropagation()}>
            <div className="nic-modal-header">
              <h3>✏️ Rename Interface</h3>
              <button
                className="nic-modal-close"
                onClick={() => setEditingNic(null)}
              >
                ×
              </button>
            </div>
            <div className="nic-modal-body">
              <div className="nic-modal-info">
                <span className="label">System Name:</span>
                <span className="value">{editingNic.name}</span>
              </div>
              <div className="nic-modal-input">
                <label>Custom Alias:</label>
                <input
                  type="text"
                  value={newAlias}
                  onChange={(e) => setNewAlias(e.target.value)}
                  onKeyPress={(e) => e.key === "Enter" && saveRename()}
                  autoFocus
                  placeholder="Enter a friendly name..."
                />
              </div>
              <p className="nic-modal-hint">
                💡 This alias will be used throughout the SafeOps interface
              </p>
            </div>
            <div className="nic-modal-footer">
              <button
                className="nic-btn-cancel"
                onClick={() => setEditingNic(null)}
              >
                Cancel
              </button>
              <button
                className="nic-btn-save"
                onClick={saveRename}
                disabled={saving || !newAlias.trim()}
              >
                {saving ? "Saving..." : "Save Changes"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Keyboard Hints */}
      <div className="nic-keyboard-hints">
        <span>
          <kbd>R</kbd> Refresh
        </span>
        <span>
          <kbd>Esc</kbd> Close modal
        </span>
      </div>
    </div>
  );
}

function NICCard({
  nic,
  priority,
  onRename,
  onTypeChange,
  onToggle,
  onCardClick,
  formatSpeed,
  formatIP,
  formatBps,
}) {
  const isOnline = nic.status === "UP";
  const typeIcon = TYPE_ICONS[nic.type] || TYPE_ICONS.UNKNOWN;

  // Check if this is a WiFi interface
  const isWiFi = nic.name &&
    (nic.name.toLowerCase().includes("wi-fi") ||
      nic.name.toLowerCase().includes("wireless") ||
      nic.name.toLowerCase().includes("wlan") ||
      nic.name.toLowerCase().includes("802.11"));

  return (
    <div
      className={`nic-card ${isOnline ? "online" : "offline"
        } ${nic.type.toLowerCase()} ${nic.isPrimary ? "primary" : ""}`}
      onClick={() => onCardClick(nic)}
      style={{ cursor: 'pointer' }}
    >
      {/* Primary/Priority Badge */}
      {nic.isPrimary && (
        <div className="nic-priority-badge primary">⭐ Primary Internet</div>
      )}
      {nic.type === "WAN" && !nic.isPrimary && priority && (
        <div className="nic-priority-badge">
          #{priority} Backup
        </div>
      )}

      {/* Card Header */}
      <div className="nic-card-header">
        <div className="nic-card-icon">{typeIcon}</div>
        <div className="nic-card-title">
          <h3>{nic.alias || nic.name}</h3>
          <span className="nic-system-name">{nic.name}</span>
        </div>
        <div
          className={`nic-status-indicator ${isOnline ? "online" : "offline"}`}
        >
          <span className="nic-status-dot"></span>
          {nic.status}
        </div>
      </div>

      {/* Card Body */}
      <div className="nic-card-body">
        <div className="nic-info-row">
          <span className="nic-label">IP Address</span>
          <span className="nic-value">{formatIP(nic.ipv4)}</span>
        </div>
        {nic.gateway && (
          <div className="nic-info-row">
            <span className="nic-label">Gateway</span>
            <span className="nic-value">{nic.gateway}</span>
          </div>
        )}
        <div className="nic-info-row">
          <span className="nic-label">Speed</span>
          <span className="nic-value">{formatSpeed(nic.speed)}</span>
        </div>
        <div className="nic-info-row">
          <span className="nic-label">MAC</span>
          <span className="nic-value nic-mac">{nic.mac || "-"}</span>
        </div>
      </div>

      {/* Card Footer */}
      <div className="nic-card-footer">
        {/* WiFi Toggle Switch */}
        {isWiFi && (
          <div className="nic-wifi-toggle" onClick={(e) => e.stopPropagation()}>
            <label className="toggle-switch">
              <input
                type="checkbox"
                checked={isOnline}
                onChange={(e) => onToggle(nic, e.target.checked)}
              />
              <span className="toggle-slider"></span>
            </label>
            <span className="toggle-label">{isOnline ? "WiFi On" : "WiFi Off"}</span>
          </div>
        )}

        {/* Regular enable/disable buttons for non-WiFi */}
        {!isWiFi && (
          <button
            className={`nic-control-btn ${isOnline ? "disable" : "enable"}`}
            onClick={(e) => {
              e.stopPropagation();
              onToggle(nic, !isOnline);
            }}
          >
            {isOnline ? "🔴 Disable" : "🟢 Enable"}
          </button>
        )}

        <select
          className="nic-type-select"
          value={nic.type}
          onChange={(e) => onTypeChange(nic, e.target.value)}
          onClick={(e) => e.stopPropagation()}
        >
          <option value="WAN">🌍 WAN</option>
          <option value="LAN">💻 LAN</option>
          <option value="VIRTUAL">☁️ Virtual</option>
        </select>
        <button className="nic-rename-btn" onClick={(e) => { e.stopPropagation(); onRename(nic); }}>
          ✏️ Rename
        </button>
      </div>

      {/* Live Speed Indicator */}
      {isOnline && (
        <div className="nic-traffic-indicator">
          <span className="nic-traffic-rx">↓ {formatBps ? formatBps(nic.rxBps) : "0 B/s"}</span>
          <span className="nic-traffic-tx">↑ {formatBps ? formatBps(nic.txBps) : "0 B/s"}</span>
        </div>
      )}
    </div>
  );
}

export default NICManagement;
