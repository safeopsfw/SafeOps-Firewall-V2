// NIC Management Page - Premium Network Interface Management
// Features: Real-time detection, rename, status monitoring, type classification

import { useState, useEffect, useCallback, useRef } from "react";
import { useNavigate } from "react-router-dom";
import "./NICManagement.css";

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

  // Connect to SSE for real-time updates
  useEffect(() => {
    const connectSSE = () => {
      eventSourceRef.current = new EventSource(NIC_SSE_URL);
      
      eventSourceRef.current.onopen = () => {
        setIsLive(true);
        setError(null);
        console.log("SSE connected - real-time updates enabled");
      };

      eventSourceRef.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          handleSSEMessage(data);
        } catch (e) {
          console.error("SSE parse error:", e);
        }
      };

      eventSourceRef.current.onerror = () => {
        setIsLive(false);
        eventSourceRef.current?.close();
        // Reconnect after 3 seconds
        setTimeout(connectSSE, 3000);
      };
    };

    connectSSE();

    return () => {
      eventSourceRef.current?.close();
    };
  }, []);

  // Handle SSE messages
  const handleSSEMessage = useCallback((data) => {
    setLastRefresh(new Date());
    setLoading(false);

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
  }, []);

  // Fallback fetch (used for manual refresh only)
  const fetchNICs = async () => {
    try {
      const res = await fetch(`${NIC_API_BASE}/nics`);
      if (!res.ok) throw new Error("Failed to fetch NICs");
      const data = await res.json();
      setNics(data.interfaces || []);
      setLastRefresh(new Date());
      setError(null);
    } catch (err) {
      setError("Backend offline - please start NIC API server");
    } finally {
      setLoading(false);
    }
  };

  // Navigate to NIC detail page
  const handleCardClick = (nic) => {
    navigate(`/network/${nic.index}`);
  };

  const showNotification = (message, type = "success") => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 3000);
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
  onCardClick,
  formatSpeed,
  formatIP,
  formatBps,
}) {
  const isOnline = nic.status === "UP";
  const typeIcon = TYPE_ICONS[nic.type] || TYPE_ICONS.UNKNOWN;

  return (
    <div
      className={`nic-card ${
        isOnline ? "online" : "offline"
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
