// Hotspot Control Panel - Floating Widget
// Controls Windows Mobile Hotspot via NIC Management API

import { useState, useEffect } from 'react';
import './HotspotPanel.css';

const NIC_API_BASE = 'http://localhost:8081/api';

function HotspotPanel() {
  const [isOpen, setIsOpen] = useState(false);
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [config, setConfig] = useState({
    ssid: 'SafeOps-Hotspot',
    password: 'SafeOps123',
  });

  // Fetch hotspot status
  const fetchStatus = async () => {
    try {
      const res = await fetch(`${NIC_API_BASE}/hotspot/status`);
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
      }
    } catch (err) {
      console.error('Failed to fetch hotspot status:', err);
    }
  };

  // Start hotspot
  const startHotspot = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${NIC_API_BASE}/hotspot/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      });

      const data = await res.json();
      if (data.success) {
        await fetchStatus();
        showNotification('Hotspot started successfully', 'success');
      } else {
        // Format multi-line error messages properly
        const errorMsg = data.error || 'Failed to start hotspot';
        showNotification(errorMsg, 'error');
        // Also show in alert for detailed errors
        if (errorMsg.includes('\n') || errorMsg.length > 100) {
          alert('Hotspot Error:\n\n' + errorMsg);
        }
      }
    } catch (err) {
      showNotification('Network error: ' + err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  // Stop hotspot
  const stopHotspot = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${NIC_API_BASE}/hotspot/stop`, {
        method: 'POST',
      });

      const data = await res.json();
      if (data.success) {
        await fetchStatus();
        showNotification('Hotspot stopped', 'success');
      } else {
        showNotification(data.error || 'Failed to stop hotspot', 'error');
      }
    } catch (err) {
      showNotification('Network error: ' + err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const showNotification = (message, type) => {
    // You can implement toast notifications here
    console.log(`[${type}] ${message}`);
  };

  // Fetch status when panel opens
  useEffect(() => {
    if (isOpen) {
      fetchStatus();
      const interval = setInterval(fetchStatus, 5000); // Refresh every 5s
      return () => clearInterval(interval);
    }
  }, [isOpen]);

  return (
    <>
      {/* Floating Toggle Button */}
      <button
        className="hotspot-toggle-btn"
        onClick={() => setIsOpen(!isOpen)}
        title="Mobile Hotspot"
      >
        📡
      </button>

      {/* Hotspot Control Panel */}
      {isOpen && (
        <div className="hotspot-panel">
          <div className="hotspot-header">
            <h3>📡 Mobile Hotspot</h3>
            <button
              className="hotspot-close-btn"
              onClick={() => setIsOpen(false)}
            >
              ×
            </button>
          </div>

          <div className="hotspot-body">
            {/* Status Section */}
            <div className="hotspot-status">
              <div className="status-indicator">
                <span
                  className={`status-dot ${status?.enabled ? 'active' : 'inactive'}`}
                ></span>
                <span className="status-text">
                  {status?.enabled ? 'Active' : 'Inactive'}
                </span>
              </div>
              {status?.enabled && status?.clientCount !== undefined && (
                <div className="client-count">
                  {status.clientCount} {status.clientCount === 1 ? 'device' : 'devices'} connected
                </div>
              )}
            </div>

            {/* Configuration Form */}
            {!status?.enabled && (
              <div className="hotspot-config">
                <div className="config-field">
                  <label>Network Name (SSID)</label>
                  <input
                    type="text"
                    value={config.ssid}
                    onChange={(e) =>
                      setConfig({ ...config, ssid: e.target.value })
                    }
                    placeholder="Enter SSID"
                    disabled={loading}
                  />
                </div>
                <div className="config-field">
                  <label>Password</label>
                  <input
                    type="password"
                    value={config.password}
                    onChange={(e) =>
                      setConfig({ ...config, password: e.target.value })
                    }
                    placeholder="Enter password (min 8 chars)"
                    minLength={8}
                    disabled={loading}
                  />
                </div>
                <p className="config-hint">
                  ℹ️ Password must be at least 8 characters
                </p>
              </div>
            )}

            {/* Active Hotspot Info */}
            {status?.enabled && (
              <div className="hotspot-info">
                <div className="info-row">
                  <span className="info-label">Network Name:</span>
                  <span className="info-value">{status.ssid}</span>
                </div>
                {status.hostedIP && (
                  <div className="info-row">
                    <span className="info-label">IP Address:</span>
                    <span className="info-value">{status.hostedIP}</span>
                  </div>
                )}
                {status.band && (
                  <div className="info-row">
                    <span className="info-label">Band:</span>
                    <span className="info-value">{status.band}</span>
                  </div>
                )}
              </div>
            )}

            {/* Control Buttons */}
            <div className="hotspot-actions">
              {!status?.enabled ? (
                <button
                  className="hotspot-btn start"
                  onClick={startHotspot}
                  disabled={loading || config.password.length < 8}
                >
                  {loading ? '⏳ Starting...' : '🟢 Start Hotspot'}
                </button>
              ) : (
                <button
                  className="hotspot-btn stop"
                  onClick={stopHotspot}
                  disabled={loading}
                >
                  {loading ? '⏳ Stopping...' : '🔴 Stop Hotspot'}
                </button>
              )}
            </div>

            {/* Help Text */}
            <div className="hotspot-help">
              <p>
                📌 Requires administrator privileges<br />
                📌 WiFi adapter must support hosted networks
              </p>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export default HotspotPanel;
