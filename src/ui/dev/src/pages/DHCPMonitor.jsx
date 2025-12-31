// Network Monitor Dashboard Page
// Features: ARP-based device detection, certificate distribution, NIC tracking
import { useState, useEffect, useCallback } from "react";
import {
    Wifi, WifiOff, Shield, ShieldCheck, ShieldX,
    Monitor, Smartphone, Laptop, RefreshCw,
    CheckCircle, XCircle, AlertCircle, Clock
} from "lucide-react";
import "./DHCPMonitor.css";

const API_BASE = "http://localhost:80"; // DHCP Monitor captive portal API

function DHCPMonitor() {
    const [devices, setDevices] = useState([]);
    const [stats, setStats] = useState({ total: 0, enrolled: 0, unenrolled: 0 });
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [lastUpdate, setLastUpdate] = useState(null);

    // Fetch devices from DHCP Monitor API
    const fetchData = useCallback(async () => {
        try {
            const [devicesRes, statsRes] = await Promise.all([
                fetch(`${API_BASE}/api/devices`),
                fetch(`${API_BASE}/api/stats`)
            ]);

            if (devicesRes.ok) {
                const data = await devicesRes.json();
                setDevices(Array.isArray(data) ? data : []);
            }
            if (statsRes.ok) {
                const data = await statsRes.json();
                setStats({
                    total: data.totalDevices || 0,
                    enrolled: data.enrolledDevices || 0,
                    unenrolled: data.unenrolledDevices || 0,
                    active: data.activeDevices || 0
                });
            }
            setError(null);
            setLastUpdate(new Date());
        } catch (err) {
            // Try health endpoint to check if service is running
            try {
                const healthRes = await fetch(`${API_BASE}/api/health`);
                if (healthRes.ok) {
                    setError("DHCP Monitor running but may need Admin privileges for port 80");
                } else {
                    setError("DHCP Monitor service not responding");
                }
            } catch {
                setError("Cannot connect to Network Monitor (port 80)");
            }
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchData();
        // Refresh every 10 seconds
        const interval = setInterval(fetchData, 10000);
        return () => clearInterval(interval);
    }, [fetchData]);

    const getDeviceIcon = (os) => {
        if (!os) return <Monitor className="w-5 h-5" />;
        const osLower = os.toLowerCase();
        if (osLower.includes("iphone") || osLower.includes("ipad") || osLower.includes("android")) {
            return <Smartphone className="w-5 h-5" />;
        }
        return <Laptop className="w-5 h-5" />;
    };

    const formatTime = (dateStr) => {
        if (!dateStr) return "N/A";
        const date = new Date(dateStr);
        return date.toLocaleString();
    };

    if (loading) {
        return (
            <div className="dhcp-monitor-loading">
                <RefreshCw className="w-8 h-8 animate-spin text-blue-500" />
                <p>Loading DHCP Monitor data...</p>
            </div>
        );
    }

    return (
        <div className="dhcp-monitor">
            {/* Header */}
            <div className="dhcp-monitor-header">
                <div className="header-left">
                    <h1>
                        <Shield className="w-8 h-8 text-green-500" />
                        Network Monitor
                    </h1>
                    <p className="subtitle">
                        ARP-based device detection & certificate distribution
                    </p>
                </div>
                <div className="header-right">
                    <button className="refresh-btn" onClick={fetchData}>
                        <RefreshCw className="w-4 h-4" />
                        Refresh
                    </button>
                    {lastUpdate && (
                        <span className="last-update">
                            <Clock className="w-4 h-4" />
                            {lastUpdate.toLocaleTimeString()}
                        </span>
                    )}
                </div>
            </div>

            {error && (
                <div className="dhcp-monitor-error">
                    <AlertCircle className="w-5 h-5" />
                    {error}
                    <span className="error-hint">
                        Run as Admin: <code>.\dhcp_monitor.exe</code>
                    </span>
                </div>
            )}

            {/* Stats Cards */}
            <div className="stats-grid">
                <div className="stat-card total">
                    <div className="stat-icon">
                        <Monitor className="w-6 h-6" />
                    </div>
                    <div className="stat-content">
                        <div className="stat-value">{stats.total || 0}</div>
                        <div className="stat-label">Total Devices</div>
                    </div>
                </div>
                <div className="stat-card enrolled">
                    <div className="stat-icon">
                        <ShieldCheck className="w-6 h-6" />
                    </div>
                    <div className="stat-content">
                        <div className="stat-value">{stats.enrolled || 0}</div>
                        <div className="stat-label">Enrolled (Cert Installed)</div>
                    </div>
                </div>
                <div className="stat-card unenrolled">
                    <div className="stat-icon">
                        <ShieldX className="w-6 h-6" />
                    </div>
                    <div className="stat-content">
                        <div className="stat-value">{stats.unenrolled || 0}</div>
                        <div className="stat-label">Unenrolled (Pending)</div>
                    </div>
                </div>
                <div className="stat-card active">
                    <div className="stat-icon">
                        <Wifi className="w-6 h-6" />
                    </div>
                    <div className="stat-content">
                        <div className="stat-value">{stats.active || 0}</div>
                        <div className="stat-label">Active Now</div>
                    </div>
                </div>
            </div>

            {/* QR Code for Portal Access */}
            <div className="qr-code-section">
                <div className="qr-code-card">
                    <h3>📱 Scan to Install Certificate</h3>
                    <p>Share this QR code with connected devices to install the security certificate</p>
                    <div className="qr-code-container">
                        <img
                            src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=http://192.168.137.1`}
                            alt="Portal QR Code"
                            className="qr-code-img"
                        />
                    </div>
                    <div className="portal-url">
                        <span>Portal URL:</span>
                        <a href="http://192.168.137.1" target="_blank" rel="noopener noreferrer">
                            http://192.168.137.1
                        </a>
                    </div>
                </div>
            </div>

            {/* Service Info */}
            <div className="service-info">
                <h3>Service Endpoints</h3>
                <div className="endpoints-grid">
                    <div className="endpoint">
                        <span className="endpoint-label">Captive Portal</span>
                        <a href="http://localhost:80" target="_blank" rel="noopener noreferrer">
                            http://localhost:80
                        </a>
                    </div>
                    <div className="endpoint">
                        <span className="endpoint-label">DNS Hijack</span>
                        <span>localhost:53 (Admin required)</span>
                    </div>
                    <div className="endpoint">
                        <span className="endpoint-label">Health Check</span>
                        <a href="http://localhost:80/api/health" target="_blank" rel="noopener noreferrer">
                            http://localhost:80/api/health
                        </a>
                    </div>
                </div>
            </div>

            {/* Devices Table */}
            <div className="devices-section">
                <h3>Connected Devices</h3>
                <div className="devices-table-container">
                    <table className="devices-table">
                        <thead>
                            <tr>
                                <th>Device</th>
                                <th>IP Address</th>
                                <th>MAC Address</th>
                                <th>NIC</th>
                                <th>Certificate</th>
                                <th>First Seen</th>
                                <th>Last Seen</th>
                            </tr>
                        </thead>
                        <tbody>
                            {devices.length === 0 ? (
                                <tr>
                                    <td colSpan="7" className="no-devices">
                                        {error ? "Unable to load devices" : "No devices detected yet"}
                                        <span className="hint">
                                            Connect a device to your network to see it here
                                        </span>
                                    </td>
                                </tr>
                            ) : (
                                devices.map((device) => (
                                    <tr key={device.ip} className={device.hasCertificate ? "enrolled" : "unenrolled"}>
                                        <td className="device-cell">
                                            <div className="device-info">
                                                {getDeviceIcon(device.os)}
                                                <div>
                                                    <div className="device-hostname">{device.hostname || "Unknown"}</div>
                                                    <div className="device-os">{device.os || "Unknown OS"}</div>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="ip-cell">{device.ip}</td>
                                        <td className="mac-cell">{device.mac}</td>
                                        <td className="nic-cell">
                                            <span className={`nic-badge ${device.nicType?.toLowerCase() || 'unknown'}`}>
                                                {device.nicInterfaceName || device.nicType || "N/A"}
                                            </span>
                                        </td>
                                        <td className="cert-cell">
                                            {device.hasCertificate ? (
                                                <span className="cert-status enrolled">
                                                    <CheckCircle className="w-4 h-4" />
                                                    Installed
                                                </span>
                                            ) : (
                                                <span className="cert-status pending">
                                                    <XCircle className="w-4 h-4" />
                                                    Pending
                                                </span>
                                            )}
                                        </td>
                                        <td className="time-cell">{formatTime(device.firstSeen)}</td>
                                        <td className="time-cell">{formatTime(device.lastSeen)}</td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* How It Works */}
            <div className="how-it-works">
                <h3>How It Works</h3>
                <div className="flow-steps">
                    <div className="flow-step">
                        <div className="step-number">1</div>
                        <div className="step-content">
                            <h4>Device Connects</h4>
                            <p>ARP Monitor detects new device on any NIC</p>
                        </div>
                    </div>
                    <div className="flow-arrow">→</div>
                    <div className="flow-step">
                        <div className="step-number">2</div>
                        <div className="step-content">
                            <h4>DNS Hijack</h4>
                            <p>All DNS queries redirected to captive portal</p>
                        </div>
                    </div>
                    <div className="flow-arrow">→</div>
                    <div className="flow-step">
                        <div className="step-number">3</div>
                        <div className="step-content">
                            <h4>Portal Shows</h4>
                            <p>User sees certificate install instructions</p>
                        </div>
                    </div>
                    <div className="flow-arrow">→</div>
                    <div className="flow-step">
                        <div className="step-number">4</div>
                        <div className="step-content">
                            <h4>Cert Installed</h4>
                            <p>Device enrolls, gets full internet access</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default DHCPMonitor;
