// Network Monitor Dashboard Page
// Features: ARP-based device detection, certificate distribution, NIC tracking
import { useState, useEffect, useCallback } from "react";
import {
    Wifi, WifiOff, Shield, ShieldCheck, ShieldX,
    Monitor, Smartphone, Laptop, RefreshCw,
    CheckCircle, XCircle, AlertCircle, Clock
} from "lucide-react";
import "./DHCPMonitor.css";

const API_BASE = "http://localhost:5050"; // Node.js backend API
const NIC_API = "http://localhost:8081"; // NIC Management API

function DHCPMonitor() {
    const [devices, setDevices] = useState([]);
    const [stats, setStats] = useState({ total: 0, enrolled: 0, unenrolled: 0 });
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [lastUpdate, setLastUpdate] = useState(null);

    // Gateway selection for QR code
    const [gateways, setGateways] = useState([
        { name: "Mobile Hotspot", ip: "192.168.137.1" },
        { name: "VirtualBox", ip: "192.168.56.1" },
        { name: "VMware", ip: "192.168.171.1" },
        { name: "Hyper-V", ip: "172.21.160.1" }
    ]);
    const [selectedGateway, setSelectedGateway] = useState("192.168.137.1");

    // Filter toggle - hide PC's own NICs by default
    const [hideLocalNics, setHideLocalNics] = useState(true);

    // Filter out local PC NICs - only show actual client devices
    const isClientDevice = (device) => {
        // Strip /32 suffix from IP for clean comparison
        const ip = device.ip ? device.ip.replace(/\/32$/, "") : "";

        // Device on hotspot subnet (192.168.137.x) = client device (except gateway .1)
        if (ip.startsWith("192.168.137.") && ip !== "192.168.137.1") {
            return true; // Always show hotspot clients
        }

        // Exclude known PC NIC patterns for other subnets
        const pcNicPatterns = [
            "Intel(R) Ethernet",
            "Intel(R) Wi-Fi",
            "VMware Virtual",
            "VirtualBox",
            "Hyper-V",
            "Bluetooth",
            "Loopback"
        ];
        // Note: Removed "Wi-Fi Direct" from exclusion - it's used for hotspot

        const nicName = device.nicInterfaceName || "";
        for (const pattern of pcNicPatterns) {
            if (nicName.includes(pattern)) {
                return false; // This is a local PC NIC
            }
        }
        return true;
    };

    // Get filtered device list
    const filteredDevices = hideLocalNics ? devices.filter(isClientDevice) : devices;

    // Fetch devices from Node.js backend API
    const fetchData = useCallback(async () => {
        try {
            const [devicesRes, statsRes] = await Promise.all([
                fetch(`${API_BASE}/api/devices`),
                fetch(`${API_BASE}/api/devices/stats`)
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
                const healthRes = await fetch(`${API_BASE}/health`);
                if (healthRes.ok) {
                    setError("Backend running but devices API may have an issue");
                } else {
                    setError("Backend service not responding");
                }
            } catch {
                setError("Cannot connect to Backend API (port 5050)");
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

    // Format IP address - remove /32 subnet suffix for cleaner display
    const formatIP = (ip) => {
        if (!ip) return "N/A";
        return ip.replace(/\/32$/, ""); // Strip /32 suffix
    };

    // Shorten NIC interface names for better readability
    const formatNIC = (nicName) => {
        if (!nicName) return "N/A";
        // Map long names to shorter versions
        const shortNames = {
            "Microsoft Wi-Fi Direct Virtual Adapter": "Wi-Fi Direct",
            "VMware Virtual Ethernet Adapter": "VMware",
            "Intel(R) Wi-Fi 6 AX201 160MHz": "Intel Wi-Fi 6",
            "Intel(R) Ethernet Connection (16) I219-LM": "Intel Ethernet",
        };
        // Check for partial matches
        for (const [longName, shortName] of Object.entries(shortNames)) {
            if (nicName.includes(longName.substring(0, 20))) {
                return shortName;
            }
        }
        // Fallback: truncate if too long
        if (nicName.length > 25) {
            return nicName.substring(0, 22) + "...";
        }
        return nicName;
    };

    // Get device display name (hostname > vendor > "Unknown Device")
    const getDeviceName = (device) => {
        if (device.hostname && device.hostname !== "Unknown") {
            return device.hostname;
        }
        if (device.vendor) {
            return device.vendor;
        }
        // Try to identify by MAC OUI or interface
        if (device.nicInterfaceName?.includes("Hotspot") || device.ip?.includes("137.")) {
            return "Mobile Device";
        }
        return "Unknown Device";
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
                        Start backend: <code>cd backend && npm start</code>
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
                    <p>Select your network and scan the QR code from your device</p>

                    {/* NIC Selector Dropdown */}
                    <div style={{ marginBottom: '1rem' }}>
                        <label style={{ marginRight: '0.5rem', fontWeight: 'bold' }}>Network:</label>
                        <select
                            value={selectedGateway}
                            onChange={(e) => setSelectedGateway(e.target.value)}
                            style={{
                                padding: '0.5rem 1rem',
                                borderRadius: '8px',
                                border: '1px solid #444',
                                backgroundColor: '#1e293b',
                                color: '#fff',
                                fontSize: '0.9rem',
                                cursor: 'pointer'
                            }}
                        >
                            {gateways.map((gw) => (
                                <option key={gw.ip} value={gw.ip}>
                                    {gw.name} ({gw.ip})
                                </option>
                            ))}
                        </select>
                    </div>

                    <div className="qr-code-container">
                        <img
                            src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=http://${selectedGateway}:8080`}
                            alt="Portal QR Code"
                            className="qr-code-img"
                        />
                    </div>
                    <div className="portal-url" style={{ textAlign: 'center', marginTop: '1rem' }}>
                        <a
                            href={`http://${selectedGateway}:8080`}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{
                                fontSize: '1.1rem',
                                fontWeight: 'bold',
                                color: '#22c55e',
                                textDecoration: 'none'
                            }}
                        >
                            http://{selectedGateway}:8080
                        </a>
                    </div>
                </div>
            </div>

            {/* Local Domain Info */}
            <div className="service-info" style={{ marginTop: '1.5rem' }}>
                <h3>🌐 Local Domain Access</h3>
                <div style={{ backgroundColor: 'rgba(34, 197, 94, 0.1)', padding: '1rem', borderRadius: '8px', marginBottom: '1rem' }}>
                    <p style={{ margin: 0, fontWeight: 'bold', color: '#22c55e', fontSize: '1.1rem' }}>
                        safeops.captiveportal.local
                    </p>
                    <p style={{ margin: '0.5rem 0 0', fontSize: '0.9rem', color: '#94a3b8' }}>
                        For devices to use this domain, configure their DNS to: <strong>{selectedGateway}</strong>
                    </p>
                </div>
                <div style={{ fontSize: '0.85rem', color: '#64748b' }}>
                    <strong>Supported domains:</strong> portal.safeops.local, safeops.captiveportal.local, captive.safeops.local
                </div>
            </div>

            {/* Service Info */}
            <div className="service-info">
                <h3>Service Endpoints</h3>
                <div className="endpoints-grid">
                    <div className="endpoint">
                        <span className="endpoint-label">Captive Portal (HTTP)</span>
                        <a href={`http://${selectedGateway}:8080`} target="_blank" rel="noopener noreferrer">
                            http://{selectedGateway}:8080
                        </a>
                    </div>
                    <div className="endpoint">
                        <span className="endpoint-label">Captive Portal (HTTPS)</span>
                        <a href={`https://${selectedGateway}:8444`} target="_blank" rel="noopener noreferrer">
                            https://{selectedGateway}:8444
                        </a>
                    </div>
                    <div className="endpoint">
                        <span className="endpoint-label">Step-CA</span>
                        <a href="https://localhost:9000/health" target="_blank" rel="noopener noreferrer">
                            https://localhost:9000
                        </a>
                    </div>
                    <div className="endpoint">
                        <span className="endpoint-label">DNS Server</span>
                        <span>{selectedGateway}:5354</span>
                    </div>
                </div>
            </div>

            {/* Devices Table */}
            <div className="devices-section">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                    <h3 style={{ margin: 0 }}>Connected Devices ({filteredDevices.length})</h3>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.85rem' }}>
                        <input
                            type="checkbox"
                            checked={hideLocalNics}
                            onChange={(e) => setHideLocalNics(e.target.checked)}
                            style={{ cursor: 'pointer' }}
                        />
                        Hide local PC NICs
                    </label>
                </div>
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
                            {filteredDevices.length === 0 ? (
                                <tr>
                                    <td colSpan="7" className="no-devices">
                                        {error ? "Unable to load devices" : hideLocalNics ? "No client devices connected" : "No devices detected yet"}
                                        <span className="hint">
                                            {hideLocalNics ? "Devices connected to your hotspot will appear here" : "Connect a device to your network to see it here"}
                                        </span>
                                    </td>
                                </tr>
                            ) : (
                                filteredDevices.map((device) => (
                                    <tr key={device.ip} className={device.hasCertificate ? "enrolled" : "unenrolled"}>
                                        <td className="device-cell">
                                            <div className="device-info">
                                                {getDeviceIcon(device.os)}
                                                <div>
                                                    <div className="device-hostname">{getDeviceName(device)}</div>
                                                    <div className="device-os">{device.vendor || device.os || "Unknown"}</div>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="ip-cell">{formatIP(device.ip)}</td>
                                        <td className="mac-cell">{device.mac}</td>
                                        <td className="nic-cell">
                                            <span className={`nic-badge ${device.nicType?.toLowerCase() || 'unknown'}`} title={device.nicInterfaceName || device.nicType || "N/A"}>
                                                {formatNIC(device.nicInterfaceName || device.nicType)}
                                            </span>
                                        </td>
                                        <td className="cert-cell">
                                            {device.hasCertificate ? (
                                                <span className="cert-status enrolled" title="Certificate downloaded - manual verification needed">
                                                    <CheckCircle className="w-4 h-4" />
                                                    Downloaded
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
                <h3>How It Works (Manual Portal Access)</h3>
                <div className="flow-steps">
                    <div className="flow-step">
                        <div className="step-number">1</div>
                        <div className="step-content">
                            <h4>Device Connects</h4>
                            <p>Device joins WiFi hotspot - internet works immediately</p>
                        </div>
                    </div>
                    <div className="flow-arrow">→</div>
                    <div className="flow-step">
                        <div className="step-number">2</div>
                        <div className="step-content">
                            <h4>Scan QR / Open Portal</h4>
                            <p>User scans QR code or visits portal.safeops.local:8080</p>
                        </div>
                    </div>
                    <div className="flow-arrow">→</div>
                    <div className="flow-step">
                        <div className="step-number">3</div>
                        <div className="step-content">
                            <h4>Download Certificate</h4>
                            <p>User downloads and installs CA certificate</p>
                        </div>
                    </div>
                    <div className="flow-arrow">→</div>
                    <div className="flow-step">
                        <div className="step-number">4</div>
                        <div className="step-content">
                            <h4>Device Trusted</h4>
                            <p>Device marked as TRUSTED - MITM inspection enabled</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default DHCPMonitor;
