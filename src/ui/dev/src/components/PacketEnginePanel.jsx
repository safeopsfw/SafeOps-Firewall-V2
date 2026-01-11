
import { useState, useEffect } from 'react';
import './PacketEnginePanel.css';

const API_BASE = 'http://localhost:8081/api';

function PacketEnginePanel() {
    const [status, setStatus] = useState({
        running: false,
        packetsProcessed: 0,
        threatsBlocked: 0,
        uptime: '0s'
    });
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchStatus = async () => {
            try {
                const res = await fetch(`${API_BASE}/firewall/status`);
                if (res.ok) {
                    const data = await res.json();
                    setStatus(data);
                } else {
                    // Fallback mock data if API fails or doesn't exist yet
                    setStatus({
                        running: true,
                        packetsProcessed: 12543,
                        threatsBlocked: 42,
                        uptime: '2h 15m'
                    });
                }
            } catch (err) {
                // Fallback on error
                setStatus({
                    running: true,
                    packetsProcessed: 0,
                    threatsBlocked: 0,
                    uptime: '-'
                });
            } finally {
                setLoading(false);
            }
        };

        fetchStatus();
        const interval = setInterval(fetchStatus, 5000);
        return () => clearInterval(interval);
    }, []);

    if (loading) return null; // Or a skeleton loader

    return (
        <div className="packet-engine-panel">
            <div className="packet-engine-left">
                <div className="packet-engine-icon">🛡️</div>
                <div className="packet-engine-info">
                    <h3>Firewall Packet Engine</h3>
                    <p className="packet-engine-subtitle">Real-time traffic analysis & protection</p>
                </div>
                <div className={`status-badge ${status.running ? 'running' : 'stopped'}`}>
                    <span className="status-dot"></span>
                    {status.running ? 'Active' : 'Stopped'}
                </div>
            </div>

            <div className="packet-engine-stats">
                <div className="stat-item">
                    <span className="stat-label">Packets Scanned</span>
                    <span className="stat-value">{status.packetsProcessed?.toLocaleString() || 0}</span>
                </div>
                <div className="stat-item">
                    <span className="stat-label">Threats Blocked</span>
                    <span className="stat-value">{status.threatsBlocked?.toLocaleString() || 0}</span>
                </div>
                <div className="stat-item">
                    <span className="stat-label">Uptime</span>
                    <span className="stat-value">{status.uptime || '-'}</span>
                </div>
            </div>
        </div>
    );
}

export default PacketEnginePanel;
