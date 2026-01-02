// PacketEnginePanel - Simple packet engine status indicator
// Shows only Running/Stopped status - no terminal output

import { useState, useEffect, useCallback } from 'react';

const PACKET_ENGINE_API = 'http://localhost:8081/api/packet-engine';

function PacketEnginePanel() {
  const [status, setStatus] = useState({ running: false });

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(`${PACKET_ENGINE_API}/status`);
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
      }
    } catch (err) {
      setStatus({ running: false, error: 'Cannot connect to API' });
    }
  }, []);

  // Poll every 5 seconds
  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  return (
    <div className="packet-engine-panel">
      <div className="packet-engine-header">
        <div className="packet-engine-title">
          <span className="packet-engine-icon">🔒</span>
          <h3>Packet Engine</h3>
        </div>
        <div className="packet-engine-status">
          <span className={`status-dot ${status.running ? 'active' : 'inactive'}`}></span>
          <span className="status-text">{status.running ? 'Running' : 'Stopped'}</span>
        </div>
      </div>

      <style>{`
        .packet-engine-panel {
          background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
          border-radius: 12px;
          border: 1px solid rgba(99, 102, 241, 0.3);
          margin-bottom: 20px;
          overflow: hidden;
        }

        .packet-engine-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 16px 20px;
        }

        .packet-engine-title {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .packet-engine-icon {
          font-size: 24px;
        }

        .packet-engine-title h3 {
          margin: 0;
          color: #f1f5f9;
          font-size: 16px;
          font-weight: 600;
        }

        .packet-engine-status {
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .status-dot {
          width: 10px;
          height: 10px;
          border-radius: 50%;
          animation: pulse 2s infinite;
        }

        .status-dot.active {
          background: #10b981;
          box-shadow: 0 0 10px #10b981;
        }

        .status-dot.inactive {
          background: #ef4444;
          box-shadow: 0 0 10px #ef4444;
          animation: none;
        }

        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }

        .status-text {
          color: #94a3b8;
          font-size: 14px;
        }
      `}</style>
    </div>
  );
}

export default PacketEnginePanel;
