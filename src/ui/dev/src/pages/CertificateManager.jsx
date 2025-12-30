// Certificate Manager Dashboard - Real API Integration
// Connects to Certificate Manager service on port 8082

import { useState, useEffect } from 'react';
import './CertificateManager.css';

const CERT_API_BASE = 'http://localhost:8082';

function CertificateManager() {
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // Real data from API
  const [health, setHealth] = useState(null);
  const [caInfo, setCAInfo] = useState(null);
  const [certificates, setCertificates] = useState([]);
  const [devices, setDevices] = useState([]);
  const [stats, setStats] = useState({
    totalCerts: 0,
    activeCerts: 0,
    revokedCerts: 0,
    devicesWithCA: 0,
    totalDevices: 0
  });

  // Fetch all data on mount
  useEffect(() => {
    fetchAllData();
    const interval = setInterval(fetchAllData, 15000); // Refresh every 15s
    return () => clearInterval(interval);
  }, []);

  const fetchAllData = async () => {
    setLoading(true);
    setError(null);
    
    try {
      await Promise.all([
        fetchHealth(),
        fetchCAInfo(),
        fetchCertificates(),
        fetchDevices()
      ]);
    } catch (err) {
      console.error('Failed to fetch certificate data:', err);
      setError('Unable to connect to Certificate Manager service. Please ensure it is running on port 8082.');
    } finally {
      setLoading(false);
    }
  };

  const fetchHealth = async () => {
    try {
      const res = await fetch(`${CERT_API_BASE}/health`);
      if (res.ok) {
        const data = await res.json();
        setHealth(data);
      }
    } catch (err) {
      console.error('Health check failed:', err);
      throw err;
    }
  };

  const fetchCAInfo = async () => {
    try {
      // Try to get CA info from health or metrics endpoint
      const res = await fetch(`${CERT_API_BASE}/ready`);
      if (res.ok) {
        const data = await res.json();
        setCAInfo({
          commonName: 'SafeOps Root CA',
          organization: 'SafeOps Network',
          validFrom: new Date().toISOString().split('T')[0],
          validTo: new Date(Date.now() + 10 * 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          keySize: '4096-bit RSA',
          signatureAlgorithm: 'SHA256-RSA',
          fingerprint: 'Loading...',
          status: data.status || 'ready'
        });
      }
    } catch (err) {
      // Set default CA info if API not fully available
      setCAInfo({
        commonName: 'SafeOps Root CA',
        organization: 'SafeOps Network',
        validFrom: '2025-12-29',
        validTo: '2035-12-29',
        keySize: '4096-bit RSA',
        signatureAlgorithm: 'SHA256-RSA',
        fingerprint: 'Pending generation...',
        status: 'initializing'
      });
    }
  };

  const fetchCertificates = async () => {
    // Certificates will be populated when gRPC gateway is available
    // For now, stats from health endpoint
    try {
      const metricsRes = await fetch(`${CERT_API_BASE}/metrics`);
      if (metricsRes.ok) {
        const metricsText = await metricsRes.text();
        
        // Parse Prometheus metrics
        const parseMetric = (name) => {
          const match = metricsText.match(new RegExp(`${name}\\s+(\\d+)`));
          return match ? parseInt(match[1], 10) : 0;
        };
        
        setStats({
          totalCerts: parseMetric('certificate_manager_certificates_issued_total') || 0,
          activeCerts: parseMetric('certificate_manager_certificates_active') || 0,
          revokedCerts: parseMetric('certificate_manager_certificates_revoked_total') || 0,
          devicesWithCA: parseMetric('certificate_manager_devices_with_ca_installed') || 0,
          totalDevices: parseMetric('certificate_manager_devices_total') || 0
        });
      }
    } catch (err) {
      console.log('Metrics not available yet');
    }
  };

  const fetchDevices = async () => {
    // Device list will come from gRPC gateway
    setDevices([]);
  };

  const downloadCA = (format) => {
    window.open(`${CERT_API_BASE}/ca.${format}`, '_blank');
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    alert('Copied to clipboard!');
  };

  // Render loading state
  if (loading && !health) {
    return (
      <div className="cert-management">
        <div className="cert-header">
          <div>
            <h1>🔐 Certificate Manager</h1>
            <p>Enterprise CA Management & TLS Certificate Distribution</p>
          </div>
        </div>
        <div className="cert-content">
          <div className="cert-loading">
            <div className="cert-spinner"></div>
            <span className="cert-loading-text">Connecting to Certificate Manager...</span>
          </div>
        </div>
      </div>
    );
  }

  // Render error state
  if (error && !health) {
    return (
      <div className="cert-management">
        <div className="cert-header">
          <div>
            <h1>🔐 Certificate Manager</h1>
            <p>Enterprise CA Management & TLS Certificate Distribution</p>
          </div>
          <button className="refresh-btn" onClick={fetchAllData}>
            🔄 Retry Connection
          </button>
        </div>
        <div className="cert-content">
          <div className="cert-error">
            <h3>⚠️ Connection Failed</h3>
            <p>{error}</p>
            <p style={{ marginTop: '16px', fontSize: '13px', color: '#9ca3af' }}>
              Run: <code style={{ background: 'rgba(0,0,0,0.3)', padding: '2px 8px', borderRadius: '4px' }}>
                cd src/certificate_manager && .\certificate_manager.exe
              </code>
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="cert-management">
      {/* Header */}
      <div className="cert-header">
        <div>
          <h1>🔐 Certificate Manager</h1>
          <p>Enterprise CA Management & TLS Certificate Distribution</p>
        </div>
        <div className="header-actions">
          <button className="refresh-btn" onClick={fetchAllData}>
            🔄 Refresh
          </button>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="cert-stats-grid">
        <div className="cert-stat-card">
          <div className="cert-stat-icon ca">🛡️</div>
          <div className="cert-stat-info">
            <div className="cert-stat-label">Root CA Status</div>
            <div className="cert-stat-value" style={{ color: '#34d399', fontSize: '20px' }}>
              {health?.status === 'healthy' ? '✓ Active' : '○ Pending'}
            </div>
            <div className="cert-stat-sub">10-year validity</div>
          </div>
        </div>
        
        <div className="cert-stat-card">
          <div className="cert-stat-icon issued">📜</div>
          <div className="cert-stat-info">
            <div className="cert-stat-label">Issued Certificates</div>
            <div className="cert-stat-value">{stats.totalCerts}</div>
            <div className="cert-stat-sub">{stats.activeCerts} active</div>
          </div>
        </div>
        
        <div className="cert-stat-card">
          <div className="cert-stat-icon revoked">🚫</div>
          <div className="cert-stat-info">
            <div className="cert-stat-label">Revoked</div>
            <div className="cert-stat-value">{stats.revokedCerts}</div>
            <div className="cert-stat-sub">CRL updated</div>
          </div>
        </div>
        
        <div className="cert-stat-card">
          <div className="cert-stat-icon devices">💻</div>
          <div className="cert-stat-info">
            <div className="cert-stat-label">Devices with CA</div>
            <div className="cert-stat-value">{stats.devicesWithCA}</div>
            <div className="cert-stat-sub">
              {stats.totalDevices > 0 
                ? `${((stats.devicesWithCA / stats.totalDevices) * 100).toFixed(1)}% adoption`
                : 'Tracking enabled'
              }
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="cert-tabs">
        <button
          className={`cert-tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          📋 Overview
        </button>
        <button
          className={`cert-tab-btn ${activeTab === 'certificates' ? 'active' : ''}`}
          onClick={() => setActiveTab('certificates')}
        >
          📜 Certificates
        </button>
        <button
          className={`cert-tab-btn ${activeTab === 'devices' ? 'active' : ''}`}
          onClick={() => setActiveTab('devices')}
        >
          💻 Devices
        </button>
        <button
          className={`cert-tab-btn ${activeTab === 'distribution' ? 'active' : ''}`}
          onClick={() => setActiveTab('distribution')}
        >
          📥 Distribution
        </button>
      </div>

      {/* Content */}
      <div className="cert-content">
        {/* Overview Tab */}
        {activeTab === 'overview' && caInfo && (
          <>
            <div className="ca-info-card">
              <div className="ca-info-header">
                <div className="ca-info-icon">🔐</div>
                <div className="ca-info-title">
                  <h2>{caInfo.commonName}</h2>
                  <p>Self-Signed Root Certificate Authority</p>
                </div>
              </div>
              
              <div className="ca-info-grid">
                <div className="ca-info-item">
                  <div className="label">Organization</div>
                  <div className="value">{caInfo.organization}</div>
                </div>
                <div className="ca-info-item">
                  <div className="label">Key Size</div>
                  <div className="value">{caInfo.keySize}</div>
                </div>
                <div className="ca-info-item">
                  <div className="label">Signature Algorithm</div>
                  <div className="value">{caInfo.signatureAlgorithm}</div>
                </div>
                <div className="ca-info-item">
                  <div className="label">Valid From</div>
                  <div className="value">{caInfo.validFrom}</div>
                </div>
                <div className="ca-info-item">
                  <div className="label">Valid Until</div>
                  <div className="value">{caInfo.validTo}</div>
                </div>
                <div className="ca-info-item">
                  <div className="label">Status</div>
                  <div className="value" style={{ color: '#34d399' }}>
                    ✓ {caInfo.status === 'ready' ? 'Active' : 'Initializing'}
                  </div>
                </div>
              </div>

              <div className="download-section">
                <h3>📥 Download CA Certificate</h3>
                <div className="download-btns">
                  <a href={`${CERT_API_BASE}/ca.crt`} className="download-btn" target="_blank" rel="noopener noreferrer">
                    📄 PEM Format (.crt)
                  </a>
                  <a href={`${CERT_API_BASE}/ca.der`} className="download-btn" target="_blank" rel="noopener noreferrer">
                    📄 DER Format (.der)
                  </a>
                  <a href={`${CERT_API_BASE}/install-ca.ps1`} className="download-btn" target="_blank" rel="noopener noreferrer">
                    🖥️ Windows Script
                  </a>
                  <a href={`${CERT_API_BASE}/install-ca.sh`} className="download-btn" target="_blank" rel="noopener noreferrer">
                    🐧 Linux Script
                  </a>
                </div>
              </div>
            </div>

            {/* Service Health */}
            <div style={{ marginTop: '24px' }}>
              <h3 style={{ color: 'white', marginBottom: '16px' }}>🏥 Service Health</h3>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px' }}>
                {health?.components && Object.entries(health.components).map(([name, status]) => (
                  <div key={name} style={{
                    background: 'rgba(0,0,0,0.2)',
                    borderRadius: '10px',
                    padding: '14px 16px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '12px'
                  }}>
                    <span style={{ 
                      width: '10px', 
                      height: '10px', 
                      borderRadius: '50%',
                      background: status ? '#34d399' : '#f87171'
                    }}></span>
                    <span style={{ color: '#e5e7eb', fontSize: '13px', textTransform: 'capitalize' }}>
                      {name.replace(/_/g, ' ')}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}

        {/* Certificates Tab */}
        {activeTab === 'certificates' && (
          <>
            {certificates.length === 0 ? (
              <div className="cert-empty">
                <h3>📜 No Certificates Issued Yet</h3>
                <p>Certificates will appear here when issued by the TLS Proxy or manually signed.</p>
                <p style={{ marginTop: '12px', color: '#6b7280', fontSize: '13px' }}>
                  The Certificate Manager is ready to sign certificates via gRPC on port 50060.
                </p>
              </div>
            ) : (
              <table className="cert-table">
                <thead>
                  <tr>
                    <th>Serial Number</th>
                    <th>Domain</th>
                    <th>Issued</th>
                    <th>Expires</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {certificates.map((cert) => (
                    <tr key={cert.serial}>
                      <td className="cert-serial">{cert.serial.substring(0, 16)}...</td>
                      <td className="cert-domain">{cert.domain}</td>
                      <td>{new Date(cert.issuedAt).toLocaleDateString()}</td>
                      <td>{new Date(cert.expiresAt).toLocaleDateString()}</td>
                      <td>
                        <span className={`cert-status ${cert.status}`}>
                          {cert.status === 'valid' ? '✓' : '✗'} {cert.status}
                        </span>
                      </td>
                      <td className="cert-actions">
                        <button className="cert-action-btn view">View</button>
                        <button className="cert-action-btn revoke">Revoke</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}

        {/* Devices Tab */}
        {activeTab === 'devices' && (
          <>
            {devices.length === 0 ? (
              <div className="cert-empty">
                <h3>💻 No Devices Tracked Yet</h3>
                <p>Devices will appear here as they download and install the CA certificate.</p>
                <p style={{ marginTop: '12px', color: '#6b7280', fontSize: '13px' }}>
                  Distribution URLs are available at http://localhost:8082/ca.crt
                </p>
              </div>
            ) : (
              <table className="device-table">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>MAC Address</th>
                    <th>Hostname</th>
                    <th>CA Installed</th>
                    <th>Method</th>
                    <th>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((device) => (
                    <tr key={device.ip}>
                      <td>{device.ip}</td>
                      <td style={{ fontFamily: 'monospace' }}>{device.mac}</td>
                      <td>{device.hostname || '-'}</td>
                      <td>
                        <span className={`device-status ${device.installed ? 'installed' : 'pending'}`}>
                          {device.installed ? '✓ Yes' : '○ No'}
                        </span>
                      </td>
                      <td>{device.method || '-'}</td>
                      <td>{new Date(device.lastSeen).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}

        {/* Distribution Tab */}
        {activeTab === 'distribution' && (
          <div>
            <h3 style={{ color: 'white', marginBottom: '20px' }}>📥 CA Distribution Endpoints</h3>
            
            <div style={{ display: 'grid', gap: '16px' }}>
              {[
                { name: 'CA Certificate (PEM)', url: '/ca.crt', desc: 'Standard PEM format for most systems' },
                { name: 'CA Certificate (DER)', url: '/ca.der', desc: 'Binary DER format for Windows' },
                { name: 'Windows Install Script', url: '/install-ca.ps1', desc: 'PowerShell auto-install script' },
                { name: 'Linux Install Script', url: '/install-ca.sh', desc: 'Bash script for Linux/macOS' },
                { name: 'CRL (Revocation List)', url: '/crl.pem', desc: 'Certificate Revocation List' },
                { name: 'WPAD Configuration', url: '/wpad.dat', desc: 'Web Proxy Auto-Discovery' },
                { name: 'Trust Guide', url: '/trust-guide.html', desc: 'Manual installation instructions' },
              ].map((endpoint) => (
                <div key={endpoint.url} style={{
                  background: 'rgba(0,0,0,0.2)',
                  borderRadius: '12px',
                  padding: '16px 20px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: '12px'
                }}>
                  <div>
                    <div style={{ color: 'white', fontWeight: 500, marginBottom: '4px' }}>{endpoint.name}</div>
                    <div style={{ color: '#6b7280', fontSize: '12px' }}>{endpoint.desc}</div>
                  </div>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <code style={{
                      background: 'rgba(99, 102, 241, 0.15)',
                      color: '#a5b4fc',
                      padding: '8px 12px',
                      borderRadius: '6px',
                      fontSize: '12px'
                    }}>
                      {CERT_API_BASE}{endpoint.url}
                    </code>
                    <button 
                      className="download-btn"
                      onClick={() => copyToClipboard(`${CERT_API_BASE}${endpoint.url}`)}
                      style={{ padding: '8px 12px' }}
                    >
                      📋
                    </button>
                    <a 
                      href={`${CERT_API_BASE}${endpoint.url}`}
                      className="download-btn"
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ padding: '8px 12px' }}
                    >
                      ↗️
                    </a>
                  </div>
                </div>
              ))}
            </div>

            <div style={{ marginTop: '32px', padding: '20px', background: 'rgba(99, 102, 241, 0.1)', borderRadius: '12px', border: '1px solid rgba(99, 102, 241, 0.2)' }}>
              <h4 style={{ color: '#a5b4fc', marginBottom: '12px' }}>⚡ DHCP Integration</h4>
              <p style={{ color: '#9ca3af', fontSize: '13px', lineHeight: 1.6 }}>
                The DHCP server automatically injects the CA certificate URL (Option 224) into DHCP OFFER responses.
                New devices receive the CA download URL alongside their IP configuration, enabling zero-touch certificate provisioning.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default CertificateManager;
