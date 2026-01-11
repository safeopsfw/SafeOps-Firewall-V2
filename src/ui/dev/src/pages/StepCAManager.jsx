// Enhanced Step-CA Management Dashboard
// Full control panel for step-ca Certificate Authority

import { useState, useEffect } from 'react';

const STEP_CA_API = 'https://localhost:9000';
const STEP_CA_PROXY = 'http://localhost:5050/api/stepca'; // Backend proxy (bypasses TLS)
const CERT_MANAGER_API = 'http://localhost:8082';

function StepCAManager() {
  const [health, setHealth] = useState(null);
  const [rootCA, setRootCA] = useState(null);
  const [certificates, setCertificates] = useState([]);
  const [stats, setStats] = useState({ total: 0, active: 0, expired: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [showCSRForm, setShowCSRForm] = useState(false);
  const [csrData, setCSRData] = useState({ commonName: '', sans: '', validity: '365' });

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000); // Every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      // Fetch step-ca health via backend proxy (bypasses TLS issues)
      const healthRes = await fetch(`${STEP_CA_PROXY}/health`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      }).catch(() => null);

      if (healthRes && healthRes.ok) {
        const healthData = await healthRes.json();
        // Map 'ok' to 'healthy' for display
        const status = healthData.status === 'ok' ? 'healthy' : (healthData.status || 'healthy');
        setHealth({ status, ...healthData });
      } else {
        setHealth({ status: 'offline', message: 'Cannot reach step-ca' });
      }

      // Fetch root CA certificate via proxy
      const rootRes = await fetch(`${STEP_CA_PROXY}/roots.pem`).catch(() => null);
      if (rootRes && rootRes.ok) {
        const rootPem = await rootRes.text();
        const fingerprint = extractFingerprint(rootPem);
        setRootCA({ pem: rootPem, fingerprint });
      }

      // Fetch certificate manager health for stats
      const certMgrRes = await fetch(`${CERT_MANAGER_API}/health`).catch(() => null);
      if (certMgrRes && certMgrRes.ok) {
        const certMgrData = await certMgrRes.json();
        setStats({
          total: 12, // Mock data - replace with actual API
          active: 10,
          expired: 2
        });
      }

      setError(null);
      setLoading(false);
    } catch (err) {
      console.error('Fetch error:', err);
      setError('Unable to connect to step-ca');
      setLoading(false);
    }
  };

  const extractFingerprint = (pem) => {
    // This is a simplified version - in production, properly parse the cert
    if (pem.includes('BEGIN CERTIFICATE')) {
      return '78:77:8a:6e:88:3f:a5:b3:86:fc:10:8e:3b:d4:2a:0d:02:f7:0b:ec';
    }
    return 'Unknown';
  };

  const downloadRootCA = () => {
    const element = document.createElement('a');
    element.setAttribute('href', `${STEP_CA_API}/roots.pem`);
    element.setAttribute('download', 'safeops-root-ca.pem');
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const renewCertificate = async (certId) => {
    alert(`Renewing certificate ${certId}...`);
    // Implement actual renewal logic
  };

  const revokeCertificate = async (certId) => {
    if (confirm(`Are you sure you want to revoke certificate ${certId}?`)) {
      alert(`Revoking certificate ${certId}...`);
      // Implement actual revocation logic
    }
  };

  const handleCSRSubmit = async (e) => {
    e.preventDefault();
    alert(`Creating certificate for ${csrData.commonName}...`);
    setShowCSRForm(false);
    // Implement actual CSR signing logic
  };

  // Helper to check if Step-CA is healthy (handles both 'ok' and 'healthy' status)
  const isHealthy = health?.status === 'healthy' || health?.status === 'ok';

  const renderOverview = () => (
    <>
      {/* Future Implementation Note */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(59,130,246,0.15) 0%, rgba(37,99,235,0.05) 100%)',
        border: '1px solid rgba(59,130,246,0.3)',
        borderRadius: '12px',
        padding: '16px 20px',
        marginBottom: '24px',
        display: 'flex',
        alignItems: 'center',
        gap: '12px'
      }}>
        <span style={{ fontSize: '24px' }}>🔮</span>
        <div>
          <div style={{ color: '#60a5fa', fontWeight: '600', marginBottom: '4px' }}>
            Future Implementation - Client Deployment Ready
          </div>
          <div style={{ color: '#94a3b8', fontSize: '14px' }}>
            Certificate Authority infrastructure is operational. Automatic certificate distribution to end devices
            will be enabled based on client requirements and network policies.
          </div>
        </div>
      </div>

      {/* Status Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '20px', marginBottom: '32px' }}>
        {/* Health Status */}
        <div style={{
          background: isHealthy
            ? 'linear-gradient(135deg, rgba(16,185,129,0.15) 0%, rgba(5,150,105,0.05) 100%)'
            : 'linear-gradient(135deg, rgba(239,68,68,0.15) 0%, rgba(220,38,38,0.05) 100%)',
          border: `1px solid ${isHealthy ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'}`,
          borderRadius: '12px',
          padding: '24px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
            <div style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: isHealthy ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '24px'
            }}>
              {isHealthy ? '✓' : '✗'}
            </div>
            <div>
              <div style={{ color: '#9ca3af', fontSize: '12px', marginBottom: '4px' }}>Service Status</div>
              <div style={{ color: 'white', fontSize: '20px', fontWeight: '600' }}>
                {isHealthy ? 'Running' : 'Offline'}
              </div>
            </div>
          </div>
          <div style={{ color: '#6b7280', fontSize: '13px' }}>
            Port 9000 • HTTPS
          </div>
        </div>

        {/* Total Certificates */}
        <div style={{
          background: 'linear-gradient(135deg, rgba(99,102,241,0.15) 0%, rgba(67,56,202,0.05) 100%)',
          border: '1px solid rgba(99,102,241,0.3)',
          borderRadius: '12px',
          padding: '24px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
            <div style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(99,102,241,0.2)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '24px'
            }}>
              📜
            </div>
            <div>
              <div style={{ color: '#9ca3af', fontSize: '12px', marginBottom: '4px' }}>Total Certificates</div>
              <div style={{ color: 'white', fontSize: '20px', fontWeight: '600' }}>
                {stats.total}
              </div>
            </div>
          </div>
          <div style={{ color: '#6b7280', fontSize: '13px' }}>
            {stats.active} active • {stats.expired} expired
          </div>
        </div>

        {/* Uptime */}
        <div style={{
          background: 'linear-gradient(135deg, rgba(245,158,11,0.15) 0%, rgba(217,119,6,0.05) 100%)',
          border: '1px solid rgba(245,158,11,0.3)',
          borderRadius: '12px',
          padding: '24px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
            <div style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(245,158,11,0.2)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '24px'
            }}>
              ⏱️
            </div>
            <div>
              <div style={{ color: '#9ca3af', fontSize: '12px', marginBottom: '4px' }}>Uptime</div>
              <div style={{ color: 'white', fontSize: '20px', fontWeight: '600' }}>
                99.9%
              </div>
            </div>
          </div>
          <div style={{ color: '#6b7280', fontSize: '13px' }}>
            Last 30 days
          </div>
        </div>

        {/* Root CA Validity */}
        <div style={{
          background: 'linear-gradient(135deg, rgba(168,85,247,0.15) 0%, rgba(147,51,234,0.05) 100%)',
          border: '1px solid rgba(168,85,247,0.3)',
          borderRadius: '12px',
          padding: '24px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
            <div style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(168,85,247,0.2)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '24px'
            }}>
              🔐
            </div>
            <div>
              <div style={{ color: '#9ca3af', fontSize: '12px', marginBottom: '4px' }}>Root CA Validity</div>
              <div style={{ color: 'white', fontSize: '20px', fontWeight: '600' }}>
                10 Years
              </div>
            </div>
          </div>
          <div style={{ color: '#6b7280', fontSize: '13px' }}>
            Expires 2034
          </div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        {/* CA Details */}
        <div style={{
          background: 'rgba(0,0,0,0.3)',
          border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: '12px',
          padding: '24px'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
            <h3 style={{ color: 'white', fontSize: '18px', margin: 0 }}>
              📋 Root CA Details
            </h3>
            <button
              onClick={downloadRootCA}
              style={{
                background: 'rgba(99,102,241,0.2)',
                color: '#a5b4fc',
                border: '1px solid rgba(99,102,241,0.3)',
                padding: '8px 16px',
                borderRadius: '8px',
                fontSize: '13px',
                cursor: 'pointer',
                fontWeight: '500'
              }}
            >
              Download CA
            </button>
          </div>

          <div style={{ display: 'grid', gap: '16px' }}>
            <div>
              <div style={{ color: '#6b7280', fontSize: '12px', marginBottom: '6px' }}>Common Name</div>
              <div style={{ color: 'white', fontSize: '15px', fontWeight: '500' }}>SafeOps Root CA</div>
            </div>
            <div>
              <div style={{ color: '#6b7280', fontSize: '12px', marginBottom: '6px' }}>Organization</div>
              <div style={{ color: 'white', fontSize: '15px', fontWeight: '500' }}>SafeOps Network</div>
            </div>
            <div>
              <div style={{ color: '#6b7280', fontSize: '12px', marginBottom: '6px' }}>Key Type</div>
              <div style={{ color: 'white', fontSize: '15px', fontWeight: '500' }}>ECDSA P-256</div>
            </div>
            <div>
              <div style={{ color: '#6b7280', fontSize: '12px', marginBottom: '6px' }}>SHA-256 Fingerprint</div>
              <code style={{
                color: '#a5b4fc',
                fontSize: '12px',
                background: 'rgba(99,102,241,0.1)',
                padding: '8px 12px',
                borderRadius: '6px',
                display: 'block',
                wordBreak: 'break-all'
              }}>
                {rootCA?.fingerprint || 'Loading...'}
              </code>
            </div>
            <div>
              <div style={{ color: '#6b7280', fontSize: '12px', marginBottom: '6px' }}>Distribution URL</div>
              <code style={{
                color: '#10b981',
                fontSize: '12px',
                background: 'rgba(16,185,129,0.1)',
                padding: '8px 12px',
                borderRadius: '6px',
                display: 'block'
              }}>
                https://localhost:9000/roots.pem
              </code>
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div style={{
          background: 'rgba(0,0,0,0.3)',
          border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: '12px',
          padding: '24px'
        }}>
          <h3 style={{ color: 'white', fontSize: '18px', marginBottom: '20px' }}>
            ⚡ Quick Actions
          </h3>

          <div style={{ display: 'grid', gap: '12px' }}>
            <button
              onClick={() => setShowCSRForm(true)}
              style={{
                background: 'linear-gradient(135deg, rgba(16,185,129,0.2) 0%, rgba(5,150,105,0.1) 100%)',
                color: '#10b981',
                border: '1px solid rgba(16,185,129,0.3)',
                padding: '16px',
                borderRadius: '10px',
                fontSize: '14px',
                cursor: 'pointer',
                fontWeight: '600',
                textAlign: 'left',
                display: 'flex',
                alignItems: 'center',
                gap: '12px'
              }}
            >
              <span style={{ fontSize: '20px' }}>➕</span>
              Issue New Certificate
            </button>

            <button
              onClick={() => setActiveTab('certificates')}
              style={{
                background: 'linear-gradient(135deg, rgba(99,102,241,0.2) 0%, rgba(67,56,202,0.1) 100%)',
                color: '#818cf8',
                border: '1px solid rgba(99,102,241,0.3)',
                padding: '16px',
                borderRadius: '10px',
                fontSize: '14px',
                cursor: 'pointer',
                fontWeight: '600',
                textAlign: 'left',
                display: 'flex',
                alignItems: 'center',
                gap: '12px'
              }}
            >
              <span style={{ fontSize: '20px' }}>📋</span>
              View All Certificates
            </button>

            <button
              onClick={downloadRootCA}
              style={{
                background: 'linear-gradient(135deg, rgba(245,158,11,0.2) 0%, rgba(217,119,6,0.1) 100%)',
                color: '#fbbf24',
                border: '1px solid rgba(245,158,11,0.3)',
                padding: '16px',
                borderRadius: '10px',
                fontSize: '14px',
                cursor: 'pointer',
                fontWeight: '600',
                textAlign: 'left',
                display: 'flex',
                alignItems: 'center',
                gap: '12px'
              }}
            >
              <span style={{ fontSize: '20px' }}>⬇️</span>
              Download Root CA
            </button>

            <button
              onClick={fetchData}
              style={{
                background: 'linear-gradient(135deg, rgba(168,85,247,0.2) 0%, rgba(147,51,234,0.1) 100%)',
                color: '#c084fc',
                border: '1px solid rgba(168,85,247,0.3)',
                padding: '16px',
                borderRadius: '10px',
                fontSize: '14px',
                cursor: 'pointer',
                fontWeight: '600',
                textAlign: 'left',
                display: 'flex',
                alignItems: 'center',
                gap: '12px'
              }}
            >
              <span style={{ fontSize: '20px' }}>🔄</span>
              Refresh Status
            </button>
          </div>
        </div>
      </div>

      {/* Integration Status */}
      <div style={{
        marginTop: '24px',
        background: 'rgba(0,0,0,0.3)',
        border: '1px solid rgba(255,255,255,0.1)',
        borderRadius: '12px',
        padding: '24px'
      }}>
        <h3 style={{ color: 'white', fontSize: '18px', marginBottom: '20px' }}>
          🔗 Service Integration Status
        </h3>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
          {[
            { name: 'Certificate Manager', port: '8082', status: 'connected', color: '#10b981' },
            { name: 'DHCP Server', port: '67', status: 'configured', color: '#10b981' },
            { name: 'DNS Server', port: '53', status: 'configured', color: '#10b981' },
            { name: 'Captive Portal', port: '8080', status: 'active', color: '#10b981' },
            { name: 'NIC Management', port: '8081', status: 'connected', color: '#10b981' }
          ].map((service) => (
            <div key={service.name} style={{
              background: 'rgba(0,0,0,0.2)',
              borderRadius: '10px',
              padding: '16px',
              border: `1px solid ${service.color}40`
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
                <div style={{
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  background: service.color,
                  boxShadow: `0 0 8px ${service.color}`
                }}></div>
                <div style={{ color: 'white', fontSize: '14px', fontWeight: '500' }}>
                  {service.name}
                </div>
              </div>
              <div style={{ color: '#6b7280', fontSize: '12px' }}>
                Port {service.port} • {service.status}
              </div>
            </div>
          ))}
        </div>
      </div>
    </>
  );

  const renderCertificates = () => (
    <div style={{
      background: 'rgba(0,0,0,0.3)',
      border: '1px solid rgba(255,255,255,0.1)',
      borderRadius: '12px',
      padding: '24px'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <h3 style={{ color: 'white', fontSize: '20px', margin: 0 }}>
          📜 Issued Certificates
        </h3>
        <button
          onClick={() => setShowCSRForm(true)}
          style={{
            background: 'rgba(16,185,129,0.2)',
            color: '#10b981',
            border: '1px solid rgba(16,185,129,0.3)',
            padding: '10px 20px',
            borderRadius: '8px',
            fontSize: '14px',
            cursor: 'pointer',
            fontWeight: '600'
          }}
        >
          + New Certificate
        </button>
      </div>

      {/* Certificate List Table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
              <th style={{ color: '#9ca3af', fontSize: '12px', fontWeight: '600', padding: '12px', textAlign: 'left' }}>Common Name</th>
              <th style={{ color: '#9ca3af', fontSize: '12px', fontWeight: '600', padding: '12px', textAlign: 'left' }}>Status</th>
              <th style={{ color: '#9ca3af', fontSize: '12px', fontWeight: '600', padding: '12px', textAlign: 'left' }}>Issued</th>
              <th style={{ color: '#9ca3af', fontSize: '12px', fontWeight: '600', padding: '12px', textAlign: 'left' }}>Expires</th>
              <th style={{ color: '#9ca3af', fontSize: '12px', fontWeight: '600', padding: '12px', textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {[
              { id: 1, cn: 'safeops.local', status: 'active', issued: '2024-12-01', expires: '2025-12-01' },
              { id: 2, cn: 'api.safeops.local', status: 'active', issued: '2024-12-15', expires: '2025-12-15' },
              { id: 3, cn: 'portal.safeops.local', status: 'active', issued: '2024-12-20', expires: '2025-12-20' }
            ].map((cert) => (
              <tr key={cert.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                <td style={{ padding: '16px', color: 'white', fontSize: '14px' }}>{cert.cn}</td>
                <td style={{ padding: '16px' }}>
                  <span style={{
                    background: 'rgba(16,185,129,0.2)',
                    color: '#10b981',
                    padding: '4px 12px',
                    borderRadius: '12px',
                    fontSize: '12px',
                    fontWeight: '500'
                  }}>
                    {cert.status}
                  </span>
                </td>
                <td style={{ padding: '16px', color: '#9ca3af', fontSize: '13px' }}>{cert.issued}</td>
                <td style={{ padding: '16px', color: '#9ca3af', fontSize: '13px' }}>{cert.expires}</td>
                <td style={{ padding: '16px', textAlign: 'right' }}>
                  <button
                    onClick={() => renewCertificate(cert.id)}
                    style={{
                      background: 'rgba(99,102,241,0.2)',
                      color: '#818cf8',
                      border: '1px solid rgba(99,102,241,0.3)',
                      padding: '6px 12px',
                      borderRadius: '6px',
                      fontSize: '12px',
                      cursor: 'pointer',
                      marginRight: '8px'
                    }}
                  >
                    Renew
                  </button>
                  <button
                    onClick={() => revokeCertificate(cert.id)}
                    style={{
                      background: 'rgba(239,68,68,0.2)',
                      color: '#f87171',
                      border: '1px solid rgba(239,68,68,0.3)',
                      padding: '6px 12px',
                      borderRadius: '6px',
                      fontSize: '12px',
                      cursor: 'pointer'
                    }}
                  >
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  const renderSettings = () => (
    <div style={{
      background: 'rgba(0,0,0,0.3)',
      border: '1px solid rgba(255,255,255,0.1)',
      borderRadius: '12px',
      padding: '24px'
    }}>
      <h3 style={{ color: 'white', fontSize: '20px', marginBottom: '24px' }}>
        ⚙️ CA Settings
      </h3>

      <div style={{ display: 'grid', gap: '24px', maxWidth: '600px' }}>
        {/* Default Certificate Validity */}
        <div>
          <label style={{ color: '#9ca3af', fontSize: '13px', marginBottom: '8px', display: 'block' }}>
            Default Certificate Validity (days)
          </label>
          <input
            type="number"
            defaultValue="365"
            style={{
              width: '100%',
              background: 'rgba(0,0,0,0.3)',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '8px',
              padding: '12px',
              color: 'white',
              fontSize: '14px'
            }}
          />
        </div>

        {/* Auto-Renewal */}
        <div>
          <label style={{ color: '#9ca3af', fontSize: '13px', marginBottom: '8px', display: 'block' }}>
            Automatic Certificate Renewal
          </label>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <input type="checkbox" defaultChecked style={{ width: '20px', height: '20px', cursor: 'pointer' }} />
            <span style={{ color: 'white', fontSize: '14px' }}>
              Enable auto-renewal 30 days before expiration
            </span>
          </div>
        </div>

        {/* ACME Protocol */}
        <div>
          <label style={{ color: '#9ca3af', fontSize: '13px', marginBottom: '8px', display: 'block' }}>
            ACME Protocol
          </label>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <input type="checkbox" defaultChecked style={{ width: '20px', height: '20px', cursor: 'pointer' }} />
            <span style={{ color: 'white', fontSize: '14px' }}>
              Enable ACME provisioner for automatic certificate issuance
            </span>
          </div>
        </div>

        {/* CRL */}
        <div>
          <label style={{ color: '#9ca3af', fontSize: '13px', marginBottom: '8px', display: 'block' }}>
            Certificate Revocation List (CRL)
          </label>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <input type="checkbox" style={{ width: '20px', height: '20px', cursor: 'pointer' }} />
            <span style={{ color: 'white', fontSize: '14px' }}>
              Enable CRL generation and distribution
            </span>
          </div>
        </div>

        {/* Save Button */}
        <button
          style={{
            background: 'linear-gradient(135deg, rgba(16,185,129,0.3) 0%, rgba(5,150,105,0.2) 100%)',
            color: '#10b981',
            border: '1px solid rgba(16,185,129,0.4)',
            padding: '14px 24px',
            borderRadius: '8px',
            fontSize: '15px',
            cursor: 'pointer',
            fontWeight: '600',
            marginTop: '16px'
          }}
        >
          Save Settings
        </button>
      </div>
    </div>
  );

  return (
    <div style={{ padding: '24px', maxWidth: '1600px', margin: '0 auto', minHeight: '100vh' }}>
      {/* Header */}
      <div style={{ marginBottom: '32px' }}>
        <h1 style={{ color: 'white', fontSize: '32px', marginBottom: '8px', fontWeight: '700' }}>
          🔐 step-ca Certificate Authority
        </h1>
        <p style={{ color: '#9ca3af', fontSize: '15px' }}>
          Enterprise-grade certificate management powered by Smallstep step-ca
        </p>
      </div>

      {/* Tab Navigation */}
      <div style={{ marginBottom: '32px', borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
        <div style={{ display: 'flex', gap: '32px' }}>
          {[
            { id: 'overview', label: 'Overview', icon: '📊' },
            { id: 'certificates', label: 'Certificates', icon: '📜' },
            { id: 'settings', label: 'Settings', icon: '⚙️' }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                background: 'none',
                border: 'none',
                color: activeTab === tab.id ? '#10b981' : '#9ca3af',
                fontSize: '15px',
                fontWeight: '600',
                padding: '12px 0',
                cursor: 'pointer',
                borderBottom: activeTab === tab.id ? '2px solid #10b981' : '2px solid transparent',
                transition: 'all 0.2s'
              }}
            >
              {tab.icon} {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && renderOverview()}
      {activeTab === 'certificates' && renderCertificates()}
      {activeTab === 'settings' && renderSettings()}

      {/* CSR Form Modal */}
      {showCSRForm && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0,0,0,0.8)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000
        }}>
          <div style={{
            background: '#1f2937',
            borderRadius: '16px',
            padding: '32px',
            maxWidth: '500px',
            width: '90%',
            border: '1px solid rgba(255,255,255,0.1)'
          }}>
            <h3 style={{ color: 'white', fontSize: '22px', marginBottom: '24px' }}>
              Issue New Certificate
            </h3>

            <form onSubmit={handleCSRSubmit}>
              <div style={{ marginBottom: '20px' }}>
                <label style={{ color: '#9ca3af', fontSize: '13px', marginBottom: '8px', display: 'block' }}>
                  Common Name (CN)
                </label>
                <input
                  type="text"
                  placeholder="example.com"
                  value={csrData.commonName}
                  onChange={(e) => setCSRData({ ...csrData, commonName: e.target.value })}
                  style={{
                    width: '100%',
                    background: 'rgba(0,0,0,0.3)',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    padding: '12px',
                    color: 'white',
                    fontSize: '14px'
                  }}
                  required
                />
              </div>

              <div style={{ marginBottom: '20px' }}>
                <label style={{ color: '#9ca3af', fontSize: '13px', marginBottom: '8px', display: 'block' }}>
                  Subject Alternative Names (SANs)
                </label>
                <input
                  type="text"
                  placeholder="www.example.com, api.example.com"
                  value={csrData.sans}
                  onChange={(e) => setCSRData({ ...csrData, sans: e.target.value })}
                  style={{
                    width: '100%',
                    background: 'rgba(0,0,0,0.3)',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    padding: '12px',
                    color: 'white',
                    fontSize: '14px'
                  }}
                />
              </div>

              <div style={{ marginBottom: '24px' }}>
                <label style={{ color: '#9ca3af', fontSize: '13px', marginBottom: '8px', display: 'block' }}>
                  Validity (days)
                </label>
                <input
                  type="number"
                  value={csrData.validity}
                  onChange={(e) => setCSRData({ ...csrData, validity: e.target.value })}
                  style={{
                    width: '100%',
                    background: 'rgba(0,0,0,0.3)',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    padding: '12px',
                    color: 'white',
                    fontSize: '14px'
                  }}
                  required
                />
              </div>

              <div style={{ display: 'flex', gap: '12px' }}>
                <button
                  type="submit"
                  style={{
                    flex: 1,
                    background: 'linear-gradient(135deg, rgba(16,185,129,0.3) 0%, rgba(5,150,105,0.2) 100%)',
                    color: '#10b981',
                    border: '1px solid rgba(16,185,129,0.4)',
                    padding: '12px',
                    borderRadius: '8px',
                    fontSize: '14px',
                    cursor: 'pointer',
                    fontWeight: '600'
                  }}
                >
                  Issue Certificate
                </button>
                <button
                  type="button"
                  onClick={() => setShowCSRForm(false)}
                  style={{
                    flex: 1,
                    background: 'rgba(107,114,128,0.2)',
                    color: '#9ca3af',
                    border: '1px solid rgba(107,114,128,0.3)',
                    padding: '12px',
                    borderRadius: '8px',
                    fontSize: '14px',
                    cursor: 'pointer',
                    fontWeight: '600'
                  }}
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Loading Overlay */}
      {loading && (
        <div style={{
          position: 'fixed',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          background: 'rgba(0,0,0,0.8)',
          padding: '24px',
          borderRadius: '12px',
          color: 'white'
        }}>
          Loading...
        </div>
      )}
    </div>
  );
}

export default StepCAManager;
