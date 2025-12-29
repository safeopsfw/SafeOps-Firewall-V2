// DHCP Management Page - Complete DHCP Server Control
// View leases, pools, stats, and manage DHCP configurations

import { useState, useEffect } from 'react';
import './DHCPManagement.css';

const NIC_API_BASE = 'http://localhost:8081/api';

function DHCPManagement() {
  const [activeTab, setActiveTab] = useState('leases');
  const [leases, setLeases] = useState([]);
  const [pools, setPools] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [filteredLeases, setFilteredLeases] = useState([]);

  // Fetch all data
  useEffect(() => {
    fetchAllData();
    const interval = setInterval(fetchAllData, 10000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchAllData = async () => {
    setLoading(true);
    try {
      await Promise.all([
        fetchLeases(),
        fetchPools(),
        fetchStats(),
      ]);
    } catch (err) {
      console.error('Failed to fetch DHCP data:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchLeases = async () => {
    try {
      const res = await fetch(`${NIC_API_BASE}/dhcp/leases?limit=100`);
      if (res.ok) {
        const data = await res.json();
        setLeases(data.leases || []);
        setFilteredLeases(data.leases || []);
      }
    } catch (err) {
      console.error('Failed to fetch leases:', err);
    }
  };

  const fetchPools = async () => {
    try {
      const res = await fetch(`${NIC_API_BASE}/dhcp/pools`);
      if (res.ok) {
        const data = await res.json();
        setPools(data.pools || []);
      }
    } catch (err) {
      console.error('Failed to fetch pools:', err);
    }
  };

  const fetchStats = async () => {
    try {
      const res = await fetch(`${NIC_API_BASE}/dhcp/stats`);
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (err) {
      console.error('Failed to fetch stats:', err);
    }
  };

  // Search leases
  const handleSearch = (query) => {
    setSearchQuery(query);
    if (!query.trim()) {
      setFilteredLeases(leases);
      return;
    }

    const lowerQuery = query.toLowerCase();
    const filtered = leases.filter(
      (lease) =>
        lease.mac.toLowerCase().includes(lowerQuery) ||
        lease.ip.toLowerCase().includes(lowerQuery) ||
        lease.hostname.toLowerCase().includes(lowerQuery)
    );
    setFilteredLeases(filtered);
  };

  // Release a lease
  const releaseLease = async (mac) => {
    if (!confirm(`Release lease for ${mac}?`)) return;

    try {
      const res = await fetch(`${NIC_API_BASE}/dhcp/leases/${mac}`, {
        method: 'DELETE',
      });

      if (res.ok) {
        await fetchLeases();
        alert('Lease released successfully');
      } else {
        alert('Failed to release lease');
      }
    } catch (err) {
      alert('Error: ' + err.message);
    }
  };

  // Format duration
  const formatDuration = (start, end) => {
    const now = new Date();
    const endDate = new Date(end);
    const diff = endDate - now;

    if (diff < 0) return 'Expired';

    const hours = Math.floor(diff / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));

    if (hours > 24) {
      const days = Math.floor(hours / 24);
      return `${days}d ${hours % 24}h`;
    }
    return `${hours}h ${minutes}m`;
  };

  return (
    <div className="dhcp-management">
      {/* Header */}
      <div className="dhcp-header">
        <div>
          <h1>DHCP Server Management</h1>
          <p>Manage DHCP leases, pools, and server configuration</p>
        </div>
        <button className="refresh-btn" onClick={fetchAllData}>
          🔄 Refresh
        </button>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-icon">📊</div>
            <div className="stat-info">
              <div className="stat-label">Total Leases</div>
              <div className="stat-value">{stats.totalLeases}</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon">✅</div>
            <div className="stat-info">
              <div className="stat-label">Active Leases</div>
              <div className="stat-value">{stats.activeLeases}</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon">⏰</div>
            <div className="stat-info">
              <div className="stat-label">Expired Leases</div>
              <div className="stat-value">{stats.expiredLeases}</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon">⏱️</div>
            <div className="stat-info">
              <div className="stat-label">Server Uptime</div>
              <div className="stat-value">{stats.uptime}</div>
            </div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="dhcp-tabs">
        <button
          className={`tab-btn ${activeTab === 'leases' ? 'active' : ''}`}
          onClick={() => setActiveTab('leases')}
        >
          📋 Leases ({leases.length})
        </button>
        <button
          className={`tab-btn ${activeTab === 'pools' ? 'active' : ''}`}
          onClick={() => setActiveTab('pools')}
        >
          🏊 Pools ({pools.length})
        </button>
      </div>

      {/* Search Bar (only for leases tab) */}
      {activeTab === 'leases' && (
        <div className="search-bar">
          <input
            type="text"
            placeholder="Search by IP, MAC, or hostname..."
            value={searchQuery}
            onChange={(e) => handleSearch(e.target.value)}
          />
        </div>
      )}

      {/* Content */}
      <div className="dhcp-content">
        {loading && (
          <div className="dhcp-loading-container">
            <div className="dhcp-loading-spinner"></div>
            <span className="dhcp-loading-text">Loading DHCP data...</span>
          </div>
        )}

        {!loading && activeTab === 'leases' && (
          <div className="leases-table">
            <table>
              <thead>
                <tr>
                  <th>MAC Address</th>
                  <th>IP Address</th>
                  <th>Hostname</th>
                  <th>State</th>
                  <th>Pool</th>
                  <th>Time Remaining</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredLeases.map((lease) => (
                  <tr key={lease.mac} className={lease.state.toLowerCase()}>
                    <td className="mac">{lease.mac}</td>
                    <td className="ip">{lease.ip}</td>
                    <td className="hostname">{lease.hostname || '-'}</td>
                    <td>
                      <span className={`state-badge ${lease.state.toLowerCase()}`}>
                        {lease.state}
                      </span>
                    </td>
                    <td>{lease.poolName}</td>
                    <td>{formatDuration(lease.leaseStart, lease.leaseEnd)}</td>
                    <td>
                      <button
                        className="release-btn"
                        onClick={() => releaseLease(lease.mac)}
                        disabled={lease.state !== 'ACTIVE'}
                      >
                        Release
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {filteredLeases.length === 0 && (
              <div className="no-data">
                <p>No leases found</p>
              </div>
            )}
          </div>
        )}

        {!loading && activeTab === 'pools' && (
          <div className="pools-grid">
            {pools.map((pool, idx) => (
              <div key={idx} className="pool-card">
                <div className="pool-header">
                  <h3>{pool.name}</h3>
                  <span className="pool-utilization">
                    {pool.utilization.toFixed(1)}% Used
                  </span>
                </div>
                <div className="pool-details">
                  <div className="pool-row">
                    <span className="label">IP Range:</span>
                    <span className="value">
                      {pool.startIP} - {pool.endIP}
                    </span>
                  </div>
                  <div className="pool-row">
                    <span className="label">Subnet:</span>
                    <span className="value">{pool.subnet}</span>
                  </div>
                  <div className="pool-row">
                    <span className="label">Gateway:</span>
                    <span className="value">{pool.gateway}</span>
                  </div>
                  <div className="pool-row">
                    <span className="label">DNS:</span>
                    <span className="value">{pool.dns}</span>
                  </div>
                  <div className="pool-row">
                    <span className="label">Lease Time:</span>
                    <span className="value">{pool.leaseTime / 3600}h</span>
                  </div>
                  <div className="pool-row">
                    <span className="label">Total IPs:</span>
                    <span className="value">{pool.totalIPs}</span>
                  </div>
                  <div className="pool-row">
                    <span className="label">Used IPs:</span>
                    <span className="value">{pool.usedIPs}</span>
                  </div>
                </div>
                <div className="pool-progress">
                  <div
                    className="pool-progress-bar"
                    style={{ width: `${pool.utilization}%` }}
                  ></div>
                </div>
              </div>
            ))}

            {pools.length === 0 && (
              <div className="no-data">
                <p>No pools configured</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default DHCPManagement;
