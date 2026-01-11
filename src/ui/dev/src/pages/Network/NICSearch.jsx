// NIC Search Page - IP/Device Lookup
// Find which NIC owns an IP, discover connected devices

import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import './Network.css'

const NIC_API = 'http://localhost:8081/api'

function NICSearch() {
  const [query, setQuery] = useState('')
  const [searching, setSearching] = useState(false)
  const [result, setResult] = useState(null)
  const [nics, setNics] = useState([])
  const [recentSearches, setRecentSearches] = useState([])
  const [filter, setFilter] = useState('all')

  // Load NICs on mount
  useEffect(() => {
    fetchNICs()
    // Load recent searches from localStorage
    const recent = JSON.parse(localStorage.getItem('nicSearchHistory') || '[]')
    setRecentSearches(recent)
  }, [])

  const fetchNICs = async () => {
    try {
      const res = await fetch(`${NIC_API}/nics`)
      const data = await res.json()
      setNics(data.interfaces || [])
    } catch (err) {
      // Use mock data
      setNics(getMockNICs())
    }
  }

  const getMockNICs = () => {
    // No mock data - return empty if API fails
    return []
  }

  const searchIP = () => {
    if (!query.trim()) return
    
    setSearching(true)
    setResult(null)

    // Simulate search delay
    setTimeout(() => {
      const searchQuery = query.trim().toLowerCase()
      
      // Search through NICs
      let foundNic = null
      let matchType = null
      
      for (const nic of nics) {
        // Check IPv4 addresses
        for (const ip of (nic.ipv4 || [])) {
          const ipOnly = ip.split('/')[0]
          if (ipOnly === searchQuery || ip === searchQuery) {
            foundNic = nic
            matchType = 'ipv4'
            break
          }
          // Check if in same subnet
          if (isInSubnet(searchQuery, ip)) {
            foundNic = nic
            matchType = 'subnet'
          }
        }
        
        // Check MAC address
        if (nic.mac?.toLowerCase().includes(searchQuery.replace(/[:-]/g, ''))) {
          foundNic = nic
          matchType = 'mac'
        }
        
        if (foundNic) break
      }

      if (foundNic) {
        setResult({
          found: true,
          nic: foundNic,
          matchType,
          searchValue: query.trim(),
          devices: getConnectedDevices(foundNic)
        })
      } else {
        setResult({
          found: false,
          searchValue: query.trim()
        })
      }

      // Add to recent searches
      addToRecentSearches(query.trim())
      setSearching(false)
    }, 300)
  }

  const isInSubnet = (ip, cidr) => {
    try {
      const [subnetIp, prefix] = cidr.split('/')
      const ipParts = ip.split('.').map(Number)
      const subnetParts = subnetIp.split('.').map(Number)
      const mask = (~0 << (32 - Number(prefix))) >>> 0
      
      const ipNum = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3]
      const subnetNum = (subnetParts[0] << 24) | (subnetParts[1] << 16) | (subnetParts[2] << 8) | subnetParts[3]
      
      return ((ipNum >>> 0) & mask) === ((subnetNum >>> 0) & mask)
    } catch {
      return false
    }
  }

  const getConnectedDevices = (nic) => {
    // TODO: Fetch real connected devices from ARP table or DHCP leases
    // No fake demo data
    return []
  }

  const addToRecentSearches = (search) => {
    const recent = [search, ...recentSearches.filter(s => s !== search)].slice(0, 5)
    setRecentSearches(recent)
    localStorage.setItem('nicSearchHistory', JSON.stringify(recent))
  }

  const filteredNics = nics.filter(nic => {
    if (filter === 'all') return true
    if (filter === 'online') return nic.status === 'UP'
    if (filter === 'offline') return nic.status === 'DOWN'
    return nic.type === filter
  })

  return (
    <div className="nic-search-page">
      <div className="search-header">
        <h1>🔍 Network Search</h1>
        <p>Find which NIC owns an IP address or MAC, discover connected devices</p>
      </div>

      {/* Search Box */}
      <div className="search-box">
        <div className="search-input-group">
          <div className="search-input-wrapper">
            <input
              type="text"
              placeholder="Enter IP address, MAC, or device name..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && searchIP()}
            />
          </div>
          <button 
            className="search-btn"
            onClick={searchIP}
            disabled={searching || !query.trim()}
          >
            {searching ? 'Searching...' : 'Search'}
          </button>
        </div>

        {/* Quick Filters */}
        <div className="quick-filters">
          {['all', 'online', 'WAN', 'LAN'].map(f => (
            <button
              key={f}
              className={`filter-chip ${filter === f ? 'active' : ''}`}
              onClick={() => setFilter(f)}
            >
              {f === 'all' ? '📋 All' : 
               f === 'online' ? '🟢 Online' :
               f === 'WAN' ? '🌍 WAN' : '💻 LAN'}
            </button>
          ))}
        </div>
      </div>

      {/* Search Result */}
      {result && (
        <div className={`search-result ${result.found ? 'found' : 'not-found'}`}>
          <div className="result-header">
            <span className="result-icon">{result.found ? '✅' : '❌'}</span>
            <div className="result-title">
              <h3>{result.found ? 'Match Found!' : 'No Match Found'}</h3>
              <p>Searched: {result.searchValue}</p>
            </div>
          </div>

          {result.found && (
            <div className="result-body">
              <div className="result-grid">
                <div className="result-item">
                  <span className="label">Interface</span>
                  <span className="value">{result.nic.alias || result.nic.name}</span>
                </div>
                <div className="result-item">
                  <span className="label">System Name</span>
                  <span className="value mono">{result.nic.name}</span>
                </div>
                <div className="result-item">
                  <span className="label">Type</span>
                  <span className="value">{result.nic.type}</span>
                </div>
                <div className="result-item">
                  <span className="label">Status</span>
                  <span className="value" style={{color: result.nic.status === 'UP' ? '#10b981' : '#ef4444'}}>
                    {result.nic.status}
                  </span>
                </div>
                <div className="result-item">
                  <span className="label">IP Address</span>
                  <span className="value mono">{result.nic.ipv4?.[0]?.split('/')[0] || '-'}</span>
                </div>
                <div className="result-item">
                  <span className="label">MAC Address</span>
                  <span className="value mono">{result.nic.mac || '-'}</span>
                </div>
                <div className="result-item">
                  <span className="label">Gateway</span>
                  <span className="value mono">{result.nic.gateway || '-'}</span>
                </div>
                <div className="result-item">
                  <span className="label">Match Type</span>
                  <span className="value">{result.matchType}</span>
                </div>
              </div>

              {/* Connected Devices */}
              {result.devices?.length > 0 && (
                <div style={{marginTop: '1.5rem'}}>
                  <h4 style={{color: '#94a3b8', marginBottom: '0.75rem'}}>
                    Connected Devices ({result.devices.length})
                  </h4>
                  <div className="devices-list">
                    {result.devices.map((device, i) => (
                      <div key={i} className="device-item">
                        <span className="icon">{device.icon}</span>
                        <div className="info">
                          <div className="name">{device.name}</div>
                          <div className="ip">{device.ip}</div>
                        </div>
                        <div className="mac">{device.mac}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <Link to={`/network/${result.nic.index}`} className="view-nic-btn">
                View Details →
              </Link>
            </div>
          )}
        </div>
      )}

      {/* Recent Searches */}
      {recentSearches.length > 0 && !result && (
        <div className="recent-searches">
          <h3>Recent Searches</h3>
          <div className="recent-list">
            {recentSearches.map((search, i) => (
              <button
                key={i}
                className="recent-item"
                onClick={() => { setQuery(search); }}
              >
                {search}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* NIC Quick List */}
      {!result && (
        <div style={{marginTop: '2rem'}}>
          <h3 style={{color: '#94a3b8', marginBottom: '1rem'}}>
            Available Interfaces ({filteredNics.length})
          </h3>
          <div className="devices-list">
            {filteredNics.map(nic => (
              <Link 
                key={nic.index}
                to={`/network/${nic.index}`}
                className="device-item"
                style={{textDecoration: 'none'}}
              >
                <span className="icon">
                  {nic.type === 'WAN' ? '🌍' : nic.type === 'LAN' ? '💻' : '☁️'}
                </span>
                <div className="info">
                  <div className="name">{nic.alias || nic.name}</div>
                  <div className="ip">{nic.ipv4?.[0]?.split('/')[0] || 'No IP'}</div>
                </div>
                <div style={{
                  padding: '0.25rem 0.75rem',
                  borderRadius: '12px',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  background: nic.status === 'UP' ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)',
                  color: nic.status === 'UP' ? '#34d399' : '#f87171'
                }}>
                  {nic.status}
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default NICSearch
