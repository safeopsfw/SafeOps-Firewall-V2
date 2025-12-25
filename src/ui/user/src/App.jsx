import { useState, useEffect } from 'react'

const API_BASE = 'http://localhost:8080/api'

function App() {
  const [status, setStatus] = useState(null)
  const [query, setQuery] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  // Fetch status on mount
  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 30000) // Refresh every 30s
    return () => clearInterval(interval)
  }, [])

  const fetchStatus = async () => {
    try {
      const res = await fetch(`${API_BASE}/status`)
      const data = await res.json()
      setStatus(data)
    } catch (err) {
      console.error('Failed to fetch status:', err)
    }
  }

  const handleSearch = async () => {
    if (!query.trim()) return
    
    setLoading(true)
    setResult(null)
    
    try {
      // Detect query type
      let endpoint = ''
      const q = query.trim()
      
      if (/^[0-9.]+$/.test(q) || q.includes(':')) {
        // IP address
        endpoint = `${API_BASE}/lookup/ip/${q}`
      } else if (/^[a-f0-9]{32,64}$/i.test(q)) {
        // Hash
        endpoint = `${API_BASE}/lookup/hash/${q}`
      } else {
        // Domain
        endpoint = `${API_BASE}/lookup/domain/${q}`
      }
      
      const res = await fetch(endpoint)
      const data = await res.json()
      setResult(data)
    } catch (err) {
      setResult({ error: err.message })
    } finally {
      setLoading(false)
    }
  }

  const formatNumber = (n) => {
    if (!n) return '0'
    return n.toLocaleString()
  }

  const getTotalRecords = () => {
    if (!status) return 0
    return Object.values(status).reduce((sum, t) => sum + (t.row_count || 0), 0)
  }

  return (
    <div className="container">
      <header className="header">
        <h1>🛡️ SafeOps Security Status</h1>
        <div className="status-badge">
          <span className="status-dot"></span>
          Protected
        </div>
      </header>

      <div className="stats-grid">
        <div className="stat-card protected">
          <h3>Total Records</h3>
          <div className="value">{formatNumber(getTotalRecords())}</div>
        </div>
        <div className="stat-card threats">
          <h3>Domains Tracked</h3>
          <div className="value">{formatNumber(status?.domains?.row_count)}</div>
        </div>
        <div className="stat-card blocked">
          <h3>IPs Monitored</h3>
          <div className="value">{formatNumber(status?.ip_blacklist?.row_count)}</div>
        </div>
        <div className="stat-card">
          <h3>Malware Hashes</h3>
          <div className="value">{formatNumber(status?.hashes?.row_count)}</div>
        </div>
      </div>

      <div className="search-box">
        <h2>🔍 Quick Lookup</h2>
        <p style={{ color: 'var(--text-secondary)', marginBottom: '1rem', fontSize: '0.875rem' }}>
          Enter an IP address, domain, or file hash to check against threat database
        </p>
        <div className="search-input">
          <input
            type="text"
            placeholder="e.g. 192.168.1.1, malware.com, or SHA256 hash..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
          />
          <button onClick={handleSearch} disabled={loading}>
            {loading ? 'Checking...' : 'Check'}
          </button>
        </div>
        
        {result && (
          <div className="result-box">
            {result.found ? (
              <>
                <span style={{ color: 'var(--accent-red)' }}>⚠️ THREAT DETECTED</span>
                {'\n\n'}
                {JSON.stringify(result, null, 2)}
              </>
            ) : result.error ? (
              <span style={{ color: 'var(--accent-yellow)' }}>Error: {result.error}</span>
            ) : (
              <span style={{ color: 'var(--accent-green)' }}>✓ No threats found for: {query}</span>
            )}
          </div>
        )}
      </div>

      <footer className="footer">
        SafeOps v2.0 • Threat Intel Database • Last updated: {new Date().toLocaleString()}
      </footer>
    </div>
  )
}

export default App
