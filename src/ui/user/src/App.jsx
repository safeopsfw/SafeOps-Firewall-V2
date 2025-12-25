import { useState, useEffect, useRef } from 'react'

const API_BASE = 'http://localhost:8080/api'

// Tables available for threat checking (excluding geolocation)
const THREAT_TABLES = [
  { id: 'domains', name: 'Domains', column: 'domain', icon: '🌐', description: 'Malicious domains' },
  { id: 'hashes', name: 'File Hashes', column: 'md5', icon: '🔐', description: 'Malware signatures' },
  { id: 'ip_blacklist', name: 'IP Blacklist', column: 'ip_address', icon: '🚫', description: 'Blocked IPs' },
  { id: 'ip_anonymization', name: 'Anonymizers', column: 'ip_address', icon: '👤', description: 'VPN/Proxy/Tor IPs' },
]

function App() {
  const [status, setStatus] = useState(null)
  const [selectedTable, setSelectedTable] = useState('ip_blacklist')
  const [searchValue, setSearchValue] = useState('')
  const [checking, setChecking] = useState(false)
  const [threatResult, setThreatResult] = useState(null)
  
  // Pipeline state
  const [pipelineStatus, setPipelineStatus] = useState({ running: false, logs: [] })
  const [showPipelineModal, setShowPipelineModal] = useState(false)
  
  const alertRef = useRef(null)

  // Fetch status on mount
  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 30000)
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

  // Trigger database update pipeline
  const triggerUpdate = async () => {
    setPipelineStatus({ running: true, logs: ['Starting pipeline...'] })
    setShowPipelineModal(true)
    
    try {
      const response = await fetch(`${API_BASE}/update`, { method: 'POST' })
      if (!response.ok) throw new Error('Failed to start pipeline')
      
      // Poll for status
      const pollStatus = async () => {
        const statusRes = await fetch(`${API_BASE}/pipeline/status`)
        const status = await statusRes.json()
        setPipelineStatus(status)
        
        if (status.running) {
          setTimeout(pollStatus, 1000)
        } else {
          fetchStatus() // Refresh stats after completion
        }
      }
      
      setTimeout(pollStatus, 1000)
    } catch (error) {
      setPipelineStatus({ 
        running: false, 
        logs: [`Error: ${error.message}`],
        lastResult: { success: false, error: error.message }
      })
    }
  }

  // Check threat against selected table
  const checkThreat = async () => {
    if (!searchValue.trim()) return
    
    setChecking(true)
    setThreatResult(null)
    
    try {
      const table = THREAT_TABLES.find(t => t.id === selectedTable)
      const endpoint = selectedTable === 'domains' 
        ? `${API_BASE}/lookup/domain/${searchValue.trim()}`
        : selectedTable === 'hashes'
        ? `${API_BASE}/lookup/hash/${searchValue.trim()}`
        : `${API_BASE}/lookup/ip/${searchValue.trim()}`
      
      const res = await fetch(endpoint)
      const data = await res.json()
      
      setThreatResult({
        table: selectedTable,
        tableName: table.name,
        value: searchValue.trim(),
        found: data.found,
        data: data.data
      })
      
      // Scroll to alert if found
      if (data.found && alertRef.current) {
        alertRef.current.scrollIntoView({ behavior: 'smooth' })
      }
    } catch (err) {
      setThreatResult({ error: err.message })
    } finally {
      setChecking(false)
    }
  }

  const formatNumber = (n) => n?.toLocaleString() || '0'
  const getTotalRecords = () => {
    if (!status) return 0
    return Object.values(status).reduce((sum, t) => sum + (t.row_count || 0), 0)
  }

  return (
    <div className="container">
      <header className="header">
        <div>
          <h1>🛡️ SafeOps Security Console</h1>
          <p className="subtitle">Threat Intelligence & Protection</p>
        </div>
        <div className="header-actions">
          <button 
            className={`update-btn ${pipelineStatus.running ? 'updating' : ''}`}
            onClick={triggerUpdate}
            disabled={pipelineStatus.running}
          >
            {pipelineStatus.running ? (
              <>⏳ Updating...</>
            ) : (
              <>🔄 Update Database</>
            )}
          </button>
          <div className="status-badge">
            <span className="status-dot"></span>
            Protected
          </div>
        </div>
      </header>

      {/* THREAT ALERT */}
      {threatResult?.found && (
        <div className="threat-alert" ref={alertRef}>
          <div className="threat-alert-header">
            <span className="threat-icon">⚠️</span>
            <div>
              <h2>THREAT DETECTED!</h2>
              <p>Match found in <strong>{threatResult.tableName}</strong></p>
            </div>
          </div>
          <div className="threat-details">
            <div className="threat-value">
              <span className="label">Searched Value:</span>
              <span className="value">{threatResult.value}</span>
            </div>
            <div className="threat-source">
              <span className="label">Source Table:</span>
              <span className="value">{threatResult.table}</span>
            </div>
            {threatResult.data && (
              <div className="threat-data">
                <span className="label">Details:</span>
                <pre>{JSON.stringify(threatResult.data, null, 2)}</pre>
              </div>
            )}
          </div>
          <div className="threat-actions">
            <strong>⚡ Recommended Actions:</strong>
            <ul>
              <li>Block this indicator at your firewall</li>
              <li>Investigate any connections to this indicator</li>
              <li>Check related events and traffic logs</li>
            </ul>
          </div>
        </div>
      )}

      {threatResult && !threatResult.found && !threatResult.error && (
        <div className="safe-alert">
          <span className="safe-icon">✅</span>
          <div>
            <h3>No Threat Found</h3>
            <p><strong>{threatResult.value}</strong> is not in the <strong>{threatResult.tableName}</strong> database</p>
          </div>
        </div>
      )}

      {/* Stats */}
      <div className="stats-grid">
        <div className="stat-card total">
          <div className="stat-icon">📊</div>
          <div>
            <h3>Total Records</h3>
            <div className="value">{formatNumber(getTotalRecords())}</div>
          </div>
        </div>
        <div className="stat-card domains">
          <div className="stat-icon">🌐</div>
          <div>
            <h3>Domains</h3>
            <div className="value">{formatNumber(status?.domains?.row_count)}</div>
          </div>
        </div>
        <div className="stat-card ips">
          <div className="stat-icon">🚫</div>
          <div>
            <h3>Blacklisted IPs</h3>
            <div className="value">{formatNumber(status?.ip_blacklist?.row_count)}</div>
          </div>
        </div>
        <div className="stat-card hashes">
          <div className="stat-icon">🔐</div>
          <div>
            <h3>Malware Hashes</h3>
            <div className="value">{formatNumber(status?.hashes?.row_count)}</div>
          </div>
        </div>
      </div>

      {/* Threat Check */}
      <div className="threat-check-box">
        <h2>🔍 Threat Intelligence Check</h2>
        <p className="description">
          Select a table and enter a value to check against the threat database
        </p>
        
        <div className="table-selector">
          {THREAT_TABLES.map(table => (
            <button
              key={table.id}
              className={`table-btn ${selectedTable === table.id ? 'active' : ''}`}
              onClick={() => setSelectedTable(table.id)}
            >
              <span className="icon">{table.icon}</span>
              <span className="name">{table.name}</span>
            </button>
          ))}
        </div>
        
        <div className="search-input">
          <input
            type="text"
            placeholder={`Enter ${THREAT_TABLES.find(t => t.id === selectedTable)?.description || 'value'} to check...`}
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && checkThreat()}
          />
          <button onClick={checkThreat} disabled={checking}>
            {checking ? 'Checking...' : 'Check Threat'}
          </button>
        </div>
      </div>

      {/* Pipeline Modal */}
      {showPipelineModal && (
        <div className="modal-overlay">
          <div className="modal">
            <div className="modal-header">
              <h3>
                {pipelineStatus.running ? (
                  <>⏳ Updating Database...</>
                ) : pipelineStatus.lastResult?.success ? (
                  <>✅ Update Complete</>
                ) : (
                  <>❌ Update Failed</>
                )}
              </h3>
              {!pipelineStatus.running && (
                <button className="close-btn" onClick={() => setShowPipelineModal(false)}>×</button>
              )}
            </div>
            
            <div className="modal-logs">
              {pipelineStatus.logs?.map((log, i) => (
                <div 
                  key={i} 
                  className={`log-line ${
                    log.includes('[ERROR]') ? 'error' :
                    log.includes('[COMPLETE]') ? 'success' :
                    log.includes('[FETCH]') ? 'fetch' :
                    log.includes('[PROCESS]') ? 'process' :
                    log.includes('[CLEANUP]') ? 'cleanup' : ''
                  }`}
                >
                  {log}
                </div>
              ))}
              {pipelineStatus.running && <div className="cursor">▌</div>}
            </div>
            
            {pipelineStatus.lastResult && !pipelineStatus.running && (
              <div className={`modal-result ${pipelineStatus.lastResult.success ? 'success' : 'error'}`}>
                {pipelineStatus.lastResult.success 
                  ? `✓ Database updated in ${pipelineStatus.lastResult.duration}`
                  : `✗ ${pipelineStatus.lastResult.error}`
                }
              </div>
            )}
            
            {!pipelineStatus.running && (
              <button className="modal-close-btn" onClick={() => setShowPipelineModal(false)}>
                Close
              </button>
            )}
          </div>
        </div>
      )}

      <footer className="footer">
        SafeOps v2.0 • Threat Intel Database • Last sync: {new Date().toLocaleString()}
      </footer>
    </div>
  )
}

export default App
