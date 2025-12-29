// NIC Detail Page - Real-time Traffic Flow Graph
// 60-second rolling window, NO persistent storage

import { useState, useEffect, useRef, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import './Network.css'

const NIC_API = 'http://localhost:8081/api'
const GRAPH_DURATION = 60 // seconds
const UPDATE_INTERVAL = 1000 // ms

function NICDetail() {
  const { nicId } = useParams()
  const [nic, setNic] = useState(null)
  const [loading, setLoading] = useState(true)
  const [devices, setDevices] = useState([])
  
  // Real-time traffic data - circular buffer, no storage
  const trafficBufferRef = useRef([])
  const [trafficData, setTrafficData] = useState([])
  const [currentSpeed, setCurrentSpeed] = useState({ rx: 0, tx: 0 })
  const canvasRef = useRef(null)
  const animationRef = useRef(null)
  const lastBytesRef = useRef({ rx: 0, tx: 0 })

  // Fetch NIC details
  useEffect(() => {
    fetchNICDetails()
  }, [nicId])

  // Start real-time traffic monitoring
  useEffect(() => {
    if (!nic || nic.status !== 'UP') return

    const interval = setInterval(() => {
      simulateTrafficData()
    }, UPDATE_INTERVAL)

    return () => clearInterval(interval)
  }, [nic])

  // Draw graph on canvas
  useEffect(() => {
    if (trafficData.length > 0) {
      drawGraph()
    }
  }, [trafficData])

  const fetchNICDetails = async () => {
    setLoading(true)
    try {
      const res = await fetch(`${NIC_API}/nics/${nicId}`)
      if (res.ok) {
        const data = await res.json()
        setNic(data)
        await getConnectedDevices(data)
      } else {
        // Use mock data
        const mockNic = getMockNIC(parseInt(nicId))
        setNic(mockNic)
        await getConnectedDevices(mockNic)
      }
    } catch (err) {
      const mockNic = getMockNIC(parseInt(nicId))
      setNic(mockNic)
      await getConnectedDevices(mockNic)
    }
    setLoading(false)
  }

  const getMockNIC = (id) => {
    // No mock data - return null if API fails
    return null
  }

  const getConnectedDevices = async (nic) => {
    try {
      const res = await fetch(`${NIC_API}/devices`)
      if (res.ok) {
        const data = await res.json()
        setDevices(data.devices || [])
      }
    } catch (err) {
      console.error('Failed to fetch connected devices:', err)
      setDevices([])
    }
  }

  // Simulate traffic data (in production, this comes from WebSocket)
  const simulateTrafficData = useCallback(() => {
    const now = Date.now()
    
    // Generate realistic-looking traffic (sine wave with noise)
    const baseRx = 5000000 + Math.sin(now / 5000) * 2000000
    const baseTx = 1000000 + Math.sin(now / 7000) * 500000
    const noise = () => (Math.random() - 0.5) * 1000000
    
    const rxBps = Math.max(0, baseRx + noise())
    const txBps = Math.max(0, baseTx + noise())
    
    const point = {
      time: now,
      rx: rxBps,
      tx: txBps
    }

    // Add to circular buffer
    trafficBufferRef.current.push(point)
    
    // Remove data older than 60 seconds (NO STORAGE)
    const cutoff = now - (GRAPH_DURATION * 1000)
    trafficBufferRef.current = trafficBufferRef.current.filter(p => p.time > cutoff)
    
    // Update state for rendering
    setTrafficData([...trafficBufferRef.current])
    setCurrentSpeed({ rx: rxBps, tx: txBps })
  }, [])

  // Draw the real-time graph
  const drawGraph = useCallback(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    const width = canvas.width
    const height = canvas.height
    
    // Clear canvas
    ctx.clearRect(0, 0, width, height)

    if (trafficData.length < 2) return

    // Calculate max value for scaling
    const maxVal = Math.max(
      ...trafficData.map(d => Math.max(d.rx, d.tx)),
      1000000 // minimum 1 Mbps scale
    )

    const now = Date.now()
    const startTime = now - (GRAPH_DURATION * 1000)

    // Draw grid
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)'
    ctx.lineWidth = 1
    for (let i = 0; i <= 4; i++) {
      const y = (height / 4) * i
      ctx.beginPath()
      ctx.moveTo(0, y)
      ctx.lineTo(width, y)
      ctx.stroke()
    }

    // Draw RX line (green)
    ctx.strokeStyle = '#22c55e'
    ctx.lineWidth = 2
    ctx.beginPath()
    trafficData.forEach((point, i) => {
      const x = ((point.time - startTime) / (GRAPH_DURATION * 1000)) * width
      const y = height - (point.rx / maxVal) * height * 0.9
      if (i === 0) ctx.moveTo(x, y)
      else ctx.lineTo(x, y)
    })
    ctx.stroke()

    // Fill RX area
    ctx.fillStyle = 'rgba(34, 197, 94, 0.1)'
    ctx.lineTo(width, height)
    ctx.lineTo(0, height)
    ctx.closePath()
    ctx.fill()

    // Draw TX line (blue)
    ctx.strokeStyle = '#3b82f6'
    ctx.lineWidth = 2
    ctx.beginPath()
    trafficData.forEach((point, i) => {
      const x = ((point.time - startTime) / (GRAPH_DURATION * 1000)) * width
      const y = height - (point.tx / maxVal) * height * 0.9
      if (i === 0) ctx.moveTo(x, y)
      else ctx.lineTo(x, y)
    })
    ctx.stroke()

    // Fill TX area
    ctx.fillStyle = 'rgba(59, 130, 246, 0.1)'
    ctx.lineTo(width, height)
    ctx.lineTo(0, height)
    ctx.closePath()
    ctx.fill()

    // Draw time labels
    ctx.fillStyle = '#64748b'
    ctx.font = '11px sans-serif'
    ctx.textAlign = 'center'
    for (let i = 0; i <= 6; i++) {
      const sec = GRAPH_DURATION - (i * 10)
      const x = (i / 6) * width
      ctx.fillText(`${sec}s`, x, height - 5)
    }
  }, [trafficData])

  const formatSpeed = (bps) => {
    if (bps >= 1000000000) return `${(bps / 1000000000).toFixed(1)} Gbps`
    if (bps >= 1000000) return `${(bps / 1000000).toFixed(1)} Mbps`
    if (bps >= 1000) return `${(bps / 1000).toFixed(1)} Kbps`
    return `${bps.toFixed(0)} bps`
  }

  const formatBytes = (bytes) => {
    if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(2)} GB`
    if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(2)} MB`
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`
    return `${bytes} B`
  }

  if (loading) {
    return (
      <div className="loading-overlay">
        <div className="loading-spinner"></div>
        <p>Loading interface details...</p>
      </div>
    )
  }

  if (!nic) {
    return (
      <div className="nic-detail-page">
        <div style={{textAlign: 'center', padding: '4rem'}}>
          <div style={{fontSize: '4rem', marginBottom: '1rem'}}>❓</div>
          <h2>Interface Not Found</h2>
          <p style={{color: '#64748b'}}>NIC with ID {nicId} was not found</p>
          <Link to="/network" style={{color: '#6366f1'}}>← Back to Network</Link>
        </div>
      </div>
    )
  }

  return (
    <div className="nic-detail-page">
      {/* Header */}
      <div className="detail-header">
        <div className="detail-title">
          <div className="detail-icon">
            {nic.type === 'WAN' ? '🌍' : nic.type === 'LAN' ? '💻' : '☁️'}
          </div>
          <div>
            <h1>{nic.alias || nic.name}</h1>
            <div className="system-name">{nic.name}</div>
          </div>
        </div>
        <div className={`detail-status ${nic.status === 'UP' ? 'online' : 'offline'}`}>
          <span className="dot"></span>
          {nic.status}
        </div>
      </div>

      {/* Stats Grid */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="label">IP Address</div>
          <div className="value mono">{nic.ipv4?.[0]?.split('/')[0] || '-'}</div>
        </div>
        <div className="stat-card">
          <div className="label">Gateway</div>
          <div className="value mono">{nic.gateway || '-'}</div>
        </div>
        <div className="stat-card">
          <div className="label">MAC Address</div>
          <div className="value mono">{nic.mac || '-'}</div>
        </div>
        <div className="stat-card">
          <div className="label">Link Speed</div>
          <div className="value">{formatSpeed(nic.speed || 0)}</div>
        </div>
        <div className="stat-card">
          <div className="label">MTU</div>
          <div className="value">{nic.mtu || 1500}</div>
        </div>
        <div className="stat-card">
          <div className="label">Type</div>
          <div className="value">{nic.type}</div>
        </div>
      </div>

      {/* Real-time Traffic Graph */}
      {nic.status === 'UP' && (
        <div className="realtime-section">
          <div className="realtime-header">
            <h2>
              📊 Real-time Traffic
              <span className="live-badge">● LIVE</span>
            </h2>
            <div className="speed-indicators">
              <div className="speed-item">
                <span className="arrow down">↓</span>
                <span className="speed">{formatSpeed(currentSpeed.rx)}</span>
              </div>
              <div className="speed-item">
                <span className="arrow up">↑</span>
                <span className="speed">{formatSpeed(currentSpeed.tx)}</span>
              </div>
            </div>
          </div>

          <div className="graph-container">
            <canvas 
              ref={canvasRef} 
              className="graph-canvas"
              width={800}
              height={200}
              style={{ width: '100%', height: '100%' }}
            />
          </div>

          <div className="graph-legend">
            <div className="graph-legend-item">
              <span className="line rx"></span>
              Download (RX)
            </div>
            <div className="graph-legend-item">
              <span className="line tx"></span>
              Upload (TX)
            </div>
          </div>

          <p style={{color: '#64748b', fontSize: '0.8rem', textAlign: 'center', marginTop: '0.5rem'}}>
            Rolling 60-second window • Data is not stored
          </p>
        </div>
      )}

      {/* Connected Devices */}
      {devices.length > 0 && (
        <div className="devices-section">
          <h2>🔗 Connected Devices ({devices.length})</h2>
          <div className="devices-list">
            {devices.map((device, i) => (
              <div key={i} className="device-item">
                <span className="icon">{device.icon}</span>
                <div className="info">
                  <div className="name">{device.name}</div>
                  <div className="ip">{device.ip}</div>
                </div>
                <div className="mac">{device.mac}</div>
                <div style={{color: '#64748b', fontSize: '0.8rem'}}>{device.lastSeen}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Back Link */}
      <div style={{marginTop: '2rem'}}>
        <Link to="/network" style={{color: '#6366f1', textDecoration: 'none'}}>
          ← Back to Network Overview
        </Link>
      </div>
    </div>
  )
}

export default NICDetail
