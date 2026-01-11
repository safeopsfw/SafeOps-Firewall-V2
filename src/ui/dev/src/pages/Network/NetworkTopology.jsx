// Network Topology - Interactive Visual Network Diagram
// Dynamically calculated layout based on detected NICs

import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import './Network.css'

const NIC_API = 'http://localhost:8081/api'

function NetworkTopology() {
  const [nics, setNics] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedNode, setSelectedNode] = useState(null)
  const [zoom, setZoom] = useState(1)
  const canvasRef = useRef(null)
  const navigate = useNavigate()

  useEffect(() => {
    fetchNICs()
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
    setLoading(false)
  }

  const getMockNICs = () => [
    { index: 16, name: 'Wi-Fi', alias: 'Primary Internet', type: 'WAN', status: 'UP', ipv4: ['192.168.1.3/24'], gateway: '192.168.1.1', mac: 'f4:26:79:73:6f:7c', speed: 144000000 },
    { index: 12, name: 'Ethernet 2', alias: 'VirtualBox Network', type: 'LAN', status: 'UP', ipv4: ['192.168.56.1/24'], mac: '0a:00:27:00:00:0c', speed: 1000000000 },
    { index: 24, name: 'Ethernet', alias: 'Backup WAN', type: 'LAN', status: 'DOWN', ipv4: ['192.168.1.2/24'], mac: '58:11:22:86:fd:c4', speed: 1000000000 },
    { index: 43, name: 'vEthernet', alias: 'Hyper-V Switch', type: 'VIRTUAL', status: 'UP', ipv4: ['172.19.192.1/20'], mac: '00:15:5d:b5:eb:f2', speed: 10000000000 },
  ]

  // Calculate dynamic node positions based on NIC count
  const calculateLayout = useCallback(() => {
    const canvasWidth = canvasRef.current?.offsetWidth || 800
    const canvasHeight = canvasRef.current?.offsetHeight || 500
    const centerX = canvasWidth / 2
    const centerY = canvasHeight / 2

    const nodes = []
    const connections = []

    // Internet node (top center)
    nodes.push({
      id: 'internet',
      type: 'internet',
      label: 'Internet',
      icon: '☁️',
      x: centerX - 30,
      y: 40,
      status: 'UP'
    })

    // Find primary gateway from WANs
    const wanNics = nics.filter(n => n.type === 'WAN' && n.status === 'UP')
    const primaryWan = wanNics[0] || nics.find(n => n.gateway)
    const gateway = primaryWan?.gateway || '192.168.1.1'

    // Gateway node (below internet)
    nodes.push({
      id: 'gateway',
      type: 'gateway',
      label: 'Gateway',
      sublabel: gateway,
      icon: '📡',
      x: centerX - 30,
      y: 130,
      status: primaryWan ? 'UP' : 'DOWN'
    })

    // Connection: Internet to Gateway
    connections.push({
      from: 'internet',
      to: 'gateway',
      active: primaryWan?.status === 'UP'
    })

    // This device node (center)
    nodes.push({
      id: 'thisDevice',
      type: 'device',
      label: 'This Device',
      sublabel: 'SafeOps Firewall',
      icon: '🖥️',
      x: centerX - 30,
      y: 240,
      status: 'UP'
    })

    // Connection: Gateway to This Device
    connections.push({
      from: 'gateway',
      to: 'thisDevice',
      active: primaryWan?.status === 'UP'
    })

    // Dynamically position NIC nodes in a row below device
    const activeNics = nics.filter(n => n.status === 'UP' || n.type === 'WAN')
    const nicCount = activeNics.length || 1
    const nicSpacing = Math.min(150, (canvasWidth - 100) / nicCount)
    const startX = centerX - ((nicCount - 1) * nicSpacing) / 2 - 30

    activeNics.forEach((nic, index) => {
      const nicNode = {
        id: `nic-${nic.index}`,
        type: 'nic',
        nicIndex: nic.index,
        label: nic.alias || nic.name,
        sublabel: nic.ipv4?.[0]?.split('/')[0] || 'No IP',
        icon: nic.type === 'WAN' ? '🌍' : nic.type === 'LAN' ? '💻' : '☁️',
        x: startX + (index * nicSpacing),
        y: 350,
        status: nic.status,
        nicType: nic.type
      }
      nodes.push(nicNode)

      // Connection: This Device to NIC
      connections.push({
        from: 'thisDevice',
        to: `nic-${nic.index}`,
        active: nic.status === 'UP'
      })

      // If WAN, also connect to gateway
      if (nic.type === 'WAN') {
        connections.push({
          from: 'gateway',
          to: `nic-${nic.index}`,
          active: nic.status === 'UP',
          dashed: true
        })
      }
    })

    // Add mock connected devices for each LAN
    const lanNics = nics.filter(n => n.type === 'LAN' && n.status === 'UP')
    lanNics.forEach((nic, nicIdx) => {
      const nicNode = nodes.find(n => n.id === `nic-${nic.index}`)
      if (!nicNode) return

      const devices = getConnectedDevices(nic)
      const deviceSpacing = 60
      const deviceStartX = nicNode.x - ((devices.length - 1) * deviceSpacing) / 2

      devices.forEach((device, devIdx) => {
        const deviceNode = {
          id: `device-${nic.index}-${devIdx}`,
          type: 'client',
          label: device.name,
          sublabel: device.ip,
          icon: device.icon,
          x: deviceStartX + (devIdx * deviceSpacing),
          y: 450,
          status: 'UP'
        }
        nodes.push(deviceNode)

        connections.push({
          from: `nic-${nic.index}`,
          to: deviceNode.id,
          active: true
        })
      })
    })

    return { nodes, connections }
  }, [nics])

  const getConnectedDevices = (nic) => {
    // Mock devices - in real implementation, this comes from ARP table
    if (nic.type === 'LAN' && nic.name.includes('VirtualBox')) {
      return [
        { name: 'Ubuntu VM', ip: '192.168.56.101', icon: '🐧' },
      ]
    }
    if (nic.type === 'WAN') {
      return []
    }
    return []
  }

  const { nodes, connections } = calculateLayout()

  const getNodeById = (id) => nodes.find(n => n.id === id)

  const handleNodeClick = (node) => {
    if (node.nicIndex) {
      navigate(`/network/${node.nicIndex}`)
    } else {
      setSelectedNode(node)
    }
  }

  const handleZoomIn = () => setZoom(z => Math.min(z + 0.2, 2))
  const handleZoomOut = () => setZoom(z => Math.max(z - 0.2, 0.5))
  const handleReset = () => setZoom(1)

  if (loading) {
    return (
      <div className="loading-overlay">
        <div className="loading-spinner"></div>
        <p>Loading network topology...</p>
      </div>
    )
  }

  return (
    <div className="topology-page">
      <div className="topology-header">
        <h1>🗺️ Network Topology</h1>
        <div className="topology-controls">
          <button className="topo-btn" onClick={handleZoomOut}>−</button>
          <button className="topo-btn" onClick={handleReset}>100%</button>
          <button className="topo-btn" onClick={handleZoomIn}>+</button>
          <button className="topo-btn" onClick={fetchNICs}>🔄 Refresh</button>
        </div>
      </div>

      <div className="topology-canvas" ref={canvasRef}>
        <svg 
          width="100%" 
          height="100%" 
          style={{ transform: `scale(${zoom})`, transformOrigin: 'center center' }}
        >
          {/* Connection Lines */}
          {connections.map((conn, i) => {
            const from = getNodeById(conn.from)
            const to = getNodeById(conn.to)
            if (!from || !to) return null

            const x1 = from.x + 30
            const y1 = from.y + 30
            const x2 = to.x + 30
            const y2 = to.y

            return (
              <g key={i}>
                <line
                  x1={x1}
                  y1={y1}
                  x2={x2}
                  y2={y2}
                  stroke={conn.active ? '#10b981' : '#475569'}
                  strokeWidth={conn.active ? 3 : 2}
                  strokeDasharray={conn.dashed ? '5,5' : 'none'}
                  opacity={conn.active ? 1 : 0.5}
                />
                {conn.active && (
                  <circle r="4" fill="#10b981">
                    <animateMotion 
                      dur="2s" 
                      repeatCount="indefinite"
                      path={`M${x1},${y1} L${x2},${y2}`}
                    />
                  </circle>
                )}
              </g>
            )
          })}
        </svg>

        {/* Nodes */}
        {nodes.map(node => (
          <div
            key={node.id}
            className={`topo-node ${node.type} ${node.status === 'UP' ? '' : 'offline'}`}
            style={{ left: node.x, top: node.y }}
            onClick={() => handleNodeClick(node)}
          >
            <div className="topo-node-icon">{node.icon}</div>
            <div className="topo-node-label">{node.label}</div>
            {node.sublabel && (
              <div className="topo-node-status">{node.sublabel}</div>
            )}
          </div>
        ))}

        {/* Legend */}
        <div className="topology-legend">
          <div className="legend-item">
            <span className="legend-dot online"></span>
            Online
          </div>
          <div className="legend-item">
            <span className="legend-dot offline"></span>
            Offline
          </div>
          <div className="legend-item">
            <span className="legend-dot wan"></span>
            WAN
          </div>
          <div className="legend-item">
            <span className="legend-dot lan"></span>
            LAN
          </div>
        </div>
      </div>

      {/* Selected Node Info */}
      {selectedNode && !selectedNode.nicIndex && (
        <div 
          style={{
            position: 'fixed',
            bottom: '2rem',
            left: '50%',
            transform: 'translateX(-50%)',
            background: 'rgba(15, 23, 42, 0.95)',
            border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: '16px',
            padding: '1rem 1.5rem',
            backdropFilter: 'blur(10px)',
            color: '#f1f5f9',
            display: 'flex',
            alignItems: 'center',
            gap: '1rem'
          }}
        >
          <span style={{fontSize: '2rem'}}>{selectedNode.icon}</span>
          <div>
            <div style={{fontWeight: 600}}>{selectedNode.label}</div>
            <div style={{color: '#94a3b8', fontSize: '0.9rem'}}>{selectedNode.sublabel}</div>
          </div>
          <button 
            onClick={() => setSelectedNode(null)}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#94a3b8',
              cursor: 'pointer',
              fontSize: '1.25rem',
              marginLeft: '1rem'
            }}
          >
            ×
          </button>
        </div>
      )}
    </div>
  )
}

export default NetworkTopology
