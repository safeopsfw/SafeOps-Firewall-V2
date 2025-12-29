// Network Layout - Sub-navigation wrapper for NIC Management pages
import { useState } from 'react'
import { Outlet, NavLink, useLocation } from 'react-router-dom'
import './Network.css'

const NAV_ITEMS = [
  { path: '/network', label: 'Overview', icon: '📊', exact: true },
  { path: '/network/search', label: 'Search', icon: '🔍' },
  { path: '/network/topology', label: 'Topology', icon: '🗺️' },
  { path: '/network/dhcp', label: 'DHCP Server', icon: '🏊' },
]

function NetworkLayout() {
  const location = useLocation()

  return (
    <div className="network-layout">
      {/* Sub-navigation */}
      <div className="network-subnav">
        {NAV_ITEMS.map(item => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.exact}
            className={({ isActive }) => `subnav-item ${isActive ? 'active' : ''}`}
          >
            <span className="subnav-icon">{item.icon}</span>
            <span className="subnav-label">{item.label}</span>
          </NavLink>
        ))}
      </div>

      {/* Page content */}
      <div className="network-content">
        <Outlet />
      </div>
    </div>
  )
}

export default NetworkLayout
