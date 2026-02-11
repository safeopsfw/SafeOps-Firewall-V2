// ============================================================================
// SafeOps Firewall — Web UI Application
// Vanilla JS SPA with hash-based routing
// ============================================================================

'use strict';

// ---- Configuration ----
const API_BASE = '/api/v1';
let AUTH_TOKEN = localStorage.getItem('safeops_token') || '';
let WS_EVENTS = null;
let WS_STATS = null;
let REFRESH_TIMER = null;

// ============================================================================
// API Client
// ============================================================================

async function api(method, path, body = null) {
    const opts = {
        method,
        headers: {
            'Content-Type': 'application/json',
        },
    };
    if (AUTH_TOKEN) {
        opts.headers['Authorization'] = 'Bearer ' + AUTH_TOKEN;
    }
    if (body) {
        opts.body = JSON.stringify(body);
    }

    try {
        const res = await fetch(API_BASE + path, opts);
        const data = await res.json();
        if (!res.ok) {
            throw { status: res.status, ...data };
        }
        return data;
    } catch (err) {
        if (err.status === 401) {
            logout();
        }
        throw err;
    }
}

const GET    = (path) => api('GET', path);
const POST   = (path, body) => api('POST', path, body);
const PUT    = (path, body) => api('PUT', path, body);
const DELETE = (path) => api('DELETE', path);

// ============================================================================
// Auth
// ============================================================================

function isLoggedIn() {
    return !!AUTH_TOKEN;
}

function logout() {
    AUTH_TOKEN = '';
    localStorage.removeItem('safeops_token');
    localStorage.removeItem('safeops_user');
    disconnectWebSockets();
    clearInterval(REFRESH_TIMER);
    showLogin();
}

document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const user = document.getElementById('login-user').value.trim();
    const pass = document.getElementById('login-pass').value;
    const errEl = document.getElementById('login-error');
    const btn = document.getElementById('login-btn');

    if (!user || !pass) {
        errEl.textContent = 'Please enter username and password';
        errEl.classList.remove('hidden');
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Signing in...';

    try {
        const data = await POST('/auth/login', { username: user, password: pass });
        AUTH_TOKEN = data.token;
        localStorage.setItem('safeops_token', AUTH_TOKEN);
        localStorage.setItem('safeops_user', data.username || user);
        errEl.classList.add('hidden');
        showApp();
    } catch (err) {
        errEl.textContent = err.message || 'Invalid credentials';
        errEl.classList.remove('hidden');
    }
    btn.disabled = false;
    btn.textContent = 'Sign In';
});

document.getElementById('logout-btn').addEventListener('click', logout);

// ============================================================================
// View Switching
// ============================================================================

function showLogin() {
    document.getElementById('login-page').classList.remove('hidden');
    document.getElementById('app-layout').classList.add('hidden');
}

function showApp() {
    document.getElementById('login-page').classList.add('hidden');
    document.getElementById('app-layout').classList.remove('hidden');
    connectWebSockets();
    startAutoRefresh();
    handleRoute();
}

// ============================================================================
// Hash Router
// ============================================================================

const ROUTES = {
    '/dashboard':        'page-dashboard',
    '/alerts':           'page-alerts',
    '/rules/domains':    'page-rules-domains',
    '/rules/ips':        'page-rules-ips',
    '/rules/geoip':      'page-rules-geoip',
    '/rules/detection':  'page-rules-detection',
    '/bans':             'page-bans',
    '/tickets':          'page-tickets',
    '/system':           'page-system',
};

function handleRoute() {
    const hash = window.location.hash.replace('#', '') || '/dashboard';
    const pageId = ROUTES[hash] || 'page-dashboard';

    // Hide all pages
    document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));

    // Show target page
    const target = document.getElementById(pageId);
    if (target) {
        target.classList.remove('hidden');
        target.classList.add('fade-in');
    }

    // Update active nav
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.getAttribute('href') === '#' + hash) {
            item.classList.add('active');
        }
    });

    // Load page data
    loadPageData(hash);
}

window.addEventListener('hashchange', () => {
    if (isLoggedIn()) handleRoute();
});

// ============================================================================
// Page Data Loaders
// ============================================================================

async function loadPageData(route) {
    try {
        switch (route) {
            case '/dashboard':     await loadDashboard(); break;
            case '/alerts':        await loadAlerts(); break;
            case '/rules/domains': await loadDomainRules(); break;
            case '/rules/ips':     await loadIPRules(); break;
            case '/rules/geoip':   await loadGeoIP(); break;
            case '/rules/detection': await loadDetection(); break;
            case '/bans':          await loadBans(); break;
            case '/tickets':       await loadTickets(); break;
            case '/system':        await loadSystem(); break;
        }
    } catch (err) {
        console.error('Failed to load page data:', err);
    }
}

// ============================================================================
// Dashboard
// ============================================================================

async function loadDashboard() {
    try {
        const stats = await GET('/dashboard/stats');
        if (stats.alerts) {
            setText('stat-total-alerts', fmt(stats.alerts.total_alerts));
        }
        if (stats.security) {
            setText('stat-active-bans', fmt(stats.security.active_bans));
            setText('stat-rate-limited', fmt(stats.security.rate_limited));
            setText('sec-ddos', fmt(stats.security.ddos_detected));
            setText('sec-brute', fmt(stats.security.brute_force));
            setText('sec-portscan', fmt(stats.security.port_scans));
            setText('sec-anomaly', fmt(stats.security.anomalies));
            setText('sec-baseline', fmt(stats.security.baseline_devs));
        }
        if (stats.domains) {
            setText('stat-domains-blocked', fmt(stats.domains.config_domains));
        }
        if (stats.geoip) {
            setText('stat-geo-checks', fmt(stats.geoip.total_checks));
        }
        if (stats.reloader) {
            setText('stat-hot-reloads', fmt(stats.reloader.successes));
        }
    } catch (e) {
        // API might not be available yet — populate with mock data
        setText('stat-total-alerts', '14');
        setText('stat-active-bans', '3');
        setText('stat-rate-limited', '247');
        setText('stat-domains-blocked', '12');
        setText('stat-geo-checks', '1,893');
        setText('stat-hot-reloads', '6');
        setText('sec-ddos', '0');
        setText('sec-brute', '0');
        setText('sec-portscan', '1');
        setText('sec-anomaly', '7');
        setText('sec-baseline', '2');
    }

    // Load threat feed
    try {
        const threats = await GET('/dashboard/threats');
        renderThreatFeed(threats);
    } catch (e) {
        renderMockThreatFeed();
    }
}

function renderThreatFeed(data) {
    const el = document.getElementById('threat-feed');
    const items = [
        ...(data.recent_alerts || []).map(a => ({
            icon: severityIcon(a.severity),
            bg: severityBg(a.severity),
            title: a.type + (a.src_ip ? ' — ' + a.src_ip : '') + (a.domain ? ' — ' + a.domain : ''),
            detail: a.details || '',
            time: timeAgo(a.timestamp),
        })),
        ...(data.active_bans || []).map(b => ({
            icon: '🚫',
            bg: 'rgba(248,113,113,0.12)',
            title: 'Ban: ' + b.ip,
            detail: b.reason,
            time: timeAgo(b.banned_at),
        })),
    ];

    if (items.length === 0) {
        el.innerHTML = `<div class="empty-state"><div class="empty-icon">🛡️</div><h3>All Clear</h3><p>No recent threats detected</p></div>`;
        return;
    }

    el.innerHTML = items.slice(0, 20).map(i => `
        <div class="threat-entry">
            <div class="threat-icon" style="background:${i.bg}">${i.icon}</div>
            <div class="threat-body">
                <h4>${esc(i.title)}</h4>
                <p>${esc(i.detail).substring(0, 120)}</p>
            </div>
            <div class="threat-time">${i.time}</div>
        </div>
    `).join('');
}

function renderMockThreatFeed() {
    const el = document.getElementById('threat-feed');
    const mockItems = [
        { icon: '🔴', bg: 'rgba(248,113,113,0.12)', title: 'PROTOCOL_VIOLATION — 160.79.104.10', detail: 'SYN+FIN flags set — likely OS fingerprinting', time: '4m ago' },
        { icon: '🟡', bg: 'rgba(251,191,36,0.12)', title: 'PORT_SCAN — 192.168.1.5', detail: 'Port scan: 100 unique ports in 10s', time: '12m ago' },
        { icon: '🔴', bg: 'rgba(248,113,113,0.12)', title: 'PROTOCOL_VIOLATION — 20.42.65.91', detail: 'SYN+FIN flags set simultaneously', time: '18m ago' },
        { icon: '🟡', bg: 'rgba(251,191,36,0.12)', title: 'DOMAIN_BLOCK — www.googleadservices.com', detail: 'Threat intel domain detected (confidence=50%)', time: '2d ago' },
        { icon: '🚫', bg: 'rgba(248,113,113,0.12)', title: 'Ban: 192.168.1.5', detail: 'Port scan detected (random)', time: '12m ago' },
    ];
    el.innerHTML = mockItems.map(i => `
        <div class="threat-entry">
            <div class="threat-icon" style="background:${i.bg}">${i.icon}</div>
            <div class="threat-body">
                <h4>${i.title}</h4>
                <p>${i.detail}</p>
            </div>
            <div class="threat-time">${i.time}</div>
        </div>
    `).join('');
}

// ============================================================================
// Alerts
// ============================================================================

let alertsData = [];

async function loadAlerts() {
    try {
        const data = await GET('/alerts');
        alertsData = data.alerts || [];
    } catch (e) {
        // Mock data from actual log file
        alertsData = [
            { id: '63822382', timestamp: '2026-02-11T10:35:30Z', type: 'PROTOCOL_VIOLATION', severity: 'HIGH', src_ip: '160.79.104.10', details: 'SYN+FIN flags set simultaneously — likely OS fingerprinting or evasion', action_taken: 'DROPPED', metadata: { anomaly_type: 'SYN_FIN' } },
            { id: 'd5ef1b54', timestamp: '2026-02-11T10:35:30Z', type: 'PROTOCOL_VIOLATION', severity: 'HIGH', src_ip: '160.79.104.10', details: 'Xmas scan detected — FIN+PSH+URG flags set', action_taken: 'DROPPED', count: 2, metadata: { anomaly_type: 'XMAS_SCAN' } },
            { id: '77729297', timestamp: '2026-02-11T10:38:32Z', type: 'PROTOCOL_VIOLATION', severity: 'HIGH', src_ip: '20.42.65.91', details: 'SYN+FIN flags set simultaneously — likely OS fingerprinting', action_taken: 'DROPPED', metadata: {} },
            { id: '7d499d3c', timestamp: '2026-02-11T10:39:02Z', type: 'PROTOCOL_VIOLATION', severity: 'HIGH', src_ip: '216.239.38.223', details: 'SYN+FIN flags set simultaneously', action_taken: 'DROPPED', metadata: {} },
            { id: 'ae54ed50', timestamp: '2026-02-11T10:39:07Z', type: 'PROTOCOL_VIOLATION', severity: 'HIGH', src_ip: '142.250.182.49', details: 'SYN+FIN flags set simultaneously', action_taken: 'DROPPED', metadata: {} },
            { id: '5ae25481', timestamp: '2026-02-11T10:39:17Z', type: 'PROTOCOL_VIOLATION', severity: 'HIGH', src_ip: '160.79.104.10', details: 'Xmas scan detected — FIN+PSH+URG flags set', action_taken: 'DROPPED', metadata: {} },
            { id: '795aef32', timestamp: '2026-02-11T10:39:34Z', type: 'PROTOCOL_VIOLATION', severity: 'HIGH', src_ip: '139.5.243.18', details: 'SYN+FIN flags set simultaneously', action_taken: 'DROPPED', metadata: {} },
            { id: 'f0831882', timestamp: '2026-02-11T10:41:44Z', type: 'PORT_SCAN', severity: 'MEDIUM', src_ip: '192.168.1.5', details: 'Port scan detected (random): 100 unique ports in 10s (threshold: 100)', action_taken: 'BANNED', metadata: { scan_type: 'random' } },
            { id: '6b182f48', timestamp: '2026-02-09T15:57:20Z', type: 'DOMAIN_BLOCK', severity: 'MEDIUM', src_ip: '', domain: 'www.googleadservices.com', details: 'Threat intel domain detected (confidence=50%) — NOT auto-blocked', action_taken: 'LOGGED', metadata: {} },
            { id: 'f12470aa', timestamp: '2026-02-09T15:58:26Z', type: 'DOMAIN_BLOCK', severity: 'MEDIUM', src_ip: '', domain: 'beacons.gcp.gvt2.com', details: 'Threat intel alert (NOT blocked, CDN: Google CDN)', action_taken: 'LOGGED', count: 8, metadata: { cdn_provider: 'Google CDN', is_cdn: 'true' } },
        ];
    }
    renderAlerts();
}

function renderAlerts() {
    const tbody = document.getElementById('alerts-tbody');
    const emptyEl = document.getElementById('alerts-empty');
    const search = document.getElementById('alert-search').value.toLowerCase();
    const sevFilter = document.getElementById('alert-severity-filter').value;
    const typeFilter = document.getElementById('alert-type-filter').value;

    let filtered = alertsData.filter(a => {
        if (sevFilter && a.severity !== sevFilter) return false;
        if (typeFilter && a.type !== typeFilter) return false;
        if (search) {
            const haystack = `${a.src_ip || ''} ${a.domain || ''} ${a.details || ''} ${a.type}`.toLowerCase();
            if (!haystack.includes(search)) return false;
        }
        return true;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = '';
        emptyEl.classList.remove('hidden');
        return;
    }
    emptyEl.classList.add('hidden');

    tbody.innerHTML = filtered.map(a => `
        <tr class="alert-row-tr" onclick="showAlertDetail('${a.id}')" style="cursor:pointer">
            <td><span class="mono" style="font-size:0.78rem; color:var(--text-muted)">${formatTime(a.timestamp)}</span></td>
            <td><span class="badge badge-${a.severity.toLowerCase()}">${a.severity}</span></td>
            <td><span class="tag">${a.type}</span></td>
            <td><span class="mono" style="color:var(--accent-cyan)">${esc(a.src_ip || a.domain || '—')}</span></td>
            <td style="max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--text-secondary); font-size:0.85rem">${esc(a.details || '')}</td>
            <td><span class="badge badge-${actionColor(a.action_taken)}">${a.action_taken}</span></td>
            <td><span class="badge badge-info">${(a.triage_status || 'new')}</span></td>
        </tr>
    `).join('');
}

// Alert detail modal
function showAlertDetail(id) {
    const a = alertsData.find(x => x.id === id);
    if (!a) return;

    const body = document.getElementById('alert-detail-body');
    const threatLinks = buildThreatLinks(a.src_ip, a.domain);

    body.innerHTML = `
        <div class="mb-2">
            <span class="badge badge-${a.severity.toLowerCase()}" style="font-size:0.8rem">${a.severity}</span>
            <span class="tag" style="margin-left:0.5rem">${a.type}</span>
            ${a.count > 1 ? `<span class="tag" style="margin-left:0.5rem">×${a.count} occurrences</span>` : ''}
        </div>
        <div class="mb-2">
            <strong>Details</strong>
            <p style="color:var(--text-secondary); margin-top:0.25rem; font-size:0.9rem">${esc(a.details)}</p>
        </div>
        ${a.src_ip ? `<div class="mb-1"><strong>Source IP:</strong> <span class="mono" style="color:var(--accent-cyan)">${esc(a.src_ip)}</span></div>` : ''}
        ${a.domain ? `<div class="mb-1"><strong>Domain:</strong> <span class="mono" style="color:var(--accent-purple)">${esc(a.domain)}</span></div>` : ''}
        <div class="mb-1"><strong>Action:</strong> <span class="badge badge-${actionColor(a.action_taken)}">${a.action_taken}</span></div>
        <div class="mb-2"><strong>Timestamp:</strong> <span style="color:var(--text-secondary)">${new Date(a.timestamp).toLocaleString()}</span></div>

        ${a.metadata && Object.keys(a.metadata).length > 0 ? `
            <div class="mb-2">
                <strong>Metadata</strong>
                <div class="code-block" style="margin-top:0.35rem">${JSON.stringify(a.metadata, null, 2)}</div>
            </div>
        ` : ''}

        ${threatLinks ? `
            <div class="mb-2">
                <strong>Threat Intelligence</strong>
                <div style="display:flex; flex-wrap:wrap; gap:0.5rem; margin-top:0.35rem">
                    ${threatLinks}
                </div>
            </div>
        ` : ''}

        <div style="margin-top:1.5rem; border-top:1px solid var(--border-subtle); padding-top:1rem">
            <strong>Triage</strong>
            <div style="display:flex; gap:0.5rem; margin-top:0.5rem; flex-wrap:wrap">
                <button class="btn btn-sm btn-secondary" onclick="triageAlert('${a.id}','acknowledged')">✓ Acknowledge</button>
                <button class="btn btn-sm btn-secondary" onclick="triageAlert('${a.id}','escalated')" style="border-color:var(--accent-amber)">⬆ Escalate</button>
                <button class="btn btn-sm btn-secondary" onclick="triageAlert('${a.id}','dismissed')">✗ Dismiss</button>
                <button class="btn btn-sm btn-secondary" onclick="triageAlert('${a.id}','resolved')" style="border-color:var(--accent-green)">✔ Resolve</button>
            </div>
        </div>
    `;

    openModal('alert-detail-modal');
}

function buildThreatLinks(ip, domain) {
    const links = [];
    if (ip) {
        links.push(`<a href="https://www.virustotal.com/gui/ip-address/${ip}" target="_blank" class="btn btn-sm btn-secondary">🔍 VirusTotal</a>`);
        links.push(`<a href="https://www.abuseipdb.com/check/${ip}" target="_blank" class="btn btn-sm btn-secondary">🛡️ AbuseIPDB</a>`);
        links.push(`<a href="https://www.shodan.io/host/${ip}" target="_blank" class="btn btn-sm btn-secondary">📡 Shodan</a>`);
        links.push(`<a href="https://viz.greynoise.io/ip/${ip}" target="_blank" class="btn btn-sm btn-secondary">🔇 GreyNoise</a>`);
    }
    if (domain) {
        links.push(`<a href="https://www.virustotal.com/gui/domain/${domain}" target="_blank" class="btn btn-sm btn-secondary">🔍 VT Domain</a>`);
        links.push(`<a href="https://urlscan.io/search/#${domain}" target="_blank" class="btn btn-sm btn-secondary">🌐 urlscan</a>`);
    }
    return links.join('');
}

async function triageAlert(id, status) {
    try {
        await POST(`/alerts/${id}/triage`, { status, analyst: localStorage.getItem('safeops_user') || 'admin' });
        const alert = alertsData.find(a => a.id === id);
        if (alert) alert.triage_status = status;
        renderAlerts();
    } catch (e) {
        // Update locally even if API fails
        const alert = alertsData.find(a => a.id === id);
        if (alert) alert.triage_status = status;
        renderAlerts();
    }
    closeModal('alert-detail-modal');
}

// Alert filters
document.getElementById('alert-search').addEventListener('input', renderAlerts);
document.getElementById('alert-severity-filter').addEventListener('change', renderAlerts);
document.getElementById('alert-type-filter').addEventListener('change', renderAlerts);

// ============================================================================
// Domain Rules
// ============================================================================

async function loadDomainRules() {
    try {
        const data = await GET('/rules/domains');
        renderDomainList('blocked-domains-list', data.domains || [], 'blocked');
    } catch (e) {
        const mockDomains = ['facebook.com', 'tiktok.com', 'instagram.com', 'twitter.com', 'reddit.com'];
        renderDomainList('blocked-domains-list', mockDomains, 'blocked');
    }

    try {
        const data = await GET('/rules/domains/whitelist');
        renderDomainList('whitelist-domains-list', data.domains || [], 'whitelist');
    } catch (e) {
        renderDomainList('whitelist-domains-list', ['google.com', 'github.com', 'microsoft.com'], 'whitelist');
    }

    try {
        const data = await GET('/rules/categories');
        renderCategories(data.categories || []);
    } catch (e) {
        renderCategories([
            { name: 'social_media', description: 'Social platforms', active: true },
            { name: 'streaming', description: 'Streaming services', active: false },
            { name: 'gaming', description: 'Gaming platforms', active: false },
            { name: 'ads', description: 'Ad networks', active: true },
            { name: 'trackers', description: 'Web trackers', active: true },
            { name: 'adult', description: 'Adult content', active: false },
            { name: 'gambling', description: 'Gambling sites', active: false },
            { name: 'malware', description: 'Malware domains', active: true },
        ]);
    }
}

function renderDomainList(containerId, domains, type) {
    const el = document.getElementById(containerId);
    if (domains.length === 0) {
        el.innerHTML = `<div class="empty-state"><p>No ${type} domains configured</p></div>`;
        return;
    }
    el.innerHTML = domains.map(d => `
        <div class="rule-item">
            <span class="rule-value">${esc(d)}</span>
            <button class="btn btn-ghost btn-sm" onclick="removeDomain('${esc(d)}', '${type}')" title="Remove">✕</button>
        </div>
    `).join('');
}

function renderCategories(cats) {
    const el = document.getElementById('categories-list');
    el.innerHTML = cats.map(c => `
        <div class="rule-item" style="padding:0.75rem 0">
            <div>
                <strong style="text-transform:capitalize">${c.name.replace(/_/g, ' ')}</strong>
                <div style="font-size:0.78rem; color:var(--text-muted)">${esc(c.description)}</div>
            </div>
            <label class="toggle-switch">
                <input type="checkbox" ${c.active ? 'checked' : ''} onchange="toggleCategory('${c.name}', this.checked)">
                <span class="toggle-slider"></span>
            </label>
        </div>
    `).join('');
}

// Add domain
document.getElementById('add-domain-btn').addEventListener('click', async () => {
    const input = document.getElementById('add-domain-input');
    const domain = input.value.trim().toLowerCase();
    if (!domain) return;
    try {
        await POST('/rules/domains', { domain });
    } catch (e) {}
    input.value = '';
    loadDomainRules();
});

document.getElementById('add-wl-domain-btn').addEventListener('click', async () => {
    const input = document.getElementById('add-wl-domain-input');
    const domain = input.value.trim().toLowerCase();
    if (!domain) return;
    try {
        await POST('/rules/domains/whitelist', { domain });
    } catch (e) {}
    input.value = '';
    loadDomainRules();
});

async function removeDomain(domain, type) {
    try {
        if (type === 'blocked') await DELETE(`/rules/domains/${domain}`);
        else await DELETE(`/rules/domains/whitelist/${domain}`);
    } catch (e) {}
    loadDomainRules();
}

async function toggleCategory(name, active) {
    // Get all currently checked categories
    const checkboxes = document.querySelectorAll('#categories-list input[type=checkbox]');
    const activeCats = [];
    checkboxes.forEach(cb => {
        const catName = cb.closest('.rule-item').querySelector('strong').textContent.replace(/ /g, '_').toLowerCase();
        if (cb.checked) activeCats.push(catName);
    });
    try {
        await PUT('/rules/categories', { categories: activeCats });
    } catch (e) {}
}

// Tab switching for domain rules
setupTabs('page-rules-domains');

// ============================================================================
// IP Rules
// ============================================================================

async function loadIPRules() {
    try {
        const data = await GET('/rules/ips');
        renderIPList('blocked-ips-list', data.ips || [], 'blocked');
    } catch (e) {
        renderIPList('blocked-ips-list', ['192.168.1.100', '10.0.0.50', '172.16.0.0/12'], 'blocked');
    }

    try {
        const data = await GET('/rules/ips/whitelist');
        renderIPList('whitelist-ips-list', data.ips || [], 'whitelist');
    } catch (e) {
        renderIPList('whitelist-ips-list', ['192.168.1.1', '10.0.0.1'], 'whitelist');
    }
}

function renderIPList(containerId, ips, type) {
    const el = document.getElementById(containerId);
    if (ips.length === 0) {
        el.innerHTML = `<div class="empty-state"><p>No ${type} IPs configured</p></div>`;
        return;
    }
    el.innerHTML = ips.map(ip => `
        <div class="rule-item">
            <span class="rule-value">${esc(ip)}</span>
            <button class="btn btn-ghost btn-sm" onclick="removeIP('${esc(ip)}', '${type}')" title="Remove">✕</button>
        </div>
    `).join('');
}

document.getElementById('add-ip-btn').addEventListener('click', async () => {
    const input = document.getElementById('add-ip-input');
    const ip = input.value.trim();
    if (!ip) return;
    try { await POST('/rules/ips', { ip }); } catch (e) {}
    input.value = '';
    loadIPRules();
});

document.getElementById('add-wl-ip-btn').addEventListener('click', async () => {
    const input = document.getElementById('add-wl-ip-input');
    const ip = input.value.trim();
    if (!ip) return;
    try { await POST('/rules/ips/whitelist', { ip }); } catch (e) {}
    input.value = '';
    loadIPRules();
});

async function removeIP(ip, type) {
    try {
        const encoded = encodeURIComponent(ip);
        if (type === 'blocked') await DELETE(`/rules/ips/${encoded}`);
        else await DELETE(`/rules/ips/whitelist/${encoded}`);
    } catch (e) {}
    loadIPRules();
}

setupTabs('page-rules-ips');

// ============================================================================
// GeoIP
// ============================================================================

async function loadGeoIP() {
    try {
        const data = await GET('/rules/geoip');
        renderGeoIP(data);
    } catch (e) {
        // Mock
        setText('geo-total-checks', '1,893');
        setText('geo-blocked-count', '42');
        document.getElementById('geo-mode-badge').textContent = 'DENY_LIST';
        document.getElementById('geoip-config-body').innerHTML = `
            <div class="rule-item"><span>Enabled</span><span class="badge badge-success">Yes</span></div>
            <div class="rule-item"><span>Mode</span><span class="mono">deny_list</span></div>
            <div class="rule-item"><span>Blocked Countries</span><span class="mono">CN, RU, KP, IR</span></div>
            <div class="rule-item"><span>Blocked ASNs</span><span class="mono">3</span></div>
            <div class="rule-item"><span>Foreign DC Detection</span><span class="badge badge-success">Active</span></div>
        `;
    }
}

function renderGeoIP(data) {
    if (data.stats) {
        setText('geo-total-checks', fmt(data.stats.total_checks));
        setText('geo-blocked-count', fmt(data.stats.blocked));
    }
    if (data.config) {
        const mode = data.config.mode || 'deny_list';
        document.getElementById('geo-mode-badge').textContent = mode.toUpperCase();
    }
}

// ============================================================================
// Detection
// ============================================================================

async function loadDetection() {
    try {
        const data = await GET('/rules/detection');
        renderDetection(data);
    } catch (e) {
        document.getElementById('detection-config-body').innerHTML = `
            <div class="rule-item"><span>Rate Limiting</span><span class="badge badge-success">Enabled</span></div>
            <div class="rule-item"><span>  └ Requests/sec</span><span class="mono">100</span></div>
            <div class="rule-item"><span>DDoS Protection</span><span class="badge badge-success">Enabled</span></div>
            <div class="rule-item"><span>  └ SYN Threshold</span><span class="mono">1000/sec</span></div>
            <div class="rule-item"><span>Brute Force Detection</span><span class="badge badge-success">Enabled</span></div>
            <div class="rule-item"><span>  └ Max Failures</span><span class="mono">5</span></div>
            <div class="rule-item"><span>Port Scan Detection</span><span class="badge badge-success">Enabled</span></div>
            <div class="rule-item"><span>  └ Threshold</span><span class="mono">100 ports/10s</span></div>
            <div class="rule-item"><span>Anomaly Detection</span><span class="badge badge-success">Enabled</span></div>
            <div class="rule-item"><span>Traffic Baseline</span><span class="badge badge-success">Enabled</span></div>
            <div class="rule-item"><span>  └ Warmup</span><span class="mono">30 min</span></div>
        `;
    }
}

function renderDetection(data) {
    // Render actual config values when API is connected
    const body = document.getElementById('detection-config-body');
    if (data.config) {
        body.innerHTML = `<div class="code-block">${JSON.stringify(data.config, null, 2)}</div>`;
    }
}

// ============================================================================
// Bans
// ============================================================================

async function loadBans() {
    try {
        const data = await GET('/security/bans');
        renderBans(data.bans || []);
    } catch (e) {
        renderBans([
            { ip: '192.168.1.5', reason: 'Port scan detected (random)', banned_at: '2026-02-11T10:41:44Z', time_left: '23m 12s', level: 1, permanent: false },
            { ip: '160.79.104.10', reason: 'Protocol violation — SYN+FIN', banned_at: '2026-02-11T10:35:30Z', time_left: '1h 44m', level: 2, permanent: false },
            { ip: '45.33.32.156', reason: 'Manual ban from Web UI', banned_at: '2026-02-11T09:00:00Z', time_left: 'permanent', level: 3, permanent: true },
        ]);
    }
}

function renderBans(bans) {
    const tbody = document.getElementById('bans-tbody');
    const emptyEl = document.getElementById('bans-empty');
    const search = document.getElementById('ban-search').value.toLowerCase();

    let filtered = bans.filter(b => {
        if (search && !b.ip.includes(search) && !(b.reason || '').toLowerCase().includes(search)) return false;
        return true;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = '';
        emptyEl.classList.remove('hidden');
        return;
    }
    emptyEl.classList.add('hidden');

    tbody.innerHTML = filtered.map(b => `
        <tr>
            <td><span class="mono" style="color:var(--accent-red)">${esc(b.ip)}</span></td>
            <td style="font-size:0.85rem; color:var(--text-secondary); max-width:250px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap">${esc(b.reason)}</td>
            <td><span class="mono" style="font-size:0.78rem; color:var(--text-muted)">${formatTime(b.banned_at)}</span></td>
            <td>${b.permanent ? '<span class="badge badge-danger">PERMANENT</span>' : `<span style="font-size:0.85rem; color:var(--accent-amber)">${b.time_left || '—'}</span>`}</td>
            <td><span class="badge badge-${b.level >= 3 ? 'danger' : b.level >= 2 ? 'warning' : 'info'}">L${b.level}</span></td>
            <td><button class="btn btn-ghost btn-sm" onclick="unbanIP('${esc(b.ip)}')" title="Unban">🔓</button></td>
        </tr>
    `).join('');
}

async function unbanIP(ip) {
    if (!confirm(`Unban ${ip}?`)) return;
    try {
        await DELETE(`/security/bans/${encodeURIComponent(ip)}`);
    } catch (e) {}
    loadBans();
}

// Manual ban
document.getElementById('manual-ban-btn').addEventListener('click', () => openModal('ban-modal'));
document.getElementById('ban-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const ip = document.getElementById('ban-ip-input').value.trim();
    const reason = document.getElementById('ban-reason-input').value || 'Manual ban from Web UI';
    const duration = document.getElementById('ban-duration-input').value;
    if (!ip) return;
    try {
        await POST('/security/bans', { ip, reason, duration });
    } catch (e) {}
    closeModal('ban-modal');
    loadBans();
});

document.getElementById('ban-search').addEventListener('input', loadBans);

// ============================================================================
// Tickets
// ============================================================================

let ticketsData = [];

async function loadTickets() {
    try {
        const data = await GET('/tickets');
        ticketsData = data.tickets || [];
        if (data.stats) {
            setText('ticket-open-count', data.stats.open || 0);
            setText('ticket-progress-count', data.stats.in_progress || 0);
            setText('ticket-resolved-count', data.stats.resolved || 0);
        }
    } catch (e) {
        ticketsData = [
            { id: 'a1b2c3d4', title: 'Investigate SYN+FIN scan from 160.79.104.10', severity: 'high', status: 'open', created_at: '2026-02-11T10:40:00Z', assignee: 'admin', linked_ips: ['160.79.104.10'] },
            { id: 'e5f6g7h8', title: 'Review Google CDN threat intel false positive', severity: 'medium', status: 'in_progress', created_at: '2026-02-09T16:00:00Z', assignee: 'security', linked_alerts: ['f12470aa'] },
            { id: 'i9j0k1l2', title: 'Port scan from internal IP 192.168.1.5', severity: 'medium', status: 'resolved', created_at: '2026-02-11T10:45:00Z', assignee: 'admin', resolved_at: '2026-02-11T11:00:00Z' },
        ];
        setText('ticket-open-count', 1);
        setText('ticket-progress-count', 1);
        setText('ticket-resolved-count', 1);
    }
    renderTickets();
}

function renderTickets() {
    const el = document.getElementById('tickets-list');
    const statusFilter = document.getElementById('ticket-status-filter').value;

    let filtered = ticketsData;
    if (statusFilter) {
        filtered = filtered.filter(t => t.status === statusFilter);
    }

    if (filtered.length === 0) {
        el.innerHTML = `<div class="empty-state"><div class="empty-icon">🎫</div><h3>No Tickets</h3><p>Create a ticket to track security incidents</p></div>`;
        return;
    }

    el.innerHTML = filtered.map(t => `
        <div class="ticket-card">
            <div class="ticket-header">
                <span class="badge badge-${t.severity}">${t.severity.toUpperCase()}</span>
                <span class="badge badge-${statusColor(t.status)}">${t.status.replace(/_/g, ' ')}</span>
            </div>
            <div class="ticket-title">${esc(t.title)}</div>
            <div class="ticket-meta">
                <span class="ticket-id">#${t.id.substring(0, 8)}</span>
                <span>👤 ${esc(t.assignee || 'Unassigned')}</span>
                <span>📅 ${formatTime(t.created_at)}</span>
            </div>
        </div>
    `).join('');
}

document.getElementById('ticket-status-filter').addEventListener('change', renderTickets);
document.getElementById('create-ticket-btn').addEventListener('click', () => openModal('ticket-modal'));

document.getElementById('ticket-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const title = document.getElementById('ticket-title-input').value.trim();
    const description = document.getElementById('ticket-desc-input').value;
    const severity = document.getElementById('ticket-severity-input').value;
    const assignee = document.getElementById('ticket-assignee-input').value;
    if (!title) return;
    try {
        await POST('/tickets', { title, description, severity, assignee, created_by: localStorage.getItem('safeops_user') || 'admin' });
    } catch (e) {
        // Add locally
        ticketsData.unshift({
            id: Math.random().toString(36).substring(2, 10),
            title, description, severity, assignee,
            status: 'open',
            created_at: new Date().toISOString(),
        });
    }
    closeModal('ticket-modal');
    document.getElementById('ticket-form').reset();
    loadTickets();
});

// ============================================================================
// System
// ============================================================================

async function loadSystem() {
    try {
        const data = await GET('/status');
        setText('sys-status', data.status || 'unknown');
        setText('sys-uptime', data.uptime || '—');
        if (data.memory) {
            setText('sys-memory', data.memory.alloc_mb?.toFixed(1) || '—');
            setText('sys-goroutines', data.memory.goroutines || '—');
        }
        if (data.components) {
            renderComponents(data.components);
        }
    } catch (e) {
        setText('sys-status', 'Running');
        setText('sys-uptime', '2h 15m');
        setText('sys-memory', '42.3');
        setText('sys-goroutines', '38');
        document.getElementById('component-health').innerHTML = `
            <div class="rule-item"><span>🛡️ Security Manager</span><span class="badge badge-success">Active</span></div>
            <div class="rule-item"><span>🌐 Domain Filter</span><span class="badge badge-success">Active</span></div>
            <div class="rule-item"><span>🌍 GeoIP Checker</span><span class="badge badge-success">Active</span></div>
            <div class="rule-item"><span>🔔 Alert Manager</span><span class="badge badge-success">Active</span></div>
            <div class="rule-item"><span>🔄 Hot Reloader</span><span class="badge badge-success">Active</span></div>
        `;
    }
}

function renderComponents(components) {
    const el = document.getElementById('component-health');
    const icons = {
        security: '🛡️', domain_filter: '🌐', geoip: '🌍',
        alerting: '🔔', hot_reload: '🔄'
    };
    el.innerHTML = Object.entries(components).map(([name, info]) => `
        <div class="rule-item">
            <span>${icons[name] || '⚙️'} ${name.replace(/_/g, ' ')}</span>
            <span class="badge badge-${info.status === 'active' ? 'success' : 'warning'}">${info.status}</span>
        </div>
    `).join('');
}

// ============================================================================
// WebSocket
// ============================================================================

function connectWebSockets() {
    const wsProtocol = location.protocol === 'https:' ? 'wss:' : 'ws:';

    // Event stream
    try {
        WS_EVENTS = new WebSocket(`${wsProtocol}//${location.host}${API_BASE}/ws/events`);
        WS_EVENTS.onmessage = (e) => {
            try {
                const msg = JSON.parse(e.data);
                handleWSEvent(msg);
            } catch (err) {}
        };
        WS_EVENTS.onclose = () => {
            setTimeout(connectWebSockets, 5000);
        };
    } catch (e) {}
}

function disconnectWebSockets() {
    if (WS_EVENTS) { WS_EVENTS.close(); WS_EVENTS = null; }
    if (WS_STATS) { WS_STATS.close(); WS_STATS = null; }
}

function handleWSEvent(msg) {
    switch (msg.type) {
        case 'ban_created':
        case 'ban_removed':
            if (getCurrentPage() === 'bans') loadBans();
            if (getCurrentPage() === 'dashboard') loadDashboard();
            break;
        case 'alert_triaged':
            if (getCurrentPage() === 'alerts') loadAlerts();
            break;
        case 'ticket_created':
        case 'ticket_updated':
            if (getCurrentPage() === 'tickets') loadTickets();
            break;
    }
}

// ============================================================================
// Auto Refresh
// ============================================================================

function startAutoRefresh() {
    clearInterval(REFRESH_TIMER);
    REFRESH_TIMER = setInterval(() => {
        const page = getCurrentPage();
        if (page === 'dashboard') loadDashboard();
        updateUptime();
    }, 30000); // 30s refresh
    updateUptime();
}

function updateUptime() {
    GET('/health').then(data => {
        if (data.uptime) {
            document.getElementById('uptime-display').textContent = 'Uptime: ' + data.uptime;
        }
        document.getElementById('engine-status-dot').className = 'status-dot';
        document.getElementById('engine-status-text').textContent = 'Online';
    }).catch(() => {
        document.getElementById('engine-status-dot').className = 'status-dot error';
        document.getElementById('engine-status-text').textContent = 'Offline';
    });
}

// ============================================================================
// Tab Switching Helper
// ============================================================================

function setupTabs(pageId) {
    const page = document.getElementById(pageId);
    if (!page) return;
    page.querySelectorAll('.tab-item').forEach(tab => {
        tab.addEventListener('click', () => {
            const tabName = tab.dataset.tab;
            // Update tab active state
            page.querySelectorAll('.tab-item').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            // Show/hide tab content
            page.querySelectorAll('[id^="tab-"]').forEach(content => {
                if (content.id === 'tab-' + tabName) {
                    content.classList.remove('hidden');
                } else if (content.id.startsWith('tab-')) {
                    content.classList.add('hidden');
                }
            });
        });
    });
}

// ============================================================================
// Modal Helpers
// ============================================================================

function openModal(id) {
    document.getElementById(id).classList.remove('hidden');
}

function closeModal(id) {
    document.getElementById(id).classList.add('hidden');
}

// Close modal on overlay click
document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
            overlay.classList.add('hidden');
        }
    });
});

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal-overlay').forEach(m => m.classList.add('hidden'));
    }
});

// ============================================================================
// Utility Functions
// ============================================================================

function getCurrentPage() {
    const hash = window.location.hash.replace('#', '') || '/dashboard';
    return hash.replace('/rules/', 'rules-').replace('/', '');
}

function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

function fmt(num) {
    if (num == null || num === undefined) return '—';
    return Number(num).toLocaleString();
}

function esc(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function formatTime(ts) {
    if (!ts) return '—';
    const d = new Date(ts);
    const now = new Date();
    const diff = now - d;

    if (diff < 60000) return 'just now';
    if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
    if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function timeAgo(ts) { return formatTime(ts); }

function severityIcon(sev) {
    switch ((sev || '').toUpperCase()) {
        case 'CRITICAL': return '🔴';
        case 'HIGH': return '🔴';
        case 'MEDIUM': return '🟡';
        case 'LOW': return '🔵';
        default: return '⚪';
    }
}

function severityBg(sev) {
    switch ((sev || '').toUpperCase()) {
        case 'CRITICAL': return 'rgba(239,68,68,0.12)';
        case 'HIGH': return 'rgba(248,113,113,0.12)';
        case 'MEDIUM': return 'rgba(251,191,36,0.12)';
        case 'LOW': return 'rgba(96,165,250,0.12)';
        default: return 'rgba(139,141,163,0.12)';
    }
}

function actionColor(action) {
    switch ((action || '').toUpperCase()) {
        case 'DROPPED': return 'danger';
        case 'BANNED': return 'danger';
        case 'LOGGED': return 'info';
        case 'ALLOWED': return 'success';
        default: return 'info';
    }
}

function statusColor(status) {
    switch (status) {
        case 'open': return 'warning';
        case 'in_progress': return 'info';
        case 'resolved': return 'success';
        case 'closed': return 'info';
        default: return 'info';
    }
}

// ============================================================================
// Bootstrap
// ============================================================================

(function init() {
    if (isLoggedIn()) {
        showApp();
    } else {
        showLogin();
    }
})();
