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

// ---- Live packet counters (updated via WebSocket) ----
let livePacketsProcessed = 0;
let livePacketsBlocked = 0;

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
// UI Helpers — Error / Empty / Loading States
// ============================================================================

function renderErrorState(el, msg) {
    if (typeof el === 'string') el = document.getElementById(el);
    if (!el) return;
    el.innerHTML = `<div class="empty-state"><div class="empty-icon">&#x26A0;&#xFE0F;</div><h3>Connection Error</h3><p>${esc(msg || 'Could not reach the engine API')}</p></div>`;
}

function renderEmptyState(el, icon, title, subtitle) {
    if (typeof el === 'string') el = document.getElementById(el);
    if (!el) return;
    el.innerHTML = `<div class="empty-state"><div class="empty-icon">${icon}</div><h3>${esc(title)}</h3><p>${esc(subtitle)}</p></div>`;
}

function renderLoadingState(el) {
    if (typeof el === 'string') el = document.getElementById(el);
    if (!el) return;
    el.innerHTML = `<div class="empty-state"><p style="color:var(--text-muted)">Loading...</p></div>`;
}

function showToast(message, type) {
    const toast = document.createElement('div');
    toast.className = 'toast toast-' + (type || 'info');
    toast.textContent = message;
    toast.style.cssText = 'position:fixed;bottom:1.5rem;right:1.5rem;padding:0.75rem 1.25rem;border-radius:0.5rem;z-index:10000;font-size:0.85rem;animation:fadeIn 0.3s ease;' +
        (type === 'success' ? 'background:rgba(34,197,94,0.15);color:var(--accent-green);border:1px solid var(--accent-green)' :
         type === 'error' ? 'background:rgba(239,68,68,0.15);color:var(--accent-red);border:1px solid var(--accent-red)' :
         'background:rgba(96,165,250,0.15);color:var(--accent-cyan);border:1px solid var(--accent-cyan)');
    document.body.appendChild(toast);
    setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 300); }, 3000);
}

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
    '/logs/verdicts':    'page-logs-verdicts',
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
            case '/dashboard':       await loadDashboard(); break;
            case '/alerts':          await loadAlerts(); break;
            case '/rules/domains':   await loadDomainRules(); break;
            case '/rules/ips':       await loadIPRules(); break;
            case '/rules/geoip':     await loadGeoIP(); break;
            case '/rules/detection': await loadDetection(); break;
            case '/bans':            await loadBans(); break;
            case '/tickets':         await loadTickets(); break;
            case '/logs/verdicts':   await loadVerdictLogs(); break;
            case '/system':          await loadSystem(); break;
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
            setText('stat-total-alerts', fmt(stats.alerts.total));
        }
        if (stats.security) {
            setText('stat-active-bans', fmt(stats.security.active_bans));
            setText('stat-rate-limited', fmt(stats.security.rate_limited));
            setText('sec-ddos', fmt(stats.security.ddos_detected));
            setText('sec-brute', fmt(stats.security.brute_force_detected));
            setText('sec-portscan', fmt(stats.security.port_scans_detected));
            setText('sec-baseline', fmt(stats.security.baseline_deviations));
        }
        if (stats.domains) {
            setText('stat-domains-blocked', fmt(stats.domains.blocked_domains));
        }
        if (stats.geoip) {
            setText('stat-geo-checks', fmt(stats.geoip.total_checks));
        }
        if (stats.reloader) {
            setText('stat-hot-reloads', fmt(stats.reloader.successes));
        }
    } catch (e) {
        // Show dashes — API not reachable
        ['stat-total-alerts', 'stat-active-bans', 'stat-rate-limited',
         'stat-domains-blocked', 'stat-geo-checks', 'stat-hot-reloads',
         'sec-ddos', 'sec-brute', 'sec-portscan', 'sec-baseline'].forEach(id => setText(id, '\u2014'));
    }

    // Live packet counters
    setText('stat-packets-processed', fmt(livePacketsProcessed));
    setText('stat-packets-blocked', fmt(livePacketsBlocked));

    // Load threat feed
    try {
        const threats = await GET('/dashboard/threats');
        renderThreatFeed(threats);
    } catch (e) {
        renderEmptyState('threat-feed', '\uD83D\uDEE1\uFE0F', 'No Data', 'Threat feed unavailable \u2014 engine API not connected');
    }
}

function renderThreatFeed(data) {
    const el = document.getElementById('threat-feed');
    const items = [
        ...(data.recent_alerts || []).map(a => ({
            icon: severityIcon(a.severity),
            bg: severityBg(a.severity),
            title: a.type + (a.source_ip ? ' \u2014 ' + a.source_ip : '') + (a.domain ? ' \u2014 ' + a.domain : ''),
            detail: a.details || '',
            time: timeAgo(a.timestamp),
        })),
        ...(data.active_bans || []).map(b => ({
            icon: '\uD83D\uDEAB',
            bg: 'rgba(248,113,113,0.12)',
            title: 'Ban: ' + b.ip,
            detail: b.reason,
            time: timeAgo(b.banned_at),
        })),
    ];

    if (items.length === 0) {
        el.innerHTML = `<div class="empty-state"><div class="empty-icon">\uD83D\uDEE1\uFE0F</div><h3>All Clear</h3><p>No recent threats detected</p></div>`;
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

// ============================================================================
// Alerts
// ============================================================================

let alertsData = [];

async function loadAlerts() {
    try {
        const data = await GET('/alerts');
        alertsData = data.alerts || [];
    } catch (e) {
        alertsData = [];
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
            <td><span class="mono" style="color:var(--accent-cyan)">${esc(a.src_ip || a.domain || '\u2014')}</span></td>
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
            ${a.count > 1 ? `<span class="tag" style="margin-left:0.5rem">\u00D7${a.count} occurrences</span>` : ''}
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
                <button class="btn btn-sm btn-secondary" onclick="triageAlert('${a.id}','acknowledged')">&#x2713; Acknowledge</button>
                <button class="btn btn-sm btn-secondary" onclick="triageAlert('${a.id}','escalated')" style="border-color:var(--accent-amber)">&#x2B06; Escalate</button>
                <button class="btn btn-sm btn-secondary" onclick="triageAlert('${a.id}','dismissed')">&#x2717; Dismiss</button>
                <button class="btn btn-sm btn-secondary" onclick="triageAlert('${a.id}','resolved')" style="border-color:var(--accent-green)">&#x2714; Resolve</button>
            </div>
        </div>
    `;

    openModal('alert-detail-modal');
}

function buildThreatLinks(ip, domain) {
    const links = [];
    if (ip) {
        links.push(`<a href="https://www.virustotal.com/gui/ip-address/${ip}" target="_blank" class="btn btn-sm btn-secondary">VT IP</a>`);
        links.push(`<a href="https://www.abuseipdb.com/check/${ip}" target="_blank" class="btn btn-sm btn-secondary">AbuseIPDB</a>`);
        links.push(`<a href="https://www.shodan.io/host/${ip}" target="_blank" class="btn btn-sm btn-secondary">Shodan</a>`);
        links.push(`<a href="https://viz.greynoise.io/ip/${ip}" target="_blank" class="btn btn-sm btn-secondary">GreyNoise</a>`);
    }
    if (domain) {
        links.push(`<a href="https://www.virustotal.com/gui/domain/${domain}" target="_blank" class="btn btn-sm btn-secondary">VT Domain</a>`);
        links.push(`<a href="https://urlscan.io/search/#${domain}" target="_blank" class="btn btn-sm btn-secondary">urlscan</a>`);
    }
    return links.join('');
}

async function triageAlert(id, status) {
    try {
        await POST(`/alerts/${id}/triage`, { status, analyst: localStorage.getItem('safeops_user') || 'admin' });
    } catch (e) {
        // Update locally even if API fails
    }
    const alert = alertsData.find(a => a.id === id);
    if (alert) alert.triage_status = status;
    renderAlerts();
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
        renderErrorState('blocked-domains-list', 'Failed to load blocked domains');
    }

    try {
        const data = await GET('/rules/domains/whitelist');
        renderDomainList('whitelist-domains-list', data.domains || [], 'whitelist');
    } catch (e) {
        renderErrorState('whitelist-domains-list', 'Failed to load whitelisted domains');
    }

    try {
        const data = await GET('/rules/categories');
        renderCategories(data.categories || []);
    } catch (e) {
        renderErrorState('categories-list', 'Failed to load categories');
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
            <button class="btn btn-ghost btn-sm" onclick="removeDomain('${esc(d)}', '${type}')" title="Remove">&#x2715;</button>
        </div>
    `).join('');
}

function renderCategories(cats) {
    const el = document.getElementById('categories-list');
    if (cats.length === 0) {
        renderEmptyState(el, '\uD83D\uDDC2\uFE0F', 'No Categories', 'No category filters configured');
        return;
    }
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
        renderErrorState('blocked-ips-list', 'Failed to load blocked IPs');
    }

    try {
        const data = await GET('/rules/ips/whitelist');
        renderIPList('whitelist-ips-list', data.ips || [], 'whitelist');
    } catch (e) {
        renderErrorState('whitelist-ips-list', 'Failed to load whitelisted IPs');
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
            <button class="btn btn-ghost btn-sm" onclick="removeIP('${esc(ip)}', '${type}')" title="Remove">&#x2715;</button>
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
        setText('geo-total-checks', '\u2014');
        setText('geo-blocked-count', '\u2014');
        document.getElementById('geo-mode-badge').textContent = '\u2014';
        renderErrorState('geoip-config-body', 'Failed to load GeoIP configuration');
    }
}

function renderGeoIP(data) {
    // Stats
    if (data.stats) {
        setText('geo-total-checks', fmt(data.stats.total_checks));
        setText('geo-blocked-count', fmt(data.stats.total_blocks || data.stats.blocked || 0));
    }

    const cfg = data.config;
    if (!cfg) {
        renderEmptyState('geoip-config-body', '\uD83C\uDF0D', 'No Config', 'GeoIP configuration not loaded');
        return;
    }

    const mode = (cfg.policy && cfg.policy.mode) || 'deny_list';
    const enabled = cfg.policy && cfg.policy.enabled;
    document.getElementById('geo-mode-badge').textContent = mode.toUpperCase();

    const body = document.getElementById('geoip-config-body');
    let html = '';

    // Policy settings
    html += `<div class="rule-item"><span>GeoIP Enabled</span><span class="badge badge-${enabled ? 'success' : 'warning'}">${enabled ? 'Yes' : 'No'}</span></div>`;
    html += `<div class="rule-item"><span>Mode</span><span class="mono">${esc(mode)}</span></div>`;
    html += `<div class="rule-item"><span>Log Blocked</span><span class="badge badge-${cfg.policy.log_blocked ? 'success' : 'info'}">${cfg.policy.log_blocked ? 'Yes' : 'No'}</span></div>`;
    html += `<div class="rule-item"><span>Enrich Alerts</span><span class="badge badge-${cfg.policy.enrich_alerts ? 'success' : 'info'}">${cfg.policy.enrich_alerts ? 'Yes' : 'No'}</span></div>`;

    // Country lists
    const countries = mode === 'deny_list'
        ? (cfg.deny_list && cfg.deny_list.countries) || []
        : (cfg.allow_list && cfg.allow_list.countries) || [];

    if (countries.length > 0) {
        const label = mode === 'deny_list' ? 'Blocked Countries' : 'Allowed Countries';
        html += `<div class="rule-item" style="flex-direction:column; align-items:flex-start; gap:0.5rem">
            <strong>${label}</strong>
            <div style="display:flex; flex-wrap:wrap; gap:0.35rem">${countries.map(c =>
                `<span class="tag">${esc(c.toUpperCase())}</span>`
            ).join('')}</div>
        </div>`;
    } else {
        html += `<div class="rule-item"><span>${mode === 'deny_list' ? 'Blocked' : 'Allowed'} Countries</span><span class="mono" style="color:var(--text-muted)">None</span></div>`;
    }

    // ASN blocking
    const asnEnabled = cfg.asn_block && cfg.asn_block.enabled;
    const blockedASNs = (cfg.asn_block && cfg.asn_block.blocked_asns) || [];
    html += `<div class="rule-item"><span>ASN Blocking</span><span class="badge badge-${asnEnabled ? 'success' : 'info'}">${asnEnabled ? 'Enabled' : 'Disabled'}</span></div>`;
    if (blockedASNs.length > 0) {
        html += `<div class="rule-item" style="flex-direction:column; align-items:flex-start; gap:0.5rem">
            <strong>Blocked ASNs</strong>
            <div style="display:flex; flex-wrap:wrap; gap:0.35rem">${blockedASNs.map(asn =>
                `<span class="tag">AS${asn}</span>`
            ).join('')}</div>
        </div>`;
    }

    // Foreign datacenter detection
    const flagDC = cfg.datacenter && cfg.datacenter.flag_foreign_datacenter;
    const homeCountry = (cfg.datacenter && cfg.datacenter.home_country) || '';
    html += `<div class="rule-item"><span>Foreign DC Detection</span><span class="badge badge-${flagDC ? 'success' : 'info'}">${flagDC ? 'Active' : 'Inactive'}</span></div>`;
    if (homeCountry) {
        html += `<div class="rule-item"><span>Home Country</span><span class="mono">${esc(homeCountry.toUpperCase())}</span></div>`;
    }

    // Cache stats from runtime
    if (data.stats && data.stats.cache_hit_rate) {
        html += `<div class="rule-item"><span>Cache Hit Rate</span><span class="mono">${esc(data.stats.cache_hit_rate)}</span></div>`;
    }

    body.innerHTML = html;
}

// ============================================================================
// Detection Config
// ============================================================================

async function loadDetection() {
    try {
        const data = await GET('/rules/detection');
        renderDetection(data);
    } catch (e) {
        renderErrorState('detection-config-body', 'Failed to load detection configuration');
    }
}

function renderDetection(data) {
    const body = document.getElementById('detection-config-body');
    const cfg = data.config;
    if (!cfg) {
        renderEmptyState(body, '\uD83D\uDD0D', 'No Config', 'Detection configuration not loaded');
        return;
    }

    let html = '';

    // DDoS module
    if (cfg.ddos) {
        html += renderDetectionModule('DDoS Protection', cfg.ddos.enabled, [
            { label: 'SYN Rate Threshold', value: fmt(cfg.ddos.syn_rate_threshold) + '/s' },
            { label: 'UDP Rate Threshold', value: fmt(cfg.ddos.udp_rate_threshold) + '/s' },
            { label: 'ICMP Rate Threshold', value: fmt(cfg.ddos.icmp_rate_threshold) + '/s' },
            { label: 'Connection Ratio', value: cfg.ddos.connection_ratio_threshold },
            { label: 'Ban Duration', value: cfg.ddos.ban_duration_minutes + ' min' },
            { label: 'Max Ban Duration', value: cfg.ddos.max_ban_duration_hours + ' hrs' },
            { label: 'Escalation Multiplier', value: cfg.ddos.escalation_multiplier + 'x' },
            { label: 'Window', value: cfg.ddos.window_seconds + 's' },
        ]);
    }

    // Rate Limiting module
    if (cfg.rate_limit) {
        html += renderDetectionModule('Rate Limiting', cfg.rate_limit.enabled, [
            { label: 'Default Rate', value: fmt(cfg.rate_limit.default_rate) + '/s per IP' },
            { label: 'Burst Size', value: fmt(cfg.rate_limit.burst_size) },
            { label: 'Global Rate', value: fmt(cfg.rate_limit.global_rate) + '/s' },
            { label: 'Cleanup Interval', value: cfg.rate_limit.cleanup_interval_seconds + 's' },
        ]);
    }

    // Brute Force module
    if (cfg.brute_force) {
        const services = cfg.brute_force.services || {};
        const serviceRows = Object.entries(services).map(([name, svc]) => ({
            label: name.toUpperCase() + ' (port ' + svc.port + ')',
            value: svc.max_failures + ' failures / ' + svc.window_seconds + 's',
        }));
        html += renderDetectionModule('Brute Force Detection', cfg.brute_force.enabled, [
            { label: 'Global Window', value: cfg.brute_force.window_seconds + 's' },
            ...serviceRows,
        ]);
    }

    // Port Scan module
    if (cfg.port_scan) {
        html += renderDetectionModule('Port Scan Detection', cfg.port_scan.enabled, [
            { label: 'Port Threshold', value: cfg.port_scan.port_threshold + ' ports' },
            { label: 'Window', value: cfg.port_scan.window_seconds + 's' },
            { label: 'Ban Duration', value: cfg.port_scan.ban_duration_minutes + ' min' },
            { label: 'Sequential Threshold', value: cfg.port_scan.sequential_threshold + ' ports' },
        ]);
    }

    // Traffic Baseline module
    if (cfg.baseline) {
        html += renderDetectionModule('Traffic Baseline', cfg.baseline.enabled, [
            { label: 'Window', value: cfg.baseline.window_minutes + ' min' },
            { label: 'Deviation Threshold', value: cfg.baseline.deviation_threshold + '\u03C3' },
            { label: 'Warmup', value: cfg.baseline.warmup_minutes + ' min' },
            { label: 'Update Interval', value: cfg.baseline.update_interval_seconds + 's' },
        ]);
    }

    // Whitelist summary
    if (cfg.whitelist) {
        const ips = (cfg.whitelist.trusted_ips || []).length;
        const cidrs = (cfg.whitelist.trusted_cidrs || []).length;
        const cdns = (cfg.whitelist.cdn_cidrs || []).length;
        html += `<div style="border:1px solid var(--border-subtle); border-radius:0.5rem; padding:1rem; margin-bottom:1rem">
            <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:0.75rem">
                <strong style="font-size:0.9rem">Whitelist</strong>
                <span class="badge badge-info">${ips + cidrs + cdns} entries</span>
            </div>
            <div class="rule-item"><span>Trusted IPs</span><span class="mono">${ips > 0 ? (cfg.whitelist.trusted_ips || []).join(', ') : 'None'}</span></div>
            <div class="rule-item"><span>Trusted CIDRs</span><span class="mono">${cidrs > 0 ? (cfg.whitelist.trusted_cidrs || []).join(', ') : 'None'}</span></div>
            <div class="rule-item"><span>CDN CIDRs</span><span class="mono">${cdns > 0 ? cdns + ' ranges' : 'None'}</span></div>
        </div>`;
    }

    // Runtime stats if available
    if (data.stats) {
        const s = data.stats;
        html += `<div style="border:1px solid var(--border-subtle); border-radius:0.5rem; padding:1rem; margin-bottom:1rem">
            <strong style="font-size:0.9rem; margin-bottom:0.75rem; display:block">Runtime Statistics</strong>`;
        if (s.Bans || s.bans) {
            const bans = s.Bans || s.bans;
            html += `<div class="rule-item"><span>Active Bans</span><span class="mono">${fmt(bans.active_bans || bans.ActiveBans || 0)}</span></div>`;
            html += `<div class="rule-item"><span>Total Bans</span><span class="mono">${fmt(bans.total_bans || bans.TotalBans || 0)}</span></div>`;
        }
        if (s.RateLimiter || s.rate_limiter) {
            const rl = s.RateLimiter || s.rate_limiter;
            html += `<div class="rule-item"><span>Rate Limit Denied</span><span class="mono">${fmt(rl.denied || rl.Denied || 0)}</span></div>`;
        }
        if (s.DDoS || s.ddos) {
            const dd = s.DDoS || s.ddos;
            html += `<div class="rule-item"><span>SYN Flood Detections</span><span class="mono">${fmt(dd.syn_detections || dd.SYNDetections || 0)}</span></div>`;
            html += `<div class="rule-item"><span>UDP Flood Detections</span><span class="mono">${fmt(dd.udp_detections || dd.UDPDetections || 0)}</span></div>`;
        }
        html += `</div>`;
    }

    body.innerHTML = html;
}

function renderDetectionModule(title, enabled, params) {
    let html = `<div style="border:1px solid var(--border-subtle); border-radius:0.5rem; padding:1rem; margin-bottom:1rem">
        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:0.75rem">
            <strong style="font-size:0.9rem">${esc(title)}</strong>
            <span class="badge badge-${enabled ? 'success' : 'warning'}">${enabled ? 'Enabled' : 'Disabled'}</span>
        </div>`;
    for (const p of params) {
        html += `<div class="rule-item"><span style="color:var(--text-secondary)">${esc(p.label)}</span><span class="mono">${esc(String(p.value))}</span></div>`;
    }
    html += '</div>';
    return html;
}

// ============================================================================
// Bans
// ============================================================================

async function loadBans() {
    try {
        const data = await GET('/security/bans');
        renderBans(data.bans || []);
    } catch (e) {
        renderBans([]);
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
            <td>${b.permanent ? '<span class="badge badge-danger">PERMANENT</span>' : `<span style="font-size:0.85rem; color:var(--accent-amber)">${b.time_left || '\u2014'}</span>`}</td>
            <td><span class="badge badge-${b.level >= 3 ? 'danger' : b.level >= 2 ? 'warning' : 'info'}">L${b.level}</span></td>
            <td><button class="btn btn-ghost btn-sm" onclick="unbanIP('${esc(b.ip)}')" title="Unban">&#x1F513;</button></td>
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
        ticketsData = [];
        setText('ticket-open-count', '\u2014');
        setText('ticket-progress-count', '\u2014');
        setText('ticket-resolved-count', '\u2014');
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
        el.innerHTML = `<div class="empty-state"><div class="empty-icon">\uD83C\uDFAB</div><h3>No Tickets</h3><p>Create a ticket to track security incidents</p></div>`;
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
                <span>${esc(t.assignee || 'Unassigned')}</span>
                <span>${formatTime(t.created_at)}</span>
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
        // Add locally as fallback
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
// Verdict Logs
// ============================================================================

let verdictOffset = 0;
const VERDICT_LIMIT = 100;

async function loadVerdictLogs() {
    verdictOffset = 0;
    await fetchVerdictPage();
}

async function fetchVerdictPage() {
    const actionFilter = document.getElementById('verdict-action-filter').value;
    let url = `/logs/verdicts?limit=${VERDICT_LIMIT}&offset=${verdictOffset}`;
    if (actionFilter) url += '&action=' + encodeURIComponent(actionFilter);

    try {
        const data = await GET(url);
        renderVerdictLogs(data);
    } catch (e) {
        renderErrorState('verdicts-tbody-container', 'Failed to load verdict logs \u2014 engine API not reachable');
        document.getElementById('verdict-pagination').innerHTML = '';
    }
}

function renderVerdictLogs(data) {
    const tbody = document.getElementById('verdicts-tbody');
    const emptyEl = document.getElementById('verdicts-empty');
    const verdicts = data.verdicts || [];

    if (verdicts.length === 0) {
        tbody.innerHTML = '';
        emptyEl.classList.remove('hidden');
        document.getElementById('verdict-pagination').innerHTML = '';
        return;
    }
    emptyEl.classList.add('hidden');

    tbody.innerHTML = verdicts.map(v => {
        const actionCls = v.action === 'DROP' ? 'danger' : v.action === 'BLOCK' ? 'warning' : 'info';
        return `<tr>
            <td><span class="mono" style="font-size:0.78rem; color:var(--text-muted)">${esc(v.ts)}</span></td>
            <td><span class="mono" style="color:var(--accent-cyan)">${esc(v.src)}:${v.sp}</span></td>
            <td><span class="mono">${esc(v.dst)}:${v.dp}</span></td>
            <td><span class="tag">${esc(v.proto)}</span></td>
            <td><span class="badge badge-${actionCls}">${esc(v.action)}</span></td>
            <td style="font-size:0.85rem">${esc(v.detector)}</td>
            <td style="font-size:0.85rem; color:var(--accent-purple)">${esc(v.domain || '')}</td>
            <td style="font-size:0.82rem; max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--text-secondary)">${esc(v.reason)}</td>
        </tr>`;
    }).join('');

    // Pagination
    const total = data.total || 0;
    const pagEl = document.getElementById('verdict-pagination');
    const pages = Math.ceil(total / VERDICT_LIMIT);
    const currentPage = Math.floor(verdictOffset / VERDICT_LIMIT) + 1;

    if (pages <= 1) {
        pagEl.innerHTML = `<span style="color:var(--text-muted); font-size:0.82rem">${total} entries</span>`;
        return;
    }

    pagEl.innerHTML = `
        <span style="color:var(--text-muted); font-size:0.82rem">${total} entries \u2014 Page ${currentPage}/${pages}</span>
        <div style="display:flex; gap:0.5rem; margin-top:0.5rem">
            <button class="btn btn-sm btn-secondary" ${currentPage <= 1 ? 'disabled' : ''} onclick="verdictPrev()">&#x2190; Prev</button>
            <button class="btn btn-sm btn-secondary" ${currentPage >= pages ? 'disabled' : ''} onclick="verdictNext()">Next &#x2192;</button>
        </div>
    `;
}

function verdictPrev() {
    verdictOffset = Math.max(0, verdictOffset - VERDICT_LIMIT);
    fetchVerdictPage();
}

function verdictNext() {
    verdictOffset += VERDICT_LIMIT;
    fetchVerdictPage();
}

// Wire filter change
document.getElementById('verdict-action-filter')?.addEventListener('change', () => {
    verdictOffset = 0;
    fetchVerdictPage();
});

// ============================================================================
// System
// ============================================================================

async function loadSystem() {
    try {
        const data = await GET('/status');
        setText('sys-status', data.status || 'unknown');
        setText('sys-uptime', data.uptime || '\u2014');
        if (data.memory) {
            setText('sys-memory', data.memory.alloc_mb?.toFixed(1) || '\u2014');
            setText('sys-goroutines', data.memory.goroutines || '\u2014');
        }
        if (data.components) {
            renderComponents(data.components);
        }
    } catch (e) {
        setText('sys-status', '\u2014');
        setText('sys-uptime', '\u2014');
        setText('sys-memory', '\u2014');
        setText('sys-goroutines', '\u2014');
        renderErrorState('component-health', 'Could not reach engine status API');
    }
}

function renderComponents(components) {
    const el = document.getElementById('component-health');
    const icons = {
        security: '\uD83D\uDEE1\uFE0F', domain_filter: '\uD83C\uDF10', geoip: '\uD83C\uDF0D',
        alerting: '\uD83D\uDD14', hot_reload: '\uD83D\uDD04'
    };
    el.innerHTML = Object.entries(components).map(([name, info]) => `
        <div class="rule-item">
            <span>${icons[name] || '\u2699\uFE0F'} ${name.replace(/_/g, ' ')}</span>
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
        case 'packet_stats':
            // Update live packet counters from engine broadcast
            if (msg.data) {
                livePacketsProcessed = msg.data.processed || msg.data.total || 0;
                livePacketsBlocked = msg.data.blocked || 0;
                setText('stat-packets-processed', fmt(livePacketsProcessed));
                setText('stat-packets-blocked', fmt(livePacketsBlocked));
            }
            break;
        case 'config_reloaded':
            showToast('Configuration reloaded successfully', 'success');
            // Refresh current page to pick up new config
            const page = getCurrentPage();
            if (page === 'dashboard') loadDashboard();
            else if (page === 'rules-detection') loadDetection();
            else if (page === 'rules-geoip') loadGeoIP();
            else if (page === 'rules-domains') loadDomainRules();
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
    return hash.replace('/rules/', 'rules-').replace('/logs/', 'logs-').replace('/', '');
}

function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

function fmt(num) {
    if (num == null || num === undefined) return '\u2014';
    return Number(num).toLocaleString();
}

function esc(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function formatTime(ts) {
    if (!ts) return '\u2014';
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
        case 'CRITICAL': return '\uD83D\uDD34';
        case 'HIGH': return '\uD83D\uDD34';
        case 'MEDIUM': return '\uD83D\uDFE1';
        case 'LOW': return '\uD83D\uDD35';
        default: return '\u26AA';
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
