<script>
  import { onMount, onDestroy } from 'svelte';
  import { EventsOn, EventsOff } from '../wailsjs/runtime/runtime.js';
  import {
    GetServices, StartService, StopService, StartAll, StopAll,
    GetWebUIState, StartWebUI, StopWebUI, OpenWebConsole,
    GetSystemStats, GetBinDir,
    IsFirstRun, GetInstallPaths, RunSetupStep, CheckPostgresReady,
    OpenReadme,
    GetSIEMState, GetSIEMDir, ChooseSIEMDir,
    StartElasticsearch, StartKibana, StopElasticsearch, StopKibana,
    OpenKibana, RunESTemplates, OpenFirewallUI,
    VerifyPrerequisites, FixMissingDatabases, FixMissingIndices,
    GetUserSettings, SaveUserSettings
  } from '../wailsjs/go/main/App.js';

  // ── State ──────────────────────────────────────────────────────────────────
  let view = 'loading';   // 'loading' | 'setup' | 'launcher'
  let services = [];
  let webUI = { backendRunning: false, frontendRunning: false };
  let stats = { cpuPercent: 0, memUsedMB: 0, memTotalMB: 0, memPercent: 0 };
  let binDir = '';
  let loadingIds = new Set();
  let toast = null;
  let toastTimer = null;

  // SIEM state
  let siem = { elasticRunning: false, kibanaRunning: false, siemDir: '', hasScripts: false, elasticPid: 0, kibanaPid: 0 };
  let siemBusy = { elastic: false, kibana: false, templates: false, choosePath: false };
  let siemPollTimer = null;

  // Prerequisites verification state
  let prereq = null; // null = not checked yet
  let prereqChecking = false;
  let prereqFixing = '';

  async function handleVerifyPrereqs() {
    prereqChecking = true;
    try { prereq = await VerifyPrerequisites(); }
    catch (e) { prereq = { error: String(e) }; }
    prereqChecking = false;
  }

  async function handleFixDBs() {
    prereqFixing = 'db';
    const r = await FixMissingDatabases();
    showToast(r, r.startsWith('error') ? 'error' : 'success');
    prereqFixing = '';
    handleVerifyPrereqs();
  }

  async function handleFixIndices() {
    prereqFixing = 'es';
    const r = await FixMissingIndices();
    showToast(r, r.startsWith('error') ? 'error' : 'success');
    prereqFixing = '';
    handleVerifyPrereqs();
  }

  // Setup wizard state
  let setupStep = 0;       // 0 = intro, 1-8 = steps
  let setupDone = false;
  let setupError = '';
  let setupMsg = '';
  let setupUsername = 'admin';
  let setupPassword = 'safeops123';
  let setupRunning = false;

  const TOTAL_STEPS = 8;
  const stepLabels = [
    '', // placeholder for index 0
    'Install PostgreSQL & Node.js',
    'Configure databases',
    'Run schema files',
    'Create admin user',
    'Setup Elasticsearch',
    'Setup Kibana',
    'Install UI dependencies',
    'Finalize & write paths',
  ];

  // ── Groups & icons ─────────────────────────────────────────────────────────
  const groupOrder = ['Core', 'Network', 'Certificates', 'Data'];
  const groupIcons = { Core: '⚡', Network: '🌐', Certificates: '🔑', Data: '📊' };
  const svcIcons = {
    'safeops-engine': '🛡',
    'firewall-engine': '🔥',
    'nic-management': '🔌',
    'dhcp-monitor': '📡',
    'captive-portal': '🚧',
    'step-ca': '🔐',
    'network-logger': '📝',
    'siem-forwarder': '📤',
    'threat-intel': '🕵',
  };

  $: grouped = groupOrder.map(g => ({
    name: g, icon: groupIcons[g] || '📦',
    services: services.filter(s => s.config.group === g),
  })).filter(g => g.services.length > 0);

  $: runningCount = services.filter(s => s.status === 'running').length;
  $: webUIStatus = webUI.frontendRunning && webUI.backendRunning ? 'running'
    : webUI.frontendRunning || webUI.backendRunning ? 'partial' : 'stopped';

  // ── Toast ──────────────────────────────────────────────────────────────────
  function showToast(msg, type = 'info') {
    toast = { msg, type };
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast = null, 3000);
  }

  // ── Setup wizard ───────────────────────────────────────────────────────────
  async function runStep(step) {
    setupRunning = true;
    setupError = '';
    setupMsg = `Running: ${stepLabels[step]}...`;
    try {
      const result = await RunSetupStep(step, setupUsername, setupPassword);
      if (result.error) {
        setupError = result.error;
      } else {
        setupMsg = result.message;
        if (result.done) {
          setupDone = true;
          setTimeout(() => { view = 'launcher'; initLauncher(); }, 2000);
        }
      }
    } catch (e) {
      setupError = String(e);
    } finally {
      setupRunning = false;
    }
  }

  async function runAllSteps() {
    for (let s = 1; s <= TOTAL_STEPS; s++) {
      setupStep = s;
      await runStep(s);
      if (setupError) break;
      await new Promise(r => setTimeout(r, 300));
    }
  }

  function skipSetup() {
    view = 'launcher';
    initLauncher();
  }

  // ── Launcher ───────────────────────────────────────────────────────────────
  async function initLauncher() {
    services = await GetServices();
    webUI = await GetWebUIState();
    stats = await GetSystemStats();
    binDir = await GetBinDir();
    siem = await GetSIEMState();
    siemPollTimer = setInterval(async () => { siem = await GetSIEMState(); }, 5000);
  }

  // ── SIEM handlers ──────────────────────────────────────────────────────────
  async function handleStartElastic() {
    siemBusy.elastic = true; siemBusy = siemBusy;
    const r = await StartElasticsearch();
    if (r) showToast(r, r.startsWith('Error') ? 'error' : 'success');
    setTimeout(async () => { siem = await GetSIEMState(); siemBusy.elastic = false; siemBusy = siemBusy; }, 3000);
  }
  async function handleStopElastic() {
    siemBusy.elastic = true; siemBusy = siemBusy;
    await StopElasticsearch();
    setTimeout(async () => { siem = await GetSIEMState(); siemBusy.elastic = false; siemBusy = siemBusy; }, 2000);
  }
  async function handleStartKibana() {
    siemBusy.kibana = true; siemBusy = siemBusy;
    const r = await StartKibana();
    if (r) showToast(r, r.startsWith('Error') ? 'error' : 'success');
    setTimeout(async () => { siem = await GetSIEMState(); siemBusy.kibana = false; siemBusy = siemBusy; }, 3000);
  }
  async function handleStopKibana() {
    siemBusy.kibana = true; siemBusy = siemBusy;
    await StopKibana();
    setTimeout(async () => { siem = await GetSIEMState(); siemBusy.kibana = false; siemBusy = siemBusy; }, 2000);
  }
  async function handleRunTemplates() {
    siemBusy.templates = true; siemBusy = siemBusy;
    const r = await RunESTemplates();
    showToast(r || 'Templates done', r && r.startsWith('Error') ? 'error' : 'success');
    siemBusy.templates = false; siemBusy = siemBusy;
  }
  async function handleChooseSIEMDir() {
    siemBusy.choosePath = true; siemBusy = siemBusy;
    const chosen = await ChooseSIEMDir();
    siemBusy.choosePath = false; siemBusy = siemBusy;
    if (chosen) { siem = await GetSIEMState(); showToast('SIEM path updated', 'success'); }
  }

  async function handleStart(id) {
    loadingIds = new Set([...loadingIds, id]);
    await StartService(id);
    setTimeout(() => { loadingIds = new Set([...loadingIds].filter(x => x !== id)); }, 2500);
  }

  async function handleStop(id) {
    loadingIds = new Set([...loadingIds, id]);
    await StopService(id);
    setTimeout(() => { loadingIds = new Set([...loadingIds].filter(x => x !== id)); }, 1500);
  }

  async function handleStartAll() { showToast('Starting all services...'); await StartAll(); }
  async function handleStopAll()  { showToast('Stopping all services...'); await StopAll(); }
  async function handleOpenConsole() { showToast('Opening browser...'); await OpenWebConsole(); }
  async function handleReadme() { await OpenReadme(); }

  // ── Lifecycle ──────────────────────────────────────────────────────────────
  onMount(async () => {
    const firstRun = await IsFirstRun();
    if (firstRun) {
      view = 'setup';
    } else {
      view = 'launcher';
      await initLauncher();
    }

    EventsOn('services:update', d => { services = d; });
    EventsOn('webui:update',    d => { webUI = d; });
    EventsOn('stats:update',    d => { stats = d; });
    EventsOn('setup:progress',  d => {
      setupMsg = d.message;
      if (d.error) setupError = d.error;
      if (d.done)  { setupDone = true; }
    });
  });

  onDestroy(() => {
    ['services:update','webui:update','stats:update','setup:progress'].forEach(EventsOff);
    if (toastTimer) clearTimeout(toastTimer);
    if (siemPollTimer) clearInterval(siemPollTimer);
  });
</script>

<!-- ── Root ───────────────────────────────────────────────────────────────── -->
<main>

  <!-- Toast -->
  {#if toast}
    <div class="toast toast-{toast.type}">{toast.msg}</div>
  {/if}

  <!-- ── Loading ─────────────────────────────────────────────────────────── -->
  {#if view === 'loading'}
    <div class="center-screen">
      <div class="spinner"></div>
      <p class="loading-text">Starting SafeOps...</p>
    </div>

  <!-- ── Setup Wizard ────────────────────────────────────────────────────── -->
  {:else if view === 'setup'}
    <div class="setup-root">
      <!-- Sidebar -->
      <div class="setup-sidebar">
        <div class="setup-logo">
          <span class="logo-icon-lg">🛡</span>
          <div>
            <div class="logo-title">SafeOps</div>
            <div class="logo-sub">First-time Setup</div>
          </div>
        </div>

        <div class="setup-steps-list">
          {#each stepLabels.slice(1) as label, i}
            {@const stepNum = i + 1}
            <div class="setup-step-item" class:step-active={setupStep === stepNum} class:step-done={setupStep > stepNum || setupDone}>
              <div class="step-num">
                {#if setupStep > stepNum || setupDone}✓{:else}{stepNum}{/if}
              </div>
              <span class="step-label">{label}</span>
            </div>
          {/each}
        </div>

        <div class="setup-sidebar-foot">
          <button class="btn-link" on:click={skipSetup}>Skip — already configured</button>
        </div>
      </div>

      <!-- Main content -->
      <div class="setup-content">
        {#if setupStep === 0}
          <!-- Welcome screen -->
          <div class="setup-welcome">
            <h1 class="setup-title">Welcome to SafeOps</h1>
            <p class="setup-desc">
              This wizard will install all required dependencies and configure SafeOps on your system.
            </p>

            <div class="setup-info-grid">
              <div class="info-card">
                <div class="info-icon">🐘</div>
                <div class="info-name">PostgreSQL 16</div>
                <div class="info-desc">Database server</div>
              </div>
              <div class="info-card">
                <div class="info-icon">🟢</div>
                <div class="info-name">Node.js 20 LTS</div>
                <div class="info-desc">JavaScript runtime</div>
              </div>
              <div class="info-card">
                <div class="info-icon">🔍</div>
                <div class="info-name">Elasticsearch 8</div>
                <div class="info-desc">SIEM data store</div>
              </div>
              <div class="info-card">
                <div class="info-icon">📊</div>
                <div class="info-name">Kibana 8</div>
                <div class="info-desc">SIEM visualization</div>
              </div>
            </div>

            <div class="setup-creds-section">
              <h3 class="creds-title">Admin Account Setup</h3>
              <p class="creds-desc">Create your default administrator credentials for the web dashboard.</p>
              <div class="creds-form">
                <label>
                  <span>Username</span>
                  <input type="text" bind:value={setupUsername} placeholder="admin" />
                </label>
                <label>
                  <span>Password</span>
                  <input type="password" bind:value={setupPassword} placeholder="safeops123" />
                </label>
              </div>
            </div>

            <div class="setup-note">
              ⚠ An internet connection is required to download installers.<br>
              Installation may take 10–20 minutes. Do not close this window.
            </div>

            <div class="setup-actions">
              <button class="btn-primary-lg" on:click={runAllSteps}>
                Start Installation
              </button>
              <button class="btn-ghost" on:click={skipSetup}>
                Skip (already installed)
              </button>
            </div>
          </div>

        {:else}
          <!-- Progress screen -->
          <div class="setup-progress-view">
            <h2 class="setup-title">Installing SafeOps</h2>

            <!-- Progress bar -->
            <div class="progress-bar-wrap">
              <div class="progress-bar-track">
                <div class="progress-bar-fill" style="width: {setupDone ? 100 : Math.round((setupStep-1)/TOTAL_STEPS*100)}%"></div>
              </div>
              <span class="progress-pct">{setupDone ? 100 : Math.round((setupStep-1)/TOTAL_STEPS*100)}%</span>
            </div>

            <!-- Current step -->
            <div class="step-status">
              {#if setupError}
                <div class="step-error">
                  <span class="err-icon">✕</span>
                  <div>
                    <div class="err-title">Step {setupStep} Failed</div>
                    <div class="err-msg">{setupError}</div>
                  </div>
                </div>
                <div class="step-error-hint">
                  You can retry, or skip to use SafeOps manually.
                </div>
                <div class="error-actions">
                  <button class="btn-primary-sm" on:click={runAllSteps} disabled={setupRunning}>Retry</button>
                  <button class="btn-ghost-sm" on:click={skipSetup}>Skip Setup</button>
                </div>
              {:else if setupDone}
                <div class="step-done-view">
                  <div class="done-icon">✓</div>
                  <h3>Installation Complete!</h3>
                  <p>SafeOps has been installed successfully. Opening launcher...</p>
                  <button class="btn-primary-sm mt-4" on:click={handleReadme}>
                    📄 View Getting Started Guide
                  </button>
                </div>
              {:else}
                <div class="step-running">
                  {#if setupRunning}<div class="spinner-sm"></div>{/if}
                  <div class="step-msg">{setupMsg || 'Preparing...'}</div>
                </div>
                <div class="steps-list-mini">
                  {#each stepLabels.slice(1) as label, i}
                    {@const n = i + 1}
                    <div class="step-mini" class:mini-active={n === setupStep} class:mini-done={n < setupStep}>
                      <span class="mini-dot">{n < setupStep ? '✓' : n === setupStep ? '●' : '○'}</span>
                      {label}
                    </div>
                  {/each}
                </div>
              {/if}
            </div>
          </div>
        {/if}
      </div>
    </div>

  <!-- ── Launcher ────────────────────────────────────────────────────────── -->
  {:else}
    <div class="launcher-root">
      <!-- Header -->
      <header class="launcher-header">
        <div class="header-logo">
          <span class="logo-icon-md">🛡</span>
          <div>
            <div class="logo-title">SafeOps</div>
            <div class="logo-sub">Network Security Platform</div>
          </div>
        </div>

        <!-- Status pills -->
        <div class="header-pills">
          <div class="pill pill-{runningCount > 0 ? 'green' : 'gray'}">
            {runningCount}/{services.length} Services
          </div>
          <div class="pill pill-{webUIStatus === 'running' ? 'green' : webUIStatus === 'partial' ? 'yellow' : 'gray'}">
            Web UI {webUIStatus === 'running' ? 'Online' : webUIStatus === 'partial' ? 'Partial' : 'Offline'}
          </div>
        </div>

        <!-- System stats -->
        <div class="header-stats">
          <div class="stat-chip" class:stat-warn={stats.cpuPercent > 70} class:stat-danger={stats.cpuPercent > 90}>
            <span class="stat-label">CPU</span>
            <span class="stat-val">{stats.cpuPercent.toFixed(1)}%</span>
          </div>
          <div class="stat-chip" class:stat-warn={stats.memPercent > 70} class:stat-danger={stats.memPercent > 90}>
            <span class="stat-label">RAM</span>
            <span class="stat-val">{stats.memUsedMB}MB</span>
          </div>
        </div>

        <!-- Actions -->
        <div class="header-actions">
          <button class="btn-sm btn-green" on:click={handleStartAll}>Start All</button>
          <button class="btn-sm btn-red-outline" on:click={handleStopAll}>Stop All</button>
          <button class="btn-sm btn-blue" on:click={handleOpenConsole}>🌐 Open Console</button>
          <button class="btn-sm btn-ghost-sm" on:click={handleReadme} title="View getting started guide">📄</button>
        </div>
      </header>

      <!-- Scrollable content -->
      <div class="launcher-body">

        <!-- Web UI Card -->
        <section class="group-section">
          <div class="group-label">
            <span>🖥</span>
            <span class="glabel-name">Web Console</span>
            <span class="glabel-badge badge-auto">Auto-Start</span>
          </div>
          <div class="webui-card">
            <div class="webui-left">
              <div class="webui-title">SafeOps Dashboard</div>
              <div class="webui-desc">React management UI + Node.js API proxy</div>
              <div class="webui-ports">
                <span class="port-tag">:3001 UI</span>
                <span class="port-tag">:5050 API</span>
              </div>
              <div class="webui-subs">
                <div class="sub-row">
                  <span class="dot {webUI.frontendRunning ? 'dot-on' : 'dot-off'}"></span>
                  <span>Frontend</span>
                  {#if webUI.frontendPid}<span class="pid">PID {webUI.frontendPid}</span>{/if}
                </div>
                <div class="sub-row">
                  <span class="dot {webUI.backendRunning ? 'dot-on' : 'dot-off'}"></span>
                  <span>Backend</span>
                  {#if webUI.backendPid}<span class="pid">PID {webUI.backendPid}</span>{/if}
                </div>
              </div>
            </div>
            <div class="webui-right">
              <div class="status-badge badge-{webUIStatus}">
                {webUIStatus === 'running' ? '● Running' : webUIStatus === 'partial' ? '◑ Partial' : '○ Stopped'}
              </div>
              <div class="webui-btns">
                {#if webUIStatus !== 'running'}
                  <button class="btn-sm btn-green" on:click={StartWebUI}>Start</button>
                {:else}
                  <button class="btn-sm btn-ghost-sm" on:click={StopWebUI}>Stop</button>
                {/if}
                <button class="btn-sm btn-blue" on:click={handleOpenConsole}>🌐 Open</button>
              </div>
            </div>
          </div>
        </section>

        <!-- SIEM Stack Section -->
        <section class="group-section">
          <div class="group-label">
            <span>🗄</span>
            <span class="glabel-name">SIEM Stack</span>
            <span class="glabel-count">{(siem.elasticRunning ? 1 : 0) + (siem.kibanaRunning ? 1 : 0)}/2</span>
            <button class="siem-path-btn" on:click={handleChooseSIEMDir} disabled={siemBusy.choosePath} title="Set SIEM scripts directory">
              {siemBusy.choosePath ? '...' : '📁 ' + (siem.siemDir ? siem.siemDir.split(/[\\/]/).slice(-2).join('/') : 'Set path...')}
            </button>
          </div>

          {#if !siem.hasScripts}
            <!-- Blinking "choose path first" banner -->
            <button class="siem-choose-banner" on:click={handleChooseSIEMDir} disabled={siemBusy.choosePath}>
              <span class="siem-banner-icon">📁</span>
              <div class="siem-banner-text">
                <div class="siem-banner-title">CHOOSE SIEM SCRIPTS LOCATION FIRST</div>
                <div class="siem-banner-sub">Click here to select the folder containing 1-start-elasticsearch.bat and 2-start-kibana.bat</div>
              </div>
              <span class="siem-banner-arrow">›</span>
            </button>

          {:else}
            <!-- First-time setup notice (templates not configured yet) -->
            {#if !siem.templatesConfigured}
              <div class="siem-setup-notice">
                <span class="siem-notice-icon">⚠</span>
                <div class="siem-notice-body">
                  <div class="siem-notice-title">First-Time SIEM Setup Required</div>
                  <div class="siem-notice-desc">Start Elasticsearch first, then click "⚙ Setup Templates" to configure the index templates for log ingestion.</div>
                </div>
                <button class="btn-sm btn-ghost-sm" on:click={handleRunTemplates} disabled={siemBusy.templates || !siem.elasticRunning}>
                  {siemBusy.templates ? '⏳ Running...' : '⚙ Setup Templates'}
                </button>
              </div>
            {/if}

            <div class="siem-grid">
              <!-- Elasticsearch card -->
              <div class="siem-card" class:siem-card-on={siem.elasticRunning} class:siem-card-starting={siem.elasticStarting}>
                <div class="siem-card-head">
                  <span class="siem-icon">🔍</span>
                  <div class="siem-meta">
                    <div class="siem-name">Elasticsearch</div>
                    <div class="siem-desc">SIEM data store · log indexing</div>
                    <div class="siem-port">:9200 REST</div>
                  </div>
                </div>
                <div class="siem-card-foot">
                  {#if siem.elasticStarting}
                    <div class="siem-progress">
                      <div class="siem-progress-bar"></div>
                    </div>
                    <span class="siem-starting-label">Starting Elasticsearch... (may take 30–60s)</span>
                  {:else}
                    <div class="card-tags">
                      <span class="status-badge badge-{siem.elasticRunning ? 'running' : 'stopped'}">
                        {siem.elasticRunning ? '● Running' : '○ Stopped'}
                      </span>
                    </div>
                  {/if}
                  <div class="siem-btns">
                    {#if !siem.elasticRunning && !siem.elasticStarting}
                      <button class="btn-sm btn-green-sm" on:click={handleStartElastic} disabled={siemBusy.elastic}>▶ Start</button>
                    {:else if siem.elasticRunning}
                      <button class="btn-sm btn-red-sm" on:click={handleStopElastic} disabled={siemBusy.elastic}>■ Stop</button>
                    {/if}
                    {#if siem.templatesConfigured}
                      <button class="btn-sm btn-ghost-sm" on:click={handleRunTemplates} disabled={siemBusy.templates || !siem.elasticRunning} title="Re-run index template setup">
                        {siemBusy.templates ? '...' : '⚙ Templates'}
                      </button>
                    {/if}
                  </div>
                </div>
              </div>

              <!-- Kibana card -->
              <div class="siem-card" class:siem-card-on={siem.kibanaRunning} class:siem-card-starting={siem.kibanaStarting}>
                <div class="siem-card-head">
                  <span class="siem-icon">📊</span>
                  <div class="siem-meta">
                    <div class="siem-name">Kibana</div>
                    <div class="siem-desc">SIEM dashboards & visualization</div>
                    <div class="siem-port">:5601 Web UI</div>
                  </div>
                </div>
                <div class="siem-card-foot">
                  {#if siem.kibanaStarting}
                    <div class="siem-progress">
                      <div class="siem-progress-bar"></div>
                    </div>
                    <span class="siem-starting-label">Starting Kibana... (may take 1–2 min)</span>
                  {:else}
                    <div class="card-tags">
                      <span class="status-badge badge-{siem.kibanaRunning ? 'running' : 'stopped'}">
                        {siem.kibanaRunning ? '● Running' : '○ Stopped'}
                      </span>
                    </div>
                  {/if}
                  <div class="siem-btns">
                    {#if !siem.kibanaRunning && !siem.kibanaStarting}
                      <button class="btn-sm btn-green-sm" on:click={handleStartKibana} disabled={siemBusy.kibana}>▶ Start</button>
                    {:else if siem.kibanaRunning}
                      <button class="btn-sm btn-red-sm" on:click={handleStopKibana} disabled={siemBusy.kibana}>■ Stop</button>
                    {/if}
                    <button class="btn-sm btn-blue" on:click={OpenKibana} disabled={!siem.kibanaRunning}>🌐 Open</button>
                  </div>
                </div>
              </div>
            </div>
          {/if}
        </section>

        <!-- Prerequisites Verification -->
        <section class="group-section">
          <div class="group-label">
            <span>🔍</span>
            <span class="glabel-name">Prerequisites</span>
            <button class="btn-sm btn-ghost-sm" on:click={handleVerifyPrereqs} disabled={prereqChecking}>
              {prereqChecking ? '⏳ Checking...' : '🔄 Verify'}
            </button>
          </div>
          {#if prereqChecking}
            <div class="prereq-card">
              <div class="siem-progress"><div class="siem-progress-bar"></div></div>
              <span class="siem-starting-label">Verifying PostgreSQL, Elasticsearch, and SIEM configuration...</span>
            </div>
          {:else if prereq}
            <div class="prereq-grid">
              <!-- PostgreSQL -->
              <div class="prereq-item" class:prereq-ok={prereq.postgresOK && (!prereq.dbsMissing || prereq.dbsMissing.length === 0)} class:prereq-warn={prereq.postgresOK && prereq.dbsMissing && prereq.dbsMissing.length > 0} class:prereq-fail={!prereq.postgresOK}>
                <span class="prereq-icon">{prereq.postgresOK ? (prereq.dbsMissing && prereq.dbsMissing.length > 0 ? '⚠' : '✓') : '✕'}</span>
                <div class="prereq-info">
                  <div class="prereq-name">PostgreSQL</div>
                  <div class="prereq-detail">
                    {#if !prereq.postgresOK}
                      Not running
                    {:else if prereq.dbsMissing && prereq.dbsMissing.length > 0}
                      Missing: {prereq.dbsMissing.join(', ')}
                    {:else}
                      All databases OK
                    {/if}
                  </div>
                </div>
                {#if prereq.postgresOK && prereq.dbsMissing && prereq.dbsMissing.length > 0}
                  <button class="btn-sm btn-green-sm" on:click={handleFixDBs} disabled={prereqFixing === 'db'}>
                    {prereqFixing === 'db' ? '⏳...' : '🔧 Fix'}
                  </button>
                {/if}
              </div>

              <!-- Elasticsearch -->
              <div class="prereq-item" class:prereq-ok={prereq.elasticOK && (!prereq.indicesMissing || prereq.indicesMissing.length === 0)} class:prereq-warn={prereq.elasticOK && prereq.indicesMissing && prereq.indicesMissing.length > 0} class:prereq-fail={!prereq.elasticOK}>
                <span class="prereq-icon">{prereq.elasticOK ? (prereq.indicesMissing && prereq.indicesMissing.length > 0 ? '⚠' : '✓') : '✕'}</span>
                <div class="prereq-info">
                  <div class="prereq-name">Elasticsearch</div>
                  <div class="prereq-detail">
                    {#if !prereq.elasticOK}
                      Not running (start ES first)
                    {:else if prereq.indicesMissing && prereq.indicesMissing.length > 0}
                      Missing: {prereq.indicesMissing.join(', ')}
                    {:else}
                      All indices OK
                    {/if}
                  </div>
                </div>
                {#if prereq.elasticOK && prereq.indicesMissing && prereq.indicesMissing.length > 0}
                  <button class="btn-sm btn-green-sm" on:click={handleFixIndices} disabled={prereqFixing === 'es'}>
                    {prereqFixing === 'es' ? '⏳...' : '🔧 Fix'}
                  </button>
                {/if}
              </div>

              <!-- SIEM Dir -->
              <div class="prereq-item" class:prereq-ok={prereq.siemDirOK} class:prereq-fail={!prereq.siemDirOK}>
                <span class="prereq-icon">{prereq.siemDirOK ? '✓' : '✕'}</span>
                <div class="prereq-info">
                  <div class="prereq-name">SIEM Scripts</div>
                  <div class="prereq-detail">{prereq.siemDirOK ? 'Scripts found' : 'Not configured — set path above'}</div>
                </div>
              </div>
            </div>
            {#if prereq.error}
              <div class="card-err-msg" style="margin-top:6px">{prereq.error}</div>
            {/if}
          {:else}
            <div class="prereq-card">
              <span class="siem-starting-label">Click "Verify" to check PostgreSQL databases, ES indices, and SIEM configuration.</span>
            </div>
          {/if}
        </section>

        <!-- Service groups -->
        {#each grouped as group}
          <section class="group-section">
            <div class="group-label">
              <span>{group.icon}</span>
              <span class="glabel-name">{group.name}</span>
              <span class="glabel-count">{group.services.filter(s=>s.status==='running').length}/{group.services.length}</span>
            </div>
            <div class="svc-grid">
              {#each group.services as svc}
                {@const busy = loadingIds.has(svc.config.id)}
                {@const icon = svcIcons[svc.config.id] || '⚙'}
                <div class="svc-card"
                  class:card-on={svc.status === 'running'}
                  class:card-err={svc.status === 'error'}
                  class:card-starting={svc.status === 'starting'}
                >
                  <!-- Card header -->
                  <div class="card-head">
                    <span class="svc-icon">{icon}</span>
                    <div class="svc-meta">
                      <div class="svc-name">{svc.config.name}</div>
                      <div class="svc-desc">{svc.config.description}</div>
                      {#if svc.config.portLabel}
                        <div class="svc-port">{svc.config.portLabel}</div>
                      {/if}
                    </div>
                  </div>

                  <!-- Card footer -->
                  <div class="card-foot">
                    {#if svc.status === 'starting'}
                      <div class="siem-progress"><div class="siem-progress-bar"></div></div>
                      <span class="siem-starting-label">Starting {svc.config.name}...</span>
                    {:else}
                      <div class="card-tags">
                        <span class="status-badge badge-{svc.status}">
                          {svc.status === 'running' ? '● Running'
                          : svc.status === 'error' ? '✕ Error'
                          : '○ Stopped'}
                        </span>
                        {#if svc.pid}<span class="pid">PID {svc.pid}</span>{/if}
                        {#if svc.config.needsAdmin}<span class="tag tag-admin">Admin</span>{/if}
                        {#if svc.config.autoStart}<span class="tag tag-auto">Auto</span>{/if}
                      </div>
                    {/if}
                    {#if svc.error}<div class="card-err-msg">{svc.error}</div>{/if}
                    <div class="card-action">
                      {#if svc.status === 'stopped' || svc.status === 'error'}
                        <button class="btn-sm btn-green-sm" on:click={() => handleStart(svc.config.id)} disabled={busy}>
                          {busy ? '...' : '▶ Start'}
                        </button>
                      {:else if svc.status === 'running'}
                        <button class="btn-sm btn-red-sm" on:click={() => handleStop(svc.config.id)} disabled={busy}>
                          {busy ? '...' : '■ Stop'}
                        </button>
                      {:else}
                        <button class="btn-sm btn-ghost-sm" disabled>⏳</button>
                      {/if}
                      {#if svc.config.id === 'firewall-engine'}
                        <button class="btn-sm btn-orange" on:click={OpenFirewallUI} title="Open Firewall Engine web UI">
                          🔥 Open UI
                        </button>
                      {/if}
                    </div>
                  </div>
                </div>
              {/each}
            </div>
          </section>
        {/each}

        <!-- Footer -->
        <div class="launcher-footer">
          <span class="footer-path">{binDir || 'detecting...'}</span>
          <span class="footer-ver">SafeOps v1.0 · Administrator</span>
        </div>
      </div>
    </div>
  {/if}

</main>

<style>
  :global(*) { box-sizing: border-box; margin: 0; padding: 0; }
  :global(html, body) { height: 100%; background: #0d1117; color: #e6edf3;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; overflow: hidden; }

  main { height: 100vh; display: flex; flex-direction: column; }

  /* ── Toast ─────────────────────────────────────────────────────────────── */
  .toast {
    position: fixed; top: 54px; right: 16px; z-index: 999;
    padding: 9px 16px; border-radius: 8px; font-size: 13px; font-weight: 500;
    box-shadow: 0 4px 16px rgba(0,0,0,.5); animation: slidein .18s ease;
  }
  .toast-info    { background: #1f6feb; color: #fff; }
  .toast-error   { background: #da3633; color: #fff; }
  .toast-success { background: #238636; color: #fff; }
  @keyframes slidein { from { opacity:0; transform:translateY(-8px); } to { opacity:1; transform:none; } }

  /* ── Loading ───────────────────────────────────────────────────────────── */
  .center-screen { display:flex; flex-direction:column; align-items:center; justify-content:center; height:100vh; gap:16px; }
  .spinner { width:36px; height:36px; border:3px solid #21262d; border-top-color:#2563eb; border-radius:50%; animation: spin .8s linear infinite; }
  .spinner-sm { width:18px; height:18px; border:2px solid #21262d; border-top-color:#2563eb; border-radius:50%; animation: spin .8s linear infinite; flex-shrink:0; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .loading-text { color:#6e7681; font-size:14px; }

  /* ── Shared ────────────────────────────────────────────────────────────── */
  .logo-icon-lg { font-size:44px; }
  .logo-icon-md { font-size:28px; }
  .logo-title { font-size:18px; font-weight:700; color:#e6edf3; letter-spacing:-.3px; }
  .logo-sub   { font-size:11px; color:#6e7681; }

  .btn-primary-lg { background:#2563eb; border:1px solid #3b82f6; color:#fff;
    padding:12px 28px; border-radius:8px; font-size:15px; font-weight:600; cursor:pointer; transition:background .15s; }
  .btn-primary-lg:hover { background:#3b82f6; }
  .btn-primary-sm { background:#2563eb; border:1px solid #3b82f6; color:#fff;
    padding:8px 18px; border-radius:6px; font-size:13px; font-weight:500; cursor:pointer; transition:background .15s; }
  .btn-primary-sm:hover:not(:disabled) { background:#3b82f6; }
  .btn-ghost { background:transparent; border:1px solid #30363d; color:#8b949e;
    padding:12px 24px; border-radius:8px; font-size:13px; cursor:pointer; transition:all .15s; }
  .btn-ghost:hover { border-color:#6e7681; color:#e6edf3; }
  .btn-ghost-sm { background:transparent; border:1px solid #30363d; color:#8b949e;
    padding:6px 12px; border-radius:6px; font-size:12px; cursor:pointer; transition:all .15s; }
  .btn-ghost-sm:hover:not(:disabled) { border-color:#6e7681; color:#e6edf3; }
  .btn-link { background:none; border:none; color:#6e7681; font-size:12px; cursor:pointer; padding:4px 8px; text-decoration:underline; }
  .btn-link:hover { color:#8b949e; }
  .mt-4 { margin-top:16px; }

  /* ── Setup Wizard ──────────────────────────────────────────────────────── */
  .setup-root { display:flex; height:100vh; }

  .setup-sidebar {
    width:220px; flex-shrink:0; background:#0d1117; border-right:1px solid #21262d;
    display:flex; flex-direction:column; padding:20px 0;
  }
  .setup-logo { display:flex; align-items:center; gap:10px; padding:0 16px 20px; border-bottom:1px solid #21262d; }

  .setup-steps-list { flex:1; padding:16px 12px; display:flex; flex-direction:column; gap:4px; overflow-y:auto; }
  .setup-step-item { display:flex; align-items:center; gap:10px; padding:8px 10px; border-radius:7px; transition:background .15s; }
  .setup-step-item.step-active { background:#1f2937; }
  .setup-step-item.step-done .step-num { background:#238636; border-color:#2ea043; color:#fff; }
  .step-num { width:22px; height:22px; border-radius:50%; border:1.5px solid #30363d; background:#0d1117;
    display:flex; align-items:center; justify-content:center; font-size:11px; font-weight:700; color:#8b949e; flex-shrink:0; }
  .setup-step-item.step-active .step-num { border-color:#2563eb; color:#60a5fa; }
  .step-label { font-size:12px; color:#8b949e; }
  .setup-step-item.step-active .step-label { color:#e6edf3; }

  .setup-sidebar-foot { padding:16px 16px 0; border-top:1px solid #21262d; }

  .setup-content { flex:1; overflow-y:auto; padding:40px 48px; background:#0d1117; }

  .setup-title { font-size:26px; font-weight:700; color:#e6edf3; margin-bottom:10px; }
  .setup-desc  { font-size:14px; color:#8b949e; margin-bottom:28px; line-height:1.6; }

  .setup-info-grid { display:grid; grid-template-columns:repeat(2,1fr); gap:12px; margin-bottom:28px; }
  .info-card { background:#161b22; border:1px solid #21262d; border-radius:10px; padding:16px; }
  .info-icon { font-size:28px; margin-bottom:6px; }
  .info-name { font-size:14px; font-weight:600; color:#e6edf3; }
  .info-desc { font-size:12px; color:#6e7681; margin-top:2px; }

  .setup-creds-section { background:#161b22; border:1px solid #21262d; border-radius:10px; padding:20px; margin-bottom:24px; }
  .creds-title { font-size:14px; font-weight:600; color:#e6edf3; margin-bottom:6px; }
  .creds-desc  { font-size:12px; color:#8b949e; margin-bottom:16px; }
  .creds-form  { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
  .creds-form label { display:flex; flex-direction:column; gap:5px; }
  .creds-form label span { font-size:12px; color:#8b949e; }
  .creds-form input {
    background:#0d1117; border:1px solid #30363d; border-radius:6px; padding:8px 10px;
    color:#e6edf3; font-size:13px; outline:none; transition:border .15s;
  }
  .creds-form input:focus { border-color:#2563eb; }

  .setup-note { background:#1f1700; border:1px solid #d2992233; border-radius:8px; padding:12px 14px; font-size:12px; color:#d29922; line-height:1.6; margin-bottom:24px; }
  .setup-actions { display:flex; gap:12px; align-items:center; flex-wrap:wrap; }

  /* Progress view */
  .setup-progress-view { max-width:640px; }
  .progress-bar-wrap { display:flex; align-items:center; gap:12px; margin:20px 0 28px; }
  .progress-bar-track { flex:1; height:6px; background:#21262d; border-radius:3px; overflow:hidden; }
  .progress-bar-fill { height:100%; background:linear-gradient(90deg,#1d4ed8,#2563eb); border-radius:3px; transition:width .4s ease; }
  .progress-pct { font-size:13px; color:#8b949e; width:36px; text-align:right; }

  .step-status { display:flex; flex-direction:column; gap:16px; }
  .step-running { display:flex; align-items:center; gap:12px; font-size:14px; color:#8b949e; }
  .step-msg { font-size:14px; color:#8b949e; }

  .step-error { display:flex; align-items:flex-start; gap:12px; background:#1a0a0a; border:1px solid #da363333; border-radius:8px; padding:16px; }
  .err-icon { font-size:18px; color:#f85149; }
  .err-title { font-size:14px; font-weight:600; color:#f85149; margin-bottom:4px; }
  .err-msg { font-size:12px; color:#da3633; }
  .step-error-hint { font-size:12px; color:#6e7681; }
  .error-actions { display:flex; gap:10px; }

  .step-done-view { display:flex; flex-direction:column; align-items:center; text-align:center; padding:32px; gap:10px; }
  .done-icon { font-size:56px; background:#0f2a1a; border:2px solid #2ea043; border-radius:50%; width:80px; height:80px; display:flex; align-items:center; justify-content:center; color:#2ea043; }
  .step-done-view h3 { font-size:20px; font-weight:700; color:#2ea043; }
  .step-done-view p { color:#8b949e; font-size:13px; }

  .steps-list-mini { display:flex; flex-direction:column; gap:6px; margin-top:8px; padding:14px 16px; background:#161b22; border-radius:8px; }
  .step-mini { display:flex; align-items:center; gap:8px; font-size:12px; color:#6e7681; }
  .step-mini.mini-done { color:#2ea043; }
  .step-mini.mini-active { color:#e6edf3; font-weight:500; }
  .mini-dot { width:16px; font-size:12px; }

  /* ── Launcher ──────────────────────────────────────────────────────────── */
  .launcher-root { display:flex; flex-direction:column; height:100vh; }

  .launcher-header {
    display:flex; align-items:center; gap:14px; flex-wrap:wrap;
    padding:10px 18px; background:#161b22; border-bottom:1px solid #21262d; flex-shrink:0;
  }
  .header-logo { display:flex; align-items:center; gap:10px; margin-right:4px; }
  .header-pills { display:flex; gap:8px; flex-wrap:wrap; }
  .pill { padding:4px 10px; border-radius:20px; font-size:11px; font-weight:600; border:1px solid; }
  .pill-green  { background:#0f2a1a; color:#2ea043; border-color:#2ea04333; }
  .pill-yellow { background:#1f1700; color:#d29922; border-color:#d2992233; }
  .pill-gray   { background:#21262d; color:#6e7681; border-color:#30363d; }

  .header-stats { display:flex; gap:8px; margin-left:auto; }
  .stat-chip { display:flex; align-items:center; gap:5px; padding:4px 10px; background:#21262d; border:1px solid #30363d; border-radius:6px; }
  .stat-label { font-size:11px; color:#6e7681; }
  .stat-val   { font-size:12px; font-weight:700; color:#58a6ff; font-variant-numeric:tabular-nums; }
  .stat-warn  .stat-val { color:#d29922; }
  .stat-danger .stat-val { color:#f85149; }

  .header-actions { display:flex; gap:6px; flex-wrap:wrap; }

  /* Buttons (launcher) */
  .btn-sm { padding:6px 13px; border-radius:6px; border:1px solid transparent; font-size:12px; font-weight:500; cursor:pointer; transition:all .15s; white-space:nowrap; }
  .btn-sm:disabled { opacity:.5; cursor:not-allowed; }
  .btn-green { background:#238636; border-color:#2ea043; color:#fff; }
  .btn-green:hover { background:#2ea043; }
  .btn-blue { background:#1d4ed8; border-color:#2563eb; color:#fff; }
  .btn-blue:hover { background:#2563eb; }
  .btn-red-outline { background:transparent; border-color:#da3633; color:#f85149; }
  .btn-red-outline:hover { background:#da363318; }
  .btn-green-sm { background:#1a4a2a; border:1px solid #2ea04360; color:#2ea043; padding:5px 10px; border-radius:5px; font-size:11px; cursor:pointer; transition:all .15s; }
  .btn-green-sm:hover:not(:disabled) { background:#238636; color:#fff; border-color:#2ea043; }
  .btn-red-sm { background:#2a1a1a; border:1px solid #da363360; color:#f85149; padding:5px 10px; border-radius:5px; font-size:11px; cursor:pointer; transition:all .15s; }
  .btn-red-sm:hover:not(:disabled) { background:#da3633; color:#fff; border-color:#da3633; }

  /* Scrollable body */
  .launcher-body { flex:1; overflow-y:auto; padding:14px 18px 20px; display:flex; flex-direction:column; gap:16px; }
  .launcher-body::-webkit-scrollbar { width:5px; }
  .launcher-body::-webkit-scrollbar-track { background:transparent; }
  .launcher-body::-webkit-scrollbar-thumb { background:#30363d; border-radius:3px; }

  /* Group section */
  .group-section { display:flex; flex-direction:column; gap:8px; }
  .group-label { display:flex; align-items:center; gap:7px; font-size:11px; font-weight:700; color:#6e7681;
    text-transform:uppercase; letter-spacing:.5px; padding-bottom:3px; border-bottom:1px solid #21262d; }
  .glabel-name { flex:1; }
  .glabel-count { font-size:10px; background:#21262d; border-radius:4px; padding:1px 6px; font-variant-numeric:tabular-nums; }
  .glabel-badge { font-size:10px; border-radius:4px; padding:1px 6px; text-transform:none; letter-spacing:0; font-weight:500; }
  .badge-auto { background:#0f2a1a; color:#2ea043; border:1px solid #2ea04333; }

  /* Web UI card */
  .webui-card { background:#161b22; border:1px solid #21262d; border-radius:10px; padding:14px 16px;
    display:flex; justify-content:space-between; align-items:center; gap:16px; }
  .webui-left { flex:1; display:flex; flex-direction:column; gap:8px; }
  .webui-title { font-size:14px; font-weight:600; color:#e6edf3; }
  .webui-desc  { font-size:12px; color:#6e7681; }
  .webui-ports { display:flex; gap:5px; flex-wrap:wrap; }
  .port-tag { font-size:11px; background:#21262d; border-radius:4px; padding:1px 7px; color:#8b949e; font-family:monospace; }
  .webui-subs { display:flex; gap:14px; flex-wrap:wrap; }
  .sub-row { display:flex; align-items:center; gap:5px; font-size:11px; color:#8b949e; }
  .webui-right { display:flex; flex-direction:column; align-items:flex-end; gap:8px; }
  .webui-btns { display:flex; gap:6px; }

  /* Dot indicators */
  .dot { width:6px; height:6px; border-radius:50%; display:inline-block; flex-shrink:0; }
  .dot-on  { background:#2ea043; box-shadow:0 0 4px #2ea043; }
  .dot-off { background:#444c56; }

  /* Status badges */
  .status-badge { font-size:11px; font-weight:600; padding:2px 8px; border-radius:5px; white-space:nowrap; }
  .badge-running  { background:#2ea04320; color:#2ea043; border:1px solid #2ea04340; }
  .badge-starting { background:#d2992220; color:#d29922; border:1px solid #d2992240; }
  .badge-stopped  { background:#21262d;   color:#6e7681; border:1px solid #30363d; }
  .badge-error    { background:#da363320; color:#f85149; border:1px solid #da363340; }
  .badge-partial  { background:#d2992220; color:#d29922; border:1px solid #d2992240; }

  /* Service grid */
  .svc-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:8px; }

  .svc-card { background:#161b22; border:1px solid #21262d; border-radius:10px; padding:13px;
    display:flex; flex-direction:column; gap:10px; transition:border-color .2s; }
  .svc-card:hover { border-color:#444c56; }
  .card-on  { border-color:#2ea04330 !important; }
  .card-err { border-color:#da363330; }

  .card-head { display:flex; gap:9px; align-items:flex-start; }
  .svc-icon  { font-size:20px; flex-shrink:0; line-height:1; }
  .svc-meta  { flex:1; }
  .svc-name  { font-size:13px; font-weight:600; color:#e6edf3; }
  .svc-desc  { font-size:11px; color:#6e7681; margin-top:2px; line-height:1.3; }
  .svc-port  { font-size:10px; color:#58a6ff; margin-top:3px; font-family:monospace; }

  .card-foot  { display:flex; flex-direction:column; gap:6px; }
  .card-tags  { display:flex; align-items:center; gap:5px; flex-wrap:wrap; }
  .card-err-msg { font-size:10px; color:#f85149; background:#da363311; border-radius:4px; padding:3px 6px; }
  .card-action { display:flex; justify-content:flex-end; }

  .pid { font-size:9px; color:#444c56; font-family:monospace; }
  .tag { font-size:9px; border-radius:4px; padding:1px 5px; font-weight:600; }
  .tag-admin { background:#1d3461; color:#58a6ff; border:1px solid #1f6feb33; }
  .tag-auto  { background:#0f2a1a; color:#2ea043; border:1px solid #2ea04333; }

  /* Footer */
  .launcher-footer { display:flex; justify-content:space-between; font-size:10px; color:#444c56;
    padding-top:6px; border-top:1px solid #21262d; font-family:monospace; }

  /* Orange "Open UI" button */
  .btn-orange { background:#7c2d04; border:1px solid #c2410c; color:#fb923c; padding:5px 10px; border-radius:5px; font-size:11px; cursor:pointer; transition:all .15s; }
  .btn-orange:hover { background:#c2410c; color:#fff; border-color:#ea580c; }

  /* SIEM path button in group label */
  .siem-path-btn { margin-left:auto; background:#161b22; border:1px solid #30363d; color:#8b949e; padding:2px 9px; border-radius:5px; font-size:10px; cursor:pointer; transition:all .15s; max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .siem-path-btn:hover:not(:disabled) { border-color:#58a6ff; color:#58a6ff; }

  /* SIEM choose-path blinking banner */
  .siem-choose-banner {
    display:flex; align-items:center; gap:14px; width:100%;
    background:linear-gradient(135deg, #1a0d00, #2a1500);
    border:2px solid #f97316; border-radius:10px; padding:16px 20px;
    cursor:pointer; text-align:left; animation: siem-pulse 1.6s ease-in-out infinite;
    transition:all .2s;
  }
  .siem-choose-banner:hover:not(:disabled) { background:linear-gradient(135deg, #2a1500, #3d1f00); border-color:#fb923c; }
  @keyframes siem-pulse {
    0%,100% { box-shadow: 0 0 0 0 #f9731640; }
    50%      { box-shadow: 0 0 0 8px #f9731600; }
  }
  .siem-banner-icon { font-size:28px; flex-shrink:0; }
  .siem-banner-text { flex:1; }
  .siem-banner-title { font-size:14px; font-weight:800; color:#fb923c; letter-spacing:.5px; text-transform:uppercase; margin-bottom:4px; }
  .siem-banner-sub   { font-size:11px; color:#fde68a; opacity:.9; }
  .siem-banner-arrow { font-size:24px; color:#f97316; font-weight:700; }

  /* SIEM first-time setup notice */
  .siem-setup-notice {
    display:flex; align-items:center; gap:10px;
    background:#0d1a0d; border:1px solid #2ea04360; border-radius:8px; padding:10px 14px; margin-bottom:4px;
  }
  .siem-notice-icon { font-size:18px; flex-shrink:0; }
  .siem-notice-body { flex:1; }
  .siem-notice-title { font-size:12px; font-weight:700; color:#2ea043; }
  .siem-notice-desc  { font-size:11px; color:#6e7681; margin-top:2px; }

  /* SIEM progress bar (indeterminate) */
  .siem-progress { height:3px; background:#21262d; border-radius:2px; overflow:hidden; margin-bottom:4px; }
  .siem-progress-bar { height:100%; background:linear-gradient(90deg,transparent,#2563eb,transparent); width:60%; animation: siem-scan 1.5s ease-in-out infinite; }
  @keyframes siem-scan { 0% { margin-left:-60%; } 100% { margin-left:160%; } }
  .siem-starting-label { font-size:10px; color:#6e7681; font-style:italic; }

  /* SIEM card starting state */
  .siem-card-starting { border-color:#2563eb40 !important; }

  /* SIEM no scripts warning (fallback) */
  .siem-no-scripts { display:flex; gap:8px; align-items:center; background:#1f1700; border:1px solid #d2992233; border-radius:8px; padding:10px 14px; font-size:12px; color:#d29922; }

  /* SIEM grid */
  .siem-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(260px,1fr)); gap:8px; }

  .siem-card { background:#161b22; border:1px solid #21262d; border-radius:10px; padding:13px; display:flex; flex-direction:column; gap:10px; transition:border-color .2s; }
  .siem-card:hover { border-color:#444c56; }
  .siem-card-on { border-color:#2ea04330 !important; }

  .siem-card-head { display:flex; gap:9px; align-items:flex-start; }
  .siem-icon { font-size:22px; flex-shrink:0; line-height:1; }
  .siem-meta { flex:1; }
  .siem-name { font-size:13px; font-weight:600; color:#e6edf3; }
  .siem-desc { font-size:11px; color:#6e7681; margin-top:2px; }
  .siem-port { font-size:10px; color:#58a6ff; margin-top:3px; font-family:monospace; }

  .siem-card-foot { display:flex; flex-direction:column; gap:6px; }
  .siem-btns { display:flex; gap:6px; justify-content:flex-end; }

  /* ── Prerequisites section ──────────────────────────────────────────── */
  .prereq-card { background:#161b22; border:1px solid #21262d; border-radius:10px; padding:12px 14px; }
  .prereq-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:8px; }
  .prereq-item { display:flex; align-items:center; gap:9px; background:#161b22; border:1px solid #21262d; border-radius:10px; padding:10px 13px; transition:border-color .2s; }
  .prereq-ok   { border-color:#2ea04340 !important; }
  .prereq-warn { border-color:#d2992240 !important; }
  .prereq-fail { border-color:#da363340 !important; }
  .prereq-icon { font-size:16px; font-weight:700; flex-shrink:0; width:20px; text-align:center; }
  .prereq-ok .prereq-icon   { color:#2ea043; }
  .prereq-warn .prereq-icon { color:#d29922; }
  .prereq-fail .prereq-icon { color:#f85149; }
  .prereq-info { flex:1; }
  .prereq-name   { font-size:12px; font-weight:600; color:#e6edf3; }
  .prereq-detail { font-size:10px; color:#6e7681; margin-top:1px; }

  /* ── Service card starting state ────────────────────────────────────── */
  .svc-card.card-starting { border-color:#2563eb40 !important; }
</style>
