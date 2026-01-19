// ============================================================================
// SafeOps Captive Portal - Trust Verification Script
// ============================================================================
// File: D:\SafeOpsFV2\src\captive_portal\internal\static\js\verify.js
// Purpose: Client-side JavaScript for OS detection, UI interactions, and
//          automatic/manual trust verification polling
//
// Features:
//   - Auto-detect client OS from User-Agent
//   - Show platform-specific installation instructions
//   - Poll server to verify certificate installation
//   - Manual "I've Installed" button handling
//   - Error handling and retry logic
//
// Author: SafeOps Phase 3A
// Date: 2026-01-03
// ============================================================================

(function () {
    'use strict';

    // ========================================================================
    // Configuration
    // ========================================================================

    const CONFIG = {
        // How often to poll for trust status (milliseconds)
        verifyInterval: 5000,  // 5 seconds

        // Maximum time to poll before giving up (milliseconds)
        verifyTimeout: 300000, // 5 minutes

        // Maximum retry attempts
        maxRetries: 60,        // 5 minutes / 5 seconds = 60 retries

        // API endpoints
        endpoints: {
            verifyTrust: '/api/verify-trust',
            markTrusted: '/api/mark-trusted',
            downloadCA: '/api/download-ca',
        },

        // Success redirect URL
        successRedirect: '/success',

        // Delay before redirect after success (ms)
        redirectDelay: 3000,
    };

    // ========================================================================
    // State Management
    // ========================================================================

    const state = {
        verifyAttempts: 0,
        verifyTimer: null,
        isVerifying: false,
        detectedOS: null,
        deviceInfo: null,
    };

    // ========================================================================
    // OS Detection
    // ========================================================================

    /**
     * Detect the client's operating system from User-Agent
     * @returns {string} One of: 'ios', 'android', 'windows', 'macos', 'linux', 'unknown'
     */
    function detectOS() {
        const ua = navigator.userAgent.toLowerCase();
        const platform = navigator.platform?.toLowerCase() || '';

        // iOS detection (iPhone, iPad, iPod)
        if (/iphone|ipad|ipod/.test(ua)) {
            return 'ios';
        }

        // Android detection
        if (/android/.test(ua)) {
            return 'android';
        }

        // macOS detection (check before Windows due to some edge cases)
        if (/macintosh|mac os x|mac_powerpc/.test(ua) || platform.includes('mac')) {
            return 'macos';
        }

        // Windows detection
        if (/windows|win32|win64/.test(ua) || platform.includes('win')) {
            return 'windows';
        }

        // Linux detection (but not Android which includes Linux in UA)
        if (/linux/.test(ua) && !/android/.test(ua)) {
            return 'linux';
        }

        // ChromeOS detection
        if (/cros/.test(ua)) {
            return 'chromeos';
        }

        return 'unknown';
    }

    /**
     * Get human-readable OS name
     * @param {string} os - OS identifier
     * @returns {string} Human-readable name
     */
    function getOSName(os) {
        const names = {
            'ios': 'iOS',
            'android': 'Android',
            'windows': 'Windows',
            'macos': 'macOS',
            'linux': 'Linux',
            'chromeos': 'ChromeOS',
            'unknown': 'Unknown',
        };
        return names[os] || 'Unknown';
    }

    // ========================================================================
    // Tab Management
    // ========================================================================

    /**
     * Initialize OS tabs and show the detected OS by default
     */
    function initializeTabs() {
        const detectedOS = detectOS();
        state.detectedOS = detectedOS;

        console.log('[SafeOps] Detected OS:', detectedOS);

        const tabs = document.querySelectorAll('.os-tab');
        const contents = document.querySelectorAll('.os-content');

        if (tabs.length === 0) {
            console.log('[SafeOps] No OS tabs found, skipping tab initialization');
            return;
        }

        // Activate the detected OS tab
        let foundMatch = false;
        tabs.forEach(tab => {
            const tabOS = tab.dataset.os;
            if (tabOS === detectedOS) {
                tab.classList.add('active');
                foundMatch = true;

                // Show corresponding content
                contents.forEach(content => {
                    if (content.dataset.os === tabOS) {
                        content.classList.add('active');
                    }
                });
            }
        });

        // If no match, default to first tab
        if (!foundMatch && tabs.length > 0) {
            tabs[0].classList.add('active');
            if (contents.length > 0) {
                contents[0].classList.add('active');
            }
        }

        // Add click handlers for manual tab switching
        tabs.forEach(tab => {
            tab.addEventListener('click', handleTabClick);
        });
    }

    /**
     * Handle tab click events
     * @param {Event} event - Click event
     */
    function handleTabClick(event) {
        const clickedTab = event.currentTarget;
        const targetOS = clickedTab.dataset.os;

        const tabs = document.querySelectorAll('.os-tab');
        const contents = document.querySelectorAll('.os-content');

        // Remove active from all tabs and contents
        tabs.forEach(tab => tab.classList.remove('active'));
        contents.forEach(content => content.classList.remove('active'));

        // Activate clicked tab
        clickedTab.classList.add('active');

        // Show corresponding content
        contents.forEach(content => {
            if (content.dataset.os === targetOS) {
                content.classList.add('active');
            }
        });

        console.log('[SafeOps] Switched to OS:', targetOS);
    }

    // ========================================================================
    // Trust Verification
    // ========================================================================

    /**
     * Check if the device is now marked as trusted
     * @returns {Promise<{trusted: boolean, device: object}>}
     */
    async function checkTrustStatus() {
        try {
            const response = await fetch(CONFIG.endpoints.verifyTrust, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'same-origin',
            });

            if (!response.ok) {
                throw new Error(`Server returned ${response.status}`);
            }

            const data = await response.json();
            return {
                trusted: data.trusted === true,
                device: data.device || null,
            };
        } catch (error) {
            console.error('[SafeOps] Trust check error:', error);
            throw error;
        }
    }

    /**
     * Single verification attempt
     */
    async function verifyOnce() {
        state.verifyAttempts++;
        console.log(`[SafeOps] Verification attempt ${state.verifyAttempts}/${CONFIG.maxRetries}`);

        try {
            const result = await checkTrustStatus();

            if (result.trusted) {
                // Success! Device is trusted
                stopVerification();
                showSuccess(result.device);
                return;
            }

            // Still untrusted, check if we should continue
            if (state.verifyAttempts >= CONFIG.maxRetries) {
                stopVerification();
                showTimeout();
                return;
            }

            // Update UI to show progress
            updateVerifyProgress();

        } catch (error) {
            console.error('[SafeOps] Verification error:', error);

            if (state.verifyAttempts >= CONFIG.maxRetries) {
                stopVerification();
                showError(error.message);
            }
        }
    }

    /**
     * Start automatic verification polling
     */
    function startVerification() {
        if (state.isVerifying) {
            console.log('[SafeOps] Already verifying, skipping');
            return;
        }

        console.log('[SafeOps] Starting verification polling');
        state.isVerifying = true;
        state.verifyAttempts = 0;

        // Update UI
        const statusElement = document.getElementById('verify-status');
        if (statusElement) {
            statusElement.innerHTML = `
                <div class="verify-waiting">
                    <div class="spinner"></div>
                    <p class="loading-text">Waiting for certificate installation...</p>
                    <p class="text-muted">Checking every ${CONFIG.verifyInterval / 1000} seconds</p>
                </div>
            `;
        }

        // Start polling
        state.verifyTimer = setInterval(verifyOnce, CONFIG.verifyInterval);

        // Also check immediately
        verifyOnce();
    }

    /**
     * Stop verification polling
     */
    function stopVerification() {
        if (state.verifyTimer) {
            clearInterval(state.verifyTimer);
            state.verifyTimer = null;
        }
        state.isVerifying = false;
        console.log('[SafeOps] Verification stopped');
    }

    /**
     * Update the verification progress UI
     */
    function updateVerifyProgress() {
        const statusElement = document.getElementById('verify-status');
        if (!statusElement) return;

        const progress = Math.round((state.verifyAttempts / CONFIG.maxRetries) * 100);
        const remaining = CONFIG.maxRetries - state.verifyAttempts;
        const timeRemaining = Math.round((remaining * CONFIG.verifyInterval) / 1000);

        statusElement.innerHTML = `
            <div class="verify-waiting">
                <div class="spinner"></div>
                <p class="loading-text">Waiting for certificate installation...</p>
                <p class="text-muted">
                    Check ${state.verifyAttempts}/${CONFIG.maxRetries} 
                    (${timeRemaining}s remaining)
                </p>
            </div>
        `;
    }

    // ========================================================================
    // Status Display Functions
    // ========================================================================

    /**
     * Show success message and redirect
     * @param {object} device - Device info from server
     */
    function showSuccess(device) {
        const statusElement = document.getElementById('verify-status');
        if (statusElement) {
            statusElement.innerHTML = `
                <div class="alert alert-success">
                    <div class="alert-icon">
                        <svg width="24" height="24" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
                        </svg>
                    </div>
                    <div class="alert-content">
                        <div class="alert-title">Certificate Installed Successfully!</div>
                        <div class="alert-message">
                            Your device is now trusted. Redirecting in ${CONFIG.redirectDelay / 1000} seconds...
                        </div>
                    </div>
                </div>
            `;
        }

        // Redirect after delay
        setTimeout(() => {
            window.location.href = CONFIG.successRedirect;
        }, CONFIG.redirectDelay);
    }

    /**
     * Show timeout message
     */
    function showTimeout() {
        const statusElement = document.getElementById('verify-status');
        if (statusElement) {
            statusElement.innerHTML = `
                <div class="alert alert-warning">
                    <div class="alert-icon">
                        <svg width="24" height="24" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/>
                        </svg>
                    </div>
                    <div class="alert-content">
                        <div class="alert-title">Verification Timeout</div>
                        <div class="alert-message">
                            We couldn't detect the certificate installation. Please ensure you 
                            installed it correctly and click below to manually confirm.
                        </div>
                        <button class="btn btn-primary" onclick="SafeOps.manualVerify()">
                            I've Installed the Certificate
                        </button>
                        <button class="btn btn-secondary" onclick="SafeOps.restartVerification()">
                            Retry Automatic Detection
                        </button>
                    </div>
                </div>
            `;
        }
    }

    /**
     * Show error message
     * @param {string} message - Error message
     */
    function showError(message) {
        const statusElement = document.getElementById('verify-status');
        if (statusElement) {
            statusElement.innerHTML = `
                <div class="alert alert-error">
                    <div class="alert-icon">
                        <svg width="24" height="24" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/>
                        </svg>
                    </div>
                    <div class="alert-content">
                        <div class="alert-title">Verification Error</div>
                        <div class="alert-message">
                            ${message || 'An error occurred. Please refresh the page and try again.'}
                        </div>
                        <button class="btn btn-primary" onclick="location.reload()">
                            Refresh Page
                        </button>
                    </div>
                </div>
            `;
        }
    }

    /**
     * Show a generic status message (for skip action)
     * @param {string} type - 'success', 'error', 'warning'
     * @param {string} title - Alert title
     * @param {string} message - Alert message
     */
    function showStatusMessage(type, title, message) {
        const statusElement = document.getElementById('verify-status');
        if (!statusElement) return;

        const iconColors = {
            success: '#10b981',
            error: '#ef4444',
            warning: '#f59e0b'
        };

        statusElement.innerHTML = `
            <div class="alert alert-${type}" style="margin-top: 20px; padding: 20px; border-radius: 12px; background: ${type === 'success' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)'};">
                <div style="display: flex; align-items: center; gap: 12px;">
                    <span style="font-size: 24px;">${type === 'success' ? '🎉' : '❌'}</span>
                    <div>
                        <div style="font-weight: bold; font-size: 1.1rem;">${title}</div>
                        <div style="color: #94a3b8; margin-top: 4px;">${message}</div>
                    </div>
                </div>
            </div>
        `;
    }

    // ========================================================================
    // Manual Verification
    // ========================================================================


    /**
     * Handle manual "I've Installed" button click
     */
    async function manualVerify() {
        const button = document.getElementById('manual-verify-btn');
        if (button) {
            button.disabled = true;
            button.innerHTML = '<span class="spinner"></span> Verifying...';
        }

        try {
            const response = await fetch(CONFIG.endpoints.markTrusted, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'same-origin',
            });

            const data = await response.json();

            if (data.success) {
                showSuccess(data.device);
            } else {
                if (button) {
                    button.disabled = false;
                    button.innerHTML = "I've Installed the Certificate";
                }
                alert(data.error || 'Failed to mark device as trusted. Please try again.');
            }
        } catch (error) {
            console.error('[SafeOps] Manual verify error:', error);
            if (button) {
                button.disabled = false;
                button.innerHTML = "I've Installed the Certificate";
            }
            alert('An error occurred. Please try again.');
        }
    }

    /**
     * Restart automatic verification
     */
    function restartVerification() {
        stopVerification();
        state.verifyAttempts = 0;
        startVerification();
    }

    // ========================================================================
    // Button Handlers
    // ========================================================================

    /**
     * Initialize button event handlers
     */
    function initializeButtons() {
        // Manual verify button
        const manualBtn = document.getElementById('manual-verify-btn');
        if (manualBtn) {
            manualBtn.addEventListener('click', manualVerify);
        }

        // Skip button (ALLOW_ONCE policy - internet without CA cert)
        const skipBtn = document.getElementById('skip-btn');
        if (skipBtn) {
            skipBtn.addEventListener('click', skipCertInstallation);
        }

        // Download buttons - intercept click to show alert after download
        document.querySelectorAll('[data-download-format]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault(); // Prevent default link behavior
                const format = e.currentTarget.dataset.downloadFormat;
                downloadCertificate(format);
            });
        });
    }

    /**
     * Handle skip button - allow internet access without CA cert (ALLOW_ONCE policy)
     */
    async function skipCertInstallation() {
        console.log('[SafeOps] User clicked Skip - granting internet access without CA cert');

        const skipBtn = document.getElementById('skip-btn');
        if (skipBtn) {
            skipBtn.disabled = true;
            skipBtn.textContent = 'Processing...';
        }

        try {
            // Call API to mark portal as shown (ALLOW_ONCE policy)
            const response = await fetch('/api/skip', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                const result = await response.json();
                console.log('[SafeOps] Skip successful:', result);

                // Show success message
                showStatusMessage('success',
                    'Internet Access Granted!',
                    'You can now browse the internet. This page will close automatically...');

                // Close window after 3 seconds
                setTimeout(() => {
                    window.close();
                    // If window.close() doesn't work, redirect to Google
                    setTimeout(() => {
                        window.location.href = 'https://www.google.com';
                    }, 500);
                }, 3000);

            } else {
                const error = await response.text();
                console.error('[SafeOps] Skip failed:', error);
                showStatusMessage('error',
                    'Error',
                    'Failed to grant internet access. Please try again.');

                if (skipBtn) {
                    skipBtn.disabled = false;
                    skipBtn.textContent = 'Skip - Give Me Internet Access';
                }
            }
        } catch (error) {
            console.error('[SafeOps] Skip request error:', error);
            showStatusMessage('error',
                'Network Error',
                'Could not connect to server. Please try again.');

            if (skipBtn) {
                skipBtn.disabled = false;
                skipBtn.textContent = 'Skip - Give Me Internet Access';
            }
        }
    }

    /**
     * Trigger certificate download in specified format
     * @param {string} format - 'pem', 'der', or 'p12'
     */
    function downloadCertificate(format) {
        const url = `${CONFIG.endpoints.downloadCA}/${format}`;

        // Create hidden link and click it
        const link = document.createElement('a');
        link.href = url;
        link.download = `SafeOps_Root_CA.${format === 'pem' ? 'crt' : format}`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        console.log('[SafeOps] Certificate download initiated:', format);

        // Show alert reminding user to install the certificate
        setTimeout(() => {
            alert('✅ Certificate Downloaded!\n\n' +
                'Please install the certificate on your device.\n\n' +
                '📱 Go to Settings → Security → Install from storage\n\n' +
                '🔒 IT Security will verify your device installation for security purposes.');
        }, 500);
    }

    // ========================================================================
    // Initialization
    // ========================================================================

    /**
     * Initialize the captive portal JavaScript
     */
    function initialize() {
        console.log('[SafeOps] Captive Portal JS initializing...');

        // Detect and store OS
        state.detectedOS = detectOS();
        console.log('[SafeOps] Detected OS:', state.detectedOS, getOSName(state.detectedOS));

        // Initialize UI components
        initializeTabs();
        initializeButtons();

        // Check if auto-verify is enabled
        const autoVerify = document.body.dataset.autoVerify;
        if (autoVerify === 'true') {
            startVerification();
        }

        console.log('[SafeOps] Initialization complete');
    }

    // ========================================================================
    // Public API
    // ========================================================================

    // Expose functions for inline onclick handlers and debugging
    window.SafeOps = {
        // Verification functions
        startVerification,
        stopVerification,
        restartVerification,
        manualVerify,
        checkTrustStatus,

        // Download function
        downloadCertificate,

        // OS detection
        detectOS,
        getOSName,

        // State access
        getState: () => ({ ...state }),
        getConfig: () => ({ ...CONFIG }),
    };

    // ========================================================================
    // DOM Ready Handler
    // ========================================================================

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        // DOM already loaded
        initialize();
    }

})();
