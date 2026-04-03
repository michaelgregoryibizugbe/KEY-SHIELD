/**
 * KeyShield Web GUI v3.0 — Advanced Frontend Logic
 */

const KeyShield = {
    eventSource: null,

    init() {
        this.bindEvents();
        this.loadSystemInfo();
        if (window.location.pathname === '/settings') {
            this.loadWhitelist();
        }
    },

    bindEvents() {
        const startBtn = document.getElementById('btn-start-scan');
        const quickBtn = document.getElementById('btn-quick-scan');
        const addWhitelistBtn = document.getElementById('btn-add-whitelist');
        
        if (startBtn) startBtn.addEventListener('click', () => this.startScan(false));
        if (quickBtn) quickBtn.addEventListener('click', () => this.startScan(true));
        if (addWhitelistBtn) addWhitelistBtn.addEventListener('click', () => this.addToWhitelist());
        
        // Handle enter key on whitelist input
        const whitelistInput = document.getElementById('whitelist-input');
        if (whitelistInput) {
            whitelistInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') this.addToWhitelist();
            });
        }
    },

    async startScan(quick = false) {
        const startBtn = document.getElementById('btn-start-scan');
        const quickBtn = document.getElementById('btn-quick-scan');
        if (startBtn) startBtn.disabled = true;
        if (quickBtn) quickBtn.disabled = true;

        this.showScanProgress();
        this.resetDetectorCards();

        try {
            const resp = await fetch('/api/scan/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ quick }),
            });

            if (resp.ok) {
                this.connectSSE();
            } else {
                const data = await resp.json();
                this.showError(data.error || 'Failed to start');
            }
        } catch (err) {
            this.showError('Connection error: ' + err.message);
        }
    },

    connectSSE() {
        if (this.eventSource) this.eventSource.close();

        this.eventSource = new EventSource('/api/scan/stream');

        this.eventSource.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.updateProgress(data);

            if (!data.running && (data.has_result || data.error)) {
                this.eventSource.close();
                this.eventSource = null;

                if (data.error) {
                    this.showError(data.error);
                } else {
                    this.loadResults();
                }
            }
        };

        this.eventSource.onerror = () => {
            if (this.eventSource) this.eventSource.close();
            this.eventSource = null;
            this.pollFallback();
        };
    },

    pollFallback() {
        const interval = setInterval(async () => {
            try {
                const resp = await fetch('/api/scan/status');
                const data = await resp.json();
                this.updateProgress(data);
                if (!data.running && (data.has_result || data.error)) {
                    clearInterval(interval);
                    data.error ? this.showError(data.error) : this.loadResults();
                }
            } catch (e) { console.error(e); }
        }, 500);
    },

    updateProgress(data) {
        const bar = document.getElementById('progress-fill');
        const text = document.getElementById('progress-text');
        const detector = document.getElementById('progress-detector');

        if (!bar) return;

        const pct = data.total > 0 ? Math.round((data.progress / data.total) * 100) : 0;
        bar.style.width = pct + '%';
        if (text) text.textContent = `${data.progress} / ${data.total} detectors`;
        if (detector) detector.textContent = data.current_detector || 'Initializing...';

        this.updateDetectorCards(data);
    },

    updateDetectorCards(data) {
        const cards = document.querySelectorAll('.detector-card');
        cards.forEach((card) => {
            const name = card.dataset.detector;
            const status = card.querySelector('.detector-status');
            if (name === data.current_detector) {
                card.classList.add('running');
                card.classList.remove('done');
                if (status) status.className = 'detector-status running';
            } else if (this.isPreviousDetector(name, data.current_detector, data.progress)) {
                card.classList.remove('running');
                card.classList.add('done');
                if (status) status.className = 'detector-status done';
            }
        });
    },

    isPreviousDetector(name, currentName, progress) {
        // Simplified logic for UI feedback
        const cards = Array.from(document.querySelectorAll('.detector-card'));
        const currentIndex = cards.findIndex(c => c.dataset.detector === currentName);
        const myIndex = cards.findIndex(c => c.dataset.detector === name);
        return myIndex < currentIndex || (currentIndex === -1 && progress > 0);
    },

    resetDetectorCards() {
        document.querySelectorAll('.detector-card').forEach(card => {
            card.classList.remove('running', 'done', 'error');
            const status = card.querySelector('.detector-status');
            if (status) status.className = 'detector-status waiting';
        });
    },

    async loadResults() {
        try {
            const resp = await fetch('/api/scan/result');
            const data = await resp.json();
            if (data.error) { this.showError(data.error); return; }
            this.renderResults(data);
        } catch (err) {
            this.showError('Failed to load results: ' + err.message);
        }
    },

    renderResults(data) {
        const container = document.getElementById('scan-results');
        if (!container) return;

        const rc = data.overall_risk.toLowerCase();
        const emojis = { 'CLEAN':'✅','LOW':'🟡','MEDIUM':'🟠','HIGH':'🔴','CRITICAL':'🚨' };

        let fhtml = '';
        if (data.findings && data.findings.length > 0) {
            const sorted = data.findings.sort((a,b) => b.level_value - a.level_value);
            fhtml = `<div class="card" style="margin-top:32px; animation: fadeInDown 0.5s ease-out;">
                <div class="card-title"><span>🛡️</span> Security Findings (${data.total_findings})</div>
                <table class="findings-table"><thead><tr>
                    <th>Severity</th><th>Details</th><th>Category</th><th>MITRE</th>
                </tr></thead><tbody>
                ${sorted.map(f => `<tr>
                    <td><span class="badge badge-${f.level.toLowerCase()}">${f.level}</span></td>
                    <td><div style="font-weight:700; color:var(--text-primary); margin-bottom:4px;">${this.esc(f.title)}</div>
                        <div class="finding-detail">
                            <div style="font-size:0.9rem; color:var(--text-secondary)">${this.esc(f.description)}</div>
                            ${f.evidence ? `<div class="evidence">${this.esc(f.evidence)}</div>` : ''}
                            ${f.recommendation ? `<div class="recommendation">💡 ${this.esc(f.recommendation)}</div>` : ''}
                            ${f.pid ? `<div style="margin-top:8px; font-size:0.8rem; color:var(--text-muted); font-weight:600;">PID: ${f.pid} | Process: ${f.process_name}</div>` : ''}
                        </div>
                    </td>
                    <td><span style="font-size:0.8rem; font-weight:600; color:var(--text-muted)">${this.esc(f.category)}</span></td>
                    <td>${f.mitre_id ? `<span class="mitre-tag">${this.esc(f.mitre_id)}</span>` : ''}</td>
                </tr>`).join('')}
                </tbody></table></div>`;
        } else {
            fhtml = `<div class="card" style="margin-top:32px; animation: fadeInDown 0.5s ease-out;"><div class="risk-meter">
                <div style="font-size:4rem; margin-bottom:16px;">🛡️</div>
                <h3 style="font-size:1.5rem; font-weight:800;">System Protected</h3>
                <p style="color:var(--text-secondary); margin-top:8px;">KeyShield found zero active threats during this scan.</p></div></div>`;
        }

        container.innerHTML = `
            <div class="card" style="animation: fadeInDown 0.4s ease-out;"><div class="risk-meter">
                <div style="font-size:0.9rem; color:var(--text-muted); font-weight:700; text-transform:uppercase; letter-spacing:0.1em;">Security Status</div>
                <div class="risk-level ${rc}">${emojis[data.overall_risk]||''} ${data.overall_risk}</div>
                <div style="font-size:0.9rem; color:var(--text-secondary); font-weight:500;">${data.duration_seconds}s Analysis &middot; ${data.scan_profile} Profile</div>
            </div></div>
            <div class="stats-grid" style="animation: fadeInDown 0.5s ease-out;">
                <div class="stat-card critical"><div class="stat-value">${data.critical}</div><div class="stat-label">Critical</div></div>
                <div class="stat-card high"><div class="stat-value">${data.high}</div><div class="stat-label">High</div></div>
                <div class="stat-card medium"><div class="stat-value">${data.medium}</div><div class="stat-label">Medium</div></div>
                <div class="stat-card low"><div class="stat-value">${data.low}</div><div class="stat-label">Low</div></div>
            </div>
            ${fhtml}
            <div style="margin-top:32px; display:flex; gap:16px; animation: fadeInDown 0.6s ease-out;">
                <a href="/report/${data.scan_id}" class="btn btn-primary">📄 View Detailed Report</a>
                <button onclick="KeyShield.enableRescan()" class="btn btn-secondary">🔄 New Scan</button>
            </div>`;

        const progress = document.getElementById('scan-progress');
        if (progress) progress.style.display = 'none';
    },

    showScanProgress() {
        const p = document.getElementById('scan-progress');
        const r = document.getElementById('scan-results');
        if (p) p.style.display = 'block';
        if (r) r.innerHTML = '';
        const bar = document.getElementById('progress-fill');
        if (bar) bar.style.width = '0%';
    },

    showError(msg) {
        const r = document.getElementById('scan-results');
        if (r) r.innerHTML = `<div class="card" style="border-color:var(--danger); animation: fadeInDown 0.4s ease-out;">
            <div class="card-title" style="color:var(--danger)"><span>❌</span> Scan Error</div>
            <p style="color:var(--text-secondary)">${this.esc(msg)}</p>
            <button onclick="KeyShield.enableRescan()" class="btn btn-primary mt-4">🔄 Try Again</button>
        </div>`;
        const p = document.getElementById('scan-progress');
        if (p) p.style.display = 'none';
        this.enableRescan();
    },

    enableRescan() {
        const s = document.getElementById('btn-start-scan');
        const q = document.getElementById('btn-quick-scan');
        if (s) s.disabled = false;
        if (q) q.disabled = false;
        
        // If results are showing, smooth scroll to top
        window.scrollTo({ top: 0, behavior: 'smooth' });
        const results = document.getElementById('scan-results');
        if (results) results.innerHTML = '';
    },

    async loadSystemInfo() {
        try {
            const resp = await fetch('/api/system');
            const data = await resp.json();
            const el = document.getElementById('system-info-data');
            if (el && data.system_info) {
                el.innerHTML = Object.entries(data.system_info).map(([k,v]) =>
                    `<div class="info-item"><span class="label">${k.replace(/_/g,' ').toUpperCase()}</span><span class="value">${v}</span></div>`
                ).join('');
            }
            
            // Highlight active profile in settings
            if (window.location.pathname === '/settings' && data.system_info.profile) {
                this.updateProfileUI(data.system_info.profile);
            }
        } catch(e) { console.error(e); }
    },

    /** Profile Management */
    async setProfile(profile) {
        try {
            const resp = await fetch('/api/config/profile', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ profile })
            });
            if (resp.ok) {
                this.updateProfileUI(profile);
            }
        } catch (e) { console.error(e); }
    },

    updateProfileUI(activeProfile) {
        const cards = document.querySelectorAll('.profile-card');
        cards.forEach(card => {
            if (card.dataset.profile === activeProfile) {
                card.classList.add('active-profile');
                card.querySelector('.detector-status').className = 'detector-status running';
            } else {
                card.classList.remove('active-profile');
                card.querySelector('.detector-status').className = 'detector-status done';
            }
        });
    },

    /** Whitelist Management */
    async loadWhitelist() {
        try {
            const resp = await fetch('/api/config/whitelist');
            const data = await resp.json();
            this.renderWhitelist(data.whitelist);
        } catch (e) { console.error(e); }
    },

    async addToWhitelist() {
        const input = document.getElementById('whitelist-input');
        const process = input.value.trim();
        if (!process) return;

        try {
            const resp = await fetch('/api/config/whitelist', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ process })
            });
            if (resp.ok) {
                input.value = '';
                this.loadWhitelist();
            }
        } catch (e) { console.error(e); }
    },

    async removeFromWhitelist(process) {
        try {
            const resp = await fetch('/api/config/whitelist', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ process })
            });
            if (resp.ok) {
                this.loadWhitelist();
            }
        } catch (e) { console.error(e); }
    },

    renderWhitelist(list) {
        const tbody = document.getElementById('whitelist-table-body');
        if (!tbody) return;

        if (list.length === 0) {
            tbody.innerHTML = '<tr><td colspan="2" style="text-align:center; color:var(--text-muted); padding:40px;">Whitelist is empty</td></tr>';
            return;
        }

        tbody.innerHTML = list.map(p => `
            <tr>
                <td><code style="background:var(--bg-primary); padding:4px 8px; border-radius:6px; color:var(--accent); font-weight:600;">${this.esc(p)}</code></td>
                <td style="text-align:right;">
                    <button onclick="KeyShield.removeFromWhitelist('${this.esc(p)}')" class="btn btn-secondary btn-sm" style="color:var(--danger)">
                        <span>🗑️</span> Remove
                    </button>
                </td>
            </tr>
        `).join('');
    },

    esc(s) {
        if (!s) return '';
        const d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    },
};

document.addEventListener('DOMContentLoaded', () => KeyShield.init());
