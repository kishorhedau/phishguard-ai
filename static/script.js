/**
 * PhishGuard AI – Frontend Script v2.0
 * Features: URL Analysis · Dark/Light Toggle · Scan History · Download Report
 */

// ── DOM references ───────────────────────────────────────────────
const urlInput            = document.getElementById('urlInput');
const analyzeBtn          = document.getElementById('analyzeBtn');
const loadingEl           = document.getElementById('loadingEl');
const errorEl             = document.getElementById('errorEl');
const errorText           = document.getElementById('errorText');
const resultCard          = document.getElementById('resultCard');
const gaugeArc            = document.getElementById('gaugeArc');
const scoreNumber         = document.getElementById('scoreNumber');
const classificationBadge = document.getElementById('classificationBadge');
const analyzedUrl         = document.getElementById('analyzedUrl');
const analyzedTime        = document.getElementById('analyzedTime');
const reasonsList         = document.getElementById('reasonsList');
const historyPanel        = document.getElementById('historyPanel');
const historyList         = document.getElementById('historyList');
const historyEmpty        = document.getElementById('historyEmpty');
const historyCount        = document.getElementById('historyCount');
const themeIcon           = document.getElementById('themeIcon');

// ── State ────────────────────────────────────────────────────────
let scanHistory = JSON.parse(localStorage.getItem('phishguard_history') || '[]');
let currentResult = null;   // last API result, used for download
let historyOpen = false;

// ── Constants ────────────────────────────────────────────────────
const ARC_LENGTH = 251;
const SEVERITY_LABELS = {
  high:   '⬆ High Risk',
  medium: '◆ Medium Risk',
  low:    '▾ Low Risk',
  none:   '✔ No Issue'
};

// ════════════════════════════════════════════════════════════════
// THEME TOGGLE
// ════════════════════════════════════════════════════════════════

function initTheme() {
  // Restore saved preference, default to dark
  const saved = localStorage.getItem('phishguard_theme') || 'dark';
  applyTheme(saved);
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  themeIcon.textContent = theme === 'dark' ? '☀️' : '🌙';
  localStorage.setItem('phishguard_theme', theme);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  applyTheme(current === 'dark' ? 'light' : 'dark');
}

// ════════════════════════════════════════════════════════════════
// HISTORY
// ════════════════════════════════════════════════════════════════

function saveToHistory(result) {
  const entry = {
    url:            result.url,
    score:          result.score,
    classification: result.classification,
    time:           new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    date:           new Date().toLocaleDateString()
  };
  // Avoid exact duplicate consecutive scans
  if (scanHistory.length > 0 && scanHistory[0].url === entry.url) {
    scanHistory.shift();
  }
  scanHistory.unshift(entry);
  if (scanHistory.length > 20) scanHistory.pop();   // keep max 20
  localStorage.setItem('phishguard_history', JSON.stringify(scanHistory));
  updateHistoryCount();
  if (historyOpen) renderHistoryList();
}

function updateHistoryCount() {
  historyCount.textContent = scanHistory.length;
}

function toggleHistory() {
  historyOpen = !historyOpen;
  if (historyOpen) {
    historyPanel.classList.remove('hidden');
    renderHistoryList();
  } else {
    historyPanel.classList.add('hidden');
  }
}

function renderHistoryList() {
  historyList.innerHTML = '';
  if (scanHistory.length === 0) {
    historyEmpty.classList.remove('hidden');
    return;
  }
  historyEmpty.classList.add('hidden');
  scanHistory.forEach((entry, i) => {
    const li = document.createElement('li');
    li.className = 'history-item';
    li.style.animationDelay = `${i * 40}ms`;

    const dotClass = entry.classification === 'Safe' ? 'safe'
                   : entry.classification === 'Suspicious' ? 'warn' : 'danger';

    li.innerHTML = `
      <span class="history-dot ${dotClass}"></span>
      <span class="history-url" title="${escapeHTML(entry.url)}">${escapeHTML(entry.url)}</span>
      <span class="history-score">${entry.score}/100</span>
      <span class="history-time">${entry.time}</span>
    `;

    // Click a history item to re-fill the input
    li.addEventListener('click', () => {
      urlInput.value = entry.url;
      urlInput.focus();
      toggleHistory();
    });

    historyList.appendChild(li);
  });
}

function clearHistory() {
  scanHistory = [];
  localStorage.removeItem('phishguard_history');
  updateHistoryCount();
  renderHistoryList();
}

// ════════════════════════════════════════════════════════════════
// DOWNLOAD REPORT
// ════════════════════════════════════════════════════════════════

function downloadReport() {
  if (!currentResult) return;

  const { url, score, classification, reasons } = currentResult;
  const now = new Date();

  // Build plain-text report
  const divider = '═'.repeat(60);
  const thinLine = '─'.repeat(60);

  const reasonLines = reasons.map(r =>
    `  ${r.icon}  [${(r.severity || 'info').toUpperCase()}]  ${r.text}`
  ).join('\n');

  const report = `
${divider}
  PHISHGUARD AI – URL SECURITY REPORT
${divider}

  Generated  : ${now.toLocaleString()}
  Tool       : PhishGuard AI v2.0

${thinLine}
  TARGET URL
${thinLine}
  ${url}

${thinLine}
  RISK ASSESSMENT
${thinLine}
  Risk Score     : ${score} / 100
  Classification : ${classification}
  Status         : ${classification === 'Safe' ? '✅ No significant threats detected'
                   : classification === 'Suspicious' ? '⚠️  Potentially suspicious – proceed with caution'
                   : '🚨 HIGH RISK – Likely phishing or malicious'}

${thinLine}
  DETECTION DETAILS
${thinLine}
${reasonLines}

${thinLine}
  DISCLAIMER
${thinLine}
  This report is generated by a heuristic engine for educational
  purposes only. It does not guarantee 100% accuracy. Always use
  multiple security tools before visiting unfamiliar URLs.

${divider}
  Made by Your Name | PhishGuard AI
${divider}
`.trim();

  // Create a downloadable .txt file
  const blob = new Blob([report], { type: 'text/plain' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);

  // Safe filename from the URL
  const safeName = url.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 40);
  link.download = `PhishGuard_Report_${safeName}_${Date.now()}.txt`;

  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(link.href);
}

// ════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════

function fillExample(url) {
  urlInput.value = url;
  urlInput.focus();
}

function escapeHTML(str) {
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(str));
  return d.innerHTML;
}

function arcColorForScore(score) {
  if (score < 30) return '#22c55e';
  if (score < 60) return '#f59e0b';
  return '#ef4444';
}

function showLoading() {
  loadingEl.classList.remove('hidden');
  resultCard.classList.add('hidden');
  errorEl.classList.add('hidden');
  analyzeBtn.disabled = true;
}

function hideLoading() {
  loadingEl.classList.add('hidden');
  analyzeBtn.disabled = false;
}

function showError(msg) {
  errorText.textContent = msg;
  errorEl.classList.remove('hidden');
}

// ════════════════════════════════════════════════════════════════
// GAUGE ANIMATION
// ════════════════════════════════════════════════════════════════

function animateScore(targetScore) {
  const color = arcColorForScore(targetScore);
  gaugeArc.style.stroke = color;
  const filled = (targetScore / 100) * ARC_LENGTH;
  gaugeArc.style.strokeDasharray = `${filled} ${ARC_LENGTH}`;

  const duration = 1200;
  const start = performance.now();

  function step(now) {
    const elapsed  = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased    = 1 - Math.pow(1 - progress, 3);
    const current  = Math.round(eased * targetScore);
    scoreNumber.textContent = current;
    scoreNumber.style.color = color;
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ════════════════════════════════════════════════════════════════
// RENDER RESULT
// ════════════════════════════════════════════════════════════════

function renderResult(data) {
  currentResult = data;
  const { score, classification, reasons, url } = data;

  // Card border class
  resultCard.className = 'result-card';
  const cls = classification === 'Safe' ? 'safe'
            : classification === 'Suspicious' ? 'warn' : 'danger';
  resultCard.classList.add(cls);

  // Badge
  classificationBadge.className = 'classification-badge ' + cls;
  const emoji = classification === 'Safe' ? '✅'
              : classification === 'Suspicious' ? '⚠️' : '🚨';
  classificationBadge.textContent = `${emoji} ${classification}`;

  // URL + time
  analyzedUrl.textContent = url;
  analyzedTime.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  // Gauge
  animateScore(score);

  // Reasons
  reasonsList.innerHTML = '';
  reasons.forEach((reason, i) => {
    const li = document.createElement('li');
    li.className = `reason-item ${reason.severity || 'none'}`;
    li.style.animationDelay = `${i * 80}ms`;
    li.innerHTML = `
      <span class="reason-icon">${reason.icon}</span>
      <div class="reason-content">
        <span class="reason-text">${escapeHTML(reason.text)}</span>
        <span class="reason-severity">${SEVERITY_LABELS[reason.severity] || ''}</span>
      </div>
    `;
    reasonsList.appendChild(li);
  });

  resultCard.classList.remove('hidden');

  // Save to history
  saveToHistory(data);
}

// ════════════════════════════════════════════════════════════════
// MAIN ANALYSIS FUNCTION
// ════════════════════════════════════════════════════════════════

async function analyzeURL() {
  const url = urlInput.value.trim();

  if (!url) {
    showError('Please enter a URL before analyzing.');
    return;
  }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    showError('URL must start with http:// or https://  (e.g. https://example.com)');
    return;
  }

  showLoading();

  try {
    const response = await fetch('/analyze', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url })
    });

    const data = await response.json();
    hideLoading();

    if (!response.ok) {
      showError(data.error || 'An error occurred. Please try again.');
      return;
    }

    renderResult(data);

  } catch (err) {
    hideLoading();
    showError('Could not connect to the PhishGuard server. Make sure Flask is running on port 5000.');
    console.error('PhishGuard API error:', err);
  }
}

// ════════════════════════════════════════════════════════════════
// EVENT LISTENERS
// ════════════════════════════════════════════════════════════════

urlInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') analyzeURL(); });
urlInput.addEventListener('input',   ()  => { errorEl.classList.add('hidden'); });

// ── Init ─────────────────────────────────────────────────────────
initTheme();
updateHistoryCount();
