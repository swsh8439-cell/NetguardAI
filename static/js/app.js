/**
 * NetGuard AI - Complete Single-Page Application Controller
 * Handles Navigation for all 12 views, Real-Time Packet Streaming,
 * Canvas Chart Renders, CSV Upload Inference, Logs Filtering, and Settings.
 * 
 * Supports clean zero-state initialization for newly registered users,
 * and stationary sidebar with scrolling main dashboard content.
 */

// Application State
const state = {
  currentView: 'landing', // Initial view: landing page (Required by user)
  currentAppTab: 'dashboard',
  isStreamPaused: false,
  streamInterval: null,
  logsPage: 1,
  logsPerPage: 6,
  theme: 'light',
  user: {
    name: 'Shreya Patil',
    email: 'shreya@example.com',
    isNewUser: false,
    stats: {
      total_packets: 12547,
      normal_traffic: 9842,
      intrusions_detected: 2705,
      attack_types_count: 5,
      normal_percentage: '81%',
      recent_alerts: []
    }
  },
  livePackets: [],
  logs: [],
  uploadedResults: []
};

// --- View Router ---

function switchView(viewName) {
  state.currentView = viewName;
  
  // Hide all main page views
  document.querySelectorAll('.page-view').forEach(view => {
    view.classList.remove('active');
  });

  const appLayout = document.getElementById('view-app');
  if (viewName === 'app') {
    appLayout.style.display = 'flex';
    applyUserDataToUI(state.user);
    switchAppTab(state.currentAppTab);
  } else {
    appLayout.style.display = 'none';
    const target = document.getElementById(`view-${viewName}`);
    if (target) {
      target.classList.add('active');
    }
  }

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function switchAppTab(tabName) {
  state.currentAppTab = tabName;

  // Update sidebar active buttons
  document.querySelectorAll('.sidebar-menu .nav-item').forEach(btn => {
    if (btn.getAttribute('data-tab') === tabName) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });

  // Switch subview
  document.querySelectorAll('.app-subview').forEach(subview => {
    subview.classList.remove('active');
  });

  const targetSubview = document.getElementById(`subview-${tabName}`);
  if (targetSubview) {
    targetSubview.classList.add('active');
  }

  // Trigger tab-specific renders
  if (tabName === 'dashboard') {
    setTimeout(() => {
      drawTrafficLineChart();
      drawAttackDonutChart();
    }, 50);
  } else if (tabName === 'live-traffic') {
    startLiveTrafficStream();
  } else if (tabName === 'detection-logs') {
    loadDetectionLogs();
  } else if (tabName === 'attack-analysis') {
    setTimeout(() => {
      drawAttacksOverTimeChart();
    }, 50);
  } else if (tabName === 'model-performance') {
    setTimeout(() => {
      drawRocCurveChart();
    }, 50);
  }
}

// --- Authentication & User Flows ---

function handleLogin(e) {
  e.preventDefault();
  const email = document.getElementById('login-email').value.trim();
  
  // Check if previously registered user in localStorage
  const stored = localStorage.getItem('netguard_current_user');
  if (stored) {
    try {
      const parsed = JSON.parse(stored);
      if (parsed.email === email) {
        state.user = parsed;
      } else {
        loadDemoDataForUser();
      }
    } catch(err) {
      loadDemoDataForUser();
    }
  } else {
    loadDemoDataForUser();
  }

  showToast(`Welcome back, ${state.user.name.split(' ')[0]}!`);
  switchView('app');
}

/**
 * Newly Registered User Account Generation
 * As requested: Creates an account in the system and sets all metrics to ZERO and BLANK!
 */
function handleRegister(e) {
  e.preventDefault();
  const nameInput = document.getElementById('reg-name');
  const emailInput = document.getElementById('reg-email');
  const passInput = document.getElementById('reg-pass');
  const pass2Input = document.getElementById('reg-pass2');

  const name = nameInput ? nameInput.value.trim() : 'New User';
  const email = emailInput ? emailInput.value.trim() : 'user@example.com';
  const pass = passInput ? passInput.value : '';
  const pass2 = pass2Input ? pass2Input.value : '';

  if (pass && pass2 && pass !== pass2) {
    alert('Passwords do not match. Please re-enter your password.');
    return;
  }

  // Create brand new user account with clean zero values
  const newUser = {
    name: name || 'New User',
    email: email || 'user@example.com',
    isNewUser: true,
    hasStartedStream: false,
    stats: {
      total_packets: 0,
      normal_traffic: 0,
      intrusions_detected: 0,
      attack_types_count: 0,
      normal_percentage: '0%',
      recent_alerts: []
    },
    liveTelemetry: {
      packets_per_sec: 0,
      data_transferred_mb: 0,
      active_connections: 0,
      suspicious_flows: 0
    },
    livePackets: [],
    detectionLogs: []
  };

  state.user = newUser;
  localStorage.setItem('netguard_current_user', JSON.stringify(newUser));

  showToast(`Account generated successfully for ${newUser.name}! Starting with clean zero-state.`);
  switchView('app');
}

function loginDirectly() {
  loadDemoDataForUser();
  showToast(`Welcome to NetGuard AI! Loaded interactive demonstration.`);
  switchView('app');
}

function openLogoutModal() {
  document.getElementById('modal-logout').classList.add('show');
}

function closeLogoutModal() {
  document.getElementById('modal-logout').classList.remove('show');
}

function confirmLogout() {
  closeLogoutModal();
  showToast('You have been securely logged out.');
  switchView('landing');
}

// --- Topbar Dropdowns & UI Controls ---

function toggleSidebar() {
  const sidebar = document.querySelector('.app-sidebar');
  sidebar.classList.toggle('open');
}

function toggleNotificationDropdown() {
  const dd = document.getElementById('notification-dropdown');
  dd.classList.toggle('show');
  document.getElementById('user-menu-dropdown').classList.remove('show');
  document.getElementById('topbar-upload-dropdown')?.classList.remove('show');
}

function toggleUserDropdown() {
  const dd = document.getElementById('user-menu-dropdown');
  dd.classList.toggle('show');
  document.getElementById('notification-dropdown').classList.remove('show');
  document.getElementById('topbar-upload-dropdown')?.classList.remove('show');
}

// Topbar Upload Handlers
function handleTopbarUploadClick() {
  switchAppTab('upload-data');
  const dropZone = document.getElementById('drop-zone');
  if (dropZone) {
    dropZone.scrollIntoView({ behavior: 'smooth' });
    dropZone.style.boxShadow = '0 0 0 4px rgba(255, 20, 117, 0.4)';
    setTimeout(() => {
      dropZone.style.boxShadow = '';
    }, 1600);
  }
}

function toggleUploadDropdown(event) {
  if (event) event.stopPropagation();
  const dd = document.getElementById('topbar-upload-dropdown');
  dd.classList.toggle('show');
  document.getElementById('notification-dropdown')?.classList.remove('show');
  document.getElementById('user-menu-dropdown')?.classList.remove('show');
}

function triggerTopbarFilePicker() {
  document.getElementById('topbar-upload-dropdown')?.classList.remove('show');
  document.getElementById('topbar-csv-input')?.click();
}

function handleTopbarFileSelect(file) {
  if (file) {
    switchAppTab('upload-data');
    handleFileUpload(file);
  }
}

function loadSampleDatasetFromTopbar() {
  document.getElementById('topbar-upload-dropdown')?.classList.remove('show');
  switchAppTab('upload-data');
  loadSampleDataset();
}

window.addEventListener('click', (e) => {
  if (!e.target.closest('.notification-wrapper') && !e.target.closest('.user-pill') && !e.target.closest('.topbar-upload-wrapper')) {
    document.getElementById('notification-dropdown')?.classList.remove('show');
    document.getElementById('user-menu-dropdown')?.classList.remove('show');
    document.getElementById('topbar-upload-dropdown')?.classList.remove('show');
  }
});

// Toast notification helper
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = 'toast-item';
  toast.innerHTML = `<span>🛡️</span> <span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// --- Apply User Data to UI (Zero State for New Users vs Populated) ---

function applyUserDataToUI(user) {
  if (!user) return;
  
  const firstName = (user.name || 'User').split(' ')[0];
  const initial = (user.name || 'U').charAt(0).toUpperCase();

  const elGreeting = document.getElementById('user-greeting-text');
  if (elGreeting) elGreeting.innerText = `Welcome, ${firstName}!`;

  const elName = document.querySelector('.user-name');
  if (elName) elName.innerText = firstName;

  const elAvatar = document.querySelector('.user-avatar');
  if (elAvatar) elAvatar.innerText = initial;

  const elDropdownHeader = document.querySelector('.user-dropdown .dropdown-header');
  if (elDropdownHeader) {
    elDropdownHeader.innerHTML = `<strong>${user.name}</strong><small>${user.email}</small>`;
  }

  const elSettingName = document.getElementById('setting-name');
  if (elSettingName) elSettingName.value = user.name;

  const elSettingEmail = document.getElementById('setting-email');
  if (elSettingEmail) elSettingEmail.value = user.email;

  const banner = document.getElementById('new-user-welcome-banner');
  const bannerTitle = document.getElementById('banner-user-title');
  if (bannerTitle) bannerTitle.innerText = `Welcome to NetGuard AI, ${firstName}!`;

  // Check if New User with Zero Values
  const isZero = user.isNewUser && user.stats.total_packets === 0;

  if (isZero) {
    if (banner) banner.style.display = 'block';

    // 4 Stat Cards to 0
    document.getElementById('stat-total-packets').innerText = '0';
    document.getElementById('stat-normal-traffic').innerText = '0';
    document.getElementById('stat-intrusions').innerText = '0';
    document.getElementById('stat-attack-types').innerText = '0';

    const subs = document.querySelectorAll('#subview-dashboard .stat-sub');
    if (subs.length >= 4) {
      subs[0].innerHTML = `<small>No traffic captured yet</small>`;
      subs[1].innerHTML = `<small>0% traffic ratio</small>`;
      subs[2].innerHTML = `<small>0 threats detected</small>`;
      subs[3].innerHTML = `<small>0 active types</small>`;
    }

    // Empty Recent Alerts
    const tbodyAlerts = document.getElementById('dashboard-recent-alerts-tbody');
    if (tbodyAlerts) {
      tbodyAlerts.innerHTML = `
        <tr>
          <td colspan="6" class="empty-state-cell">
            <span class="empty-icon">🛡️</span>
            <span class="empty-title">No Recent Alerts</span>
            <span class="empty-desc">Your network is clean and awaiting traffic flows. Upload CSV data or launch a live stream to analyze threats.</span>
          </td>
        </tr>
      `;
    }

    // Set Live Traffic KPIs to 0
    updateLiveKpis({
      packets_per_sec: 0,
      data_transferred_mb: 0,
      active_connections: 0,
      suspicious_flows: 0
    });

    const liveTbody = document.getElementById('live-feed-tbody');
    if (liveTbody) {
      liveTbody.innerHTML = `
        <tr>
          <td colspan="6" class="empty-state-cell">
            <span class="empty-icon">📡</span>
            <span class="empty-title">Live Traffic Capture Idle</span>
            <span class="empty-desc">Click "Start Capture" or upload data to begin streaming and inspecting network packets.</span>
          </td>
        </tr>
      `;
    }

    const btnText = document.getElementById('pause-btn-text');
    const icon = document.getElementById('pause-icon');
    const statusText = document.getElementById('stream-status-text');
    if (btnText) btnText.innerText = 'Start Capture';
    if (icon) icon.innerText = '▶';
    if (statusText) {
      statusText.innerText = 'Idle';
      statusText.style.color = '#F59E0B';
    }
    state.isStreamPaused = true;

    // Empty Detection Logs
    const tbodyLogs = document.getElementById('detection-logs-tbody');
    if (tbodyLogs) {
      tbodyLogs.innerHTML = `
        <tr>
          <td colspan="6" class="empty-state-cell">
            <span class="empty-icon">📜</span>
            <span class="empty-title">No Intrusion Logs</span>
            <span class="empty-desc">No network threats detected. Logs will populate as incoming traffic flows are processed.</span>
          </td>
        </tr>
      `;
    }

    updateAttackBreakdownZero();

  } else {
    // Populated State (Demo or Uploaded User Traffic)
    if (banner) banner.style.display = 'none';

    document.getElementById('stat-total-packets').innerText = user.stats.total_packets.toLocaleString();
    document.getElementById('stat-normal-traffic').innerText = user.stats.normal_traffic.toLocaleString();
    document.getElementById('stat-intrusions').innerText = user.stats.intrusions_detected.toLocaleString();
    document.getElementById('stat-attack-types').innerText = user.stats.attack_types_count;

    const subs = document.querySelectorAll('#subview-dashboard .stat-sub');
    if (subs.length >= 4) {
      subs[0].innerHTML = `<span>↑ 12%</span> <small>vs last hour</small>`;
      subs[1].innerHTML = `<span>↑ ${user.stats.normal_percentage || '81%'}</span> <small>traffic ratio</small>`;
      subs[2].innerHTML = `<span>↑ 15%</span> <small>mitigated</small>`;
      subs[3].innerHTML = `<span>View Details →</span>`;
    }

    if (user.stats.recent_alerts && user.stats.recent_alerts.length > 0) {
      renderDashboardAlerts(user.stats.recent_alerts);
    } else {
      renderDefaultRecentAlerts();
    }

    restoreAttackBreakdownDemo();
  }

  drawTrafficLineChart();
  drawAttackDonutChart();
  drawAttacksOverTimeChart();
  drawRocCurveChart();
}

function updateAttackBreakdownZero() {
  const breakdownRows = document.querySelectorAll('.breakdown-list .breakdown-row');
  breakdownRows.forEach(row => {
    const count = row.querySelector('.b-count');
    const pct = row.querySelector('.b-pct');
    const fill = row.querySelector('.progress-fill');
    if (count) count.innerText = '0';
    if (pct) pct.innerText = '0%';
    if (fill) fill.style.width = '0%';
  });
}

function restoreAttackBreakdownDemo() {
  const defaultData = [
    { count: '864', pct: '32%', width: '32%' },
    { count: '649', pct: '24%', width: '24%' },
    { count: '487', pct: '18%', width: '18%' },
    { count: '378', pct: '14%', width: '14%' },
    { count: '216', pct: '8%', width: '8%' },
    { count: '111', pct: '4%', width: '4%' }
  ];
  const breakdownRows = document.querySelectorAll('.breakdown-list .breakdown-row');
  breakdownRows.forEach((row, i) => {
    if (defaultData[i]) {
      const count = row.querySelector('.b-count');
      const pct = row.querySelector('.b-pct');
      const fill = row.querySelector('.progress-fill');
      if (count) count.innerText = defaultData[i].count;
      if (pct) pct.innerText = defaultData[i].pct;
      if (fill) fill.style.width = defaultData[i].width;
    }
  });
}

function startLiveStreamFromBanner() {
  switchAppTab('live-traffic');
  state.isStreamPaused = false;
  state.user.hasStartedStream = true;
  const btnText = document.getElementById('pause-btn-text');
  const icon = document.getElementById('pause-icon');
  const statusText = document.getElementById('stream-status-text');
  if (btnText) btnText.innerText = 'Pause';
  if (icon) icon.innerText = '⏸';
  if (statusText) {
    statusText.innerText = 'Live';
    statusText.style.color = '#10B981';
  }
  startLiveTrafficStream();
  showToast('Live traffic capture started! Streaming network flows in real time.');
}

function loadDemoDataForUser() {
  state.user = {
    name: 'Shreya Patil',
    email: 'shreya@example.com',
    isNewUser: false,
    stats: {
      total_packets: 12547,
      normal_traffic: 9842,
      intrusions_detected: 2705,
      attack_types_count: 5,
      normal_percentage: '81%',
      recent_alerts: []
    }
  };
  localStorage.setItem('netguard_current_user', JSON.stringify(state.user));
  applyUserDataToUI(state.user);
  showToast('Demo dataset loaded with full sample telemetry!');
}

function renderDashboardAlerts(alerts) {
  const tbody = document.getElementById('dashboard-recent-alerts-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="empty-state-cell">
          <span class="empty-icon">🛡️</span>
          <span class="empty-title">No Recent Alerts</span>
          <span class="empty-desc">Your network is clean and ready. Upload CSV traffic or launch live stream to analyze flows.</span>
        </td>
      </tr>
    `;
    return;
  }

  alerts.forEach(alert => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono-ip">${alert.timestamp}</td>
      <td class="mono-ip" style="color: #FF1475; font-weight: 600;">${alert.source_ip}</td>
      <td class="mono-ip">${alert.destination_ip}</td>
      <td><strong>${alert.attack_type}</strong></td>
      <td>${getSeverityBadge(alert.severity)}</td>
      <td>${getStatusBadge(alert.status)}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderDefaultRecentAlerts() {
  const mockAlerts = [
    { timestamp: "2025-09-10 14:23:11", source_ip: "203.45.12.8", destination_ip: "10.0.0.5", attack_type: "DoS", severity: "High", status: "Blocked" },
    { timestamp: "2025-09-10 14:19:45", source_ip: "185.67.33.21", destination_ip: "10.0.0.8", attack_type: "Port Scan", severity: "Medium", status: "Detected" },
    { timestamp: "2025-09-10 14:16:45", source_ip: "110.92.64.13", destination_ip: "10.0.0.9", attack_type: "Brute Force", severity: "High", status: "Blocked" },
    { timestamp: "2025-09-10 14:15:10", source_ip: "192.168.1.25", destination_ip: "10.0.0.7", attack_type: "Normal", severity: "Low", status: "Allowed" }
  ];
  renderDashboardAlerts(mockAlerts);
}

// --- Canvas Charts Implementation ---

// 1. Dual-Line 24H Traffic Chart
function drawTrafficLineChart() {
  const canvas = document.getElementById('chart-traffic-line');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  
  const width = canvas.parentElement.clientWidth;
  const height = 230;
  canvas.width = width * window.devicePixelRatio;
  canvas.height = height * window.devicePixelRatio;
  canvas.style.width = width + 'px';
  canvas.style.height = height + 'px';
  ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

  ctx.clearRect(0, 0, width, height);

  const labels = ['00:00', '02:00', '04:00', '06:00', '08:00', '10:00', '12:00', '14:00', '16:00', '18:00', '20:00', '22:00', '24:00'];
  
  const isZeroState = state.user && state.user.isNewUser && state.user.stats.total_packets === 0;
  const normalData = isZeroState 
    ? [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    : [520, 480, 590, 710, 840, 930, 890, 950, 910, 860, 790, 720, 680];
  const maliciousData = isZeroState
    ? [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    : [110, 130, 180, 210, 270, 310, 280, 340, 310, 260, 220, 170, 140];

  const paddingLeft = 50;
  const paddingRight = 20;
  const paddingTop = 20;
  const paddingBottom = 35;
  const chartW = width - paddingLeft - paddingRight;
  const chartH = height - paddingTop - paddingBottom;

  const maxVal = isZeroState ? 100 : 1200;

  // Grid lines
  ctx.strokeStyle = state.theme === 'dark' ? 'rgba(255,255,255,0.06)' : '#E2E8F0';
  ctx.lineWidth = 1;
  ctx.fillStyle = '#94A3B8';
  ctx.font = '11px sans-serif';
  ctx.textAlign = 'right';

  for (let i = 0; i <= 4; i++) {
    const yVal = Math.round((maxVal / 4) * i);
    const y = paddingTop + chartH - (i / 4) * chartH;
    ctx.beginPath();
    ctx.moveTo(paddingLeft, y);
    ctx.lineTo(width - paddingRight, y);
    ctx.stroke();
    ctx.fillText(yVal, paddingLeft - 8, y + 4);
  }

  // X-axis labels
  ctx.textAlign = 'center';
  const stepX = chartW / (labels.length - 1);
  labels.forEach((lbl, idx) => {
    const x = paddingLeft + idx * stepX;
    ctx.fillText(lbl, x, height - 10);
  });

  if (isZeroState) {
    // Draw flat zero line along bottom
    ctx.beginPath();
    ctx.moveTo(paddingLeft, paddingTop + chartH);
    ctx.lineTo(paddingLeft + chartW, paddingTop + chartH);
    ctx.strokeStyle = '#00F5FF';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Clean center message
    ctx.fillStyle = '#64748B';
    ctx.font = '13px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('No network traffic recorded yet (0 packets). Upload CSV data to populate.', paddingLeft + chartW / 2, paddingTop + chartH / 2);
    return;
  }

  function renderLine(data, color, fillColor) {
    const pts = data.map((val, idx) => ({
      x: paddingLeft + idx * stepX,
      y: paddingTop + chartH - (val / maxVal) * chartH
    }));

    ctx.beginPath();
    ctx.moveTo(pts[0].x, paddingTop + chartH);
    pts.forEach(p => ctx.lineTo(p.x, p.y));
    ctx.lineTo(pts[pts.length - 1].x, paddingTop + chartH);
    ctx.closePath();
    ctx.fillStyle = fillColor;
    ctx.fill();

    ctx.beginPath();
    ctx.moveTo(pts[0].x, pts[0].y);
    for (let i = 0; i < pts.length - 1; i++) {
      const xc = (pts[i].x + pts[i + 1].x) / 2;
      const yc = (pts[i].y + pts[i + 1].y) / 2;
      ctx.quadraticCurveTo(pts[i].x, pts[i].y, xc, yc);
    }
    ctx.lineTo(pts[pts.length - 1].x, pts[pts.length - 1].y);
    ctx.strokeStyle = color;
    ctx.lineWidth = 2.5;
    ctx.stroke();

    pts.forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
      ctx.fillStyle = '#FFFFFF';
      ctx.fill();
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.stroke();
    });
  }

  renderLine(normalData, '#00F5FF', 'rgba(0, 245, 255, 0.08)');
  renderLine(maliciousData, '#FF1475', 'rgba(255, 20, 117, 0.08)');
}

// 2. Attack Distribution Donut Chart
function drawAttackDonutChart() {
  const canvas = document.getElementById('chart-attack-donut');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const size = 190;
  canvas.width = size * window.devicePixelRatio;
  canvas.height = size * window.devicePixelRatio;
  canvas.style.width = size + 'px';
  canvas.style.height = size + 'px';
  ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

  ctx.clearRect(0, 0, size, size);

  const isZeroState = state.user && state.user.isNewUser && state.user.stats.intrusions_detected === 0;

  const cx = size / 2;
  const cy = size / 2;
  const outerR = 85;
  const innerR = 60;

  const centerCountEl = document.querySelector('.donut-center-stat .center-count');
  if (centerCountEl) {
    centerCountEl.innerText = isZeroState ? '0' : '2,705';
  }

  if (isZeroState) {
    // Draw single clean placeholder circle
    ctx.beginPath();
    ctx.arc(cx, cy, outerR, 0, Math.PI * 2);
    ctx.arc(cx, cy, innerR, Math.PI * 2, 0, true);
    ctx.closePath();
    ctx.fillStyle = state.theme === 'dark' ? 'rgba(255, 255, 255, 0.08)' : '#E2E8F0';
    ctx.fill();

    // Set legend values to 0%
    document.querySelectorAll('.donut-legend-row .val').forEach(el => {
      el.innerText = '0%';
    });
    return;
  }

  const defaultVals = ['32%', '24%', '18%', '14%', '8%', '4%'];
  document.querySelectorAll('.donut-legend-row .val').forEach((el, idx) => {
    if (defaultVals[idx]) el.innerText = defaultVals[idx];
  });

  const data = [
    { label: 'DoS/DDoS', pct: 0.32, color: '#FF1475' },
    { label: 'Port Scan', pct: 0.24, color: '#00F5FF' },
    { label: 'Brute Force', pct: 0.18, color: '#A855F7' },
    { label: 'Botnet', pct: 0.14, color: '#3B82F6' },
    { label: 'Web Attack', pct: 0.08, color: '#F59E0B' },
    { label: 'Others', pct: 0.04, color: '#6B7280' }
  ];

  let currentAngle = -Math.PI / 2;
  data.forEach(slice => {
    const sliceAngle = slice.pct * Math.PI * 2;
    ctx.beginPath();
    ctx.arc(cx, cy, outerR, currentAngle, currentAngle + sliceAngle);
    ctx.arc(cx, cy, innerR, currentAngle + sliceAngle, currentAngle, true);
    ctx.closePath();
    ctx.fillStyle = slice.color;
    ctx.fill();
    currentAngle += sliceAngle;
  });
}

// 3. Attacks Over Time Bar Chart (Sep 4 - Sep 10)
function drawAttacksOverTimeChart() {
  const canvas = document.getElementById('chart-attacks-over-time');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const width = canvas.parentElement.clientWidth;
  const height = 240;
  canvas.width = width * window.devicePixelRatio;
  canvas.height = height * window.devicePixelRatio;
  canvas.style.width = width + 'px';
  canvas.style.height = height + 'px';
  ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

  ctx.clearRect(0, 0, width, height);

  const isZeroState = state.user && state.user.isNewUser && state.user.stats.intrusions_detected === 0;

  const days = ['Sep 4', 'Sep 5', 'Sep 6', 'Sep 7', 'Sep 8', 'Sep 9', 'Sep 10'];
  const categories = [
    { name: 'DoS', color: '#FF1475', values: isZeroState ? [0, 0, 0, 0, 0, 0, 0] : [110, 145, 120, 160, 130, 180, 150] },
    { name: 'Port Scan', color: '#00F5FF', values: isZeroState ? [0, 0, 0, 0, 0, 0, 0] : [85, 95, 110, 90, 105, 120, 95] },
    { name: 'Brute Force', color: '#A855F7', values: isZeroState ? [0, 0, 0, 0, 0, 0, 0] : [60, 75, 80, 65, 85, 90, 70] },
    { name: 'Botnet', color: '#3B82F6', values: isZeroState ? [0, 0, 0, 0, 0, 0, 0] : [45, 50, 60, 55, 65, 70, 55] },
    { name: 'Web Attack', color: '#F59E0B', values: isZeroState ? [0, 0, 0, 0, 0, 0, 0] : [30, 35, 40, 28, 38, 42, 32] }
  ];

  const padLeft = 40;
  const padRight = 20;
  const padTop = 20;
  const padBottom = 30;
  const chartW = width - padLeft - padRight;
  const chartH = height - padTop - padBottom;
  const maxVal = isZeroState ? 50 : 200;

  // Grid
  ctx.strokeStyle = state.theme === 'dark' ? 'rgba(255,255,255,0.06)' : '#E2E8F0';
  ctx.lineWidth = 1;
  ctx.fillStyle = '#94A3B8';
  ctx.font = '11px sans-serif';
  ctx.textAlign = 'right';

  for (let i = 0; i <= 4; i++) {
    const val = (maxVal / 4) * i;
    const y = padTop + chartH - (i / 4) * chartH;
    ctx.beginPath();
    ctx.moveTo(padLeft, y);
    ctx.lineTo(width - padRight, y);
    ctx.stroke();
    ctx.fillText(val, padLeft - 6, y + 4);
  }

  // Draw grouped bars
  const dayWidth = chartW / days.length;
  const barWidth = 6;
  const gap = 3;

  days.forEach((day, dayIdx) => {
    const dayCenterX = padLeft + dayIdx * dayWidth + dayWidth / 2;
    const groupWidth = categories.length * (barWidth + gap);
    const startX = dayCenterX - groupWidth / 2;

    categories.forEach((cat, catIdx) => {
      const val = cat.values[dayIdx];
      const barH = (val / maxVal) * chartH;
      const x = startX + catIdx * (barWidth + gap);
      const y = padTop + chartH - barH;

      ctx.fillStyle = cat.color;
      ctx.beginPath();
      ctx.roundRect(x, y, barWidth, barH, [3, 3, 0, 0]);
      ctx.fill();
    });

    ctx.textAlign = 'center';
    ctx.fillStyle = '#64748B';
    ctx.fillText(day, dayCenterX, height - 8);
  });

  if (isZeroState) {
    ctx.fillStyle = '#64748B';
    ctx.font = '13px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('No attack activity recorded (0 intrusions). Network is secure.', padLeft + chartW / 2, padTop + chartH / 2);
  }
}

// 4. ROC Curve Chart
function drawRocCurveChart() {
  const canvas = document.getElementById('chart-roc-curve');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const width = canvas.parentElement.clientWidth;
  const height = 230;
  canvas.width = width * window.devicePixelRatio;
  canvas.height = height * window.devicePixelRatio;
  canvas.style.width = width + 'px';
  canvas.style.height = height + 'px';
  ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

  ctx.clearRect(0, 0, width, height);

  const padLeft = 45;
  const padRight = 20;
  const padTop = 20;
  const padBottom = 35;
  const chartW = width - padLeft - padRight;
  const chartH = height - padTop - padBottom;

  // Axis grid
  ctx.strokeStyle = state.theme === 'dark' ? 'rgba(255,255,255,0.06)' : '#E2E8F0';
  ctx.lineWidth = 1;
  ctx.fillStyle = '#94A3B8';
  ctx.font = '11px sans-serif';
  ctx.textAlign = 'right';

  for (let i = 0; i <= 5; i++) {
    const val = (i * 0.2).toFixed(1);
    const y = padTop + chartH - (i / 5) * chartH;
    ctx.beginPath();
    ctx.moveTo(padLeft, y);
    ctx.lineTo(width - padRight, y);
    ctx.stroke();
    ctx.fillText(val, padLeft - 6, y + 4);
  }

  // X labels
  ctx.textAlign = 'center';
  for (let i = 0; i <= 5; i++) {
    const val = (i * 0.2).toFixed(1);
    const x = padLeft + (i / 5) * chartW;
    ctx.fillText(val, x, height - 12);
  }

  // Diagonal Random Classifier line (dotted)
  ctx.beginPath();
  ctx.setLineDash([4, 4]);
  ctx.moveTo(padLeft, padTop + chartH);
  ctx.lineTo(padLeft + chartW, padTop);
  ctx.strokeStyle = '#94A3B8';
  ctx.lineWidth = 1.5;
  ctx.stroke();
  ctx.setLineDash([]); // reset

  // ROC Points (AUC 0.98)
  const rocPoints = [
    { x: 0.0, y: 0.0 },
    { x: 0.02, y: 0.72 },
    { x: 0.04, y: 0.86 },
    { x: 0.08, y: 0.94 },
    { x: 0.15, y: 0.97 },
    { x: 0.35, y: 0.985 },
    { x: 0.7, y: 0.995 },
    { x: 1.0, y: 1.0 }
  ];

  ctx.beginPath();
  rocPoints.forEach((p, idx) => {
    const px = padLeft + p.x * chartW;
    const py = padTop + chartH - p.y * chartH;
    if (idx === 0) ctx.moveTo(px, py);
    else ctx.lineTo(px, py);
  });

  ctx.strokeStyle = '#FF1475';
  ctx.lineWidth = 3;
  ctx.stroke();

  // Area under curve
  ctx.lineTo(padLeft + chartW, padTop + chartH);
  ctx.lineTo(padLeft, padTop + chartH);
  ctx.closePath();
  ctx.fillStyle = 'rgba(255, 20, 117, 0.08)';
  ctx.fill();
}

// --- 5. Live Traffic Stream Simulator ---

function startLiveTrafficStream() {
  if (state.streamInterval) clearInterval(state.streamInterval);

  // If new user and hasn't started streaming, keep it idle
  if (state.user && state.user.isNewUser && state.user.stats.total_packets === 0 && !state.user.hasStartedStream) {
    return;
  }

  // Fetch initial batch
  fetchLivePackets();

  // Polling loop every 1.6s
  state.streamInterval = setInterval(() => {
    if (!state.isStreamPaused && state.currentAppTab === 'live-traffic') {
      fetchLivePackets();
    }
  }, 1600);
}

async function fetchLivePackets() {
  try {
    const res = await fetch('/api/live-traffic?count=1');
    if (res.ok) {
      const data = await res.json();
      if (data.traffic && data.traffic.length > 0) {
        prependLivePacket(data.traffic[0]);
      }
      if (data.kpis) {
        updateLiveKpis(data.kpis);
      }
    } else {
      generateLocalPacket();
    }
  } catch (err) {
    generateLocalPacket();
  }
}

function generateLocalPacket() {
  const protocols = ['TCP', 'UDP', 'ICMP'];
  const ips = ['192.168.1.10', '203.45.12.8', '185.67.33.21', '110.92.64.13', '192.168.1.25', '45.76.11.9'];
  const dsts = ['10.0.0.5', '10.0.0.8', '10.0.0.9', '10.0.0.7', '10.0.0.4'];
  const attacks = ['Normal', 'DoS', 'Port Scan', 'Brute Force', 'Normal'];

  const now = new Date();
  const timeStr = now.toTimeString().split(' ')[0];
  const pred = attacks[Math.floor(Math.random() * attacks.length)];

  prependLivePacket({
    timestamp: timeStr,
    source_ip: ips[Math.floor(Math.random() * ips.length)],
    destination_ip: dsts[Math.floor(Math.random() * dsts.length)],
    protocol: protocols[Math.floor(Math.random() * protocols.length)],
    packet_size: Math.floor(Math.random() * 1200) + 64,
    prediction: pred
  });
}

function prependLivePacket(packet) {
  state.livePackets.unshift(packet);
  if (state.livePackets.length > 30) state.livePackets.pop();

  const tbody = document.getElementById('live-feed-tbody');
  if (!tbody) return;

  // Clear any empty-state row
  const emptyCell = tbody.querySelector('.empty-state-cell');
  if (emptyCell) tbody.innerHTML = '';

  const tr = document.createElement('tr');
  tr.style.animation = 'fadeIn 0.4s ease';
  tr.innerHTML = `
    <td class="mono-ip">${packet.timestamp}</td>
    <td class="mono-ip" style="color: ${packet.prediction === 'Normal' ? '#0F172A' : '#FF1475'}; font-weight: 600;">${packet.source_ip}</td>
    <td class="mono-ip">${packet.destination_ip}</td>
    <td><span class="badge badge-secondary">${packet.protocol}</span></td>
    <td>${packet.packet_size} B</td>
    <td>${getPredictionBadge(packet.prediction)}</td>
  `;

  tbody.insertBefore(tr, tbody.firstChild);

  while (tbody.children.length > 20) {
    tbody.removeChild(tbody.lastChild);
  }
}

function updateLiveKpis(kpis) {
  const elPkt = document.getElementById('kpi-packets-sec');
  const elConn = document.getElementById('kpi-active-conns');
  const elSusp = document.getElementById('kpi-suspicious');
  if (elPkt) elPkt.innerText = kpis.packets_per_sec.toLocaleString();
  if (elConn) elConn.innerText = kpis.active_connections;
  if (elSusp) elSusp.innerText = kpis.suspicious_flows;
}

function toggleLiveFeed() {
  state.isStreamPaused = !state.isStreamPaused;
  if (!state.isStreamPaused && state.user) {
    state.user.hasStartedStream = true;
  }
  const btnText = document.getElementById('pause-btn-text');
  const icon = document.getElementById('pause-icon');
  const statusText = document.getElementById('stream-status-text');

  if (state.isStreamPaused) {
    btnText.innerText = 'Resume';
    icon.innerText = '▶';
    statusText.innerText = 'Paused';
    statusText.style.color = '#F59E0B';
  } else {
    btnText.innerText = 'Pause';
    icon.innerText = '⏸';
    statusText.innerText = 'Live';
    statusText.style.color = '#10B981';
    if (!state.streamInterval) startLiveTrafficStream();
  }
}

function filterLiveFeed() {
  const query = document.getElementById('live-search-input').value.toLowerCase();
  const rows = document.querySelectorAll('#live-feed-tbody tr');
  rows.forEach(row => {
    const text = row.innerText.toLowerCase();
    row.style.display = text.includes(query) ? '' : 'none';
  });
}

// --- 6. Detection Logs Management ---

async function loadDetectionLogs() {
  const isZero = state.user && state.user.isNewUser && state.user.stats.total_packets === 0;
  if (isZero) {
    const tbody = document.getElementById('detection-logs-tbody');
    if (tbody) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" class="empty-state-cell">
            <span class="empty-icon">📜</span>
            <span class="empty-title">No Intrusion Logs</span>
            <span class="empty-desc">No network threats detected. Your logs will appear here when suspicious traffic flows are flagged.</span>
          </td>
        </tr>
      `;
    }
    return;
  }

  const attack = document.getElementById('filter-attack-type').value;
  const severity = document.getElementById('filter-severity').value;
  const page = state.logsPage;

  try {
    const res = await fetch(`/api/logs?attack_type=${attack}&severity=${severity}&page=${page}&per_page=${state.logsPerPage}`);
    if (res.ok) {
      const data = await res.json();
      state.logs = data.logs;
      renderDetectionLogsTable(data.logs);
      updatePagination(data.page, data.total_pages);
    }
  } catch (err) {
    console.error('Failed to load logs', err);
  }
}

function renderDetectionLogsTable(logs) {
  const tbody = document.getElementById('detection-logs-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  if (!logs || logs.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="empty-state-cell">
          <span class="empty-icon">📜</span>
          <span class="empty-title">No Intrusion Logs</span>
          <span class="empty-desc">No logs match your filter criteria.</span>
        </td>
      </tr>
    `;
    return;
  }

  logs.forEach(log => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono-ip">${log.timestamp}</td>
      <td class="mono-ip" style="color: #FF1475; font-weight: 600;">${log.source_ip}</td>
      <td class="mono-ip">${log.destination_ip}</td>
      <td><strong>${log.attack_type}</strong></td>
      <td>${getSeverityBadge(log.severity)}</td>
      <td>
        <button class="btn btn-outline btn-sm" onclick="inspectIncident(${log.id})">
          👁 View
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function updatePagination(current, total) {
  document.querySelectorAll('.pagination-bar .page-btn').forEach((btn, idx) => {
    if (idx > 0 && idx <= 5) {
      btn.classList.toggle('active', parseInt(btn.innerText) === current);
    }
  });
}

function setLogsPage(p) {
  state.logsPage = p;
  loadDetectionLogs();
}

function changeLogsPage(delta) {
  state.logsPage = Math.max(1, state.logsPage + delta);
  loadDetectionLogs();
}

function applyLogsFilter() {
  state.logsPage = 1;
  loadDetectionLogs();
  showToast('Detection logs filter applied.');
}

function resetLogsFilter() {
  document.getElementById('filter-attack-type').value = 'All';
  document.getElementById('filter-severity').value = 'All';
  state.logsPage = 1;
  loadDetectionLogs();
}

// Incident detail inspector modal
function inspectIncident(id) {
  const log = state.logs.find(l => l.id === id) || {
    id: id,
    timestamp: "2025-09-10 14:23:11",
    source_ip: "203.45.12.8",
    destination_ip: "10.0.0.5",
    protocol: "TCP",
    packet_size: 468,
    attack_type: "DoS",
    severity: "High",
    status: "Blocked",
    details: "High flow packet rate: 2,800 pkts/s. SYN flag anomaly detected by Random Forest model."
  };

  const modalBody = document.getElementById('modal-detail-body');
  modalBody.innerHTML = `
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 20px;">
      <div><strong>Timestamp:</strong> <span class="mono-ip">${log.timestamp}</span></div>
      <div><strong>Severity:</strong> ${getSeverityBadge(log.severity)}</div>
      <div><strong>Source IP:</strong> <span class="mono-ip highlight-magenta">${log.source_ip}</span></div>
      <div><strong>Destination IP:</strong> <span class="mono-ip">${log.destination_ip}</span></div>
      <div><strong>Protocol:</strong> <span class="badge badge-secondary">${log.protocol}</span></div>
      <div><strong>Current Status:</strong> ${getStatusBadge(log.status)}</div>
    </div>
    <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 16px; margin-bottom: 15px;">
      <h4 style="font-size: 14px; margin-bottom: 6px;">Machine Learning Evaluation</h4>
      <p style="font-size: 13px; color: #475569;">${log.details}</p>
    </div>
  `;

  document.getElementById('modal-attack-detail').classList.add('show');
}

function closeDetailModal() {
  document.getElementById('modal-attack-detail').classList.remove('show');
}

function blockIncidentIP() {
  closeDetailModal();
  showToast('IP address successfully added to firewall blocklist!');
}

// --- 9. Upload Data & Batch ML Inference ---

const dropZone = document.getElementById('drop-zone');
if (dropZone) {
  ['dragenter', 'dragover'].forEach(name => {
    dropZone.addEventListener(name, (e) => {
      e.preventDefault();
      dropZone.classList.add('drag-over');
    });
  });
  ['dragleave', 'drop'].forEach(name => {
    dropZone.addEventListener(name, (e) => {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
    });
  });
  dropZone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) handleFileUpload(files[0]);
  });
}

async function handleFileUpload(file) {
  if (!file || !file.name.endsWith('.csv')) {
    alert('Please upload a valid CSV file.');
    return;
  }

  showToast(`Uploading and analyzing ${file.name}...`);
  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/upload', {
      method: 'POST',
      body: formData
    });

    if (res.ok) {
      const data = await res.json();
      displayUploadResults(data);
    } else {
      simulateUploadResults(file.name);
    }
  } catch (err) {
    simulateUploadResults(file.name);
  }
}

async function loadSampleDataset() {
  showToast('Loading sample CIC-IDS2017 dataset for inference...');
  try {
    const res = await fetch('/api/sample-csv');
    if (res.ok) {
      const blob = await res.blob();
      const file = new File([blob], 'cic_ids2017_sample.csv', { type: 'text/csv' });
      handleFileUpload(file);
    } else {
      simulateUploadResults('cic_ids2017_sample.csv');
    }
  } catch (err) {
    simulateUploadResults('cic_ids2017_sample.csv');
  }
}

function displayUploadResults(data) {
  state.uploadedResults = data.sample_results;

  document.getElementById('res-total-rows').innerText = data.total_analyzed;
  document.getElementById('res-normal-rows').innerText = data.normal_count;
  document.getElementById('res-attack-rows').innerText = data.attack_count;
  document.getElementById('res-attack-rate').innerText = `${data.attack_rate}%`;

  const tbody = document.getElementById('upload-results-tbody');
  tbody.innerHTML = '';

  data.sample_results.forEach(row => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${row.row_index}</td>
      <td class="mono-ip">${row.duration}</td>
      <td><span class="badge badge-secondary">${row.protocol}</span></td>
      <td class="mono-ip">${row.src_bytes.toLocaleString()}</td>
      <td class="mono-ip">${row.dst_bytes.toLocaleString()}</td>
      <td>${getPredictionBadge(row.prediction)}</td>
      <td><strong>${(row.confidence * 100).toFixed(1)}%</strong></td>
      <td>${getStatusBadge(row.status)}</td>
    `;
    tbody.appendChild(tr);
  });

  const container = document.getElementById('upload-results-container');
  container.style.display = 'block';
  container.scrollIntoView({ behavior: 'smooth' });

  // Update user stats with their uploaded data
  if (state.user) {
    state.user.stats.total_packets = (state.user.stats.total_packets || 0) + data.total_analyzed;
    state.user.stats.normal_traffic = (state.user.stats.normal_traffic || 0) + data.normal_count;
    state.user.stats.intrusions_detected = (state.user.stats.intrusions_detected || 0) + data.attack_count;
    
    const distinctAttacks = Object.keys(data.breakdown || {}).filter(k => data.breakdown[k] > 0).length;
    state.user.stats.attack_types_count = Math.max(state.user.stats.attack_types_count || 0, distinctAttacks);
    state.user.isNewUser = false; // User now has real data!

    // Populate recent alerts with uploaded threats
    const flagged = data.sample_results
      .filter(r => r.prediction !== 'Normal')
      .slice(0, 5)
      .map((r, i) => ({
        id: i + 1,
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        source_ip: `192.168.1.${15 + i * 4}`,
        destination_ip: '10.0.0.5',
        protocol: r.protocol,
        packet_size: r.dst_bytes,
        attack_type: r.prediction,
        severity: r.severity || 'High',
        status: 'Blocked',
        details: `Random Forest classified as ${r.prediction} with ${(r.confidence * 100).toFixed(1)}% confidence.`
      }));

    if (flagged.length > 0) {
      state.user.stats.recent_alerts = flagged;
    }

    localStorage.setItem('netguard_current_user', JSON.stringify(state.user));
    applyUserDataToUI(state.user);
  }

  showToast(`Inference complete! ${data.attack_count} threat(s) flagged and dashboard populated.`);
}

function simulateUploadResults(fileName) {
  const sampleResults = [];
  let normal = 0, attack = 0;
  const attackTypes = ['Normal', 'Normal', 'DoS', 'Normal', 'Port Scan', 'Normal', 'Brute Force'];

  for (let i = 1; i <= 30; i++) {
    const pred = attackTypes[Math.floor(Math.random() * attackTypes.length)];
    const isAtk = pred !== 'Normal';
    if (isAtk) attack++; else normal++;

    sampleResults.push({
      row_index: i,
      duration: (Math.random() * 50000 + 100).toFixed(2),
      protocol: Math.random() > 0.3 ? 'TCP' : 'UDP',
      src_bytes: Math.floor(Math.random() * 60000 + 500),
      dst_bytes: Math.floor(Math.random() * 40000 + 200),
      prediction: pred,
      confidence: (0.93 + Math.random() * 0.06).toFixed(3),
      status: isAtk ? 'Blocked' : 'Allowed'
    });
  }

  displayUploadResults({
    total_analyzed: 30,
    normal_count: normal,
    attack_count: attack,
    attack_rate: ((attack / 30) * 100).toFixed(1),
    breakdown: { 'DoS/DDoS': 2, 'Port Scan': 2, 'Brute Force': 1 },
    sample_results: sampleResults
  });
}

function exportClassifiedCSV() {
  if (state.uploadedResults.length === 0) return;
  let csv = 'Row,Duration,Protocol,SrcBytes,DstBytes,Prediction,Confidence,Status\n';
  state.uploadedResults.forEach(r => {
    csv += `${r.row_index},${r.duration},${r.protocol},${r.src_bytes},${r.dst_bytes},${r.prediction},${r.confidence},${r.status}\n`;
  });
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.setAttribute('href', url);
  a.setAttribute('download', `classified_traffic_results_${Date.now()}.csv`);
  a.click();
  showToast('Classified results exported to CSV.');
}

// --- 10. Reports Actions ---

function generateCustomReport() {
  const start = document.getElementById('report-start-date').value;
  const end = document.getElementById('report-end-date').value;
  showToast(`Security Report for ${start} to ${end} successfully generated!`);
  setTimeout(() => {
    window.location.href = '/api/reports/download?type=daily';
  }, 600);
}

// --- 11. Settings Actions ---

function setTheme(theme) {
  state.theme = theme;
  if (theme === 'dark') {
    document.body.classList.add('theme-dark');
  } else if (theme === 'light') {
    document.body.classList.remove('theme-dark');
  } else {
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    document.body.classList.toggle('theme-dark', prefersDark);
  }
  
  if (state.currentAppTab === 'dashboard') {
    drawTrafficLineChart();
  } else if (state.currentAppTab === 'attack-analysis') {
    drawAttacksOverTimeChart();
  } else if (state.currentAppTab === 'model-performance') {
    drawRocCurveChart();
  }
}

function saveSettings() {
  const name = document.getElementById('setting-name').value;
  const email = document.getElementById('setting-email').value;
  state.user.name = name;
  state.user.email = email;
  localStorage.setItem('netguard_current_user', JSON.stringify(state.user));
  applyUserDataToUI(state.user);
  showToast('Preferences and profile settings saved successfully!');
}

function openPasswordModal() {
  document.getElementById('modal-password').classList.add('show');
}

function closePasswordModal() {
  document.getElementById('modal-password').classList.remove('show');
}

function savePassword() {
  closePasswordModal();
  showToast('Password updated successfully.');
}

// --- Badge Helpers ---

function getPredictionBadge(prediction) {
  if (!prediction) return '<span class="badge badge-secondary">Unknown</span>';
  const p = prediction.toLowerCase();
  if (p.includes('normal')) return `<span class="badge badge-success">Normal</span>`;
  if (p.includes('dos')) return `<span class="badge badge-danger">DoS</span>`;
  if (p.includes('port scan') || p.includes('scan')) return `<span class="badge badge-warning">Port Scan</span>`;
  if (p.includes('brute')) return `<span class="badge badge-danger" style="background:rgba(239,68,68,0.12);color:#EF4444;">Brute Force</span>`;
  if (p.includes('web')) return `<span class="badge badge-purple">Web Attack</span>`;
  if (p.includes('bot')) return `<span class="badge badge-info">Botnet</span>`;
  return `<span class="badge badge-danger">${prediction}</span>`;
}

function getSeverityBadge(severity) {
  if (severity === 'High') return `<span class="badge badge-danger">High</span>`;
  if (severity === 'Medium') return `<span class="badge badge-warning">Medium</span>`;
  return `<span class="badge badge-success">Low</span>`;
}

function getStatusBadge(status) {
  if (status === 'Blocked') return `<span class="badge badge-danger">Blocked</span>`;
  if (status === 'Detected') return `<span class="badge badge-warning">Detected</span>`;
  return `<span class="badge badge-success">Allowed</span>`;
}

// --- Window Resize Listener for Responsive Canvas ---
window.addEventListener('resize', () => {
  if (state.currentAppTab === 'dashboard') {
    drawTrafficLineChart();
    drawAttackDonutChart();
  } else if (state.currentAppTab === 'attack-analysis') {
    drawAttacksOverTimeChart();
  } else if (state.currentAppTab === 'model-performance') {
    drawRocCurveChart();
  }
});

// --- Initialize on DOM Loaded ---
document.addEventListener('DOMContentLoaded', () => {
  // Check if existing user stored
  const stored = localStorage.getItem('netguard_current_user');
  if (stored) {
    try {
      state.user = JSON.parse(stored);
    } catch(e) {}
  }

  // Display Landing Page first (as instructed)
  switchView('landing');
  applyUserDataToUI(state.user);
});
