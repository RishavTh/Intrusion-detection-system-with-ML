// ── State ────────────────────────────────────────────────────
const API       = '';
let lastId      = 0;
let allAlerts   = [];
let statsCache  = {};
let feedCleared = false;
let termLines   = 0;
let termAlerts  = 0;
let prevTotal   = 0;

// Charts
let donutC, lineC, barC, horizC, hourC, eventC, confC;

// ── Chart defaults ────────────────────────────────────────────
Chart.defaults.color       = '#4a6080';
Chart.defaults.borderColor = '#141e2e';
Chart.defaults.font.family = "'JetBrains Mono',monospace";
Chart.defaults.font.size   = 10;

// ── Tab switching ─────────────────────────────────────────────
const TAB_TITLES = {
  overview  : ['OVERVIEW',    'Security Dashboard'],
  threats   : ['THREAT FEED', 'Live Alert Stream'],
  analytics : ['ANALYTICS',   'Threat Intelligence'],
  terminal  : ['LOG TERMINAL','Real-Time Log Monitor'],
  geomap    : ['GEO ATTACK MAP', 'Real-time attacker origin tracking'],
  apistatus : ['API STATUS',  'System Health Monitor'],
};

function switchTab(name) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  document.querySelector(`[data-tab="${name}"]`).classList.add('active');
  const [title, sub] = TAB_TITLES[name];
  document.getElementById('page-title').textContent = title;
  document.getElementById('page-sub').textContent   = sub;
  if (name === 'analytics') buildAnalyticsCharts();
  if (name === 'geomap') { setTimeout(()=>{ buildGeoMap(); if(geoMap) geoMap.invalidateSize(); }, 150); }
  if (name === 'geomap') { setTimeout(()=>{ buildGeoMap(); if(geoMap) geoMap.invalidateSize(); }, 150); }
}

// ── Init overview charts ──────────────────────────────────────
function initCharts() {
  // Donut
  donutC = new Chart(document.getElementById('donutChart'), {
    type: 'doughnut',
    data: {
      labels  : ['SSH Brute Force','Sudo Abuse','Foreign IP','Port Scan','Suspicious'],
      datasets: [{
        data           : [0,0,0,0],
        backgroundColor: ['#ff335522','#ffcc0022','#aa55ff22','#2a3a5022'],
        borderColor    : ['#ff3355',  '#ffcc00',  '#aa55ff',  '#4a6080'],
        borderWidth    : 1.5,
        hoverOffset    : 5
      }]
    },
    options:{
      responsive:false, cutout:'74%',
      plugins:{ legend:{display:false} },
      animation:{ duration:500 }
    }
  });

  // Line
  lineC = new Chart(document.getElementById('lineChart'), {
    type:'line',
    data:{
      labels:[],
      datasets:[{
        label:'Alerts',
        data:[],
        borderColor:'#00d4ff',
        backgroundColor:'rgba(0,212,255,0.05)',
        borderWidth:1.5,
        pointRadius:3,
        pointBackgroundColor:'#00d4ff',
        tension:0.4,fill:true
      }]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        x:{grid:{color:'#141e2e'},ticks:{maxTicksLimit:10,maxRotation:0}},
        y:{grid:{color:'#141e2e'},beginAtZero:true}
      },
      animation:{duration:400}
    }
  });

  // Bar - top IPs
  barC = new Chart(document.getElementById('barChart'), {
    type:'bar',
    data:{labels:[],datasets:[{
      label:'Attacks',data:[],
      backgroundColor:['#ff335533','#ff773033','#ffcc0033','#aa55ff33','#00d4ff33'],
      borderColor    :['#ff3355',  '#ff7730',  '#ffcc00',  '#aa55ff',  '#00d4ff'],
      borderWidth:1,borderRadius:3
    }]},
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        x:{grid:{display:false},ticks:{font:{size:9},maxRotation:25}},
        y:{grid:{color:'#141e2e'},beginAtZero:true}
      },
      animation:{duration:400}
    }
  });
}

// ── Build analytics charts (built once on tab open) ───────────
let analyticsBuilt = false;
function buildAnalyticsCharts() {
  if (analyticsBuilt && allAlerts.length === 0) return;
  analyticsBuilt = true;

  // Horizontal bar — threat types
  // Use full database counts from statsCache — not just last 100 alerts
  const susp = Math.max(
    (statsCache.total_alerts||0)-(statsCache.ssh_brute_force||0)
    -(statsCache.sudo_abuse||0)-(statsCache.foreign_ip||0)
    -(statsCache.port_scan||0), 0
  );
  const threatCounts = {
    ssh_brute_force: statsCache.ssh_brute_force || 0,
    sudo_abuse:      statsCache.sudo_abuse      || 0,
    foreign_ip:      statsCache.foreign_ip      || 0,
    port_scan:       statsCache.port_scan        || 0,
    suspicious:      susp
  };

  if (horizC) horizC.destroy();
  horizC = new Chart(document.getElementById('horizBarChart'), {
    type:'bar',
    data:{
      labels:['SSH Brute Force','Sudo Abuse','Foreign IP','Port Scan','Suspicious'],
      datasets:[{
        data:[
          threatCounts.ssh_brute_force, threatCounts.sudo_abuse,
          threatCounts.foreign_ip,      threatCounts.port_scan, threatCounts.suspicious
        ],
        backgroundColor:['#ff335530','#ffcc0030','#aa55ff30','#ff773030','#2a3a5030'],
        borderColor    :['#ff3355',  '#ffcc00',  '#aa55ff',  '#ff7730',  '#4a6080'],
        borderWidth:1,borderRadius:4
      }]
    },
    options:{
      indexAxis:'y',responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        x:{grid:{color:'#141e2e'},beginAtZero:true},
        y:{grid:{display:false}}
      }
    }
  });

  // Hour pattern
  const hourData = new Array(24).fill(0);
  allAlerts.forEach(a => {
    try {
      const h = new Date(a.detected_at).getHours();
      if (!isNaN(h)) hourData[h]++;
    } catch {}
  });

  if (hourC) hourC.destroy();
  hourC = new Chart(document.getElementById('hourChart'), {
    type:'bar',
    data:{
      labels: Array.from({length:24},(_,i)=>`${i}h`),
      datasets:[{
        label:'Alerts',data:hourData,
        backgroundColor:'#00d4ff22',borderColor:'#00d4ff',borderWidth:1,borderRadius:2
      }]
    },
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        x:{grid:{display:false},ticks:{font:{size:8}}},
        y:{grid:{color:'#141e2e'},beginAtZero:true}
      }
    }
  });

  // Event type
  const evtCounts = {};
  allAlerts.forEach(a => {
    const e = a.event_type || 'unknown';
    evtCounts[e] = (evtCounts[e] || 0) + 1;
  });
  const evtKeys = Object.keys(evtCounts);
  const evtVals = evtKeys.map(k => evtCounts[k]);
  const COLORS  = ['#ff3355','#ff7730','#ffcc00','#00ff88','#00d4ff','#aa55ff'];

  if (eventC) eventC.destroy();
  eventC = new Chart(document.getElementById('eventChart'), {
    type:'pie',
    data:{
      labels:evtKeys,
      datasets:[{
        data:evtVals,
        backgroundColor:COLORS.map(c=>c+'33'),
        borderColor:COLORS,borderWidth:1.5
      }]
    },
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{
        legend:{
          position:'right',
          labels:{font:{size:9},boxWidth:10,padding:8}
        }
      }
    }
  });

  // Confidence distribution
  const buckets = [0,0,0,0,0]; // 0-20, 20-40, 40-60, 60-80, 80-100
  allAlerts.forEach(a => {
    const c = parseFloat(a.confidence)||0;
    const i = Math.min(Math.floor(c/20), 4);
    buckets[i]++;
  });

  if (confC) confC.destroy();
  confC = new Chart(document.getElementById('confChart'), {
    type:'bar',
    data:{
      labels:['0–20%','20–40%','40–60%','60–80%','80–100%'],
      datasets:[{
        data:buckets,
        backgroundColor:['#00ff8833','#00d4ff33','#ffcc0033','#ff773033','#ff335533'],
        borderColor    :['#00ff88',  '#00d4ff',  '#ffcc00',  '#ff7730',  '#ff3355'],
        borderWidth:1,borderRadius:4
      }]
    },
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        x:{grid:{display:false}},
        y:{grid:{color:'#141e2e'},beginAtZero:true}
      }
    }
  });

  // Attacker profiles
  const ipMap = {};
  allAlerts.forEach(a => {
    const ip = a.source_ip||'unknown';
    if (!ipMap[ip]) ipMap[ip] = {count:0,threats:{},conf:[]};
    ipMap[ip].count++;
    const t = a.threat_type||'suspicious';
    ipMap[ip].threats[t] = (ipMap[ip].threats[t]||0)+1;
    ipMap[ip].conf.push(parseFloat(a.confidence)||0);
  });
  const ranked = Object.entries(ipMap)
    .sort((a,b)=>b[1].count-a[1].count)
    .slice(0,8);

  const tbody = document.getElementById('attacker-tbody');
  if (!ranked.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-msg">NO DATA</td></tr>';
    return;
  }
  tbody.innerHTML = ranked.map(([ip,d],i) => {
    const topThreat = Object.entries(d.threats).sort((a,b)=>b[1]-a[1])[0][0];
    const avgConf   = (d.conf.reduce((a,b)=>a+b,0)/d.conf.length).toFixed(1);
    const sev       = d.count>20?'sev-critical':d.count>10?'sev-high':d.count>5?'sev-medium':'sev-low';
    const sevLabel  = d.count>20?'CRITICAL':d.count>10?'HIGH':d.count>5?'MEDIUM':'LOW';
    return `<tr>
      <td style="color:var(--dim)">${i+1}</td>
      <td style="color:var(--bright)">${ip}</td>
      <td style="color:var(--red);font-weight:700">${d.count}</td>
      <td><span class="tbadge ${tbCls(topThreat)}">${fmtThreat(topThreat)}</span></td>
      <td>${avgConf}%</td>
      <td><span class="sev ${sev}">${sevLabel}</span></td>
    </tr>`;
  }).join('');
}

// ── Update overview charts ────────────────────────────────────
function updateCharts(stats) {
  const susp = Math.max(
    (stats.total_alerts||0)-(stats.ssh_brute_force||0)
    -(stats.sudo_abuse||0)-(stats.foreign_ip||0), 0
  );

  // Donut
  donutC.data.datasets[0].data = [
    stats.ssh_brute_force||0, stats.sudo_abuse||0,
    stats.foreign_ip||0,      stats.port_scan||0, susp
  ];
  donutC.update();
  document.getElementById('d-total').textContent = stats.total_alerts||0;

  // Donut legend
  const LC = ['#ff3355','#ffcc00','#aa55ff','#ff7730','#4a6080'];
  const LN = ['SSH Brute Force','Sudo Abuse','Foreign IP','Port Scan','Suspicious'];
  const LV = donutC.data.datasets[0].data;
  document.getElementById('donut-legend').innerHTML =
    LN.map((n,i)=>`
    <div class="dl-item">
      <div class="dl-left">
        <div class="dl-dot" style="background:${LC[i]}"></div>
        <span class="dl-name">${n}</span>
      </div>
      <span class="dl-val">${LV[i]}</span>
    </div>`).join('');

  // Line - last 30 alerts cumulative
  const recent = [...allAlerts].reverse().slice(0,30);
  lineC.data.labels              = recent.map(a=>fmtTime(a.detected_at));
  lineC.data.datasets[0].data   = recent.map((_,i)=>i+1);
  lineC.update();

  // Bar - top IPs
  const ipCount = {};
  allAlerts.forEach(a=>{
    const ip = a.source_ip||'unknown';
    if (ip!=='unknown') ipCount[ip]=(ipCount[ip]||0)+1;
  });
  const sorted = Object.entries(ipCount).sort((a,b)=>b[1]-a[1]).slice(0,5);
  barC.data.labels            = sorted.map(x=>x[0]);
  barC.data.datasets[0].data  = sorted.map(x=>x[1]);
  barC.update();

  // Mini table
  const mini = allAlerts.slice(0,5);
  document.getElementById('mini-tbody').innerHTML = mini.length
    ? mini.map(a=>`<tr>
        <td>${fmtTime(a.detected_at)}</td>
        <td style="color:var(--bright)">${a.source_ip||'?'}</td>
        <td>${a.username||'?'}</td>
        <td><span class="tbadge ${tbCls(a.threat_type)}">${fmtThreat(a.threat_type)}</span></td>
        <td>${a.confidence||0}%</td>
      </tr>`).join('')
    : '<tr><td colspan="5" class="empty-msg">NO ALERTS YET</td></tr>';

  // Threat level
  const total = stats.total_alerts||0;
  const tlEl  = document.getElementById('tl-val');
  if (total > 100) {
    tlEl.textContent='CRITICAL'; tlEl.className='tl-val tl-critical';
  } else if (total > 50) {
    tlEl.textContent='HIGH'; tlEl.className='tl-val tl-high';
  } else if (total > 10) {
    tlEl.textContent='MEDIUM'; tlEl.className='tl-val tl-medium';
  } else {
    tlEl.textContent='LOW'; tlEl.className='tl-val tl-low';
  }
}

// ── KPI update ────────────────────────────────────────────────
function updateKPIs(s) {
  animNum('k-total',   s.total_alerts||0);
  animNum('k-ssh',     s.ssh_brute_force||0);
  animNum('k-sudo',    s.sudo_abuse||0);
  animNum('k-foreign', s.foreign_ip||0);
  animNum('k-portscan', s.port_scan||0);

  // Percentage of total
  const tot = s.total_alerts || 1;
  const pct = n => ((n/tot)*100).toFixed(1) + '%';
  const el  = id => document.getElementById(id);
  if(el('pct-ssh'))      el('pct-ssh').textContent      = pct(s.ssh_brute_force||0);
  if(el('pct-sudo'))     el('pct-sudo').textContent     = pct(s.sudo_abuse||0);
  if(el('pct-foreign'))  el('pct-foreign').textContent  = pct(s.foreign_ip||0);
  if(el('pct-portscan')) el('pct-portscan').textContent = pct(s.port_scan||0);
  animNum('tb-total',  s.total_alerts||0);

  // Sidebar counts
  const susp = Math.max((s.total_alerts||0)-(s.ssh_brute_force||0)-(s.sudo_abuse||0)-(s.foreign_ip||0),0);
  document.getElementById('sb-ssh').textContent    = s.ssh_brute_force||0;
  document.getElementById('sb-sudo').textContent   = s.sudo_abuse||0;
  document.getElementById('sb-foreign').textContent= s.foreign_ip||0;
  document.getElementById('sb-portscan').textContent = s.port_scan||0;
  document.getElementById('sb-susp').textContent   = susp;

  // Nav badge
  const nb = document.getElementById('nb-threats');
  if ((s.total_alerts||0)>0){nb.textContent=s.total_alerts;nb.classList.add('show');}
}

function animNum(id, target) {
  const el  = document.getElementById(id);
  if (!el) return;
  const cur = parseInt(el.textContent)||0;
  if (cur===target) return;
  const step = Math.max(1, Math.ceil(Math.abs(target-cur)/15));
  let v=cur;
  const t=setInterval(()=>{
    v=v<target?Math.min(v+step,target):Math.max(v-step,target);
    el.textContent=v;
    if(v===target)clearInterval(t);
  },30);
}

// ── Toast notifications ───────────────────────────────────────
function showToast(alert) {
  const container = document.getElementById('toast-container');
  if (container.children.length >= 4) container.removeChild(container.firstChild);

  const cls   = tbCls(alert.threat_type).replace('tbadge ','').replace('tb-','toast-');
  const icon  = alert.threat_type?.includes('ssh') ? '🔴'
              : alert.threat_type?.includes('sudo') ? '🟡'
              : alert.threat_type?.includes('foreign') ? '🟣' : '⚪';
  const title = fmtThreat(alert.threat_type);

  const el = document.createElement('div');
  el.className = `toast toast-${cls}`;
  el.innerHTML = `
    <span class="toast-icon">${icon}</span>
    <div class="toast-body">
      <div class="toast-title">${title}</div>
      <div class="toast-msg">${alert.source_ip||'unknown'} → ${alert.event_type||'unknown'}</div>
      <div class="toast-time">${fmtTime(alert.detected_at)} · ${alert.confidence||0}% confidence</div>
    </div>
    <span class="toast-close" onclick="this.parentElement.remove()">✕</span>`;

  container.appendChild(el);
  setTimeout(()=>{
    el.style.animation='toastout .3s ease-out forwards';
    setTimeout(()=>el.remove(), 300);
  }, 5000);
}

// ── Terminal logging ──────────────────────────────────────────
function addTermLine(text, cls='term-normal') {
  const body = document.getElementById('term-body');
  const line = document.createElement('div');
  line.className = `term-line ${cls}`;
  const ts = new Date().toLocaleTimeString('en-GB');
  line.textContent = `[${ts}] ${text}`;
  body.appendChild(line);
  termLines++;
  document.getElementById('term-count').textContent = termLines;

  if (document.getElementById('auto-scroll').checked) {
    body.scrollTop = body.scrollHeight;
  }
  // Keep max 500 lines
  while (body.children.length > 500) body.removeChild(body.firstChild);
}

function addAlertToTerminal(a) {
  termAlerts++;
  document.getElementById('term-alerts').textContent = termAlerts;
  const icon = a.threat_type?.includes('ssh') ? '🔴'
             : a.threat_type?.includes('sudo') ? '🟡'
             : a.threat_type?.includes('foreign') ? '🟣' : '⚠';
  const cls  = a.threat_type?.includes('ssh') ? 'term-alert'
             : a.threat_type?.includes('sudo') ? 'term-warn' : 'term-info';
  addTermLine(`${icon} ALERT #${a.id} | ${fmtThreat(a.threat_type)} | ${a.source_ip||'?'} | ${a.username||'?'} | ${a.event_type||'?'} | ${a.confidence||0}%`, cls);
  if (a.raw_log) addTermLine(`   └─ ${a.raw_log.substring(0,120)}`, 'term-dim');
}

function clearTerminal() {
  const b = document.getElementById('term-body');
  b.innerHTML = '<div class="term-line term-system">[ Terminal cleared ]</div>';
  termLines = 0; termAlerts = 0;
  document.getElementById('term-count').textContent  = 0;
  document.getElementById('term-alerts').textContent = 0;
}

// ── Render feed table ─────────────────────────────────────────
function renderFeed(alerts) {
  const tbody = document.getElementById('feed-tbody');
  document.getElementById('feed-count').textContent = `${alerts.length} alerts`;

  if (!alerts.length) {
    tbody.innerHTML=`<tr><td colspan="10" class="empty-msg">
      <div class="scan-anim"><div class="scan-bar"></div>SCANNING FOR THREATS...</div>
    </td></tr>`;
    return;
  }
  tbody.innerHTML = alerts.map(a => {
    const conf  = parseFloat(a.confidence)||0;
    const cc    = conf>=80?'c-high':conf>=50?'c-medium':'c-low';
    const sev   = getSev(a.threat_type, conf);
    const isNew = a.id===lastId ? 'new-row' : '';
    const raw   = (a.raw_log||'').substring(0,80)+(a.raw_log?.length>80?'...':'');
    return `<tr class="${isNew}">
      <td style="color:var(--dim)">${a.id}</td>
      <td>${fmtDate(a.detected_at)}</td>
      <td style="color:var(--bright)">${a.source_ip||'?'}</td>
      <td>${a.username||'?'}</td>
      <td>${a.event_type||'?'}</td>
      <td><span class="tbadge ${tbCls(a.threat_type)}">${fmtThreat(a.threat_type)}</span></td>
      <td><div class="conf-wrap">
        <div class="conf-track"><div class="conf-fill ${cc}" style="width:${conf}%"></div></div>
        <span class="conf-pct">${conf}%</span>
      </div></td>
      <td>${a.service||'?'}</td>
      <td><span class="sev ${sev.cls}">${sev.label}</span></td>
      <td><span class="raw-log" title="${a.raw_log||''}">${raw}</span></td>
    </tr>`;
  }).join('');
}

// ── Filter feed ───────────────────────────────────────────────
function filteredAlerts() {
  const search = (document.getElementById('feed-search')?.value||'').toLowerCase();
  const threat = document.getElementById('feed-filter')?.value||'';
  const sev    = document.getElementById('feed-sev')?.value||'';
  return allAlerts.filter(a => {
    const ms = !search || [a.source_ip,a.username,a.event_type,a.threat_type,a.service]
      .some(v=>(v||'').toLowerCase().includes(search));
    const mt = !threat || (a.threat_type||'').includes(threat);
    const mv = !sev    || getSev(a.threat_type, parseFloat(a.confidence)||0).label===sev;
    return ms && mt && mv;
  });
}
function filterFeed() { renderFeed(filteredAlerts()); }

function clearFeed() {
  feedCleared=true;
  document.getElementById('feed-tbody').innerHTML=
    `<tr><td colspan="10" class="empty-msg"><div class="scan-anim"><div class="scan-bar"></div>VIEW CLEARED</div></td></tr>`;
  document.getElementById('feed-count').textContent='0 alerts';
  setTimeout(()=>{feedCleared=false;},500);
}

// ── Export CSV ────────────────────────────────────────────────
function exportCSV() {
  const headers = ['id','detected_at','source_ip','username','event_type','threat_type','confidence','service'];
  const rows    = allAlerts.map(a=>headers.map(h=>`"${(a[h]||'').toString().replace(/"/g,'""')}"`).join(','));
  const csv     = [headers.join(','), ...rows].join('\n');
  const blob    = new Blob([csv], {type:'text/csv'});
  const url     = URL.createObjectURL(blob);
  const a       = document.createElement('a');
  a.href=url; a.download=`ids_alerts_${Date.now()}.csv`; a.click();
  URL.revokeObjectURL(url);
}

// ── Data fetching ─────────────────────────────────────────────
async function fetchStats() {
  try {
    const r = await fetch(`${API}/api/stats`);
    const s = await r.json();
    statsCache = s;
    updateKPIs(s);
    updateCharts(s);
    document.getElementById('ss-monitor').textContent = '● ACTIVE';
    document.getElementById('ss-monitor').className   = 'ss-val green';
    document.getElementById('term-status').textContent = 'MONITORING';
    document.getElementById('term-status').className   = 'green';
  } catch {
    document.getElementById('ss-monitor').textContent = '● OFFLINE';
    document.getElementById('ss-monitor').className   = 'ss-val';
  }
}

async function pollAlerts() {
  try {
    const r    = await fetch(`${API}/api/alerts/live/${lastId}`);
    const data = await r.json();
    if (data.alerts?.length > 0) {
      data.alerts.forEach(a => {
        allAlerts.unshift(a);
        lastId = Math.max(lastId, a.id);
        showToast(a);
        addAlertToTerminal(a);
      });
      if (!feedCleared) renderFeed(filteredAlerts());
      if (analyticsBuilt) { analyticsBuilt=false; buildAnalyticsCharts(); }
    }
    document.getElementById('tb-last').textContent =
      allAlerts[0] ? fmtTime(allAlerts[0].detected_at) : '--:--:--';
  } catch(e) { console.warn(e); }
}

async function loadInitial() {
  try {
    const r    = await fetch(`${API}/api/alerts`);
    const data = await r.json();
    if (data.alerts?.length > 0) {
      allAlerts = data.alerts;
      lastId    = Math.max(...data.alerts.map(a=>a.id));
      renderFeed(filteredAlerts());
      // Load recent alerts into terminal
      const recent = [...data.alerts].reverse().slice(-20);
      recent.forEach(a => addAlertToTerminal(a));
      addTermLine(`── Loaded ${allAlerts.length} existing alerts from database ──`, 'term-system');
    }
  } catch(e) { console.warn(e); }
}

// ── Clock ─────────────────────────────────────────────────────
function tick() {
  const t = new Date().toLocaleTimeString('en-GB');
  document.getElementById('ss-time').textContent = t;
}

// ── Helpers ───────────────────────────────────────────────────
function tbCls(t) {
  if (!t) return 'tb-other';
  if (t === 'authorized')                           return 'tb-ok';
  if (t.includes('ssh'))                            return 'tb-ssh';
  if (t.includes('sudo'))                           return 'tb-sudo';
  if (t.includes('foreign'))                        return 'tb-foreign';
  if (t.includes('port_scan') || t === 'port_scan') return 'tb-portscan';
  return 'tb-other';
}
function fmtThreat(t) {
  if (!t||t==='none')                               return '⚪ Suspicious';
  if (t === 'authorized')                           return '✅ Authorized';
  if (t.includes('ssh'))                            return '🔴 SSH Brute Force';
  if (t.includes('sudo'))                           return '🟡 Sudo Abuse';
  if (t.includes('foreign'))                        return '🟣 Foreign IP';
  if (t.includes('port_scan') || t === 'port_scan') return '🟠 Port Scan';
  return '⚪ Suspicious';
}
function getSev(threat, conf) {
  if (threat === 'authorized')
    return {cls:'sev-info',    label:'INFO'};
  if ((threat||'').includes('ssh') && conf>=80)
    return {cls:'sev-critical',label:'CRITICAL'};
  if ((threat||'').includes('ssh') || conf>=80)
    return {cls:'sev-high',    label:'HIGH'};
  if ((threat||'').includes('sudo') || conf>=50)
    return {cls:'sev-medium',  label:'MEDIUM'};
  return {cls:'sev-low', label:'LOW'};
}
function fmtDate(s) {
  if (!s) return 'N/A';
  try { return new Date(s).toLocaleString('en-GB'); } catch { return s; }
}
function fmtTime(s) {
  if (!s) return '--:--';
  try { return new Date(s).toLocaleTimeString('en-GB'); } catch { return s; }
}

// ── Start ─────────────────────────────────────────────────────
initCharts();
loadInitial();
fetchStats();
tick();

setInterval(pollAlerts, 4000);
setInterval(fetchStats, 8000);
setInterval(tick,       1000);

// ═══════════════════════════════════════════════════════════
// GEO MAP — Real-time attacker origin tracking
// ═══════════════════════════════════════════════════════════
let geoMap     = null;
let geoMarkers = [];
const geoCache = {};

const THREAT_CLR = {
  ssh_brute_force: '#ff3355',
  sudo_abuse     : '#ffcc00',
  foreign_ip     : '#aa55ff',
  port_scan      : '#ff7730',
  authorized     : '#00ff88',
  suspicious     : '#4a6080',
};

function isPrivateIP(ip) {
  if (!ip || ip === 'unknown') return true;
  return (
    ip.startsWith('192.168.') ||
    ip.startsWith('10.')      ||
    ip.startsWith('172.16.')  ||
    ip.startsWith('172.17.')  ||
    ip.startsWith('172.18.')  ||
    ip.startsWith('127.')     ||
    ip === 'localhost'
  );
}

async function fetchGeoIP(ip) {
  if (geoCache[ip] !== undefined) return geoCache[ip];
  if (isPrivateIP(ip)) { geoCache[ip] = null; return null; }
  try {
    const r = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,lat,lon`,
      { signal: AbortSignal.timeout(5000) }
    );
    const d = await r.json();
    if (d.status === 'success') {
      geoCache[ip] = d;
      return d;
    }
    geoCache[ip] = null;
  } catch(e) {
    geoCache[ip] = null;
  }
  return null;
}

function initLeaflet() {
  if (geoMap) return;
  const el = document.getElementById('leaflet-map');
  if (!el || typeof L === 'undefined') return;

  geoMap = L.map('leaflet-map', {
    center         : [20, 0],
    zoom           : 2,
    zoomControl    : true,
    attributionControl: false,
  });

  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    maxZoom: 18,
  }).addTo(geoMap);
}

function makeIcon(color, count) {
  const size = Math.min(10 + Math.log2(count + 1) * 5, 32);
  return L.divIcon({
    className: '',
    html: `<div style="
      width:${size}px;height:${size}px;
      background:${color};
      border-radius:50%;
      border:2px solid rgba(255,255,255,0.35);
      box-shadow:0 0 10px ${color},0 0 20px ${color}55;
      cursor:pointer;
    "></div>`,
    iconSize  : [size, size],
    iconAnchor: [size/2, size/2],
    popupAnchor: [0, -size/2],
  });
}

function countryFlag(code) {
  if (!code || code.length !== 2) return '🌐';
  try {
    return String.fromCodePoint(
      ...[...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)
    );
  } catch(e) { return '🌐'; }
}

async function buildGeoMap() {
  const el = document.getElementById('leaflet-map');
  if (!el) return;

  initLeaflet();
  if (!geoMap) return;

  // Clear existing markers
  geoMarkers.forEach(m => geoMap.removeLayer(m));
  geoMarkers = [];
  document.getElementById('geo-tbody').innerHTML =
    '<tr><td colspan="6" style="text-align:center;color:var(--dim);padding:20px">🔍 Fetching geo data...</td></tr>';

  // Build unique IP summary from allAlerts
  const ipMap = {};
  allAlerts.forEach(a => {
    const ip = a.source_ip || 'unknown';
    if (isPrivateIP(ip)) return;
    if (!ipMap[ip]) ipMap[ip] = { ip, threat_type: a.threat_type, count: 0 };
    ipMap[ip].count++;
  });

  const ipList = Object.values(ipMap);
  document.getElementById('geo-total-ips').textContent = ipList.length;

  if (ipList.length === 0) {
    document.getElementById('geo-tbody').innerHTML =
      '<tr><td colspan="6" style="text-align:center;color:var(--dim);padding:20px">No external IPs detected yet</td></tr>';
    document.getElementById('geo-mapped').textContent = '0';
    return;
  }

  // Fetch geo for all IPs (ip-api allows 45 req/min free)
  const rows    = [];
  const bounds  = [];
  const ctryCnt = {};
  let   mapped  = 0;

  for (const item of ipList) {
    const geo = await fetchGeoIP(item.ip);
    if (!geo) continue;

    mapped++;
    const color = THREAT_CLR[item.threat_type] || '#4a6080';

    // Add marker to map
    const marker = L.marker([geo.lat, geo.lon], {
      icon: makeIcon(color, item.count)
    });

    marker.bindPopup(`
      <div style="
        background:#0d1929;color:#e2e8f0;
        padding:12px;border-radius:8px;
        min-width:200px;font-family:monospace;font-size:12px;
        border:1px solid ${color}44;
      ">
        <div style="color:${color};font-weight:700;margin-bottom:8px;font-size:13px">
          ${fmtThreat(item.threat_type)}
        </div>
        <div>🌍 ${countryFlag(geo.countryCode)} ${geo.country}</div>
        <div>🏙 ${geo.city || 'Unknown city'}</div>
        <div>🖥 ${item.ip}</div>
        <div style="color:${color};margin-top:6px">⚡ ${item.count} attack${item.count>1?'s':''}</div>
      </div>
    `, { maxWidth: 250 });

    marker.addTo(geoMap);
    geoMarkers.push(marker);
    bounds.push([geo.lat, geo.lon]);

    // Country stats
    ctryCnt[geo.country] = (ctryCnt[geo.country]||0) + item.count;

    // Table row
    rows.push({ geo, item, color });
  }

  // Update stats
  document.getElementById('geo-total-countries').textContent = Object.keys(ctryCnt).length;
  document.getElementById('geo-mapped').textContent = mapped;

  const topEntry = Object.entries(ctryCnt).sort((a,b)=>b[1]-a[1])[0];
  document.getElementById('geo-top-country').textContent =
    topEntry ? `${countryFlag('')} ${topEntry[0]}` : '—';

  // Fit map bounds
  if (bounds.length > 0) {
    try { geoMap.fitBounds(bounds, { padding: [40, 40], maxZoom: 6 }); }
    catch(e) {}
  }

  // Build table
  const tbody = document.getElementById('geo-tbody');
  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--dim);padding:20px">No external IPs resolved</td></tr>';
    return;
  }

  rows.sort((a,b) => b.item.count - a.item.count);
  tbody.innerHTML = rows.map(({geo, item, color}) => `
    <tr>
      <td style="font-size:1.4rem">${countryFlag(geo.countryCode)}</td>
      <td>${geo.country}</td>
      <td style="color:var(--dim)">${geo.city||'—'}</td>
      <td style="font-family:monospace;color:var(--acc)">${item.ip}</td>
      <td style="color:${color};font-weight:700">${item.count}</td>
      <td><span class="tbadge ${tbCls(item.threat_type)}">${fmtThreat(item.threat_type)}</span></td>
    </tr>
  `).join('');
}

// ── PDF Report Generator ──────────────────────────────────
async function generateReport() {
  const btn = document.getElementById('report-btn');
  const orig = btn.innerHTML;
  btn.innerHTML = '⏳ GENERATING...';
  btn.disabled = true;
  btn.style.opacity = '0.7';
  try {
    const r = await fetch('/api/generate-report');
    if (!r.ok) throw new Error('Server error');
    const blob = await r.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    const ts   = new Date().toISOString().slice(0,19).replace(/[T:]/g, '-');
    a.href     = url;
    a.download = `IDS_Security_Report_${ts}.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    btn.innerHTML = '✅ DOWNLOADED!';
    setTimeout(() => { btn.innerHTML = orig; btn.disabled = false; btn.style.opacity = '1'; }, 3000);
  } catch(e) {
    btn.innerHTML = '❌ ERROR';
    setTimeout(() => { btn.innerHTML = orig; btn.disabled = false; btn.style.opacity = '1'; }, 3000);
  }
}

async function downloadReport() {
  const btn = document.getElementById('rpt-btn');
  btn.textContent = '⏳ GENERATING...';
  btn.disabled = true;
  try {
    const r = await fetch('/api/generate-report');
    const blob = await r.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `NIST_IDS_Report_${new Date().toISOString().slice(0,10)}.pdf`;
    a.click();
    btn.textContent = '✅ DOWNLOADED!';
    setTimeout(() => { btn.textContent = '📄 NIST REPORT'; btn.disabled = false; }, 3000);
  } catch(e) {
    btn.textContent = '❌ ERROR - retry';
    setTimeout(() => { btn.textContent = '📄 NIST REPORT'; btn.disabled = false; }, 3000);
  }
}

// ── API Status Checker ────────────────────────────────────
const API_ENDPOINTS = [
  { key: 'health',  url: '/api/health',          desc: 'Health check' },
  { key: 'stats',   url: '/api/stats',            desc: 'KPI stats' },
  { key: 'alerts',  url: '/api/alerts',           desc: 'Alert list' },
  { key: 'live',    url: '/api/alerts/live/0',    desc: 'Live polling' },
  { key: 'report',  url: '/api/generate-report',  desc: 'PDF report', skipBody: true },
];

function setCardStatus(key, status, ms, detail) {
  const badge = document.getElementById('badge-' + key);
  const meta  = document.getElementById('meta-' + key);
  const card  = document.getElementById('card-' + key);
  if (!badge || !meta || !card) return;

  if (status === 'OK') {
    badge.style.background = 'rgba(0,255,136,0.15)';
    badge.style.color      = '#00ff88';
    badge.textContent      = '✅ OK';
    card.style.borderColor = 'rgba(0,255,136,0.25)';
    meta.style.color       = '#00ff88';
    meta.textContent       = `${ms}ms — ${detail}`;
  } else if (status === 'SLOW') {
    badge.style.background = 'rgba(255,204,0,0.15)';
    badge.style.color      = '#ffcc00';
    badge.textContent      = '🟡 SLOW';
    card.style.borderColor = 'rgba(255,204,0,0.25)';
    meta.style.color       = '#ffcc00';
    meta.textContent       = `${ms}ms — response slow`;
  } else {
    badge.style.background = 'rgba(255,51,85,0.15)';
    badge.style.color      = '#ff3355';
    badge.textContent      = '❌ ERROR';
    card.style.borderColor = 'rgba(255,51,85,0.25)';
    meta.style.color       = '#ff3355';
    meta.textContent       = detail || 'Failed to connect';
  }
}

async function checkEndpoint(ep) {
  const start = performance.now();
  try {
    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 6000);
    const res        = await fetch(ep.url, { signal: controller.signal });
    clearTimeout(timeout);
    const ms = Math.round(performance.now() - start);

    if (!res.ok) {
      setCardStatus(ep.key, 'ERROR', ms, `HTTP ${res.status}`);
      return 'ERROR';
    }

    // For report endpoint just check headers not body
    let detail = '';
    if (ep.skipBody) {
      const ct = res.headers.get('content-type') || '';
      detail = ct.includes('pdf') ? 'PDF returned' : 'Responded OK';
    } else {
      const data = await res.json();
      if (ep.key === 'stats') {
        const total = data.total_alerts || 0;
        detail = `${total} total alerts`;
      } else if (ep.key === 'alerts') {
        const count = Array.isArray(data) ? data.length : '?';
        detail = `${count} alerts returned`;
      } else if (ep.key === 'live') {
        detail = 'Polling active';
      } else if (ep.key === 'geo') {
        const count = Array.isArray(data) ? data.length : '?';
        detail = `${count} geo alerts`;
      } else if (ep.key === 'health') {
        detail = data.status || 'Running';
      } else {
        detail = 'OK';
      }
    }

    const status = ms > 2000 ? 'SLOW' : 'OK';
    setCardStatus(ep.key, status, ms, detail);
    return status;
  } catch (e) {
    const ms = Math.round(performance.now() - start);
    const msg = e.name === 'AbortError' ? 'Timeout after 6s' : e.message;
    setCardStatus(ep.key, 'ERROR', ms, msg);
    return 'ERROR';
  }
}

async function runApiChecks() {
  const btn = document.getElementById('api-check-btn');
  const banner = document.getElementById('api-overall-banner');
  btn.textContent = '⏳ CHECKING...';
  btn.disabled = true;
  banner.style.borderLeftColor = '#ffcc00';
  banner.style.color = '#ffcc00';
  banner.innerHTML = '⏳ &nbsp;Checking all endpoints...';

  // Reset all badges to CHECKING
  API_ENDPOINTS.forEach(ep => {
    const badge = document.getElementById('badge-' + ep.key);
    const meta  = document.getElementById('meta-' + ep.key);
    const card  = document.getElementById('card-' + ep.key);
    if (badge) { badge.textContent = '⏳ CHECKING'; badge.style.background = 'rgba(255,204,0,0.1)'; badge.style.color = '#ffcc00'; }
    if (meta)  { meta.textContent = 'Testing...'; meta.style.color = '#ffcc00'; }
    if (card)  { card.style.borderColor = 'rgba(255,204,0,0.2)'; }
  });

  // Run all checks in parallel
  const results = await Promise.all(API_ENDPOINTS.map(ep => checkEndpoint(ep)));

  const ok    = results.filter(r => r === 'OK').length;
  const slow  = results.filter(r => r === 'SLOW').length;
  const error = results.filter(r => r === 'ERROR').length;
  const total = results.length;

  // Update overall banner
  if (error === 0 && slow === 0) {
    banner.style.borderLeftColor = '#00ff88';
    banner.style.color = '#00ff88';
    banner.innerHTML = `✅ &nbsp;All ${total} endpoints operational — system fully healthy`;
  } else if (error === 0) {
    banner.style.borderLeftColor = '#ffcc00';
    banner.style.color = '#ffcc00';
    banner.innerHTML = `🟡 &nbsp;${ok} OK · ${slow} slow · ${error} errors — system running with warnings`;
  } else {
    banner.style.borderLeftColor = '#ff3355';
    banner.style.color = '#ff3355';
    banner.innerHTML = `❌ &nbsp;${ok} OK · ${slow} slow · ${error} errors — some endpoints failing`;
  }

  // Update last checked time
  const now = new Date();
  document.getElementById('api-last-checked').textContent =
    now.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  btn.textContent = '🔄 RUN CHECKS';
  btn.disabled = false;
}

// Auto-run when tab is opened
const _origSwitchTab = switchTab;
switchTab = function(name) {
  _origSwitchTab(name);
  if (name === 'apistatus') runApiChecks();
};
