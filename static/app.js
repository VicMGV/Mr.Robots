const API = 'http://127.0.0.1:8000';

function switchTab(name, btn) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('view-' + name).classList.add('active');
  if (name === 'dashboard') loadDashboard();
}

async function loadDashboard() {
  try {
    const [sum, log] = await Promise.all([
      fetch(API + '/audit/summary').then(r => r.json()),
      fetch(API + '/audit').then(r => r.json()),
    ]);
    document.getElementById('m-total').textContent = sum.total_requests ?? 0;
    document.getElementById('m-blocked').textContent = sum.blocked ?? 0;
    document.getElementById('m-warned').textContent = sum.warned ?? 0;
    document.getElementById('m-risk').textContent = sum.avg_risk_score != null ? sum.avg_risk_score.toFixed(2) : '0.00';
    const blocked = sum.blocked ?? 0;
    document.getElementById('hdr-threats').innerHTML =
      `<div class="dot ${blocked > 0 ? 'warn' : 'ok'}"></div> THREATS: ${blocked}`;
    if (sum.models_used) {
      document.getElementById('models-used').textContent =
        Object.entries(sum.models_used).map(([k,v]) => `${k}:${v}`).join(' | ');
    }
    renderLog(log);
    renderBreakdown(log);
  } catch(e) {
    document.getElementById('audit-log').innerHTML =
      `<div class="loading" style="color:var(--danger)">Cannot reach gateway at ${API}<br>Make sure the server is running.</div>`;
  }
}

function renderLog(log) {
  const el = document.getElementById('audit-log');
  if (!log.length) { el.innerHTML = '<div class="loading">No requests yet</div>'; return; }
  el.innerHTML = log.slice(-30).reverse().map(e => {
    const score = parseFloat(e.risk_score || 0);
    const sc = score >= 0.65 ? 'score-hi' : score >= 0.35 ? 'score-md' : 'score-lo';
    const action = (e.action || 'allow').toLowerCase();
    const t = new Date(e.timestamp).toLocaleTimeString();
    const preview = (e.prompt_preview || e.prompt || '—').substring(0, 55);
    return `<div class="log-row">
      <span class="badge ${action}">${action.toUpperCase()}</span>
      <span class="log-time">${t}</span>
      <span class="log-prompt">${preview}</span>
      <span class="log-score ${sc}">${score.toFixed(2)}</span>
    </div>`;
  }).join('');
}

function renderBreakdown(log) {
  const el = document.getElementById('threat-breakdown');
  const counts = {};
  log.forEach(e => { if (e.threat_type && e.threat_type !== 'clean') counts[e.threat_type] = (counts[e.threat_type]||0)+1; });
  const entries = Object.entries(counts).sort((a,b) => b[1]-a[1]);
  const max = entries[0]?.[1] || 1;
  if (!entries.length) { el.innerHTML = '<div class="loading">No threats detected yet</div>'; return; }
  const colors = { prompt_injection:'d', jailbreak:'d', data_exfiltration:'w', policy_bypass:'w', agent_abuse:'d', unsafe_behavior:'d' };
  el.innerHTML = entries.map(([k,v]) => `
    <div class="bar-row">
      <span class="bar-lbl">${k.replace(/_/g,' ')}</span>
      <div class="bar-track"><div class="bar-fill ${colors[k]||''}" style="width:${Math.round(v/max*100)}%"></div></div>
      <span class="bar-cnt">${v}</span>
    </div>`).join('');
}

function handleKey(e) {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMsg(); }
}

async function sendMsg() {
  const input = document.getElementById('chat-input');
  const prompt = input.value.trim();
  if (!prompt) return;
  const apiKey = document.getElementById('api-key').value;
  const dept = document.getElementById('dept').value;
  const model = document.getElementById('model').value;
  input.value = '';
  const btn = document.getElementById('send-btn');
  btn.disabled = true;
  const msgsEl = document.getElementById('msgs');
  const empty = msgsEl.querySelector('.empty');
  if (empty) empty.remove();
  appendMsg('user', prompt);
  const typingEl = appendTyping();
  try {
    const res = await fetch(API + '/v1/ai/request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
      body: JSON.stringify({ prompt, preferred_model: model, department: dept }),
    });
    typingEl.remove();
    const data = await res.json();
    if (res.ok) {
      appendMsg('bot', data.content);
      updateIndicators(data.risk_score, 'clean', 'allow', data.model_used);
    } else {
      const d = data.detail || {};
      const detail = d.threat_type
        ? `THREAT: ${d.threat_type} | RISK: ${(d.risk_score||0).toFixed(3)} | ACTION: ${d.action}`
        : (d.reason || d.error || 'Request denied');
      appendMsg('blocked', `⚠ BLOCKED\n${detail}`);
      updateIndicators(d.risk_score, d.threat_type, d.action, null);
    }
  } catch(e) {
    typingEl.remove();
    appendMsg('blocked', `Cannot reach gateway at ${API}`);
  }
  btn.disabled = false;
  msgsEl.scrollTop = msgsEl.scrollHeight;
}

function appendMsg(type, text) {
  const msgsEl = document.getElementById('msgs');
  const div = document.createElement('div');
  div.className = 'msg ' + type;
  div.innerHTML = `<div class="bubble">${text.replace(/\n/g,'<br>')}</div><div class="mmeta">${new Date().toLocaleTimeString()}</div>`;
  msgsEl.appendChild(div);
  msgsEl.scrollTop = msgsEl.scrollHeight;
  return div;
}

function appendTyping() {
  const msgsEl = document.getElementById('msgs');
  const div = document.createElement('div');
  div.className = 'msg bot';
  div.innerHTML = `<div class="bubble"><div class="typing"><span></span><span></span><span></span></div></div>`;
  msgsEl.appendChild(div);
  msgsEl.scrollTop = msgsEl.scrollHeight;
  return div;
}

function updateIndicators(risk, threat, action, model) {
  const score = parseFloat(risk || 0);
  const cls = score >= 0.65 ? 'd' : score >= 0.35 ? 'w' : 'g';
  const el = document.getElementById('ind-risk');
  el.className = 'ind-v ' + cls;
  el.textContent = score.toFixed(3);
  document.getElementById('ind-threat').textContent = threat || '—';
  document.getElementById('ind-action').textContent = action || '—';
  document.getElementById('ind-model').textContent = model || '—';
}

loadDashboard();
setInterval(loadDashboard, 15000);

function usePrompt(btn) {
  const input = document.getElementById('chat-input');
  input.value = btn.textContent.trim();
  // Switch to chat tab if not already there
  const chatTab = document.querySelector('.tab-btn:nth-child(2)');
  if (!document.getElementById('view-chat').classList.contains('active')) {
    switchTab('chat', chatTab);
  }
  input.focus();
}