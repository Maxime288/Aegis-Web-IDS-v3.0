from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify
import socket
import threading
from datetime import datetime
import json

app = Flask(__name__)
app.secret_key = "URUS_SECRET_KEY_2026"

USER_ADMIN = "admin"
PASS_ADMIN = "urus2026"
alerts = []
stats = {"FILE_MODIFIED": 0, "FILE_ADDED": 0, "SUSPICIOUS_PROC": 0, "BRUTEFORCE": 0}

def udp_listener():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("0.0.0.0", 9999))
        while True:
            data, addr = s.recvfrom(1024)
            msg = data.decode()
            timestamp = datetime.now().strftime("%H:%M:%S")
            alerts.append({"ip": addr[0], "msg": msg, "time": timestamp})
            for key in stats.keys():
                if key in msg:
                    stats[key] += 1

threading.Thread(target=udp_listener, daemon=True).start()

# ─────────────────────────────────────────────
#  LOGIN PAGE
# ─────────────────────────────────────────────
LOGIN_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AEGIS — Secure Access</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:        #07090b;
  --surface:   #0c1014;
  --surface2:  #111820;
  --border:    #1c2730;
  --border2:   #263542;
  --accent:    #bf3124;
  --accent2:   #e03d2e;
  --accent-dim:#7a1e15;
  --text:      #c5d5e0;
  --text-dim:  #4e6475;
  --text-xs:   #334856;
  --green:     #27c272;
  --amber:     #e8a030;
  --mono:      'IBM Plex Mono', monospace;
  --sans:      'DM Sans', sans-serif;
}

html, body {
  height: 100%;
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  overflow: hidden;
}

/* ── Noise texture overlay ── */
body::after {
  content: '';
  position: fixed;
  inset: 0;
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E");
  pointer-events: none;
  z-index: 0;
  opacity: .5;
}

/* ── Animated dot grid ── */
.dot-grid {
  position: fixed;
  inset: 0;
  background-image: radial-gradient(circle, rgba(191,49,36,0.12) 1px, transparent 1px);
  background-size: 32px 32px;
  animation: gridDrift 40s linear infinite;
  pointer-events: none;
  z-index: 0;
}
@keyframes gridDrift {
  0%   { background-position: 0 0; }
  100% { background-position: 32px 32px; }
}

/* ── Radial vignette ── */
.vignette {
  position: fixed;
  inset: 0;
  background: radial-gradient(ellipse 80% 80% at 50% 50%, transparent 30%, rgba(7,9,11,0.92) 100%);
  pointer-events: none;
  z-index: 0;
}

/* ── Scan beam ── */
.scan {
  position: fixed;
  left: 0; right: 0;
  height: 1px;
  background: linear-gradient(90deg, transparent 0%, rgba(191,49,36,0.18) 40%, rgba(191,49,36,0.22) 50%, rgba(191,49,36,0.18) 60%, transparent 100%);
  animation: scanMove 12s linear infinite;
  pointer-events: none;
  z-index: 1;
}
@keyframes scanMove { 0% { top: -1px; } 100% { top: 100vh; } }

/* ── Layout ── */
.page {
  position: relative;
  z-index: 2;
  height: 100vh;
  display: grid;
  grid-template-columns: 1fr 420px 1fr;
  align-items: center;
  padding: 0 40px;
}

/* ── Side panels ── */
.side {
  opacity: 0;
  animation: riseIn 0.7s ease 0.5s forwards;
}
.side.right { text-align: right; }

@keyframes riseIn {
  from { opacity: 0; transform: translateY(12px); }
  to   { opacity: 1; transform: translateY(0); }
}

.side-heading {
  font-family: var(--mono);
  font-size: 9px;
  letter-spacing: .22em;
  color: var(--text-xs);
  text-transform: uppercase;
  margin-bottom: 28px;
}

.side-item { margin-bottom: 24px; }
.side-label {
  font-family: var(--mono);
  font-size: 9px;
  letter-spacing: .18em;
  color: var(--text-dim);
  text-transform: uppercase;
  margin-bottom: 5px;
}
.side-value {
  font-family: var(--mono);
  font-size: 13px;
  color: var(--text);
  display: flex;
  align-items: center;
  gap: 8px;
}
.side.right .side-value { justify-content: flex-end; }

.pip {
  width: 5px; height: 5px;
  border-radius: 50%;
  flex-shrink: 0;
}
.pip.green { background: var(--green); box-shadow: 0 0 5px var(--green); animation: pipBlink 2.4s ease infinite; }
.pip.amber { background: var(--amber); box-shadow: 0 0 5px var(--amber); animation: pipBlink 1.8s ease infinite .4s; }
@keyframes pipBlink { 0%,100%{opacity:1} 50%{opacity:.25} }

.bar-track { height: 2px; background: var(--border); border-radius: 1px; margin-top: 7px; overflow: hidden; }
.bar-fill  { height: 100%; border-radius: 1px; transition: width 1s ease; animation: barGrow 1.8s ease 0.8s both; }
@keyframes barGrow { from { width: 0 !important; } }

.big-num {
  font-family: var(--mono);
  font-size: 38px;
  color: #fff;
  line-height: 1;
  font-weight: 300;
}

/* ── Card ── */
.card {
  position: relative;
  background: var(--surface);
  border: 1px solid var(--border);
  padding: 44px 40px 36px;
  opacity: 0;
  animation: riseIn 0.55s ease 0.1s forwards;
  clip-path: polygon(0 0, calc(100% - 16px) 0, 100% 16px, 100% 100%, 16px 100%, 0 calc(100% - 16px));
}

/* Top accent bar */
.card::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--accent), transparent);
  animation: sweep 4s ease 1s infinite;
}
@keyframes sweep {
  0%   { opacity: 0; background-position: -100% 0; }
  20%  { opacity: 1; }
  80%  { opacity: 1; }
  100% { opacity: 0; background-position: 200% 0; }
}

/* Corner cuts */
.card-corner {
  position: absolute;
  width: 8px; height: 8px;
  border-color: var(--accent-dim);
  border-style: solid;
}
.card-corner.bl { bottom: -1px; left: -1px; border-width: 0 0 1px 1px; }
.card-corner.br { bottom: -1px; right: -1px; border-width: 0 1px 1px 0; }

/* ── Logo ── */
.logo { display: flex; align-items: center; gap: 18px; margin-bottom: 32px; }
.logo-icon { width: 44px; height: 44px; flex-shrink: 0; }
.logo-name {
  font-family: var(--mono);
  font-size: 24px;
  font-weight: 400;
  letter-spacing: .35em;
  color: #fff;
  line-height: 1;
}
.logo-sub {
  font-family: var(--mono);
  font-size: 9px;
  color: var(--text-dim);
  letter-spacing: .18em;
  margin-top: 5px;
}

/* ── Divider ── */
.divider {
  height: 1px;
  background: var(--border);
  margin-bottom: 28px;
  position: relative;
  overflow: hidden;
}
.divider::after {
  content: '';
  position: absolute;
  top: 0; left: -60%;
  width: 60%; height: 100%;
  background: linear-gradient(90deg, transparent, var(--accent-dim), transparent);
  animation: divSweep 3.5s ease 1s infinite;
}
@keyframes divSweep { 0%{left:-60%} 100%{left:110%} }

/* ── Error banner ── */
.error {
  display: none;
  font-family: var(--mono);
  font-size: 11px;
  color: var(--accent2);
  background: rgba(191,49,36,.08);
  border-left: 2px solid var(--accent);
  padding: 9px 14px;
  margin-bottom: 20px;
  letter-spacing: .04em;
  animation: riseIn .25s ease;
}
.error.show { display: flex; align-items: center; gap: 8px; }

/* ── Fields ── */
.field { margin-bottom: 18px; }
.field-label {
  font-family: var(--mono);
  font-size: 9px;
  letter-spacing: .2em;
  color: var(--text-dim);
  text-transform: uppercase;
  display: block;
  margin-bottom: 7px;
}
.field-wrap { position: relative; }
.field-ico {
  position: absolute;
  left: 13px; top: 50%;
  transform: translateY(-50%);
  opacity: .28;
  pointer-events: none;
}
.field-ico svg { width: 14px; height: 14px; fill: none; stroke: var(--text); stroke-width: 1.5; stroke-linecap: round; stroke-linejoin: round; display: block; }

input[type="text"],
input[type="password"] {
  width: 100%;
  padding: 11px 40px 11px 40px;
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--text);
  font-family: var(--mono);
  font-size: 13px;
  outline: none;
  border-radius: 0;
  transition: border-color .2s, background .2s, box-shadow .2s;
  -webkit-appearance: none;
}
input:focus {
  border-color: var(--accent-dim);
  background: #080c0f;
  box-shadow: 0 0 0 3px rgba(191,49,36,.08);
}
input::placeholder { color: var(--text-xs); font-size: 12px; }

.eye-btn {
  position: absolute;
  right: 12px; top: 50%;
  transform: translateY(-50%);
  background: none; border: none;
  cursor: pointer; padding: 0; opacity: .28;
  transition: opacity .2s;
}
.eye-btn:hover { opacity: .75; }
.eye-btn svg { width: 15px; height: 15px; fill: none; stroke: var(--text); stroke-width: 1.5; stroke-linecap: round; stroke-linejoin: round; display: block; }

/* ── Submit ── */
.btn-auth {
  width: 100%;
  padding: 13px;
  background: var(--accent);
  border: none;
  color: #fff;
  font-family: var(--mono);
  font-size: 12px;
  letter-spacing: .28em;
  text-transform: uppercase;
  cursor: pointer;
  position: relative;
  overflow: hidden;
  transition: background .2s, transform .1s;
  margin-top: 6px;
  clip-path: polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px));
}
.btn-auth:hover  { background: var(--accent2); }
.btn-auth:active { transform: scale(.99); }
.btn-auth .shine {
  position: absolute;
  inset: 0;
  background: linear-gradient(90deg, transparent 0%, rgba(255,255,255,.07) 50%, transparent 100%);
  transform: translateX(-100%);
  transition: transform .4s ease;
}
.btn-auth:hover .shine { transform: translateX(100%); }

/* ── Footer ── */
.card-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 24px;
}
.card-footer span {
  font-family: var(--mono);
  font-size: 9px;
  color: var(--text-xs);
  letter-spacing: .1em;
}
.ver-tag {
  font-family: var(--mono);
  font-size: 9px;
  color: var(--accent-dim);
  border: 1px solid var(--accent-dim);
  padding: 2px 8px;
  letter-spacing: .12em;
}

/* ── Responsive ── */
@media (max-width: 960px) {
  .side { display: none; }
  .page { grid-template-columns: 1fr; justify-items: center; }
  .card { width: 90%; max-width: 400px; }
}

/* ── Reduced motion ── */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
}
</style>
</head>
<body>
<div class="dot-grid"></div>
<div class="vignette"></div>
<div class="scan"></div>

<div class="page">

  <!-- LEFT PANEL -->
  <div class="side">
    <div class="side-heading">// System Status</div>

    <div class="side-item">
      <div class="side-label">Network</div>
      <div class="side-value"><span class="pip green"></span>UDP :9999 active</div>
      <div class="bar-track"><div class="bar-fill" style="width:22%;background:var(--green);"></div></div>
    </div>

    <div class="side-item">
      <div class="side-label">Threat Level</div>
      <div class="side-value"><span class="pip amber"></span>Moderate — L2</div>
      <div class="bar-track"><div class="bar-fill" style="width:48%;background:var(--amber);"></div></div>
    </div>

    <div class="side-item">
      <div class="side-label">Active Agents</div>
      <div class="side-value">
        <span class="big-num" id="agentCount">0</span>
      </div>
    </div>

    <div class="side-item">
      <div class="side-label">Session Uptime</div>
      <div class="side-value" id="uptime" style="font-family:var(--mono);font-size:14px;">00:00:00</div>
    </div>
  </div>

  <!-- CENTER CARD -->
  <div class="card">
    <div class="card-corner bl"></div>
    <div class="card-corner br"></div>

    <!-- Logo -->
    <div class="logo">
      <div class="logo-icon">
        <svg viewBox="0 0 44 44" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M22 3L38 10V23C38 32 31 38.5 22 41C13 38.5 6 32 6 23V10Z" fill="none" stroke="#bf3124" stroke-width="1.2"/>
          <path d="M22 9L34 14.5V23C34 29.5 29 34.5 22 36.5C15 34.5 10 29.5 10 23V14.5Z" fill="rgba(191,49,36,0.07)" stroke="#7a1e15" stroke-width="0.8"/>
          <!-- Eye motif -->
          <ellipse cx="22" cy="23" rx="7" ry="4.5" fill="none" stroke="rgba(191,49,36,0.5)" stroke-width="0.8"/>
          <circle cx="22" cy="23" r="2.5" fill="none" stroke="#bf3124" stroke-width="1.2"/>
          <circle cx="22" cy="23" r="1" fill="#bf3124"/>
          <!-- Scan lines -->
          <line x1="15" y1="19" x2="29" y2="19" stroke="rgba(191,49,36,0.25)" stroke-width="0.5"/>
          <line x1="15" y1="27" x2="29" y2="27" stroke="rgba(191,49,36,0.25)" stroke-width="0.5"/>
        </svg>
      </div>
      <div>
        <div class="logo-name">AEGIS</div>
        <div class="logo-sub">Intrusion Detection System · URUS v3.1</div>
      </div>
    </div>

    <div class="divider"></div>

    <!-- Error -->
    <div class="error" id="errMsg">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><circle cx="12" cy="16" r="1" fill="currentColor"/></svg>
      Authentication failed — invalid credentials
    </div>

    <!-- Form -->
    <form action="/auth" method="post" id="loginForm">

      <div class="field">
        <label class="field-label" for="user">Operator ID</label>
        <div class="field-wrap">
          <span class="field-ico">
            <svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>
          </span>
          <input type="text" name="user" id="user" placeholder="admin" autocomplete="off" spellcheck="false">
        </div>
      </div>

      <div class="field">
        <label class="field-label" for="pass">Access Key</label>
        <div class="field-wrap">
          <span class="field-ico">
            <svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>
          </span>
          <input type="password" name="password" id="pass" placeholder="••••••••">
          <button type="button" class="eye-btn" onclick="togglePass()" id="eyeBtn" aria-label="Toggle password visibility">
            <svg id="eyeIcon" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
        </div>
      </div>

      <button type="submit" class="btn-auth">
        <span class="shine"></span>
        Authenticate &nbsp;→
      </button>

    </form>

    <div class="card-footer">
      <span>URUS Security Framework</span>
      <span class="ver-tag">v3.1.0</span>
    </div>
  </div>

  <!-- RIGHT PANEL -->
  <div class="side right">
    <div class="side-heading">// Intelligence Feed</div>

    <div class="side-item">
      <div class="side-label">Last Incident</div>
      <div class="side-value" style="justify-content:flex-end;" id="lastInc">No recent activity</div>
    </div>

    <div class="side-item">
      <div class="side-label">Total Alerts (session)</div>
      <div class="side-value" style="justify-content:flex-end;">
        <span class="big-num" id="totalAlerts">0</span>
      </div>
    </div>

    <div class="side-item">
      <div class="side-label">Encryption</div>
      <div class="side-value" style="justify-content:flex-end;">
        <span class="pip green"></span>AES-256 active
      </div>
    </div>

    <div class="side-item">
      <div class="side-label">Auth Mode</div>
      <div class="side-value" style="justify-content:flex-end;">Role-based access</div>
    </div>
  </div>

</div><!-- /page -->

<script>
  /* Show error */
  if (window.location.search.includes('error=1')) {
    document.getElementById('errMsg').classList.add('show');
  }

  /* Uptime counter */
  let sec = 0;
  setInterval(() => {
    sec++;
    const h = String(Math.floor(sec/3600)).padStart(2,'0');
    const m = String(Math.floor((sec%3600)/60)).padStart(2,'0');
    const s = String(sec%60).padStart(2,'0');
    document.getElementById('uptime').textContent = h+':'+m+':'+s;
  }, 1000);

  /* Agent count animation */
  let c = 0, t = 7;
  const iv = setInterval(() => {
    c++;
    document.getElementById('agentCount').textContent = c;
    if (c >= t) clearInterval(iv);
  }, 140);

  /* Password toggle */
  function togglePass() {
    const inp = document.getElementById('pass');
    const ico = document.getElementById('eyeIcon');
    if (inp.type === 'password') {
      inp.type = 'text';
      ico.innerHTML = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/>';
    } else {
      inp.type = 'password';
      ico.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
    }
  }
</script>
</body>
</html>"""


# ─────────────────────────────────────────────
#  DASHBOARD PAGE
# ─────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AEGIS — Operations Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:        #07090b;
  --surface:   #0c1014;
  --surface2:  #111820;
  --surface3:  #151f28;
  --border:    #1c2730;
  --border2:   #263542;
  --accent:    #bf3124;
  --accent2:   #e03d2e;
  --accent-dim:#7a1e15;
  --text:      #c5d5e0;
  --text-dim:  #4e6475;
  --text-xs:   #2e4050;
  --green:     #27c272;
  --amber:     #e8a030;
  --blue:      #3498db;
  --mono:      'IBM Plex Mono', monospace;
  --sans:      'DM Sans', sans-serif;
}

html, body {
  height: 100%;
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  overflow: hidden;
}

/* ── Subtle background grid ── */
body::before {
  content: '';
  position: fixed;
  inset: 0;
  background-image: radial-gradient(circle, rgba(191,49,36,0.06) 1px, transparent 1px);
  background-size: 28px 28px;
  pointer-events: none;
  z-index: 0;
}

/* ── Navbar ── */
.navbar {
  position: relative;
  z-index: 20;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  height: 52px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 20px;
  flex-shrink: 0;
}

.nb-brand {
  display: flex;
  align-items: center;
  gap: 12px;
}
.nb-brand svg { width: 24px; height: 24px; }
.nb-name {
  font-family: var(--mono);
  font-size: 14px;
  letter-spacing: .32em;
  color: #fff;
}
.nb-ver {
  font-family: var(--mono);
  font-size: 8px;
  color: var(--accent);
  letter-spacing: .1em;
  margin-top: 2px;
}

/* ── Navbar center: breadcrumb ── */
.nb-center {
  display: flex;
  align-items: center;
  gap: 8px;
  font-family: var(--mono);
  font-size: 10px;
  color: var(--text-dim);
  letter-spacing: .12em;
}
.nb-center .sep { color: var(--text-xs); }
.nb-center .active { color: var(--text); }

.nb-right {
  display: flex;
  align-items: center;
  gap: 20px;
}
.nb-status {
  font-family: var(--mono);
  font-size: 10px;
  color: var(--text-dim);
  display: flex;
  align-items: center;
  gap: 7px;
  letter-spacing: .1em;
}
.nb-status .pip {
  width: 5px; height: 5px; border-radius: 50%;
  background: var(--green);
  box-shadow: 0 0 5px var(--green);
  animation: pipBlink 2.2s ease infinite;
}
@keyframes pipBlink { 0%,100%{opacity:1} 50%{opacity:.2} }

.nb-time {
  font-family: var(--mono);
  font-size: 12px;
  color: var(--text);
  letter-spacing: .06em;
  min-width: 70px;
  text-align: right;
}

.btn-logout {
  font-family: var(--mono);
  font-size: 9px;
  letter-spacing: .18em;
  color: var(--text-dim);
  text-decoration: none;
  border: 1px solid var(--border2);
  padding: 5px 12px;
  transition: color .2s, border-color .2s, background .2s;
  text-transform: uppercase;
  cursor: pointer;
}
.btn-logout:hover {
  color: var(--accent2);
  border-color: var(--accent-dim);
  background: rgba(191,49,36,.05);
}
.btn-logout:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}

/* ── Main layout ── */
.layout {
  position: relative;
  z-index: 1;
  display: flex;
  flex-direction: column;
  height: calc(100vh - 52px);
  padding: 14px;
  gap: 12px;
  overflow: hidden;
}

/* ── Metric cards ── */
.metrics {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 10px;
  flex-shrink: 0;
}

.mc {
  background: var(--surface);
  border: 1px solid var(--border);
  padding: 14px 16px 12px;
  position: relative;
  overflow: hidden;
  cursor: default;
  transition: border-color .2s, background .2s;
}
.mc:hover { background: var(--surface2); }
.mc::after {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
}
.mc.red::after    { background: var(--accent); }
.mc.amber::after  { background: var(--amber); }
.mc.blue::after   { background: var(--blue); }
.mc.green::after  { background: var(--green); }

/* Animated stripe on hover */
.mc::before {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(135deg, rgba(255,255,255,.02) 0%, transparent 60%);
  opacity: 0;
  transition: opacity .2s;
}
.mc:hover::before { opacity: 1; }

.mc-top {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 10px;
}
.mc-label {
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: .2em;
  color: var(--text-dim);
  text-transform: uppercase;
}
.mc-icon {
  opacity: .12;
  flex-shrink: 0;
}
.mc-icon svg { width: 18px; height: 18px; fill: none; stroke: var(--text); stroke-width: 1.5; stroke-linecap: round; stroke-linejoin: round; }

.mc-value {
  font-family: var(--mono);
  font-size: 34px;
  color: #fff;
  font-weight: 300;
  line-height: 1;
  margin-bottom: 5px;
}
.mc-tag {
  font-family: var(--mono);
  font-size: 8px;
  color: var(--text-xs);
  letter-spacing: .12em;
  text-transform: uppercase;
}

/* ── Content row ── */
.content {
  display: grid;
  grid-template-columns: 260px 1fr;
  gap: 12px;
  flex: 1;
  min-height: 0;
}

/* ── Panels ── */
.panel {
  background: var(--surface);
  border: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.panel-hdr {
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-shrink: 0;
  gap: 8px;
}
.panel-title {
  font-family: var(--mono);
  font-size: 9px;
  letter-spacing: .2em;
  color: var(--text-dim);
  text-transform: uppercase;
}
.panel-badge {
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: .1em;
  color: var(--accent);
  border: 1px solid var(--accent-dim);
  padding: 2px 7px;
  background: rgba(191,49,36,.05);
}
.panel-badge.green {
  color: var(--green);
  border-color: rgba(39,194,114,.3);
  background: rgba(39,194,114,.05);
}

.panel-body {
  flex: 1;
  overflow: hidden;
  padding: 16px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}

/* ── Donut chart ── */
.chart-wrap {
  width: 100%;
  max-width: 180px;
  margin-bottom: 4px;
}

/* ── Legend ── */
.legend {
  width: 100%;
  padding: 0 16px 14px;
  flex-shrink: 0;
}
.leg-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 7px 0;
  border-bottom: 1px solid var(--border);
  cursor: default;
  transition: background .15s;
  border-radius: 2px;
  padding-inline: 4px;
}
.leg-item:last-child { border-bottom: none; }
.leg-item:hover { background: var(--surface2); }
.leg-left { display: flex; align-items: center; gap: 9px; }
.leg-dot { width: 6px; height: 6px; border-radius: 1px; flex-shrink: 0; }
.leg-name {
  font-family: var(--mono);
  font-size: 10px;
  color: var(--text);
  letter-spacing: .05em;
}
.leg-count {
  font-family: var(--mono);
  font-size: 10px;
  color: var(--text-dim);
}

/* ── Log panel ── */
.log-body {
  flex: 1;
  overflow-y: auto;
  padding: 0;
}
.log-body::-webkit-scrollbar { width: 3px; }
.log-body::-webkit-scrollbar-track { background: var(--bg); }
.log-body::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }

/* Log search bar */
.log-search {
  padding: 10px 16px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
  display: flex;
  align-items: center;
  gap: 10px;
}
.log-search-ico { opacity: .3; flex-shrink: 0; }
.log-search-ico svg { width: 13px; height: 13px; fill: none; stroke: var(--text); stroke-width: 1.5; stroke-linecap: round; stroke-linejoin: round; }
.log-search input {
  background: none;
  border: none;
  outline: none;
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text);
  width: 100%;
}
.log-search input::placeholder { color: var(--text-xs); }

/* Table */
table { width: 100%; border-collapse: collapse; }
thead { position: sticky; top: 0; z-index: 5; }
thead th {
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: .2em;
  text-transform: uppercase;
  color: var(--text-dim);
  padding: 9px 14px;
  background: var(--surface2);
  border-bottom: 1px solid var(--border);
  text-align: left;
  font-weight: 400;
  white-space: nowrap;
}
tbody tr {
  border-bottom: 1px solid var(--border);
  transition: background .12s;
  animation: rowIn .28s ease both;
}
@keyframes rowIn {
  from { opacity: 0; transform: translateX(-5px); }
  to   { opacity: 1; transform: translateX(0); }
}
tbody tr:hover { background: var(--surface2); }
tbody td {
  padding: 9px 14px;
  font-size: 12px;
  vertical-align: middle;
}
.td-ip {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--blue);
  white-space: nowrap;
}
.td-msg { color: var(--text); }
.td-time {
  font-family: var(--mono);
  font-size: 10px;
  color: var(--text-dim);
  white-space: nowrap;
  text-align: right;
}

/* Badges */
.badge {
  display: inline-flex;
  align-items: center;
  font-family: var(--mono);
  font-size: 8px;
  letter-spacing: .1em;
  padding: 2px 6px;
  margin-right: 8px;
  vertical-align: middle;
  border-radius: 1px;
}
.badge-red   { color: var(--accent2); border: 1px solid var(--accent-dim); background: rgba(191,49,36,.07); }
.badge-amber { color: var(--amber);   border: 1px solid rgba(232,160,48,.3); background: rgba(232,160,48,.06); }
.badge-blue  { color: var(--blue);    border: 1px solid rgba(52,152,219,.3); background: rgba(52,152,219,.06); }

/* Empty state */
.empty-state {
  text-align: center;
  padding: 50px 20px;
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text-dim);
  letter-spacing: .1em;
  line-height: 2;
}
.empty-icon { opacity: .15; margin-bottom: 12px; }
.empty-icon svg { width: 28px; height: 28px; fill: none; stroke: var(--text); stroke-width: 1; }

/* ── Responsive ── */
@media (max-width: 960px) {
  .content { grid-template-columns: 1fr; }
  .panel:first-child { display: none; }
  .metrics { grid-template-columns: repeat(2, 1fr); }
}
@media (max-width: 540px) {
  .metrics { grid-template-columns: 1fr 1fr; }
  .nb-center { display: none; }
}

/* ── Reduced motion ── */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
}
</style>
</head>
<body>

<!-- NAVBAR -->
<nav class="navbar" role="navigation" aria-label="Main navigation">
  <div class="nb-brand">
    <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <path d="M12 2L20 6V13C20 17.4 16.5 21 12 22.5C7.5 21 4 17.4 4 13V6Z" fill="none" stroke="#bf3124" stroke-width="1.2"/>
      <ellipse cx="12" cy="13" rx="4" ry="2.5" fill="none" stroke="rgba(191,49,36,0.5)" stroke-width="0.8"/>
      <circle cx="12" cy="13" r="1.2" fill="#bf3124"/>
    </svg>
    <div>
      <div class="nb-name">AEGIS</div>
      <div class="nb-ver">IDS · URUS v3.1</div>
    </div>
  </div>

  <div class="nb-center" aria-label="Breadcrumb">
    <span>Root</span>
    <span class="sep">/</span>
    <span>Operations</span>
    <span class="sep">/</span>
    <span class="active">Dashboard</span>
  </div>

  <div class="nb-right">
    <div class="nb-status" role="status" aria-live="polite">
      <span class="pip"></span>
      <span>MONITORING ACTIF</span>
    </div>
    <div class="nb-time" id="navTime" aria-live="polite" aria-label="Current time">--:--:--</div>
    <a href="/logout" class="btn-logout" aria-label="Log out">DÉCONNEXION</a>
  </div>
</nav>

<!-- MAIN LAYOUT -->
<div class="layout" role="main">

  <!-- METRICS ROW -->
  <div class="metrics" role="region" aria-label="Security metrics">

    <div class="mc red" role="status" aria-label="Files modified">
      <div class="mc-top">
        <div class="mc-label">Fichiers modifiés</div>
        <div class="mc-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
        </div>
      </div>
      <div class="mc-value" id="mFilesMod">__FILE_MOD__</div>
      <div class="mc-tag">FILE_MODIFIED</div>
    </div>

    <div class="mc amber" role="status" aria-label="Files added">
      <div class="mc-top">
        <div class="mc-label">Fichiers ajoutés</div>
        <div class="mc-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
        </div>
      </div>
      <div class="mc-value" id="mFilesAdd">__FILE_ADD__</div>
      <div class="mc-tag">FILE_ADDED</div>
    </div>

    <div class="mc blue" role="status" aria-label="Suspicious processes">
      <div class="mc-top">
        <div class="mc-label">Processus suspects</div>
        <div class="mc-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
        </div>
      </div>
      <div class="mc-value" id="mProcs">__PROCS__</div>
      <div class="mc-tag">SUSPICIOUS_PROC</div>
    </div>

    <div class="mc green" role="status" aria-label="Brute-force attempts">
      <div class="mc-top">
        <div class="mc-label">Brute-force</div>
        <div class="mc-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        </div>
      </div>
      <div class="mc-value" id="mBrute">__BRUTE__</div>
      <div class="mc-tag">BRUTEFORCE</div>
    </div>

  </div><!-- /metrics -->

  <!-- CONTENT ROW -->
  <div class="content">

    <!-- LEFT: Chart panel -->
    <div class="panel" role="region" aria-label="Threat distribution chart">
      <div class="panel-hdr">
        <span class="panel-title">Répartition</span>
        <span class="panel-badge" id="totalBadge">__TOTAL__ TOTAL</span>
      </div>
      <div class="panel-body">
        <div class="chart-wrap" role="img" aria-label="Donut chart showing threat distribution">
          <canvas id="myChart"></canvas>
        </div>
      </div>
      <div class="legend" role="list" aria-label="Chart legend">
        <div class="leg-item" role="listitem">
          <div class="leg-left">
            <div class="leg-dot" style="background:#e03d2e;"></div>
            <span class="leg-name">Fichiers</span>
          </div>
          <span class="leg-count" id="lFiles">__FILES_TOTAL__</span>
        </div>
        <div class="leg-item" role="listitem">
          <div class="leg-left">
            <div class="leg-dot" style="background:#3498db;"></div>
            <span class="leg-name">Processus</span>
          </div>
          <span class="leg-count" id="lProcs">__PROCS__</span>
        </div>
        <div class="leg-item" role="listitem">
          <div class="leg-left">
            <div class="leg-dot" style="background:#e8a030;"></div>
            <span class="leg-name">Brute-force</span>
          </div>
          <span class="leg-count" id="lBrute">__BRUTE__</span>
        </div>
      </div>
    </div>

    <!-- RIGHT: Log panel -->
    <div class="panel" role="region" aria-label="Event journal">
      <div class="panel-hdr">
        <span class="panel-title">Journal des événements</span>
        <span class="panel-badge green" id="logCount">__ALERT_COUNT__ ENTRÉES</span>
      </div>
      <div class="log-search" role="search">
        <span class="log-search-ico" aria-hidden="true">
          <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        </span>
        <input type="text" id="logFilter" placeholder="Filtrer les événements…" aria-label="Filter events" oninput="filterLog(this.value)">
      </div>
      <div class="log-body" id="logBody">
        __LOG_ROWS__
      </div>
    </div>

  </div><!-- /content -->

</div><!-- /layout -->

<script>
  /* ── Clock ── */
  function updateClock() {
    const n = new Date();
    document.getElementById('navTime').textContent =
      String(n.getHours()).padStart(2,'0')+':'+
      String(n.getMinutes()).padStart(2,'0')+':'+
      String(n.getSeconds()).padStart(2,'0');
  }
  setInterval(updateClock, 1000);
  updateClock();

  /* ── Chart ── */
  const ctx = document.getElementById('myChart').getContext('2d');
  const filesVal = __FILES_TOTAL__;
  const procsVal = __PROCS__;
  const bruteVal = __BRUTE__;
  const isEmpty  = (filesVal + procsVal + bruteVal) === 0;

  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Fichiers','Processus','BruteForce'],
      datasets: [{
        data: isEmpty ? [1,1,1] : [filesVal,procsVal,bruteVal],
        backgroundColor: isEmpty
          ? ['#1c2730','#1c2730','#1c2730']
          : ['#e03d2e','#3498db','#e8a030'],
        borderColor: '#0c1014',
        borderWidth: 5,
        hoverBorderColor: '#0c1014',
        hoverOffset: 4,
      }]
    },
    options: {
      cutout: '74%',
      plugins: {
        legend: { display: false },
        tooltip: {
          enabled: !isEmpty,
          backgroundColor: '#111820',
          titleColor: '#c5d5e0',
          bodyColor: '#c5d5e0',
          borderColor: '#1c2730',
          borderWidth: 1,
          padding: 10,
          titleFont: { family: 'IBM Plex Mono', size: 10 },
          bodyFont:  { family: 'IBM Plex Mono', size: 10 },
          callbacks: {
            label: ctx => ' ' + ctx.label + ': ' + ctx.raw
          }
        }
      },
      animation: { animateRotate: true, duration: 900, easing: 'easeInOutQuart' }
    }
  });

  /* ── Log filter ── */
  function filterLog(q) {
    const rows = document.querySelectorAll('#logBody tbody tr');
    const lower = q.toLowerCase();
    rows.forEach(r => {
      r.style.display = r.textContent.toLowerCase().includes(lower) ? '' : 'none';
    });
  }

  /* ── Live refresh every 10s ── */
  setInterval(() => {
    fetch('/api/stats').then(r => r.json()).then(d => {
      document.getElementById('mFilesMod').textContent = d.FILE_MODIFIED;
      document.getElementById('mFilesAdd').textContent = d.FILE_ADDED;
      document.getElementById('mProcs').textContent    = d.SUSPICIOUS_PROC;
      document.getElementById('mBrute').textContent    = d.BRUTEFORCE;
      const tot = d.FILE_MODIFIED + d.FILE_ADDED + d.SUSPICIOUS_PROC + d.BRUTEFORCE;
      document.getElementById('totalBadge').textContent = tot + ' TOTAL';
      document.getElementById('lFiles').textContent = d.FILE_MODIFIED + d.FILE_ADDED;
      document.getElementById('lProcs').textContent = d.SUSPICIOUS_PROC;
      document.getElementById('lBrute').textContent = d.BRUTEFORCE;
    }).catch(() => {});
  }, 10000);
</script>
</body>
</html>"""


def build_log_rows(alerts_list):
    if not alerts_list:
        return '''<div class="empty-state">
  <div class="empty-icon">
    <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" stroke-linecap="round" stroke-linejoin="round"/></svg>
  </div>
  [ NO EVENTS RECORDED ]<br>En attente de données agents…
</div>'''
    rows = []
    for a in reversed(alerts_list):
        msg = a['msg']
        if 'BRUTEFORCE' in msg:
            badge = '<span class="badge badge-amber">BRUTE</span>'
        elif 'SUSPICIOUS_PROC' in msg:
            badge = '<span class="badge badge-blue">PROC</span>'
        else:
            badge = '<span class="badge badge-red">ALERT</span>'
        rows.append(
            f'<tr>'
            f'<td class="td-ip">{a["ip"]}</td>'
            f'<td class="td-msg">{badge}{msg}</td>'
            f'<td class="td-time">{a["time"]}</td>'
            f'</tr>'
        )
    return (
        '<table role="table">'
        '<thead><tr>'
        '<th scope="col" style="width:110px">Agent IP</th>'
        '<th scope="col">Événement</th>'
        '<th scope="col" style="width:80px;text-align:right">Heure</th>'
        '</tr></thead>'
        '<tbody>' + ''.join(rows) + '</tbody>'
        '</table>'
    )


@app.route('/')
def login():
    return LOGIN_HTML

@app.route('/auth', methods=['POST'])
def auth():
    if request.form['user'] == USER_ADMIN and request.form['password'] == PASS_ADMIN:
        session['logged_in'] = True
        return redirect(url_for('dashboard'))
    return redirect(url_for('login') + '?error=1')

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    files_total = stats['FILE_MODIFIED'] + stats['FILE_ADDED']
    total = files_total + stats['SUSPICIOUS_PROC'] + stats['BRUTEFORCE']
    html = DASHBOARD_HTML
    html = html.replace('__FILE_MOD__',    str(stats['FILE_MODIFIED']))
    html = html.replace('__FILE_ADD__',    str(stats['FILE_ADDED']))
    html = html.replace('__PROCS__',       str(stats['SUSPICIOUS_PROC']))
    html = html.replace('__BRUTE__',       str(stats['BRUTEFORCE']))
    html = html.replace('__FILES_TOTAL__', str(files_total))
    html = html.replace('__TOTAL__',       str(total))
    html = html.replace('__ALERT_COUNT__', str(len(alerts)))
    html = html.replace('__LOG_ROWS__',    build_log_rows(alerts))
    return html

@app.route('/api/stats')
def api_stats():
    if not session.get('logged_in'):
        return jsonify({}), 403
    return jsonify(stats)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
