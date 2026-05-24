#!/usr/bin/env python3
"""
Aegis-Web-IDS v3.0 — Agent de surveillance
Surveille les logs système, détecte les intrusions et envoie les données au serveur Aegis.

Usage:
    python3 aegis-agent.py --key <AGENT_KEY> --server http://SERVER_IP:5000 --name "mon-serveur"

Options:
    --key       Clé unique générée par le dashboard (obligatoire)
    --server    URL du serveur Aegis (ex: http://192.168.1.10:5000)
    --name      Nom de l'hôte affiché dans le dashboard
    --id        ID de l'agent (optionnel, détecté automatiquement)
    --interval  Intervalle d'envoi en secondes (défaut: 10)
    --logfile   Fichier log à surveiller (défaut: /var/log/auth.log,/var/log/syslog)
"""

import os
import re
import sys
import time
import json
import socket
import platform
import argparse
import threading
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ─── Configuration par défaut ────────────────────────────────────────────────
VERSION = "3.0.0"
DEFAULT_LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/fail2ban.log",
]

# ─── Règles de détection IDS ─────────────────────────────────────────────────
IDS_RULES = [
    # SSH
    {
        "id": "SSH-001",
        "pattern": re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d\.]+)", re.I),
        "type": "SSH Brute Force",
        "severity": "high",
        "extract": {"user": 1, "src_ip": 2},
        "target": "sshd",
    },
    {
        "id": "SSH-002",
        "pattern": re.compile(r"Invalid user (\S+) from ([\d\.]+)", re.I),
        "type": "SSH Invalid User",
        "severity": "medium",
        "extract": {"user": 1, "src_ip": 2},
        "target": "sshd",
    },
    {
        "id": "SSH-003",
        "pattern": re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d\.]+)", re.I),
        "type": "SSH Login Success",
        "severity": "low",
        "extract": {"user": 1, "src_ip": 2},
        "target": "sshd",
    },
    {
        "id": "SSH-004",
        "pattern": re.compile(r"POSSIBLE BREAK-IN ATTEMPT", re.I),
        "type": "SSH Break-In Attempt",
        "severity": "critical",
        "extract": {},
        "target": "sshd",
    },
    # Sudo
    {
        "id": "SUDO-001",
        "pattern": re.compile(r"sudo.*COMMAND=(.*)", re.I),
        "type": "Sudo Command",
        "severity": "low",
        "extract": {"target": 1},
        "target": "sudo",
    },
    {
        "id": "SUDO-002",
        "pattern": re.compile(r"sudo.*authentication failure", re.I),
        "type": "Sudo Auth Failure",
        "severity": "medium",
        "extract": {},
        "target": "sudo",
    },
    # Kernel / iptables
    {
        "id": "FW-001",
        "pattern": re.compile(r"iptables.*DROP.*SRC=([\d\.]+).*DST=([\d\.]+).*DPT=(\d+)", re.I),
        "type": "Firewall DROP",
        "severity": "medium",
        "extract": {"src_ip": 1, "target": 2},
        "target": "iptables",
    },
    # Apache / Nginx
    {
        "id": "WEB-001",
        "pattern": re.compile(r'([\d\.]+).*"(?:GET|POST|PUT|DELETE|HEAD) (.*?) HTTP.*" (4\d{2}|5\d{2})'),
        "type": "HTTP Error",
        "severity": "low",
        "extract": {"src_ip": 1, "target": 2},
        "target": "web",
    },
    {
        "id": "WEB-002",
        "pattern": re.compile(r'([\d\.]+).*".*(?:\.\.\/|etc/passwd|/etc/shadow|cmd=|exec\(|eval\(|UNION SELECT|<script|javascript:)', re.I),
        "type": "Web Attack",
        "severity": "critical",
        "extract": {"src_ip": 1},
        "target": "web",
    },
    {
        "id": "WEB-003",
        "pattern": re.compile(r'([\d\.]+).*".*(?:sqlmap|nikto|nmap|masscan|nuclei|dirbuster|gobuster|hydra)', re.I),
        "type": "Scanner Detected",
        "severity": "high",
        "extract": {"src_ip": 1},
        "target": "web",
    },
    # Fail2ban
    {
        "id": "F2B-001",
        "pattern": re.compile(r"fail2ban.*Ban ([\d\.]+)", re.I),
        "type": "Fail2ban Ban",
        "severity": "high",
        "extract": {"src_ip": 1},
        "target": "fail2ban",
    },
    # PAM / auth
    {
        "id": "PAM-001",
        "pattern": re.compile(r"pam_unix.*authentication failure.*user=(\S+)", re.I),
        "type": "PAM Auth Failure",
        "severity": "medium",
        "extract": {"user": 1},
        "target": "pam",
    },
    # Connexion root
    {
        "id": "ROOT-001",
        "pattern": re.compile(r"session opened for user root", re.I),
        "type": "Root Login",
        "severity": "critical",
        "extract": {},
        "target": "root",
    },
]

# ─── Compteur brute-force (seuil : 5 tentatives / 60s) ───────────────────────
bf_tracker = {}   # src_ip -> [timestamps]
BF_THRESHOLD = 5
BF_WINDOW    = 60

def is_brute_force(src_ip):
    """Retourne True si l'IP dépasse le seuil de tentatives."""
    now = time.time()
    times = bf_tracker.setdefault(src_ip, [])
    times = [t for t in times if now - t < BF_WINDOW]
    times.append(now)
    bf_tracker[src_ip] = times
    return len(times) >= BF_THRESHOLD


# ──────────────────────────────────────────────────────────────────────────────
#  AGENT
# ──────────────────────────────────────────────────────────────────────────────
class AegisAgent:
    def __init__(self, key, server, name, agent_id, interval):
        self.key       = key
        self.server    = server.rstrip("/")
        self.name      = name
        self.agent_id  = agent_id or ""
        self.interval  = interval
        self.hostname  = socket.gethostname()
        self.start_time = time.time()

        self._pending_alerts = []
        self._pending_logs   = []
        self._lock = threading.Lock()
        self._file_positions = {}   # path -> byte offset

    # ── Réseau ─────────────────────────────────────────────────────────────
    def _post(self, path, payload):
        url  = self.server + path
        body = json.dumps(payload).encode()
        req  = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            print(f"[Aegis][WARN] HTTP {e.code} sur {path}")
        except Exception as e:
            print(f"[Aegis][WARN] Erreur réseau ({path}): {e}")
        return None

    # ── Uptime ─────────────────────────────────────────────────────────────
    def get_uptime(self):
        try:
            with open("/proc/uptime") as f:
                secs = float(f.read().split()[0])
            d, r = divmod(int(secs), 86400)
            h, r = divmod(r, 3600)
            m    = r // 60
            if d:
                return f"{d}j {h}h {m}m"
            return f"{h}h {m}m"
        except Exception:
            elapsed = int(time.time() - self.start_time)
            m, s = divmod(elapsed, 60)
            h, m = divmod(m, 60)
            return f"{h}h {m}m {s}s"

    def get_local_ip(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    # ── Heartbeat ───────────────────────────────────────────────────────────
    def heartbeat(self):
        payload = {
            "key":      self.key,
            "id":       self.agent_id,
            "name":     self.name,
            "hostname": self.hostname,
            "ip":       self.get_local_ip(),
            "uptime":   self.get_uptime(),
            "version":  VERSION,
            "os":       platform.system() + " " + platform.release(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        resp = self._post("/api/agent/heartbeat", payload)
        if resp and resp.get("agent_id"):
            self.agent_id = resp["agent_id"]
            print(f"[Aegis] Heartbeat OK — agent_id={self.agent_id}")
        return resp

    # ── Envoi alertes & logs ───────────────────────────────────────────────
    def flush(self):
        with self._lock:
            alerts = list(self._pending_alerts)
            logs   = list(self._pending_logs)
            self._pending_alerts.clear()
            self._pending_logs.clear()

        if alerts:
            r = self._post("/api/agent/alerts", {"key": self.key, "id": self.agent_id, "alerts": alerts})
            if r:
                print(f"[Aegis] {len(alerts)} alerte(s) envoyée(s)")

        if logs:
            r = self._post("/api/agent/logs", {"key": self.key, "id": self.agent_id, "logs": logs})
            if r:
                print(f"[Aegis] {len(logs)} log(s) envoyé(s)")

    # ── Analyse d'une ligne ─────────────────────────────────────────────────
    def analyze_line(self, line, source="syslog"):
        ts = datetime.now(timezone.utc).isoformat()
        log_entry = {
            "timestamp": ts,
            "message":   line.strip(),
            "source":    source,
            "severity":  "info",
        }
        with self._lock:
            self._pending_logs.append(log_entry)

        for rule in IDS_RULES:
            m = rule["pattern"].search(line)
            if not m:
                continue

            src_ip = m.group(rule["extract"]["src_ip"]) if "src_ip" in rule["extract"] else "—"
            target = m.group(rule["extract"]["target"]) if "target" in rule["extract"] else rule["target"]

            severity = rule["severity"]
            # Élève la sévérité si brute-force détecté
            if src_ip != "—" and rule["id"].startswith("SSH-001"):
                if is_brute_force(src_ip):
                    severity = "critical"

            alert = {
                "type":      rule["type"],
                "severity":  severity,
                "src_ip":    src_ip,
                "target":    str(target)[:120],
                "rule":      rule["id"],
                "message":   line.strip()[:200],
                "timestamp": ts,
                "source":    source,
            }

            print(f"[Aegis][ALERTE] {rule['id']} — {rule['type']} — {severity.upper()} — {src_ip}")
            with self._lock:
                self._pending_alerts.append(alert)

    # ── Surveillance d'un fichier log ───────────────────────────────────────
    def tail_file(self, path):
        """Lit les nouvelles lignes d'un fichier depuis la dernière position."""
        if not os.path.isfile(path):
            return

        # Initialise la position à la fin du fichier au premier appel
        if path not in self._file_positions:
            self._file_positions[path] = os.path.getsize(path)
            return

        try:
            size = os.path.getsize(path)
            pos  = self._file_positions[path]

            # Rotation de log détectée
            if size < pos:
                pos = 0

            if size == pos:
                return

            with open(path, "r", errors="replace") as f:
                f.seek(pos)
                for line in f:
                    if line.strip():
                        self.analyze_line(line, source=os.path.basename(path))
                self._file_positions[path] = f.tell()

        except PermissionError:
            print(f"[Aegis][WARN] Permission refusée : {path} (relancer avec sudo ?)")
        except Exception as e:
            print(f"[Aegis][WARN] Erreur lecture {path}: {e}")

    # ── Surveillance journald (systemd) ────────────────────────────────────
    def poll_journald(self):
        """Lit les logs récents via journalctl."""
        try:
            result = subprocess.run(
                ["journalctl", "-n", "50", "--since", "-30s",
                 "--no-pager", "-o", "short-iso", "--no-hostname"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if line.strip():
                    self.analyze_line(line, source="journald")
        except FileNotFoundError:
            pass  # journalctl non disponible
        except Exception as e:
            print(f"[Aegis][WARN] journald: {e}")

    # ── Boucle principale ──────────────────────────────────────────────────
    def run(self, log_files):
        print(f"[Aegis] Démarrage de l'agent '{self.name}' — serveur: {self.server}")
        print(f"[Aegis] Intervalle d'envoi: {self.interval}s")
        print(f"[Aegis] Fichiers surveillés: {', '.join(log_files)}")

        # Premier heartbeat
        resp = self.heartbeat()
        if resp is None:
            print("[Aegis][WARN] Serveur inaccessible — l'agent continuera à réessayer")

        tick = 0
        while True:
            try:
                # Surveillance des fichiers
                for f in log_files:
                    self.tail_file(f)

                # journald en complément
                self.poll_journald()

                # Envoi périodique
                tick += 1
                if tick >= self.interval:
                    self.heartbeat()
                    self.flush()
                    tick = 0

                time.sleep(1)

            except KeyboardInterrupt:
                print("\n[Aegis] Arrêt de l'agent.")
                self.flush()
                break
            except Exception as e:
                print(f"[Aegis][ERROR] {e}")
                time.sleep(5)


# ─── Point d'entrée ──────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Aegis-Web-IDS Agent v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--key",      required=True,  help="Clé d'agent (depuis le dashboard)")
    parser.add_argument("--server",   required=True,  help="URL du serveur Aegis (ex: http://192.168.1.10:5000)")
    parser.add_argument("--name",     default=socket.gethostname(), help="Nom de l'hôte")
    parser.add_argument("--id",       default="",     help="ID agent (optionnel)")
    parser.add_argument("--interval", default=10, type=int, help="Intervalle d'envoi (s)")
    parser.add_argument("--logs",     default="",     help="Fichiers log supplémentaires (séparés par ',')")

    args = parser.parse_args()

    # Fichiers à surveiller
    log_files = [f for f in DEFAULT_LOG_FILES if os.path.isfile(f)]
    if args.logs:
        for p in args.logs.split(","):
            p = p.strip()
            if p and os.path.isfile(p):
                log_files.append(p)

    if not log_files:
        print("[Aegis][WARN] Aucun fichier log trouvé. Seul journald sera utilisé.")

    agent = AegisAgent(
        key=args.key,
        server=args.server,
        name=args.name,
        agent_id=args.id,
        interval=args.interval,
    )
    agent.run(log_files)


if __name__ == "__main__":
    main()
