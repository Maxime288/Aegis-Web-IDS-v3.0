#!/usr/bin/env python3
"""
Aegis-Web-IDS v3.0 — Agent
Surveille le système et envoie les alertes au serveur Aegis.

Usage:
  ./aegis-agent --key <AGENT_KEY> --server http://<HOST>:5000 --name <HOSTNAME>

Options:
  --key       Clé d'agent générée par le dashboard
  --server    URL du serveur Aegis (ex: http://192.168.1.100:5000)
  --name      Nom de la machine (ex: web-server-01)
  --interval  Intervalle de polling en secondes (défaut: 30)
  --no-proc   Désactiver la surveillance des processus
  --no-files  Désactiver la surveillance des fichiers
  --no-ssh    Désactiver la détection bruteforce SSH
"""

import argparse
import hashlib
import json
import logging
import os
import platform
import re
import signal
import socket
import sys
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

# ─── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("aegis-agent")

# ─── Constants ─────────────────────────────────────────────────────────────────

VERSION = "3.0.0"
HEARTBEAT_INTERVAL = 60      # secondes entre chaque heartbeat
MONITOR_INTERVAL   = 30      # secondes entre chaque scan
SSH_LOG_PATHS      = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
]
WATCHED_DIRS = [
    "/etc",
    "/bin",
    "/usr/bin",
    "/sbin",
    "/usr/sbin",
]
SUSPICIOUS_PROCS = [
    "nmap", "netcat", "nc", "ncat", "masscan",
    "hydra", "medusa", "hashcat", "john",
    "sqlmap", "nikto", "gobuster", "dirb",
    "msfconsole", "msfvenom", "metasploit",
    "tcpdump", "wireshark", "tshark",
    "mimikatz", "bloodhound", "crackmapexec",
    "socat", "cryptcat", "powercat",
    "python3 -c", "python -c", "bash -i",
    "sh -i", "perl -e", "ruby -e",
]

BRUTE_THRESHOLD = 5   # tentatives en 60s = bruteforce
BRUTE_WINDOW    = 60  # secondes

# ─── Globals ───────────────────────────────────────────────────────────────────

running = True
agent_info = {}
file_hashes: dict[str, str] = {}
ssh_fail_tracker: dict[str, list] = {}   # ip -> [timestamps]
last_ssh_pos: dict[str, int] = {}         # logfile -> byte offset
alerts_sent = 0
critical_sent = 0
start_time = time.time()

# ─── HTTP helpers ──────────────────────────────────────────────────────────────

def api_post(server: str, path: str, payload: dict, key: str, timeout: int = 10) -> dict | None:
    url = server.rstrip("/") + path
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-Agent-Key": key,
            "Authorization": f"Bearer {key}",
            "User-Agent": f"AegisAgent/{VERSION}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        log.warning("HTTP %s on POST %s: %s", e.code, path, e.reason)
    except urllib.error.URLError as e:
        log.warning("Cannot reach server: %s", e.reason)
    except Exception as e:
        log.warning("POST error: %s", e)
    return None


def api_get(server: str, path: str, key: str, timeout: int = 10) -> dict | None:
    url = server.rstrip("/") + path
    req = urllib.request.Request(
        url,
        headers={
            "X-Agent-Key": key,
            "Authorization": f"Bearer {key}",
            "User-Agent": f"AegisAgent/{VERSION}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        log.debug("GET %s error: %s", path, e)
    return None

# ─── Registration ──────────────────────────────────────────────────────────────

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def register(server: str, key: str, name: str) -> bool:
    """Envoie la registration au serveur Aegis."""
    payload = {
        "key":          key,
        "name":         name,
        "hostname":     socket.gethostname(),
        "ip":           get_local_ip(),
        "os":           platform.system(),
        "os_version":   platform.version(),
        "arch":         platform.machine(),
        "version":      VERSION,
        "status":       "online",
        "enrolled_at":  datetime.utcnow().isoformat() + "Z",
    }
    log.info("Enregistrement auprès du serveur %s …", server)
    result = api_post(server, "/api/agents/enroll", payload, key)
    if result:
        log.info("Agent enregistré avec succès. ID: %s", result.get("id", key[:12]))
        return True
    # Le dashboard peut fonctionner sans retour serveur (mode local)
    log.warning("Serveur inaccessible — mode surveillance seul activé.")
    return False

# ─── Alert sender ──────────────────────────────────────────────────────────────

def send_alert(server: str, key: str, name: str,
               alert_type: str, message: str, severity: str = "warning",
               source_ip: str = "local"):
    global alerts_sent, critical_sent
    payload = {
        "agent_key":    key,
        "agent_name":   name,
        "type":         alert_type,
        "message":      message,
        "severity":     severity,
        "source_ip":    source_ip,
        "timestamp":    datetime.utcnow().isoformat() + "Z",
        "hostname":     socket.gethostname(),
    }
    result = api_post(server, "/api/logs", payload, key)
    if result:
        alerts_sent += 1
        if severity == "critical":
            critical_sent += 1
        log.info("[ALERTE %s] %s → %s", severity.upper(), alert_type, message[:80])
    else:
        # Fallback: UDP (pour compatibilité avec l'ancien udp_listener du serveur)
        _send_udp_fallback(server, f"[{alert_type}] {message}")
        alerts_sent += 1
        if severity == "critical":
            critical_sent += 1


def _send_udp_fallback(server: str, message: str):
    """Envoie via UDP sur le port 9999 (compatibilité aegis_server.py v1)."""
    try:
        host = server.split("://")[-1].split(":")[0].split("/")[0]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message.encode(), (host, 9999))
        sock.close()
    except Exception as e:
        log.debug("UDP fallback error: %s", e)

# ─── Heartbeat ─────────────────────────────────────────────────────────────────

def heartbeat_loop(server: str, key: str, name: str, interval: int):
    while running:
        uptime_s = int(time.time() - start_time)
        h, m, s = uptime_s // 3600, (uptime_s % 3600) // 60, uptime_s % 60
        payload = {
            "key":           key,
            "name":          name,
            "status":        "online",
            "uptime":        f"{h:02d}:{m:02d}:{s:02d}",
            "alerts_count":  alerts_sent,
            "critical_count":critical_sent,
            "version":       VERSION,
            "last_seen":     datetime.utcnow().isoformat() + "Z",
        }
        api_post(server, "/api/agents/heartbeat", payload, key)
        log.debug("Heartbeat envoyé (uptime %s)", payload["uptime"])
        time.sleep(interval)

# ─── File integrity monitoring ─────────────────────────────────────────────────

def hash_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def build_baseline(dirs: list[str]) -> dict[str, str]:
    baseline = {}
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for fname in files:
                fp = os.path.join(root, fname)
                h = hash_file(fp)
                if h:
                    baseline[fp] = h
    log.info("Baseline fichiers: %d fichiers surveillés", len(baseline))
    return baseline


def check_files(server: str, key: str, name: str):
    global file_hashes
    for path, old_hash in list(file_hashes.items()):
        if not os.path.exists(path):
            send_alert(server, key, name,
                       "FILE_DELETED",
                       f"Fichier supprimé: {path}",
                       severity="warning")
            del file_hashes[path]
            continue
        new_hash = hash_file(path)
        if new_hash and new_hash != old_hash:
            send_alert(server, key, name,
                       "FILE_MODIFIED",
                       f"Modification détectée: {path}",
                       severity="critical")
            file_hashes[path] = new_hash

    # Nouveaux fichiers dans les répertoires surveillés
    for d in WATCHED_DIRS:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for fname in files:
                fp = os.path.join(root, fname)
                if fp not in file_hashes:
                    h = hash_file(fp)
                    if h:
                        file_hashes[fp] = h
                        send_alert(server, key, name,
                                   "FILE_ADDED",
                                   f"Nouveau fichier: {fp}",
                                   severity="warning")

# ─── Process monitoring ────────────────────────────────────────────────────────

_seen_pids: set[int] = set()

def check_processes(server: str, key: str, name: str):
    try:
        procs = _list_processes()
    except Exception as e:
        log.debug("Process list error: %s", e)
        return

    for pid, cmdline in procs:
        cmd_lower = cmdline.lower()
        for suspect in SUSPICIOUS_PROCS:
            if suspect in cmd_lower and pid not in _seen_pids:
                _seen_pids.add(pid)
                send_alert(server, key, name,
                           "SUSPICIOUS_PROC",
                           f"Processus suspect (PID {pid}): {cmdline[:120]}",
                           severity="critical")
                break


def _list_processes() -> list[tuple[int, str]]:
    result = []
    proc_dir = Path("/proc")
    for entry in proc_dir.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="replace").strip()
            if cmdline:
                result.append((int(entry.name), cmdline))
        except Exception:
            pass
    return result

# ─── SSH Bruteforce detection ──────────────────────────────────────────────────

_SSH_FAIL_RE = re.compile(
    r"(?:Failed password|Invalid user|authentication failure).*?(?:from\s+)?([\d.]+)",
    re.IGNORECASE,
)
_SSH_ACCEPT_RE = re.compile(
    r"Accepted (?:password|publickey) for .+ from ([\d.]+)",
    re.IGNORECASE,
)


def check_ssh_logs(server: str, key: str, name: str):
    for logpath in SSH_LOG_PATHS:
        if not os.path.isfile(logpath):
            continue
        try:
            with open(logpath, "rb") as f:
                start = last_ssh_pos.get(logpath, max(0, os.path.getsize(logpath) - 8192))
                f.seek(start)
                new_data = f.read()
                last_ssh_pos[logpath] = f.tell()

            text = new_data.decode(errors="replace")
            now = time.time()

            for m in _SSH_FAIL_RE.finditer(text):
                ip = m.group(1)
                if not ip:
                    continue
                ssh_fail_tracker.setdefault(ip, [])
                ssh_fail_tracker[ip].append(now)
                # Nettoyer les anciens
                ssh_fail_tracker[ip] = [t for t in ssh_fail_tracker[ip] if now - t < BRUTE_WINDOW]
                if len(ssh_fail_tracker[ip]) >= BRUTE_THRESHOLD:
                    send_alert(server, key, name,
                               "BRUTEFORCE",
                               f"Bruteforce SSH détecté depuis {ip} "
                               f"({len(ssh_fail_tracker[ip])} tentatives en {BRUTE_WINDOW}s)",
                               severity="critical",
                               source_ip=ip)
                    ssh_fail_tracker[ip] = []  # reset pour éviter le spam

            for m in _SSH_ACCEPT_RE.finditer(text):
                ip = m.group(1)
                send_alert(server, key, name,
                           "SSH_LOGIN",
                           f"Connexion SSH réussie depuis {ip}",
                           severity="info",
                           source_ip=ip)

        except PermissionError:
            log.debug("Permission refusée: %s (relancer en sudo)", logpath)
        except Exception as e:
            log.debug("SSH log error %s: %s", logpath, e)

# ─── Main monitor loop ─────────────────────────────────────────────────────────

def monitor_loop(server: str, key: str, name: str, interval: int,
                 do_files: bool, do_proc: bool, do_ssh: bool):
    while running:
        if do_files:
            try:
                check_files(server, key, name)
            except Exception as e:
                log.warning("File check error: %s", e)
        if do_proc:
            try:
                check_processes(server, key, name)
            except Exception as e:
                log.warning("Process check error: %s", e)
        if do_ssh:
            try:
                check_ssh_logs(server, key, name)
            except Exception as e:
                log.warning("SSH check error: %s", e)
        time.sleep(interval)

# ─── Graceful shutdown ─────────────────────────────────────────────────────────

def shutdown(signum, frame):
    global running
    log.info("Arrêt de l'agent Aegis…")
    running = False


signal.signal(signal.SIGINT,  shutdown)
signal.signal(signal.SIGTERM, shutdown)

# ─── Entry point ───────────────────────────────────────────────────────────────

def main():
    global file_hashes

    parser = argparse.ArgumentParser(
        description="Aegis-Web-IDS Agent v" + VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--key",      required=True, help="Clé d'agent (générée par le dashboard)")
    parser.add_argument("--server",   required=True, help="URL du serveur Aegis (ex: http://192.168.1.100:5000)")
    parser.add_argument("--name",     required=True, help="Nom de la machine")
    parser.add_argument("--interval", type=int, default=MONITOR_INTERVAL, help="Intervalle de scan en secondes (défaut: 30)")
    parser.add_argument("--no-proc",  action="store_true", help="Désactiver la surveillance des processus")
    parser.add_argument("--no-files", action="store_true", help="Désactiver la surveillance des fichiers")
    parser.add_argument("--no-ssh",   action="store_true", help="Désactiver la détection bruteforce SSH")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════════════╗
║          AEGIS-WEB-IDS AGENT  v{VERSION}              ║
║                 URUS Security Framework              ║
╠══════════════════════════════════════════════════════╣
║  Machine  : {args.name:<41}║
║  Serveur  : {args.server:<41}║
║  Clé      : {args.key[:20]+'…':<41}║
╚══════════════════════════════════════════════════════╝
""")

    # Registration
    register(args.server, args.key, args.name)

    # Build file baseline
    if not args.no_files:
        log.info("Construction du baseline fichiers (peut prendre quelques secondes)…")
        file_hashes = build_baseline(WATCHED_DIRS)

    # Threads
    threads = []

    hb = threading.Thread(
        target=heartbeat_loop,
        args=(args.server, args.key, args.name, HEARTBEAT_INTERVAL),
        daemon=True,
        name="heartbeat",
    )
    threads.append(hb)
    hb.start()

    mon = threading.Thread(
        target=monitor_loop,
        args=(args.server, args.key, args.name, args.interval,
              not args.no_files, not args.no_proc, not args.no_ssh),
        daemon=True,
        name="monitor",
    )
    threads.append(mon)
    mon.start()

    log.info("Agent démarré. Surveillance en cours… (Ctrl+C pour arrêter)")

    while running:
        time.sleep(1)

    log.info("Agent arrêté proprement.")


if __name__ == "__main__":
    main()
