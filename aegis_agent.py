#!/usr/bin/env python3
import os
import sys
import time
import json
import socket
import uuid
import psutil
import requests
import threading

# Configuration chargée via /etc/aegis/agent.conf
CONFIG_PATH = "/etc/aegis/agent.conf"
AGENT_ID_PATH = "/etc/aegis/agent.id"

def load_config():
    if not os.path.exists(CONFIG_PATH):
        print(f"[-] Fichier de configuration manquant: {CONFIG_PATH}")
        sys.exit(1)
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

def get_agent_id():
    if os.path.exists(AGENT_ID_PATH):
        with open(AGENT_ID_PATH, "r") as f:
            return f.read().strip()
    else:
        new_id = str(uuid.uuid4())[:8] # Génère un identifiant court
        os.makedirs(os.path.dirname(AGENT_ID_PATH), exist_ok=True)
        with open(AGENT_ID_PATH, "w") as f:
            f.write(new_id)
        return new_id

def get_system_stats():
    """Récupère l'utilisation CPU, RAM, OS et IP locale pour correspondre au dashboard."""
    try:
        # Récupération de l'IP locale principale
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except Exception:
        ip_address = "127.0.0.1"

    return {
        "cpu": psutil.cpu_percent(interval=None),
        "ram": psutil.virtual_memory().percent,
        "ip": ip_address,
        "os": "Ubuntu " + os.popen("lsb_release -rs").read().strip()
    }

def send_heartbeat(api_url, headers, agent_id, hostname):
    """Envoie un intervalle de statut régulier (Heartbeat/Keepalive)"""
    while True:
        stats = get_system_stats()
        payload = {
            "agent_id": agent_id,
            "hostname": hostname,
            "ip": stats["ip"],
            "os": stats["os"],
            "cpu_usage": stats["cpu"],
            "ram_usage": stats["ram"],
            "status": "online",
            "last_seen": int(time.time() * 1000)
        }
        try:
            # Endpoint POST vers l'API de gestion des agents Aegis
            response = requests.post(f"{api_url}/api/agents/heartbeat", json=payload, headers=headers, timeout=5)
            if response.status_code != 200:
                print(f"[-] Échec Heartbeat: code {response.status_code}")
        except Exception as e:
            print(f"[-] Erreur de connexion avec l'API Aegis: {e}")
        
        time.sleep(10) # Intervalle ajustable (Wazuh utilise généralement entre 10s et 60s)

def monitor_auth_logs(api_url, headers, agent_id, hostname):
    """Analyse en continu /var/log/auth.log pour détecter les attaques par force brute (style Wazuh OSSEC)"""
    LOG_FILE = "/var/log/auth.log"
    if not os.path.exists(LOG_FILE):
        return

    print("[+] Lancement du module d'analyse des logs d'authentification...")
    with open(LOG_FILE, "r") as f:
        # Se positionne à la fin actuelle du fichier pour ne lire que les nouveaux événements
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            
            # Détection simple de tentatives de connexions SSH infructueuses
            if "Failed password" in line or "Invalid user" in line:
                severity = "high" if "root" in line else "medium"
                alert_payload = {
                    "agent_id": agent_id,
                    "hostname": hostname,
                    "type": "Brute Force SSH",
                    "message": line.strip(),
                    "severity": severity,
                    "timestamp": int(time.time() * 1000)
                }
                try:
                    requests.post(f"{api_url}/api/alerts", json=alert_payload, headers=headers, timeout=5)
                except Exception:
                    pass

def main():
    config = load_config()
    api_url = config["api_url"].rstrip('/')
    api_key = config["api_key"]
    
    agent_id = get_agent_id()
    hostname = socket.gethostname()
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    
    print(f"[+] Agent Aegis Initialisé [ID: {agent_id} | Hôte: {hostname}]")
    
    # Thread 1: Heartbeat d'état système
    t_heartbeat = threading.Thread(target=send_heartbeat, args=(api_url, headers, agent_id, hostname), daemon=True)
    t_heartbeat.start()
    
    # Thread 2: Analyseur de Logs SSH (Analyse comportementale de sécurité)
    t_logs = threading.Thread(target=monitor_auth_logs, args=(api_url, headers, agent_id, hostname), daemon=True)
    t_logs.start()
    
    # Main loop pour garder le service en vie
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[+] Arrêt de l'agent.")

if __name__ == "__main__":
    main()
