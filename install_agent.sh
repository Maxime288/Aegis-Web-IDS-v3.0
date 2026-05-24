#!/usr/bin/env bash
set -e

# Vérification des privilèges root
if [ "$EUID" -ne 0 ]; then
  echo "[-] Veuillez exécuter ce script en tant que root (sudo)."
  exit 1
fi

# Analyse des arguments
API_URL=""
API_KEY=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --api-url) API_URL="$2"; shift ;;
        --api-key) API_KEY="$2"; shift ;;
        *) echo "Option inconnue: $1"; exit 1 ;;
    esac
    shift
done

if [ -z "$API_URL" ] || [ -z "$API_KEY" ]; then
    echo "[-] Erreur : Les arguments --api-url et --api-key sont obligatoires."
    exit 1
fi

echo "[+] Installation des dépendances système (Python3, pip, psutil)..."
apt-get update -y
apt-get install -y python3 python3-pip python3-psutil python3-requests

# Création des répertoires de configuration
mkdir -p /etc/aegis /opt/aegis

# Génération du fichier de configuration de l'agent
echo "[+] Configuration des accès API..."
cat <<EOF > /etc/aegis/agent.conf
{
  "api_url": "$API_URL",
  "api_key": "$API_KEY"
}
EOF
chmod 600 /etc/aegis/agent.conf

# Téléchargement/Écriture du script de l'agent
echo "[+] Déploiement de l'exécutable de l'agent Aegis..."
# (Dans votre dépôt, ce code se placera dans aegis_agent.py)
cat << 'EOF' > /opt/aegis/aegis_agent.py
# (Coller ici l'intégralité du code Python présenté à l'étape 2)
EOF

chmod +x /opt/aegis/aegis_agent.py

# Création du service Systemd pour la persistance
echo "[+] Création et activation du service systemd 'aegis-agent'..."
cat <<EOF > /etc/systemd/system/aegis-agent.service
[Unit]
Description=Aegis Web-IDS Endpoint Monitoring Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/aegis/aegis_agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Rechargement et démarrage du service
systemctl daemon-reload
systemctl enable aegis-agent
systemctl restart aegis-agent

echo "[+] Installation réussie ! L'agent Aegis écoute et communique désormais avec votre serveur."
