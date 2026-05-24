#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  Aegis-Web-IDS v3.0 — Script d'installation de l'agent (Ubuntu/Debian)
#  Usage : sudo bash install-agent.sh --key <CLE> --server <URL> [--name <NOM>]
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

REPO_RAW="https://raw.githubusercontent.com/Maxime288/Aegis-Web-IDS-v3.0/main"
AGENT_URL="${REPO_RAW}/aegis-agent.py"
INSTALL_DIR="/opt/aegis-agent"
SERVICE_FILE="/etc/systemd/system/aegis-agent.service"
PYTHON_BIN=""

# Couleurs
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[Aegis]${NC} $*"; }
ok()    { echo -e "${GREEN}[Aegis] ✔${NC} $*"; }
warn()  { echo -e "${YELLOW}[Aegis] ⚠${NC} $*"; }
error() { echo -e "${RED}[Aegis] ✘${NC} $*"; exit 1; }

# ─── Vérification root ──────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || error "Ce script doit être exécuté en tant que root (sudo)."

# ─── Arguments ──────────────────────────────────────────────────────────────
AGENT_KEY=""
AGENT_SERVER=""
AGENT_NAME=$(hostname)
AGENT_ID=""
AGENT_INTERVAL="10"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --key)      AGENT_KEY="$2";      shift 2;;
    --server)   AGENT_SERVER="$2";   shift 2;;
    --name)     AGENT_NAME="$2";     shift 2;;
    --id)       AGENT_ID="$2";       shift 2;;
    --interval) AGENT_INTERVAL="$2"; shift 2;;
    *) warn "Argument inconnu : $1"; shift;;
  esac
done

[[ -n "$AGENT_KEY"    ]] || error "Argument --key requis."
[[ -n "$AGENT_SERVER" ]] || error "Argument --server requis."

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║       Aegis-Web-IDS Agent Installer      ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""
info "Hôte     : $AGENT_NAME"
info "Serveur  : $AGENT_SERVER"
info "Clé      : ${AGENT_KEY:0:12}..."
echo ""

# ─── Python ─────────────────────────────────────────────────────────────────
info "Recherche de Python 3..."
for py in python3 python3.11 python3.10 python3.9; do
  if command -v "$py" &>/dev/null; then
    PYTHON_BIN="$py"
    ok "Python trouvé : $($py --version)"
    break
  fi
done

if [[ -z "$PYTHON_BIN" ]]; then
  info "Installation de Python 3..."
  apt-get update -qq
  apt-get install -y -qq python3 python3-urllib3
  PYTHON_BIN="python3"
fi

# ─── Dossier d'installation ─────────────────────────────────────────────────
info "Création du répertoire $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# ─── Téléchargement de l'agent ───────────────────────────────────────────────
info "Téléchargement de l'agent depuis GitHub..."
if command -v curl &>/dev/null; then
  curl -fsSL "$AGENT_URL" -o "$INSTALL_DIR/aegis-agent.py"
elif command -v wget &>/dev/null; then
  wget -q "$AGENT_URL" -O "$INSTALL_DIR/aegis-agent.py"
else
  error "curl ou wget est requis."
fi
chmod +x "$INSTALL_DIR/aegis-agent.py"
ok "Agent téléchargé dans $INSTALL_DIR/aegis-agent.py"

# ─── Fichier de configuration ────────────────────────────────────────────────
cat > "$INSTALL_DIR/aegis.conf" <<EOF
# Aegis-Web-IDS Agent Configuration
AGENT_KEY=$AGENT_KEY
AGENT_SERVER=$AGENT_SERVER
AGENT_NAME=$AGENT_NAME
AGENT_ID=$AGENT_ID
AGENT_INTERVAL=$AGENT_INTERVAL
EOF
chmod 600 "$INSTALL_DIR/aegis.conf"
ok "Configuration écrite dans $INSTALL_DIR/aegis.conf"

# ─── Service systemd ────────────────────────────────────────────────────────
info "Création du service systemd..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Aegis-Web-IDS Agent v3.0
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$PYTHON_BIN $INSTALL_DIR/aegis-agent.py \\
    --key $AGENT_KEY \\
    --server $AGENT_SERVER \\
    --name "$AGENT_NAME" \\
    --id "$AGENT_ID" \\
    --interval $AGENT_INTERVAL
Restart=on-failure
RestartSec=15s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aegis-agent

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable aegis-agent
systemctl start aegis-agent
ok "Service aegis-agent activé et démarré"

# ─── Vérification ───────────────────────────────────────────────────────────
sleep 3
STATUS=$(systemctl is-active aegis-agent || true)
if [[ "$STATUS" == "active" ]]; then
  ok "L'agent est ${GREEN}actif${NC} !"
else
  warn "Statut: $STATUS — vérifiez avec : journalctl -u aegis-agent -n 30"
fi

echo ""
echo -e "${GREEN}══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation terminée !${NC}"
echo -e "${GREEN}══════════════════════════════════════════════${NC}"
echo ""
echo "  Statut   : systemctl status aegis-agent"
echo "  Logs     : journalctl -u aegis-agent -f"
echo "  Arrêter  : systemctl stop aegis-agent"
echo "  Désinstaller : systemctl disable --now aegis-agent && rm -rf $INSTALL_DIR $SERVICE_FILE"
echo ""
