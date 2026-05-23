#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════════
# Aegis-Web-IDS v3.0 — Script d'installation automatique de l'agent
# Usage: sudo bash install-aegis-agent.sh --key <CLE> --server <URL> --name <NOM>
# ════════════════════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="aegis-agent"
AGENT_BIN="$INSTALL_DIR/aegis-agent"
TARBALL="aegis-agent-linux-amd64.tar.gz"
GITHUB_RELEASE="https://github.com/Maxime288/Aegis-Web-IDS-v3.0/releases/latest/download/$TARBALL"

# ── Parse args ──────────────────────────────────────────────────────────────────
KEY="" SERVER="" NAME=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --key)    KEY="$2";    shift 2 ;;
    --server) SERVER="$2"; shift 2 ;;
    --name)   NAME="$2";   shift 2 ;;
    *) warn "Argument inconnu: $1"; shift ;;
  esac
done

[[ -z "$KEY"    ]] && err "Argument requis: --key <AGENT_KEY>"
[[ -z "$SERVER" ]] && err "Argument requis: --server <URL>"
[[ -z "$NAME"   ]] && err "Argument requis: --name <HOSTNAME>"

echo -e "${CYAN}"
cat << 'EOF'
    ╔═══════════════════════════════════════════════╗
    ║   AEGIS-WEB-IDS — Installation de l'agent    ║
    ║           URUS Security Framework             ║
    ╚═══════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# ── Root check ─────────────────────────────────────────────────────────────────
[[ "$(id -u)" -ne 0 ]] && err "Ce script doit être exécuté en tant que root (sudo)."

# ── Download ───────────────────────────────────────────────────────────────────
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

log "Téléchargement de l'agent depuis GitHub…"
if command -v wget &>/dev/null; then
    wget -q "$GITHUB_RELEASE" -O "$TMPDIR/$TARBALL" \
    || err "Échec du téléchargement. Vérifiez que la Release GitHub existe."
elif command -v curl &>/dev/null; then
    curl -sSL "$GITHUB_RELEASE" -o "$TMPDIR/$TARBALL" \
    || err "Échec du téléchargement."
else
    err "wget ou curl requis."
fi

# ── Extract & install ──────────────────────────────────────────────────────────
log "Extraction et installation…"
tar xzf "$TMPDIR/$TARBALL" -C "$TMPDIR/"
install -m 755 "$TMPDIR/aegis-agent" "$AGENT_BIN"
log "Binaire installé dans $AGENT_BIN"

# ── Systemd service ────────────────────────────────────────────────────────────
if command -v systemctl &>/dev/null; then
    log "Création du service systemd…"
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=Aegis IDS Agent v3.0
Documentation=https://github.com/Maxime288/Aegis-Web-IDS-v3.0
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$AGENT_BIN --key "$KEY" --server "$SERVER" --name "$NAME"
Restart=always
RestartSec=10
User=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aegis-agent

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$SERVICE_NAME"
    log "Service systemd activé et démarré."
    systemctl status "$SERVICE_NAME" --no-pager -l | head -20
else
    warn "systemd non disponible. Lancement manuel:"
    warn "  sudo $AGENT_BIN --key '$KEY' --server '$SERVER' --name '$NAME' &"
    # Fallback: run in background
    nohup "$AGENT_BIN" --key "$KEY" --server "$SERVER" --name "$NAME" \
        >> /var/log/aegis-agent.log 2>&1 &
    log "Agent démarré en arrière-plan (PID $!). Logs: /var/log/aegis-agent.log"
fi

echo ""
log "${GREEN}Installation terminée !${NC}"
log "L'agent apparaîtra dans le dashboard sous 30 secondes."
echo ""
echo -e "  Machine : ${CYAN}$NAME${NC}"
echo -e "  Serveur : ${CYAN}$SERVER${NC}"
echo -e "  Clé     : ${CYAN}${KEY:0:20}…${NC}"
