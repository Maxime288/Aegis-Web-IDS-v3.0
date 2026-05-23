# Aegis-Web-IDS v3.0 — Agent Linux

Agent de surveillance pour le dashboard **Aegis-Web-IDS**.  
Il surveille les fichiers système, les processus suspects et les tentatives de bruteforce SSH.

---

## 📦 Fichiers fournis

| Fichier | Description |
|---|---|
| `aegis-agent` | Binaire Linux x86-64 (standalone, aucune dépendance) |
| `aegis-agent-linux-amd64.tar.gz` | Archive à publier comme Release GitHub |
| `aegis-agent.py` | Code source Python |
| `install-aegis-agent.sh` | Script d'installation automatique (systemd) |

---

## 🚀 Mise en ligne sur GitHub (OBLIGATOIRE pour que le dashboard fonctionne)

Le dashboard pointe vers :
```
https://github.com/Maxime288/Aegis-Web-IDS-v3.0/releases/latest/download/aegis-agent-linux-amd64.tar.gz
```

### Étapes :

1. Aller sur https://github.com/Maxime288/Aegis-Web-IDS-v3.0/releases/new
2. **Tag** : `v3.0.0`
3. **Titre** : `Aegis Agent v3.0.0`
4. Glisser-déposer le fichier `aegis-agent-linux-amd64.tar.gz` dans les assets
5. Cliquer **Publish release**

Après ça, le `wget` du dashboard fonctionnera automatiquement.

---

## 🔧 Installation manuelle sur une machine Ubuntu/Debian

```bash
# Depuis le dashboard, copier la commande générée ou :
wget https://github.com/Maxime288/Aegis-Web-IDS-v3.0/releases/latest/download/aegis-agent-linux-amd64.tar.gz
tar xzf aegis-agent-linux-amd64.tar.gz
sudo ./aegis-agent --key aegis_VOTRE_CLE --server http://192.168.1.117:5000 --name "ubuntu"
```

## 🔧 Installation automatique (recommandé)

```bash
curl -sSL https://github.com/Maxime288/Aegis-Web-IDS-v3.0/releases/latest/download/install-aegis-agent.sh \
  | sudo bash -s -- --key aegis_VOTRE_CLE --server http://192.168.1.117:5000 --name "ubuntu"
```

---

## 🛡️ Ce que l'agent surveille

- **Intégrité des fichiers** : `/etc`, `/bin`, `/usr/bin`, `/sbin`, `/usr/sbin`
  - Fichiers modifiés → alerte `FILE_MODIFIED` (critical)
  - Nouveaux fichiers → alerte `FILE_ADDED` (warning)
  - Fichiers supprimés → alerte `FILE_DELETED` (warning)

- **Processus suspects** : nmap, netcat, hydra, sqlmap, msfconsole, reverse shells, etc.
  → alerte `SUSPICIOUS_PROC` (critical)

- **Bruteforce SSH** : 5+ tentatives en 60s depuis la même IP
  → alerte `BRUTEFORCE` (critical)

- **Connexions SSH réussies** → alerte `SSH_LOGIN` (info)

---

## 📡 Communication avec le serveur

| Endpoint | Méthode | Usage |
|---|---|---|
| `/api/agents/enroll` | POST | Enregistrement initial |
| `/api/agents/heartbeat` | POST | Ping toutes les 60s |
| `/api/logs` | POST | Envoi des alertes |

Headers envoyés : `X-Agent-Key: <key>` + `Authorization: Bearer <key>`

---

## ⚙️ Options

```
--key       Clé d'agent (générée par le dashboard)    [requis]
--server    URL du serveur Aegis                       [requis]
--name      Nom affiché dans le dashboard              [requis]
--interval  Intervalle de scan en secondes (défaut: 30)
--no-proc   Désactiver la surveillance des processus
--no-files  Désactiver la surveillance des fichiers
--no-ssh    Désactiver la détection bruteforce SSH
```

---

## 🔄 Compatibilité

- **OS** : Linux x86-64 (Ubuntu 20.04+, Debian 11+, RHEL 8+)
- **Privilèges** : `sudo` recommandé (pour lire `/var/log/auth.log`)
- **Dépendances** : aucune (binaire standalone)
