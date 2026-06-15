# 04 — Déploiement des Agents Wazuh

## Objectif

L'agent Wazuh est responsable de la collecte locale des événements
(sécurité Windows, Sysmon, journaux Linux, intégrité fichiers, etc.)
et de leur transmission sécurisée vers le Wazuh Manager pour analyse.

Installer et enrôler l'agent Wazuh sur les 3 endpoints du lab (DC01, win10-client,
ubuntu-endpoint) afin qu'ils remontent leurs logs au Wazuh Manager.

---

## Architecture agents

```
DC01 (192.168.100.10)          ┐
  [Wazuh Agent]                │
                               ├──► Wazuh Manager (192.168.100.50:1514)
win10-client (192.168.100.20)  │         │
  [Wazuh Agent]                │         ▼
                               │    Wazuh Indexer → Dashboard
ubuntu-endpoint (192.168.100.30)┘
  [Wazuh Agent]
```

---

## 1. Agent sur DC01 (Windows Server 2022)

### Installation via le Dashboard

1. Navigateur → `https://192.168.100.50`
2. **Agents → Deploy new agent**
3. Paramètres :
   - OS : **Windows**
   - Server address : `192.168.100.50`
   - Agent name : `DC01`

> ![NewAgent-DC01](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-4/Config_newagent.PNG): Page "Deploy new agent" avec les paramètres DC01 remplis.

### Commande générée (PowerShell 64 bits Administrateur sur DC01)

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi `
  -OutFile $env:tmp\wazuh-agent.msi; `
  msiexec.exe /i $env:tmp\wazuh-agent.msi /q `
  WAZUH_MANAGER='192.168.100.50' `
  WAZUH_AGENT_NAME='DC01' `
  WAZUH_REGISTRATION_SERVER='192.168.100.50'
```

### Démarrage du service

```powershell
NET START WazuhSvc
```

Résultat attendu :
```
The Wazuh service was started successfully.
```

> ![lancement-wazuh](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-4/lancement_wazuh.PNG) : PowerShell sur DC01 montrant `The Wazuh service was started successfully`.

---

## 2. Agent sur win10-client (Windows 10 Pro)

### Installation via le Dashboard

1. **Agents → Deploy new agent**
2. Paramètres :
   - OS : **Windows**
   - Server address : `192.168.100.50`
   - Agent name : `win10-client`

### Commande générée (PowerShell 64 bits Administrateur sur win10-client)

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi `
  -OutFile $env:tmp\wazuh-agent.msi; `
  msiexec.exe /i $env:tmp\wazuh-agent.msi /q `
  WAZUH_MANAGER='192.168.100.50' `
  WAZUH_AGENT_NAME='win10-client' `
  WAZUH_REGISTRATION_SERVER='192.168.100.50'
```

### Démarrage du service

```powershell
NET START WazuhSvc
```

---

## 3. Agent sur ubuntu-endpoint (Ubuntu 22.04)

### Installation via le Dashboard

1. **Agents → Deploy new agent**
2. Paramètres :
   - OS : **DEB amd64**
   - Server address : `192.168.100.50`
   - Agent name : `ubuntu-endpoint`

> ![NewAgent-Ubuntu](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-4/deploy_ubuntu.PNG) : Page "Deploy new agent" avec les paramètres ubuntu-endpoint remplis.

### Commande générée (terminal sur ubuntu-endpoint)

```bash
# Ajout de la clé GPG Wazuh
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg \
  --import && chmod 644 /usr/share/keyrings/wazuh.gpg

# Ajout du dépôt
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
  https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list

# Installation
sudo apt update && sudo apt install wazuh-agent -y
```

### Configuration et démarrage

```bash
sudo sed -i 's/MANAGER_IP/192.168.100.50/' /var/ossec/etc/ossec.conf
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

### Vérification

```bash
sudo systemctl status wazuh-agent
```

Résultat attendu : **active (running)**

> ![Agent-Ubuntu](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-4/agent_ubuntu.PNG) : `systemctl status wazuh-agent` sur ubuntu-endpoint
> affichant **active (running)** en vert.

---

## 4. Vérification globale

### Côté Dashboard

Navigateur → `https://192.168.100.50` → **Agents**

Les 3 agents doivent apparaître avec le statut **Active** (point vert).

> ![Agents-dashboard](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-4/agents_dashboard.PNG) : Page Agents du Dashboard Wazuh montrant DC01,
> win10-client et ubuntu-endpoint avec le statut **Active** en vert.
> C'est le screenshot le plus important de cette étape.

### Côté serveur (wazuh-server)

```bash
sudo /var/ossec/bin/agent_control -l
```

Résultat attendu :

```
Wazuh agent_control. List of available agents:
   ID: 000, Name: wazuh-server (server), IP: 127.0.0.1, Active/Local
   ID: 001, Name: DC01, IP: 192.168.100.10, Active
   ID: 002, Name: win10-client, IP: 192.168.100.20, Active
   ID: 003, Name: ubuntu-endpoint, IP: 192.168.100.30, Active
```

> ![Agent-server-cli](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-4/agents_cli.PNG) : Output de `agent_control -l` sur wazuh-server
> listant les 3 agents avec le statut `Active`.

---

## 5. Vérification des logs entrants

Sur `wazuh-server`, confirme que les logs arrivent bien :

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

Tu dois voir des événements en temps réel provenant des 3 agents.

---

## Récapitulatif des agents enrôlés

| ID | Agent | IP | OS | Statut |
|---|---|---|---|---|
| 001 | DC01 | 192.168.100.10 | Windows Server 2022 | Active ✅ |
| 002 | win10-client | 192.168.100.20 | Windows 10 Pro | Active ✅ |
| 003 | ubuntu-endpoint | 192.168.100.30 | Ubuntu 22.04 | Active ✅ |

---

## Problèmes courants

| Problème | Cause probable | Fix |
|---|---|---|
| Agent en statut `Disconnected` | Pare-feu bloquant le port 1514 | Ouvrir le port 1514 sur wazuh-server : `sudo ufw allow 1514` |
| `NET START WazuhSvc` échoue | Installation MSI incomplète | Relancer la commande d'installation en PowerShell 64 bits admin |
| Agent n'apparaît pas dans le Dashboard | Délai de synchronisation | Attendre 2-3 minutes et rafraîchir |
| Erreur `sed` sur ubuntu-endpoint | `MANAGER_IP` déjà remplacé | Vérifier `/var/ossec/etc/ossec.conf` : `<address>192.168.100.50</address>` |
