# 03 — Wazuh : Installation & Configuration

## Objectif
Déployer la stack Wazuh complète (Manager + Indexer + Dashboard) sur `wazuh-server`
en utilisant le script d'installation automatique officiel.

---

## Environnement

| Paramètre | Valeur |
|---|---|
| Serveur | wazuh-server — 192.168.100.50 |
| OS | Ubuntu 22.04 LTS Server |
| RAM allouée | 6 Go |
| CPU alloués | 4 cœurs |
| Disque | 80 Go |

---

## Architecture Wazuh

```
┌─────────────────────────────────────────────┐
│              wazuh-server (192.168.100.50)   │
│                                              │
│  ┌──────────────┐     ┌──────────────────┐  │
│  │Wazuh Manager │────►│  Wazuh Indexer   │  │
│  │  port 1514   │     │ (OpenSearch)     │  │
│  │  port 1515   │     │   port 9200      │  │
│  └──────────────┘     └────────┬─────────┘  │
│                                │             │
│                       ┌────────▼─────────┐  │
│                       │ Wazuh Dashboard  │  │
│                       │   port 443       │  │
│                       └──────────────────┘  │
└─────────────────────────────────────────────┘
```

| Composant | Rôle | Port |
|---|---|---|
| Wazuh Manager | Reçoit les logs des agents, applique les règles de détection | 1514 (agents) · 1515 (enrôlement) |
| Wazuh Indexer | Stocke et indexe les alertes (basé sur OpenSearch) | 9200 |
| Wazuh Dashboard | Interface web de visualisation et d'investigation | 443 (HTTPS) |

---

## 1. Mise à jour du système

```bash
sudo apt update && sudo apt upgrade -y
```

---

## 2. Installation automatique (one-liner officiel)

Wazuh fournit un script qui installe et configure les 3 composants automatiquement :

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash wazuh-install.sh -a
```

> ⏱️ **Durée estimée** : 10 à 20 minutes selon les performances de la VM.
> Ne pas interrompre le script.

### Output attendu en fin d'installation

```
INFO: --- Summary ---
INFO: You can access the web interface https://192.168.100.50
    User: admin
    Password: xxxxxxxxxxxxxxxx
```

> ⚠️ **Noter immédiatement le mot de passe généré** — il ne sera pas affiché à nouveau.
> Pour le retrouver si perdu :
> ```bash
> sudo tar -O -xvf wazuh-install-files.tar ./wazuh-passwords.txt
> ```

---

## 3. Vérification des services

```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

Les trois doivent afficher **active (running)**.

> ![systemctl](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/wazuh_services.PNG) : Output de `systemctl status wazuh-manager`
> montrant `active (running)` en vert.

Pour activer le démarrage automatique au boot :

```bash
sudo systemctl enable wazuh-manager wazuh-indexer wazuh-dashboard
```

---

## 4. Accès au Dashboard

Depuis le navigateur de la **machine hôte** :

```
https://192.168.100.50
```

> Accepter l'avertissement de certificat SSL (normal en environnement lab) :
> Chrome → "Paramètres avancés" → "Continuer vers 192.168.100.50"

### Credentials de connexion

| Champ | Valeur |
|---|---|
| Utilisateur | `admin` |
| Mot de passe | *(généré à l'installation — étape 2)* |

> ![WazuhLogin](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/WazuhLogin.PNG) : Page de login Wazuh Dashboard dans le navigateur
> (`https://192.168.100.50`).

> ![WazuhDashboard](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/Wazuh_dashboard.PNG) : Dashboard Wazuh après connexion, montrant
> 0 agents actifs (état initial avant déploiement des agents).

---

## 5. Vérification de l'API Wazuh

```bash
curl -k -u admin:<TON_MOT_DE_PASSE> https://localhost:55000/
```

Réponse attendue :

```json
{
  "data": {
    "title": "Wazuh App REST API",
    "api_version": "4.x.x"
  }
}
```

---

## 6. Ports ouverts (référence)

```bash
sudo ss -tlnp | grep -E '443|1514|1515|9200|55000'
```

| Port | Service | Description |
|---|---|---|
| 443 | Wazuh Dashboard | Interface web HTTPS |
| 1514 | Wazuh Manager | Réception logs agents |
| 1515 | Wazuh Manager | Enrôlement des agents |
| 9200 | Wazuh Indexer | API OpenSearch |
| 55000 | Wazuh Manager | API REST Wazuh |

> ![ListeningPorts](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/Listening_ports.PNG) : Output de la commande `ss -tlnp` montrant
> les ports 443, 1514, 1515, 9200 et 55000 en écoute.

---

## 7. Structure des fichiers Wazuh (référence)

```
/var/ossec/                    ← Répertoire principal Wazuh
├── etc/
│   ├── ossec.conf             ← Configuration principale du Manager
│   └── rules/                 ← Règles de détection custom (notre dossier)
├── logs/
│   ├── alerts/alerts.log      ← Alertes générées
│   └── ossec.log              ← Logs du Manager
└── ruleset/
    └── rules/                 ← Règles Wazuh par défaut (ne pas modifier)
```

> Les règles custom se placent dans `/var/ossec/etc/rules/` — on y reviendra
> à l'étape 5 (règles de détection).

---

## Problèmes courants

| Problème | Cause probable | Fix |
|---|---|---|
| Dashboard inaccessible | Service non démarré | `sudo systemctl start wazuh-dashboard` |
| Certificat SSL rejeté | Certificat auto-signé | Accepter l'exception dans le navigateur |
| Mot de passe perdu | Non noté à l'install | `sudo tar -O -xvf wazuh-install-files.tar ./wazuh-passwords.txt` |
| Port 9200 inaccessible | Indexer pas encore démarré | Attendre 2-3 min après l'install |
