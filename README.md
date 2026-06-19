# SOC-HomeLab
 SOC Home Lab — Wazuh SIEM/EDR, Active Directory, simulation d'attaques MITRE ATT&amp;CK
# 🛡️ SOC Home Lab — Wazuh SIEM/EDR + Active Directory

![Status](https://img.shields.io/badge/status-completed-green)
![Wazuh](https://img.shields.io/badge/Wazuh-4.7.5-blue)
![Windows Server](https://img.shields.io/badge/Windows_Server-2022-0078D4)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-mapped-red)
![License](https://img.shields.io/badge/license-MIT-green)

> Environnement SOC complet déployé sous VMware pour simuler, détecter et investiguer des attaques réelles 
> Mimikatz, Pass-the-Hash, mouvement latéral avec **Wazuh** comme SIEM/EDR et **Active Directory** comme cible.

---

## 🎯 Objectifs du projet

Ce lab a pour but de reproduire les conditions réelles d'un environnement SOC :

- Déployer et administrer un **Active Directory** (Windows Server 2022) avec utilisateurs, OUs et GPOs d'audit
- Installer et configurer une stack **Wazuh** complète (Manager + Indexer + Dashboard)
- Déployer des **agents Wazuh** sur endpoints Windows et Linux
- Écrire des **règles de détection custom** mappées au framework MITRE ATT&CK
- Simuler des **attaques réelles** depuis Kali Linux et analyser les alertes générées
- Produire un **rapport d'investigation d'incident** complet

---

## 🗺️ Architecture du lab

```
192.168.100.0/24 — VMware NAT Network
│
├── 192.168.100.10   DC01              Windows Server 2022   AD DS · DNS
├── 192.168.100.20   win10-client      Windows 10 Pro        Endpoint + Wazuh Agent
├── 192.168.100.30   ubuntu-endpoint   Ubuntu 22.04          Endpoint + Wazuh Agent
├── 192.168.100.40   kali              Kali Linux            Attacker machine
└── 192.168.100.50   wazuh-server      Ubuntu 22.04          Wazuh Manager + Indexer + Dashboard
```
---

## 🧰 Stack technique

| Composant | Technologie | Version |
|---|---|---|
| SIEM / EDR | Wazuh | 4.x |
| Active Directory | Windows Server | 2022 |
| Endpoint Windows | Windows 10 Pro | 22H2 |
| Endpoint Linux | Ubuntu | 22.04 LTS |
| Attacker | Kali Linux | Rolling |
| Hyperviseur | VMware Workstation Pro | 17+ |
| Log enrichment | Sysmon (SwiftOnSecurity config) | Latest |
| Framework | MITRE ATT&CK | v14 |

---

## 📁 Structure du repo

```
SOC-HomeLab/
├── README.md
├── docs/
│   ├── 00-architecture.md        # Schéma réseau, choix techniques
│   ├── 01-lab-setup.md           # Installation VMware, VMs, réseau
│   ├── 02-active-directory.md    # AD DS, OUs, GPO d'audit, utilisateurs
│   ├── 03-wazuh-install.md       # Wazuh Manager + Indexer + Dashboard
│   ├── 04-agents.md              # Déploiement agents Windows & Linux
│   ├── 05-detection-rules.md     # Règles custom Wazuh (XML)
│   ├── 06-attack-simulations.md  # Mimikatz, PTH, Nmap, Brute force
│   └── 07-incident-report.md     # Rapport d'investigation complet
├── rules/
│   ├── local_rules.xml           # Règles de détéction 
├── screenshots/                  # Captures d'écran des alertes Wazuh
└── scripts/

```

---

## ⚔️ Attaques simulées

| Attaque | Outil | MITRE ATT&CK | Règle Wazuh |
---

## 🔍 Règles de détection custom (extrait)

---

## 📊 Progression

- [✔] Étape 1 — Repo & structure du projet
- [✔] Étape 2 — Configuration réseau VMware & création des VMs
- [✔] Étape 3 — Active Directory (AD DS, GPO, utilisateurs)
- [✔] Étape 4 — Installation Wazuh Server
- [✔] Étape 5 — Déploiement des agents sur les endpoints
- [✔] Étape 6 — Règles de détection custom
- [✔] Étape 7 — Simulations d'attaques
- [✔] Étape 8 — Rapport d'investigation d'incident

---

## 📄 Rapport d'incident

---

## 📚 Ressources

- [Wazuh Documentation](https://documentation.wazuh.com)
- [MITRE ATT&CK](https://attack.mitre.org)
- [Sysmon Config (SwiftOnSecurity)](https://github.com/SwiftOnSecurity/sysmon-config)
- [Impacket](https://github.com/fortra/impacket)

---

## 📝 License

MIT — libre d'utilisation et d'adaptation.
