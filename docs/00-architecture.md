# 00 — Architecture du Lab SOC

## Vue d'ensemble

Ce lab reproduit un environnement d'entreprise simplifié avec un Active Directory,
des endpoints Windows et Linux, une machine attaquante et un SIEM/EDR Wazuh.
L'objectif est de simuler des attaques réelles et de valider leur détection.

---

## Schéma réseau

```
┌─────────────────────────────────────────────────────────────────┐
│                  VMware Workstation — Host                       │
│              Ryzen 5 7700X — 32 Go RAM                          │
│                                                                  │
│         VMnet2 — NAT Network — 192.168.100.0/24                 │
│                        │                                         │
│          ┌─────────────┴──────────────┐                         │
│          │         vSwitch NAT        │                         │
│          └──┬──────┬───────┬──────┬──┘                         │
│             │      │       │      │                              │
│    ┌────────▼─┐ ┌──▼─────┐ │  ┌──▼──────────────────┐         │
│    │   DC01   │ │win10   │ │  │    wazuh-server       │         │
│    │          │ │-client │ │  │                        │         │
│    │WinSrv2022│ │Win10Pro│ │  │  Wazuh Manager         │         │
│    │AD DS·DNS │ │        │ │  │  Wazuh Indexer         │         │
│    │.100.10   │ │.100.20 │ │  │  Wazuh Dashboard       │         │
│    │          │ │        │ │  │  .100.50               │         │
│    │[WazuhAgt]│ │[WazuhAgt] │  └────────────────────┘         │
│    └──────────┘ └────────┘ │                                    │
│                             │                                    │
│                    ┌────────▼──────┐                            │
│                    │ubuntu-endpoint│                            │
│                    │Ubuntu 22.04   │                            │
│                    │.100.30        │                            │
│                    │[Wazuh Agent]  │                            │
│                    └───────────────┘                            │
│                                                                  │
│    ┌──────────┐                                                  │
│    │  kali    │  ─ ─ ─ ─ ─ ─ ─ ─ ► Attaques simulées          │
│    │Kali Linux│                                                  │
│    │.100.40   │                                                  │
│    └──────────┘                                                  │
└─────────────────────────────────────────────────────────────────┘

        ──────►  Trafic réseau normal
        - - - ►  Attaques simulées (Mimikatz, PTH, Nmap...)
        [Wazuh Agent] = Agent Wazuh installé sur l'endpoint
```

---

## Inventaire des machines

| VM | Hostname | OS | IP | Rôle | RAM | CPU |
|---|---|---|---|---|---|---|
| 1 | `DC01` | Windows Server 2022 Std Eval | 192.168.100.10 | Active Directory · DNS | 4 Go | 2 |
| 2 | `win10-client` | Windows 10 Pro 22H2 | 192.168.100.20 | Endpoint cible | 2 Go | 2 |
| 3 | `ubuntu-endpoint` | Ubuntu 22.04 LTS Server | 192.168.100.30 | Endpoint cible | 2 Go | 1 |
| 4 | `kali` | Kali Linux Rolling | 192.168.100.40 | Machine attaquante | 2 Go | 2 |
| 5 | `wazuh-server` | Ubuntu 22.04 LTS Server | 192.168.100.50 | SIEM · EDR · Dashboard | 6 Go | 4 |

**Total** : 16 Go RAM · ~11 vCPUs · ~250 Go stockage

---

## Stack technique

| Composant | Technologie | Version | Rôle |
|---|---|---|---|
| Hyperviseur | VMware Workstation Pro | 17+ | Virtualisation des VMs |
| Réseau virtuel | VMware VMnet2 NAT | — | Isolation réseau du lab |
| SIEM / EDR | Wazuh Manager | 4.x | Collecte et corrélation des logs |
| Moteur de recherche | Wazuh Indexer (OpenSearch) | 4.x | Stockage et indexation des alertes |
| Interface | Wazuh Dashboard | 4.x | Visualisation des alertes |
| Agents | Wazuh Agent | 4.x | Collecte locale sur les endpoints |
| Enrichissement logs | Sysmon (SwiftOnSecurity) | Latest | Télémétrie avancée Windows |
| Active Directory | Windows Server 2022 AD DS | — | Annuaire, authentification, GPO |
| Framework détection | MITRE ATT&CK | v14 | Mapping des techniques d'attaque |
| Attaques simulées | Mimikatz · Impacket · Nmap · Hydra | Latest | Simulation d'adversaires |

---

## Flux de données

```
Endpoints (DC01, win10-client, ubuntu-endpoint)
        │
        │  Wazuh Agent — port 1514 (UDP/TCP)
        ▼
Wazuh Manager (192.168.100.50)
        │
        │  API interne
        ▼
Wazuh Indexer — port 9200 (OpenSearch)
        │
        │
        ▼
Wazuh Dashboard — port 443 (HTTPS)
        │
        │  Navigateur
        ▼
SOC Analyst (machine hôte)
```

---

## Choix techniques justifiés

### Pourquoi Wazuh ?
Wazuh est un SIEM/EDR open source activement maintenu, utilisé en production
dans de nombreuses entreprises. Il couvre la collecte de logs, la détection
d'intrusion (HIDS), la gestion des vulnérabilités et la réponse active —
tout ce qu'un SOC analyst manipule au quotidien. Sa compatibilité native avec
MITRE ATT&CK et ses règles de détection en XML le rendent idéal pour un lab
portfolio.

### Pourquoi Active Directory ?
AD est présent dans plus de 90% des entreprises. La grande majorité des
attaques ciblées (ransomware, APT) passent par une compromission de l'AD.
Maîtriser sa configuration et la détection d'attaques AD (Pass-the-Hash,
Kerberoasting, DCSync) est une compétence fondamentale pour un SOC analyst.

### Pourquoi VMware ?
VMware Workstation offre des performances supérieures à VirtualBox pour les
labs multi-VMs, avec un meilleur support des réseaux virtuels isolés. Le mode
NAT de VMnet2 permet un accès internet aux VMs tout en les isolant du réseau
physique — indispensable pour des simulations d'attaques sécurisées.

### Pourquoi Ubuntu 22.04 pour Wazuh ?
Wazuh supporte officiellement Ubuntu 22.04 LTS et c'est la distribution
recommandée dans leur documentation. La version LTS garantit la stabilité
sur la durée du projet.

---

## Périmètre de sécurité

> ⚠️ Ce lab est **entièrement isolé** sur un réseau VMware NAT.
> Les attaques simulées (Mimikatz, Pass-the-Hash, etc.) ne sortent
> jamais du réseau virtuel 192.168.100.0/24 et n'affectent pas
> le réseau physique ou internet.

---

## Documentation associée

| Fichier | Contenu |
|---|---|
| [01-lab-setup.md](01-lab-setup.md) | Installation VMware, VMs, réseau |
| [02-active-directory.md](02-active-directory.md) | AD DS, OUs, GPO, utilisateurs |
| [03-wazuh-install.md](03-wazuh-install.md) | Wazuh Manager + Indexer + Dashboard |
| [04-agents.md](04-agents.md) | Déploiement agents Windows & Linux |
| [05-detection-rules.md](05-detection-rules.md) | Règles custom Wazuh (XML) |
| [06-attack-simulations.md](06-attack-simulations.md) | Mimikatz, PTH, Nmap, Brute force |
| [07-incident-report.md](07-incident-report.md) | Rapport d'investigation complet |
