# SOC Home Lab — Wazuh / Sysmon / Active Directory

![Status](https://img.shields.io/badge/status-completed-green)
![Wazuh](https://img.shields.io/badge/Wazuh-4.7.5-blue)
![Windows Server](https://img.shields.io/badge/Windows_Server-2022-0078D4)
![Sysmon](https://img.shields.io/badge/Sysmon-enabled-5C2D91)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-mapped-red)

Laboratoire SOC complet déployé sous **VMware** afin de simuler, détecter et investiguer des attaques sur un environnement **Active Directory**.

Le projet combine :

- **Wazuh** comme SIEM / EDR ;
- **Sysmon** pour enrichir la télémétrie Windows ;
- **Active Directory** comme environnement cible ;
- **Kali Linux** pour simuler des attaques ;
- des **règles de détection personnalisées** ;
- le mapping **MITRE ATT&CK** ;
- un **rapport d'investigation d'incident** complet.

---

## Objectif

L'objectif du laboratoire est de reproduire un workflow SOC réaliste :

```text
Infrastructure
    ↓
Collecte de logs
    ↓
Détection
    ↓
Simulation d'attaques
    ↓
Alertes
    ↓
Corrélation
    ↓
Investigation
    ↓
Réponse à incident
```

Le lab permet notamment de pratiquer :

- l'administration d'un environnement Active Directory ;
- la collecte et l'analyse des logs Windows/Linux ;
- la configuration de Sysmon ;
- le développement de règles Wazuh ;
- la détection comportementale ;
- le tuning et la réduction des faux positifs ;
- la simulation de techniques offensives ;
- la corrélation d'alertes ;
- l'investigation et la rédaction d'un rapport d'incident.

---

## Architecture

```text
192.168.100.0/24 — VMware NAT Network

┌──────────────────────┐
│ Kali Linux           │
│ 192.168.100.40       │
│ Attacker             │
└──────────┬───────────┘
           │
           │ Attack simulations
           ▼
┌──────────────────────┐
│ DC01                 │
│ Windows Server 2022  │
│ AD DS / DNS          │
│ 192.168.100.10       │
└──────────┬───────────┘
           │
           │ Windows Events / Sysmon
           ▼
┌──────────────────────┐
│ win10-client         │
│ Windows 10           │
│ 192.168.100.20       │
└──────────┬───────────┘
           │
           │ Wazuh Agent
           ▼
┌──────────────────────┐
│ wazuh-server         │
│ Ubuntu 22.04         │
│ Manager / Indexer    │
│ Dashboard            │
│ 192.168.100.50       │
└──────────────────────┘

┌──────────────────────┐
│ ubuntu-endpoint      │
│ Ubuntu 22.04         │
│ 192.168.100.30       │
│ Wazuh Agent          │
└──────────────────────┘
```

---

## Stack technique

| Composant | Technologie |
|---|---|
| SIEM / EDR | Wazuh |
| Active Directory | Windows Server 2022 |
| Endpoint Windows | Windows 10 |
| Endpoint Linux | Ubuntu 22.04 |
| Attacker | Kali Linux |
| Télémétrie Windows | Sysmon |
| Hyperviseur | VMware Workstation Pro |
| Framework | MITRE ATT&CK |
| Scripting / administration | PowerShell, Bash |

---

## Collecte de télémétrie

Les endpoints Windows utilisent **Sysmon** afin d'enrichir les événements disponibles pour la détection.

Événements utilisés notamment :

| Event ID | Description |
|---|---|
| Sysmon 1 | Process Creation |
| Sysmon 3 | Network Connection |
| Sysmon 10 | Process Access |
| Sysmon 11 | File Creation |
| Sysmon 13 | Registry Modification |
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4720 | User Account Created |

Les événements Sysmon sont collectés dans Wazuh via une configuration partagée appliquée aux agents Windows.

---

# Règles de détection personnalisées

Le laboratoire contient **9 règles Wazuh custom** destinées à détecter plusieurs techniques offensives.

| Rule ID | Détection | MITRE ATT&CK | Niveau |
|---|---|---|---|
| 100001 | Mimikatz par nom de processus | T1003.001 | 15 |
| 100003 | Accès mémoire à LSASS | T1003.001 | 15 |
| 100010 | Authentification NTLM réseau suspecte | T1550.002 | 12 |
| 100030 | Brute force RDP | T1110.001 | 12 |
| 100050 | Création de compte utilisateur | T1136.001 | 12 |
| 100060 | PowerShell encodé | T1059.001 | 12 |
| 100091 | Création de compte via CLI | T1136.001 | 12 |
| 100092 | Suppression des shadow copies | T1490 | 15 |
| 100094 | Exécution depuis un dossier suspect | T1059 | 10 |

Les règles sont disponibles dans :

```text
rules/local_rules.xml
```

---

## Détection en profondeur

Certaines techniques sont détectées avec plusieurs signaux complémentaires.

### Credential Dumping

```text
Mimikatz
    ↓
Rule 100001
Process name detection
```

et :

```text
LSASS memory access
    ↓
Sysmon Event ID 10
    ↓
Rule 100003
Behavioral detection
```

Cette approche permet de combiner :

```text
signature-based detection
+
behavior-based detection
```

La détection comportementale reste pertinente même si l'outil offensif est renommé.

---

## Gestion des faux positifs

Le développement des règles inclut également une phase de tuning.

Exemple :

```text
Rule 100003
LSASS memory access
```

Certains processus Windows légitimes peuvent accéder à `lsass.exe`.

Une liste d'exclusion est donc utilisée pour réduire les faux positifs sur des processus tels que :

```text
svchost.exe
winlogon.exe
lsass.exe
services.exe
MsMpEng.exe
WmiPrvSE.exe
```

La règle liée aux authentifications NTLM est également traitée comme un **signal nécessitant une corrélation**, et non comme une preuve suffisante de Pass-the-Hash à elle seule.

---

# Kill Chain simulée

Le laboratoire simule une séquence d'attaque complète :

```text
Brute Force RDP
        ↓
Credential Dumping
        ↓
Pass-the-Hash
        ↓
Persistence
        ↓
PowerShell Obfuscation
        ↓
Inhibit System Recovery
        ↓
Linux compromise
```

---

## 1. Brute Force RDP

**Technique MITRE :**

```text
T1110.001 — Password Guessing
```

Simulation réalisée depuis Kali contre `win10-client`.

Détection :

```text
5 échecs d'authentification
dans une fenêtre de 60 secondes
        ↓
Rule 100030
```

Source principale :

```text
Windows Event ID 4625
```

---

## 2. Credential Dumping — Mimikatz

**Technique MITRE :**

```text
T1003.001 — OS Credential Dumping / LSASS Memory
```

Deux détections complémentaires sont déclenchées :

```text
100001 → Mimikatz process
100003 → accès mémoire LSASS
```

Cette partie du lab illustre l'intérêt d'une détection en profondeur.

---

## 3. Pass-the-Hash

**Technique MITRE :**

```text
T1550.002 — Pass the Hash
```

Le scénario utilise **Impacket PsExec** afin de simuler un mouvement latéral à partir d'un hash NTLM.

La détection s'appuie sur plusieurs événements :

```text
NTLM Logon Type 3
+
création d'un service distant
+
activité ADMIN$
```

La corrélation permet d'obtenir un signal plus fiable qu'une authentification NTLM isolée.

---

## 4. Persistance

**Technique MITRE :**

```text
T1136.001 — Create Account
```

Le scénario simule la création d'un compte local de persistance.

Deux signaux complémentaires sont utilisés :

```text
Event ID 4720
+
commande net user /add
```

---

## 5. PowerShell encodé

**Technique MITRE :**

```text
T1059.001 — PowerShell
```

La règle détecte notamment les arguments :

```text
-enc
-encodedcommand
```

dans la ligne de commande d'un processus PowerShell.

---

## 6. Inhibit System Recovery

**Technique MITRE :**

```text
T1490 — Inhibit System Recovery
```

Le scénario simule la suppression des shadow copies.

Exemples détectés :

```text
vssadmin delete shadows
wmic shadowcopy delete
bcdedit recoveryenabled
```

Ce type de comportement est particulièrement intéressant dans les scénarios ransomware.

---

## 7. Détection Linux

Le laboratoire inclut également un endpoint Linux.

Le scénario couvre notamment :

```text
Brute force SSH
        ↓
activité post-compromission
        ↓
création d'un compte
        ↓
corrélation d'alertes Wazuh
```

Cette partie permet de tester une détection multi-OS au sein du même SIEM.

---

# Investigation d'incident

Le laboratoire se termine par la rédaction d'un rapport d'investigation complet.

Le rapport contient :

- résumé exécutif ;
- environnement impacté ;
- timeline ;
- analyse technique ;
- IoCs ;
- mapping MITRE ATT&CK ;
- analyse des faux positifs ;
- actions de confinement ;
- éradication ;
- recommandations ;
- retour à la normale.

Le rapport est disponible ici :

```text
docs/07-incident-report.md
```

---

## Exemple de timeline

```text
Brute Force RDP
        ↓
Mimikatz
        ↓
LSASS Access
        ↓
Pass-the-Hash
        ↓
Account Creation
        ↓
Encoded PowerShell
        ↓
Shadow Copy Deletion
        ↓
Linux compromise
```

Le scénario permet de travailler sur la **corrélation de plusieurs alertes** afin de reconstituer une chaîne d'attaque complète.

---

## MITRE ATT&CK

Le laboratoire couvre notamment :

| Tactique | Technique | ID |
|---|---|---|
| Credential Access | OS Credential Dumping | T1003.001 |
| Lateral Movement | Pass the Hash | T1550.002 |
| Credential Access | Brute Force | T1110.001 |
| Persistence | Create Account | T1136.001 |
| Execution | PowerShell | T1059.001 |
| Impact | Inhibit System Recovery | T1490 |

---

# Résultats

Le laboratoire a permis de valider :

- un environnement Active Directory fonctionnel ;
- la collecte de logs Windows et Linux ;
- l'intégration de Sysmon avec Wazuh ;
- le développement de **9 règles de détection custom** ;
- plusieurs scénarios offensifs ;
- la détection de techniques MITRE ATT&CK ;
- la corrélation de plusieurs événements ;
- la réduction des faux positifs ;
- l'analyse d'alertes ;
- la rédaction d'un rapport d'investigation.

---

# Documentation

La documentation complète du laboratoire est disponible dans :

```text
docs/
├── 00-architecture.md
├── 01-lab-setup.md
├── 02-active-directory.md
├── 03-wazuh-install.md
├── 04-agents.md
├── 05-detection-rules.md
├── 06-attack-simulations.md
└── 07-incident-report.md
```

---

# Structure du repository

```text
SOC-HomeLab/
│
├── README.md
│
├── docs/
│   ├── 00-architecture.md
│   ├── 01-lab-setup.md
│   ├── 02-active-directory.md
│   ├── 03-wazuh-install.md
│   ├── 04-agents.md
│   ├── 05-detection-rules.md
│   ├── 06-attack-simulations.md
│   └── 07-incident-report.md
│
├── rules/
│   └── local_rules.xml
│
├── screenshots/
│
└── scripts/
```

---

# Compétences mises en pratique

- Security Operations
- SIEM / EDR
- Wazuh
- Sysmon
- Active Directory
- Windows Event Logs
- Detection Engineering
- Incident Response
- Threat Hunting
- Alert Triage
- MITRE ATT&CK
- Windows Security
- Linux Security
- PowerShell
- VMware
- Network Security

---

# Sécurité

Toutes les simulations sont réalisées dans un environnement de laboratoire isolé sous VMware.

Les adresses utilisées appartiennent exclusivement au réseau privé :

```text
192.168.100.0/24
```

Les credentials, hashes et autres informations sensibles affichés publiquement sont anonymisés lorsque nécessaire.

---

# Conclusion

Ce projet reproduit un workflow SOC complet :

```text
Infrastructure
        ↓
Telemetry
        ↓
Detection Engineering
        ↓
Attack Simulation
        ↓
Alerting
        ↓
Correlation
        ↓
Investigation
        ↓
Incident Response
```

L'objectif n'était pas uniquement de déployer Wazuh, mais de construire un environnement permettant de travailler concrètement sur la **détection, le tuning, l'investigation et la réponse à incident**.

---

## Ressources

- [Wazuh Documentation](https://documentation.wazuh.com)
- [MITRE ATT&CK](https://attack.mitre.org)
- [Sysmon — Microsoft Sysinternals](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Impacket](https://github.com/fortra/impacket)

---

## Licence

MIT — libre d'utilisation et d'adaptation.
