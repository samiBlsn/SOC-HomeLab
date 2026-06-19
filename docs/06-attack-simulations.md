# 06 — Simulations d'attaques

## Objectif
Simuler une kill chain complète depuis Kali Linux contre l'infrastructure
Active Directory du lab, valider la détection de chaque technique par Wazuh,
et démontrer la couverture multi-OS (Windows + Linux).

---

## Environnement

| Machine | IP | Rôle |
|---|---|---|
| Kali Linux | 192.168.100.40 | Attaquant |
| DC01 | 192.168.100.10 | Cible principale (AD) |
| win10-client | 192.168.100.20 | Cible mouvement latéral |
| ubuntu-endpoint | 192.168.100.30 | Cible Linux |
| wazuh-server | 192.168.100.50 | Détection (SIEM) |

> ⚠️ **Rappel** : Toutes les attaques sont réalisées dans un réseau VMware
> isolé (192.168.100.0/24). Aucun trafic malveillant ne sort vers internet
> ou le réseau physique.

---

## Kill Chain simulée

```
[Kali 192.168.100.40]
        │
        ├── 1. Accès initial      → Brute force RDP          (T1110.001)
        ├── 2. Credential dump    → Mimikatz / LSASS          (T1003.001)
        ├── 3. Mouvement latéral  → Pass-the-Hash             (T1550.002)
        ├── 4. Persistance        → Création compte backdoor  (T1136.001)
        ├── 5. Obfuscation        → PowerShell encodé         (T1059.001)
        ├── 6. Impact             → Shadow copies supprimées  (T1490)
        ├── 7. Execution suspecte → Dossier temporaire        (T1059)
        └── 8. Linux              → SSH BF + corrélation      (T1110.001)
```

---

## Attaque 1 — Brute Force RDP

**Technique MITRE** : T1110.001 — Password Guessing
**Depuis** : Kali (192.168.100.40)
**Cible** : win10-client (192.168.100.20)
**Règle déclenchée** : 100030

### Contexte
Tentative de deviner le mot de passe d'un compte via le protocole RDP (port 3389).
Simulation d'un scénario de password guessing contre un service RDP exposé.
Cibler win10-client plutôt que DC01 est plus réaliste, en vrai pentest on cible
les workstations en premier pour éviter de locker des comptes AD sensibles.

### Prérequis
RDP activé sur win10-client :
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Bureau à distance"
```

### Commande
```bash
hydra -l badmin -P /usr/share/wordlists/rockyou.txt rdp://192.168.100.20 -t 4 -V
```

### Détection Wazuh
Chaque tentative échouée génère un Event ID 4625. La règle 100030 corrèle
5 échecs consécutifs depuis la même IP en moins de 60 secondes.

> ![HydraKali](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/attaque_hydra_kali.PNG) : Hydra en cours d'exécution depuis Kali.
> ![alerte100030](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/alerte_100030.PNG) : Alerte Rule ID 100030 dans le Dashboard Wazuh avec l'IP source visible.

---

## Attaque 2 — Credential Dumping (Mimikatz) (Simulation de Credential Dumping après compromission d'un serveur critique)

**Technique MITRE** : T1003.001 — OS Credential Dumping / LSASS Memory
**Depuis** : DC01
**Cible** : DC01
**Règles déclenchées** : 100001, 100003

### Contexte
Extraction des credentials (hashes NTLM) stockés en mémoire par `lsass.exe`.
Outil offensif le plus utilisé dans les attaques ciblées et les ransomwares.
Deux règles se déclenchent simultanément — détection par nom de processus (100001)
ET par comportement d'accès mémoire (100003) — illustrant la défense en profondeur.

### Commande
```powershell
C:\mimikatz\x64\mimikatz.exe "privilege::debug" "lsadump::lsa /patch" "exit"
```

### Détection Wazuh

| Règle | Déclencheur | Event |
|---|---|---|
| 100001 | Nom du processus `mimikatz.exe` | Sysmon ID 1 |
| 100003 | Accès mémoire à `lsass.exe` | Sysmon ID 10 |

> ![ConsoleMimikatz](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/console_mimikatz.PNG) : Console Mimikatz avec les hashes NTLM visibles sur DC01.
> ![Alertesmimikatz](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/alertes_mimikatz.PNG) : Alertes 100001 et 100003 simultanées dans le Dashboard Wazuh.
> ![Alerte100030](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/alerte_100030.PNG) : Détail de l'alerte 100003 montrant le processus source.

---

## Attaque 3 — Pass-the-Hash (Impacket)

**Technique MITRE** : T1550.002 — Use Alternate Authentication Material / Pass the Hash / Techniques associées observables :
- T1021.002 SMB/Windows Admin Shares
- T1543.003 Windows Service
**Depuis** : Kali (192.168.100.40)
**Cible** : win10-client (192.168.100.20)
**Règles déclenchées** : 100010, 92650 (native)

### Contexte
Utilisation du hash NTLM récupéré via Mimikatz pour s'authentifier sur une autre machine sans connaître le mot de passe en clair. 
Technique clé du mouvement latéral en environnement AD, largement utilisée par les groupes APT et opérateurs ransomware après avoir compromis un premier système.

### Commande
```bash
impacket-psexec badmin@192.168.100.20 -hashes :HASH_NTLM -codec cp850
```

### Résultat obtenu
```
[*] Found writable share ADMIN$
[*] Uploading file xxxxxxxx.exe
[*] Creating service xxxx on win10-client
Microsoft Windows [version 10.0.19045]
C:\Windows\system32> whoami
autorite nt\système
```

> **Note** : L'affichage `autorite nt\système` correspond à `NT AUTHORITY\SYSTEM`
> sur un système Windows en français, privilèges les plus élevés possibles.

### Détection Wazuh
- **100010** — Authentification NTLM réseau (Logon Type 3) détectée sur win10-client
- **92650** — Règle native Wazuh détectant la création de service depuis `ADMIN$`
  (signature caractéristique d'Impacket PsExec)

> ![Impacket](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/passTheHash_impacket_kali.PNG) : Shell Impacket avec `whoami` → `autorite nt\système`.
> ![AlertesPTH](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/alertes_PTH.PNG) : Alertes 100010 et 92650 dans le Dashboard Wazuh.
> ![Alerte100030](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/alerte_100010.PNG) : Détail de l'alerte 100010 montrant Logon Type 3 + NTLM.

---

## Attaque 4 — Persistance (Création compte backdoor)

**Technique MITRE** : T1136.001 — Create Account / Local Account
**Depuis** : Shell Impacket sur win10-client
**Cible** : win10-client
**Règles déclenchées** : 100050, 100091

### Contexte
Après avoir obtenu un accès SYSTEM, l'attaquant crée un compte local pour maintenir
son accès même si la session initiale est fermée ou les credentials initiaux changés.
Technique de persistance classique observée dans la majorité des incidents réels.

### Commandes
```cmd
net user backdoor Password123! /add
net localgroup Administrateurs backdoor /add
```

### Détection Wazuh
Deux règles complémentaires se déclenchent :
- **100050** — basée sur l'Event ID 4720 (création de compte Windows)
- **100091** — basée sur la ligne de commande Sysmon (`net user /add`)

> **Note** : La règle 100050 s'appuie sur le même Event ID 4720 que la règle
> native 60109, mais remonte la criticité à niveau 12 et ajoute le mapping
> MITRE ATT&CK T1136.001 pour faciliter le triage SOC.

> ![Backdoor](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/PTH_backdoorcreation.PNG) : Commande `net user backdoor /add` dans le shell Impacket.
> ![AlertesBackdoor](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/alertes_backdoor.PNG) : Alertes 100050 et 100091 dans le Dashboard Wazuh.

---

## Attaque 5 — Obfuscation PowerShell encodé

**Technique MITRE** : T1059.001 — Command and Scripting Interpreter / PowerShell
**Depuis** : DC01
**Cible** : DC01
**Règle déclenchée** : 100060

### Contexte
Encodage des commandes PowerShell en base64 pour bypasser les solutions de détection
basées sur les signatures. Très utilisé dans les droppers de malwares et scripts
de post-exploitation. La commande encodée correspond à `ipconfig` dans ce test.

### Commande
```powershell
powershell -enc aQBwAGMAbwBuAGYAaQBnAA==
```

### Détection Wazuh
Sysmon Event ID 1 capture la ligne de commande complète incluant `-enc` et la
chaîne base64. La règle 100060 matche sur la présence du flag `-enc`.


> ![PowershellEncode](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/ps_encode.PNG)
> ![AlertesPsEncode](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/alerte_100060.PNG) : Alerte Rule ID 100060 dans le Dashboard avec
> la commandLine encodée visible dans le détail.

---

## Attaque 6 — Simulation comportement ransomware (Shadow Copies)

**Technique MITRE** : T1490 — Inhibit System Recovery
**Depuis** : DC01
**Cible** : DC01
**Règle déclenchée** : 100092

### Contexte
Suppression des points de restauration Windows pour empêcher la récupération
des fichiers après chiffrement. De nombreux ransomwares utilisent cette technique pour empêcher la restauration système (Ryuk, LockBit, BlackCat). C'est l'une des premières actions exécutées
par un ransomware avant de chiffrer les fichiers.

### Commandes
```powershell
# Créer une shadow copy puis la supprimer
wmic shadowcopy call create Volume='C:\'
vssadmin delete shadows /all /quiet
```

### Détection Wazuh
Sysmon Event ID 1 capture la ligne de commande `vssadmin delete shadows`.
La règle 100092 de niveau 15 (Critique) se déclenche immédiatement.

> ![CmdShadow](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/shadow_copiescmd.PNG)
> ![PowershellEncode](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/alerte_100092.PNG) : Alerte Rule ID 100092 niveau 15 Critique dans le Dashboard.

---

## Attaque 7 — Exécution depuis dossier suspect

**Technique MITRE** : Cette règle détecte un comportement suspect sans correspondre directement à une technique MITRE ATT&CK spécifique. Elle sert d'indicateur contextuel à corréler avec d'autres alertes.
**Depuis** : DC01
**Cible** : DC01
**Règle déclenchée** : 100094

### Contexte
Les malwares et outils offensifs sont fréquemment déposés dans des dossiers
temporaires (`%TEMP%`, `Downloads`) avant exécution pour éviter les répertoires
surveillés. Un exécutable lancé depuis ces chemins est anormal en entreprise.

### Commandes
```powershell
copy C:\Windows\System32\whoami.exe $env:TEMP\test.exe
& $env:TEMP\test.exe
```

### Détection Wazuh
Sysmon Event ID 1 logue le chemin complet de l'image exécutée.
La règle 100094 matche sur la présence de `\temp\` dans le chemin.

> ![Alerte100094](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/alerte_100094.PNG) : Alerte Rule ID 100094 dans le Dashboard avec
> le chemin `\AppData\Local\Temp\test.exe` visible dans le détail.

---

## Attaque 8 — SSH Brute Force Linux

**Technique MITRE** : T1110.001 — Password Guessing
**Depuis** : Kali (192.168.100.40)
**Cible** : ubuntu-endpoint (192.168.100.30)
**Règle déclenchée** : 5763 (native)

### Contexte
Tentative de connexion SSH par force brute sur un endpoint Linux. 
Wazuh monitore nativement les logs auth.log sur Ubuntu, ce qui permet la détection sans nécessiter Sysmon.

### Commande
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.100.30 -t 4
```

### Détection Wazuh
Wazuh analyse nativement `/var/log/auth.log` sur Ubuntu. La règle native 5763
détecte le pattern de brute force SSH et génère une alerte.

> ![HydraKaliUbuntu](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/bruteforce_ubuntu.PNG) : Hydra SSH en cours depuis Kali.
> ![Alerte5763](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/alerte_5763.PNG): Alerte Rule ID 5763 dans le Dashboard Wazuh.

---

## Attaque 9 — Corrélation attaque + création de compte (Linux)

**Technique MITRE** : T1136.001 — Create Account
**Depuis** : ubuntu-endpoint
**Cible** : ubuntu-endpoint
**Règles déclenchées** : 40101, 40501 (natives — corrélation automatique)

### Contexte
Après le brute force SSH, la création d'un compte sur ubuntu-endpoint déclenche une corrélation automatique Wazuh particulièrement intéressante.
La règle 40501 détecte qu'une attaque a été suivie d'une création de compte, ce qui constitue un pattern de compromission typique. 
Cette corrélation native illustre la capacité du SIEM à contextualiser automatiquement les événements.

### Commandes
```bash
sudo useradd -m hacker
```

### Détection Wazuh
Wazuh corrèle automatiquement :
- **40101** — Attaque détectée sur le système
- **40501** — *"Attacks followed by the addition of a user"* — corrélation
  automatique entre l'attaque précédente et la création de compte

> ![alertesUbuntu](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/attaque_ubuntu.PNG) : Alertes 40101 et 40501 dans le Dashboard montrant
> la corrélation automatique Wazuh.
> ![Alerte40501](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-6/alerte40501.PNG) : Détail de l'alerte 40501 montrant le contexte de corrélation.

---

## Résultats — Vue d'ensemble des alertes

| Heure | Règle | Description | Niveau | Cible |
|---|---|---|---|---|
| T+0 min | 100030 | Brute force RDP | 12 — Haut | win10-client |
| T+10 min | 100001 | Mimikatz — nom processus | 15 — Critique | DC01 |
| T+10 min | 100003 | Accès mémoire LSASS | 15 — Critique | DC01 |
| T+20 min | 100010 | Pass-the-Hash NTLM | 12 — Haut | win10-client |
| T+20 min | 92650 | Mouvement latéral Impacket | 12 — Haut | win10-client |
| T+25 min | 100050 | Création compte backdoor | 12 — Haut | win10-client |
| T+25 min | 100091 | net user /add CLI | 12 — Haut | win10-client |
| T+30 min | 100060 | PowerShell encodé | 12 — Haut | DC01 |
| T+35 min | 100092 | Shadow copies supprimées | 15 — Critique | DC01 |
| T+40 min | 100094 | Exécution dossier suspect | 10 — Moyen | DC01 |
| T+45 min | 5763 | SSH Brute Force Linux | 10 — Moyen | ubuntu-endpoint |
| T+50 min | 40101 | Attaque Linux détectée | 10 — Moyen | ubuntu-endpoint |
| T+50 min | 40501 | Attaque + création compte | 12 — Haut | ubuntu-endpoint |

---

## Matrice MITRE ATT&CK couverte

| Tactique | Technique | ID | Outil | OS |
|---|---|---|---|---|
| Initial Access | Brute Force | T1110.001 | Hydra | Windows + Linux |
| Credential Access | OS Credential Dumping | T1003.001 | Mimikatz | Windows |
| Lateral Movement | Pass the Hash | T1550.002 | Impacket | Windows |
| Persistence | Create Account | T1136.001 | net user | Windows |
| Execution | PowerShell | T1059.001 | PowerShell | Windows |
| Impact | Inhibit System Recovery | T1490 | vssadmin | Windows |
| Execution | Suspicious Path | T1059 | — | Windows |
| Persistence | Create Account Linux | T1136.001 | useradd | Linux |
