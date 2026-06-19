# 07 — Rapport d'Investigation d'Incident

**Référence** : IR-2024-001
**Date de détection** : 15 Mars 2024
**Date du rapport** : 16 Mars 2024
**Analyste** : Sami
**Environnement** : SOC Home Lab — lab.local
**Sévérité** : 🔴 CRITIQUE
**Statut** : Résolu (environnement de test)

---

## 1. Résumé Exécutif

Le 15 Mars 2024, la plateforme SIEM Wazuh a détecté une séquence d'alertes
indiquant une compromission critique de plusieurs actifs Windows du domaine
`lab.local`. Un attaquant a initié une attaque par brute force RDP, obtenu
un accès au Domain Controller, extrait des credentials via Mimikatz, puis
effectué un mouvement latéral vers un poste client en utilisant la technique
Pass-the-Hash. L'attaquant a ensuite établi une persistance via la création
d'un compte backdoor et tenté de compromettre la capacité de récupération
du système en supprimant les shadow copies, comportement caractéristique
d'un opérateur ransomware. Après compromission de l'environnement Windows,
l'attaquant a étendu ses actions vers les systèmes Linux accessibles sur
le réseau interne.

**Impact** : Compromission critique de plusieurs actifs Windows avec exposition
potentielle du domaine Active Directory. Credentials du compte `LAB\badmin`
exposés, persistance établie sur deux machines Windows et un endpoint Linux.

---

## 2. Environnement

| Machine | IP | Rôle |
|---|---|---|
| Kali Linux | 192.168.100.40 | Machine attaquante |
| DC01 | 192.168.100.10 | Contrôleur de domaine |
| win10-client | 192.168.100.20 | Poste utilisateur |
| ubuntu-endpoint | 192.168.100.30 | Endpoint Linux |
| wazuh-server | 192.168.100.50 | SIEM |

---

## 3. Timeline de l'incident

| Heure | Règle | Événement | Machine | Niveau |
|---|---|---|---|---|
| T+00:00 | 100030 | Brute force RDP — 5 échecs en 60s depuis 192.168.100.40 | win10-client | Haut |
| T+10:00 | 100001 | Mimikatz exécuté — `C:\mimikatz\x64\mimikatz.exe` | DC01 | Critique |
| T+10:00 | 100003 | Accès mémoire LSASS par processus non légitime | DC01 | Critique |
| T+20:00 | 100010 | Authentification NTLM réseau suspecte (Logon Type 3) | win10-client | Haut |
| T+20:00 | 92650 | Service créé depuis ADMIN$ — signature Impacket PsExec | win10-client | Haut |
| T+25:00 | 100050 | Nouveau compte utilisateur créé — `backdoor` | win10-client | Haut |
| T+25:00 | 100091 | `net user backdoor /add` détecté en ligne de commande | win10-client | Haut |
| T+30:00 | 100060 | PowerShell avec commande encodée base64 détecté | DC01 | Haut |
| T+35:00 | 100092 | Suppression des shadow copies — comportement ransomware | DC01 | Critique |
| T+40:00 | 100094 | Exécution depuis dossier temporaire suspect | DC01 | Moyen |
| T+45:00 | 5763 | Brute force SSH détecté sur endpoint Linux | ubuntu-endpoint | Moyen |
| T+50:00 | 40101 | Attaque détectée sur système Linux | ubuntu-endpoint | Moyen |
| T+50:00 | 40501 | Corrélation : attaque suivie d'une création de compte | ubuntu-endpoint | Haut |

---

## 4. Analyse technique

### 4.1 Accès initial — Brute Force RDP (T1110.001)

L'attaquant a initié une attaque par brute force sur le service RDP de
`win10-client` depuis l'IP `192.168.100.40` via l'outil Hydra. La règle
100030 a détecté 5 échecs d'authentification consécutifs en moins de
60 secondes. Une authentification réussie a ensuite permis l'accès initial
au poste cible.

**Event ID** : 4625 (échec d'authentification)
**IP source** : 192.168.100.40
**Compte ciblé** : `LAB\badmin`

---

### 4.2 Credential Dumping — Mimikatz (T1003.001)

Après avoir obtenu un accès sur DC01, l'attaquant a exécuté Mimikatz
pour extraire les credentials en mémoire. Deux règles se sont déclenchées
simultanément, illustrant la détection en profondeur.

- **100001** : Sysmon Event ID 1 a loggué la création du processus
  `C:\mimikatz\x64\mimikatz.exe` sous l'utilisateur `LAB\Administrateur`
- **100003** : Sysmon Event ID 10 a détecté l'accès à la mémoire de
  `lsass.exe` par un processus non légitime

**Compte compromis** : `LAB\badmin` (compte de domaine)
**Hash NTLM extrait** : `0f41d338c49a5f89****************`
**Processus source** : `C:\mimikatz\x64\mimikatz.exe`
**Processus cible** : `C:\Windows\System32\lsass.exe`
**Hashes du binaire Mimikatz** :
- MD5 : `29EFD64DD3C7FE1E2B022B7AD73A1BA5`
- SHA256 : `61C0810A23580CF492A6BA4F7654566108331E7A4134C968C2D6A05261B2D8A1`

> Note : Le hash NTLM complet est disponible dans le rapport interne
> confidentiel. Il est partiellement masqué ici conformément aux bonnes
> pratiques de publication.

---

### 4.3 Mouvement latéral — Pass-the-Hash (T1550.002)

Le hash NTLM du compte `LAB\badmin` a été utilisé via Impacket PsExec
pour obtenir un shell sur `win10-client` sans connaître le mot de passe
en clair. L'attaquant a obtenu les privilèges `NT AUTHORITY\SYSTEM`.

- **100010** : Authentification NTLM réseau (Logon Type 3) détectée.
  Cette règle identifie les authentifications NTLM réseau pouvant être
  observées lors d'un Pass-the-Hash. Elle ne permet pas à elle seule de
  confirmer cette technique et doit être corrélée avec d'autres indicateurs.
- **92650** : Création d'un service Windows depuis `ADMIN$` — signature
  caractéristique d'Impacket PsExec, confirmant le mouvement latéral.

**Outil utilisé** : Impacket PsExec
**Privilèges obtenus** : NT AUTHORITY\SYSTEM

---

### 4.4 Persistance — Création de compte backdoor (T1136.001)

Depuis le shell SYSTEM sur `win10-client`, l'attaquant a créé un compte
local et l'a ajouté au groupe Administrateurs locaux pour maintenir un
accès persistant même en cas de révocation des credentials initiaux.

```
net user backdoor Password123! /add
net localgroup Administrateurs backdoor /add
```

Deux règles complémentaires ont détecté cette action :
- **100050** : Event ID 4720 (création de compte Windows)
- **100091** : Ligne de commande `net user /add` via Sysmon Event ID 1

> Note : La règle 100050 s'appuie sur le même Event ID 4720 que la règle
> native Wazuh 60109, mais remonte la criticité à niveau 12 et ajoute
> le mapping MITRE ATT&CK T1136.001 pour faciliter le triage SOC.

---

### 4.5 Obfuscation — PowerShell encodé (T1059.001)

L'attaquant a utilisé PowerShell avec une commande encodée en base64
pour tenter de bypasser les détections basées sur les signatures.

**Commande détectée** : `powershell -enc aQBwAGMAbwBuAGYAaQBnAA==`
**Décodée** : `ipconfig`

La règle 100060 a détecté le flag `-enc` dans la ligne de commande
via Sysmon Event ID 1.

---

### 4.6 Impact — Suppression des shadow copies (T1490)

La suppression des shadow copies est la signature caractéristique d'un
opérateur ransomware. Cette action empêche la restauration du système
via les points de restauration Windows. Elle est observée dans la
quasi-totalité des attaques ransomware modernes (Ryuk, LockBit, BlackCat).

```
vssadmin delete shadows /all /quiet
```

La règle 100092 de niveau Critique (15) s'est déclenchée immédiatement
via la détection de la ligne de commande par Sysmon Event ID 1.

---

### 4.7 Extension vers Linux — ubuntu-endpoint

Après compromission de l'environnement Windows, l'attaquant a étendu
ses actions vers les systèmes Linux accessibles sur le réseau interne.
Une attaque par brute force SSH a été lancée contre `ubuntu-endpoint`,
suivie de la création d'un compte utilisateur local.

La corrélation automatique Wazuh entre les règles 40101 et 40501 a mis
en évidence ce pattern de compromission sans nécessiter de règle custom.

**Outil utilisé** : Hydra (brute force SSH)
**Compte créé** : `hacker`

---

## 5. Indicateurs de Compromission (IoCs)

### Hashes
| Type | Valeur | Description |
|---|---|---|
| NTLM | `0f41d338c49a5f89****************` | Hash compte `LAB\badmin` (masqué) |
| MD5 | `29EFD64DD3C7FE1E2B022B7AD73A1BA5` | Binaire Mimikatz |
| SHA256 | `61C0810A23580CF492A6BA4F7654566108331E7A4134C968C2D6A05261B2D8A1` | Binaire Mimikatz |

### IPs
| IP | Rôle |
|---|---|
| 192.168.100.40 | Machine attaquante (Kali Linux) |

### Fichiers
| Chemin | Description |
|---|---|
| `C:\mimikatz\x64\mimikatz.exe` | Outil de credential dumping |
| `C:\Users\...\AppData\Local\Temp\test.exe` | Binaire exécuté depuis chemin suspect |

### Comptes compromis ou créés
| Compte | Machine | Action |
|---|---|---|
| `LAB\badmin` | lab.local | Compte de domaine compromis — hash NTLM exposé |
| `backdoor` | win10-client | Compte local créé par l'attaquant (persistance) |
| `hacker` | ubuntu-endpoint | Compte Linux créé post-compromission |

---

## 6. Analyse MITRE ATT&CK

| Tactique | Technique | ID | Règle(s) |
|---|---|---|---|
| Initial Access | Brute Force | T1110.001 | 100030, 5763 |
| Credential Access | OS Credential Dumping | T1003.001 | 100001, 100003 |
| Lateral Movement | Pass the Hash | T1550.002 | 100010, 92650 |
| Persistence | Create Account | T1136.001 | 100050, 100091 |
| Execution | PowerShell | T1059.001 | 100060 |
| Impact | Inhibit System Recovery | T1490 | 100092 |

---

## 7. Faux positifs identifiés

Durant l'investigation, deux comportements légitimes ont généré des alertes
nécessitant une analyse supplémentaire avant d'être écartés.

**Règle 100003 (accès LSASS)** : Des accès périodiques à `lsass.exe` par
des processus système Windows (renouvellement de tokens Kerberos) ont généré
des alertes répétées. La règle a été affinée avec une liste d'exclusion des
processus légitimes (`svchost.exe`, `winlogon.exe`, `csrss.exe`, etc.).
Référence : [docs/05-detection-rules.md](05-detection-rules.md)

**Règle 100010 (NTLM réseau)** : Des authentifications NTLM légitimes entre
machines du domaine ont généré des alertes. Cette règle nécessite une corrélation
avec d'autres indicateurs pour confirmer un Pass-the-Hash réel — la règle 92650
(création de service depuis ADMIN$) constitue cet indicateur complémentaire.

La gestion des faux positifs fait partie intégrante du cycle d'amélioration
des règles de détection et du travail quotidien d'un SOC analyst.

---

## 8. Réponse à incident

Actions effectuées suite à la détection des alertes :

### Confinement
1. Isolation de `win10-client` du réseau (désactivation de la carte réseau)
2. Isolation de `ubuntu-endpoint` du réseau
3. Blocage de l'IP source `192.168.100.40` au niveau du pare-feu

### Éradication
4. Suppression du compte `backdoor` sur `win10-client`
5. Suppression du compte `hacker` sur `ubuntu-endpoint`
6. Désactivation temporaire du compte `LAB\badmin`
7. Rotation des credentials du compte `LAB\badmin`
8. Suppression du binaire Mimikatz (`C:\mimikatz\x64\`)

### Vérification
9. Vérification de l'absence d'autres comptes suspects via `Get-ADUser -Filter *`
10. Analyse des Event ID 4624/4625 sur DC01 pour identifier d'éventuels
    accès supplémentaires non détectés
11. Vérification de l'intégrité des GPOs du domaine

### Retour à la normale
12. Réactivation du compte `LAB\badmin` avec nouveau mot de passe
13. Reconnexion des machines au réseau après validation
14. Surveillance renforcée pendant 48h post-incident

---

## 9. Recommandations

### Immédiates
- Réinitialiser tous les mots de passe et hashes NTLM des comptes exposés
- Auditer l'ensemble des comptes locaux sur toutes les machines du domaine
- Analyser les logs complets de DC01 pour identifier d'autres actions

### Court terme
- Désactiver NTLM v1 sur l'ensemble du domaine et forcer Kerberos
- Activer la protection LSA (`RunAsPPL`) pour empêcher l'accès à `lsass.exe`
- Déployer une politique de mots de passe renforcée (longueur minimale 16 caractères)
- Restreindre l'accès RDP aux seuls administrateurs via GPO
- Activer Windows Defender Credential Guard sur les endpoints

### Long terme
- Implémenter le principe du moindre privilège — limiter les comptes Domain Admin
- Déployer un PAM (Privileged Access Management) pour les comptes administrateurs
- Mettre en place une segmentation réseau pour limiter le mouvement latéral
- Intégrer Suricata comme IDS réseau pour détecter les scans et le trafic malveillant
- Mettre en place des alertes sur les connexions hors horaires de bureau

---

## 10. Conclusion

Cette investigation démontre l'efficacité d'une approche de détection en
profondeur combinant Sysmon, Wazuh et des règles custom mappées MITRE ATT&CK.
La kill chain complète a été détectée — de l'accès initial jusqu'à l'impact —
avec un total de 13 alertes générées couvrant 6 tactiques MITRE ATT&CK distinctes.

Les points clés de cette investigation :

- La **corrélation d'alertes** (100001 + 100003, 100010 + 92650, 40101 + 40501)
  a permis de reconstituer rapidement la chronologie de l'attaque et de
  distinguer les vrais positifs des faux positifs
- La **détection comportementale** (accès LSASS via Sysmon Event ID 10) s'est
  révélée plus robuste que la détection par signature (nom du processus) —
  un attaquant renommant Mimikatz aurait contourné 100001 mais pas 100003
- La **gestion des faux positifs** sur les règles 100003 et 100010 a nécessité
  un affinement itératif des règles, processus normal dans un environnement SOC réel
- La couverture **multi-OS** (Windows + Linux) démontre la polyvalence de Wazuh
  comme solution SIEM unifiée sans agent propriétaire supplémentaire

---

*Rapport rédigé par Sami — SOC Home Lab | Wazuh v4.7.5 + Active Directory*
