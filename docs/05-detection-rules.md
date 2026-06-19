# 05 — Règles de détection custom & Sysmon

## Objectif
Enrichir la télémétrie Windows avec Sysmon et créer des règles de détection
custom dans Wazuh mappées au framework MITRE ATT&CK, couvrant les principales
techniques d'attaque simulées dans ce lab.

---

## Pourquoi Sysmon ?

Par défaut, Windows ne loggue pas suffisamment de détails pour détecter des
attaques sophistiquées. Sysmon (System Monitor) est un driver Microsoft qui
enrichit considérablement la télémétrie en ajoutant :

| Event ID Sysmon | Ce qu'il détecte |
|---|---|
| 1 | Création de processus + ligne de commande complète |
| 3 | Connexions réseau initiées par un processus |
| 7 | Chargement de DLL |
| 10 | **Accès à la mémoire d'un processus** ← clé pour Mimikatz |
| 11 | Création de fichiers |
| 13 | Modification de clés de registre |

Sans Sysmon, Mimikatz peut s'exécuter sans qu'aucun log exploitable ne soit
généré. Avec Sysmon, l'accès à la mémoire de `lsass.exe` est immédiatement
visible via l'Event ID 10.

> **Note** : Les événements Sysmon de type NetworkConnect (Event ID 3) dépendent
> de la configuration Sysmon utilisée. Certaines configurations communautaires,
> comme SwiftOnSecurity, filtrent une partie des connexions réseau afin de limiter
> le volume de logs. La détection de scans réseau via Sysmon Event ID 3 peut donc
> être incomplète selon la configuration appliquée.

---

## 1. Installation de Sysmon

Exécuté en **PowerShell 64 bits Administrateur** sur **DC01** et **win10-client** :

```powershell
# Téléchargement de Sysmon
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Sysmon.zip
Expand-Archive -Path C:\Sysmon.zip -DestinationPath C:\Sysmon

# Téléchargement de la config SwiftOnSecurity (standard industrie)
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Sysmon\sysmonconfig.xml

# Installation
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
```

### Vérification

```powershell
Get-Service Sysmon64
```

> ![Sysmon_running](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-5/Sysmon_running.PNG) : `Get-Service Sysmon64` affichant `Running` sur DC01.

---

## 2. Configuration Wazuh pour collecter les logs Sysmon

Pour que Wazuh collecte les logs Sysmon et pour éviter de devoir configurer chaque endpoint manuellement, nous utilisons une configuration partagée par groupe.

### 2.1 Création du dossier de configuration partagée

Sur **wazuh-server** :

```bash
mkdir -p /var/ossec/etc/shared/windows
```

### 2.2 Création du fichier agent.conf

```bash
nano /var/ossec/etc/shared/windows/agent.conf
```

```xml
<agent_config>

  <!-- Collecte des événements Sysmon -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

</agent_config>
```

Cette configuration indique aux agents Windows de collecter le journal `Microsoft-Windows-Sysmon/Operational`.

### 2.3 Association des agents Windows au groupe

Dans l'interface Wazuh, créer le groupe "windows" et ajouter les endpoints :

```
Management → Groups → Add new group
```

Les agents appartenant au groupe `windows` récupèrent automatiquement `/var/ossec/etc/shared/windows/agent.conf`.

> ![Groups](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-5/manage_groups.PNG)

---

## 3. Règles de détection custom

Les règles sont définies dans `/var/ossec/etc/rules/local_rules.xml`.
Chaque règle est mappée à une technique MITRE ATT&CK et surveille
des Event IDs Windows spécifiques.

---

### Règle 100001 — Mimikatz via nom de processus
**MITRE** : T1003.001 — OS Credential Dumping / LSASS Memory
**Niveau** : 15 (Critique)
**Event ID surveillé** : Sysmon Event ID 1 (création de processus)

**Raisonnement** : Cette règle détecte les exécutions directes de Mimikatz via
son nom de processus. Elle est principalement pédagogique et destinée au
laboratoire. En environnement réel, un attaquant renommera généralement
l'exécutable afin d'éviter une détection basée sur le nom du fichier.
C'est pourquoi elle est combinée avec la règle 100003 qui détecte le
comportement (accès LSASS) plutôt que le nom.

```xml
<rule id="100001" level="15">
  <if_group>windows</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)mimikatz</field>
  <description>CRITIQUE - Mimikatz détecté via nom de processus</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
  <group>credential_access,mimikatz,</group>
</rule>
```

---

### Règle 100003 — Accès mémoire LSASS
**MITRE** : T1003.001 — OS Credential Dumping / LSASS Memory
**Niveau** : 15 (Critique)
**Event ID surveillé** : Sysmon Event ID 10 (accès mémoire inter-processus)

**Raisonnement** : C'est la règle la plus robuste contre le credential dumping.
`lsass.exe` stocke les credentials en mémoire. Tout processus qui accède
à sa mémoire hors processus système légitimes est suspect. Sysmon Event ID 10
est le seul moyen natif de détecter cet accès sans EDR commercial.

La liste d'exclusion (`negate="yes"`) évite les faux positifs générés par les
processus système Windows qui accèdent légitimement à LSASS. En production,
cette liste devrait être complétée avec les outils de sécurité autorisés
(antivirus, EDR).

```xml
<rule id="100003" level="15">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^10$</field>
  <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe</field>
  <field name="win.eventdata.sourceImage" type="pcre2" negate="yes">(?i)(svchost\.exe|wininit\.exe|lsass\.exe|services\.exe|winlogon\.exe|wlms\.exe|csrss\.exe|MsMpEng\.exe|taskmgr\.exe|WmiPrvSE\.exe)</field>
  <description>CRITIQUE - Accès mémoire LSASS par processus non légitime</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
  <group>credential_access,lsass,</group>
</rule>
```

---

### Règle 100010 — Authentification NTLM réseau suspecte
**MITRE** : T1550.002 — Use Alternate Authentication Material / Pass the Hash
**Niveau** : 12 (Haut)
**Event ID surveillé** : Windows Security Event ID 4624 (ouverture de session)

**Raisonnement** : Cette règle identifie les authentifications réseau NTLM
(Logon Type 3) pouvant être observées lors d'un Pass-the-Hash. Elle ne permet
pas à elle seule de confirmer cette technique — une authentification NTLM réseau
peut être parfaitement légitime dans certains environnements. Elle doit être
corrélée avec d'autres indicateurs (heure inhabituelle, compte sensible,
alertes Mimikatz préalables) pour constituer un signal fiable.

```xml
<rule id="100010" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4624$</field>
  <field name="win.eventdata.logonType">^3$</field>
  <field name="win.eventdata.authenticationPackageName">^NTLM$</field>
  <description>HAUT - Authentification NTLM réseau suspecte (Pass-the-Hash possible)</description>
  <mitre>
    <id>T1550.002</id>
  </mitre>
  <group>lateral_movement,pass_the_hash,</group>
</rule>
```

---

### Règle 100030 — Brute Force RDP
**MITRE** : T1110.001 — Brute Force / Password Guessing
**Niveau** : 12 (Haut)
**Logique** : 5 échecs d'authentification depuis la même IP en 60 secondes

**Raisonnement** : Un attaquant qui tente de deviner un mot de passe RDP
génère des Event ID 4625 (échec de connexion) en rafale. Le seuil de 5 échecs
en 60 secondes est suffisamment bas pour détecter une attaque tout en évitant
les faux positifs liés aux erreurs de frappe normales (1-2 tentatives).

Cette règle s'appuie sur la règle native Wazuh 60122 qui détecte
les échecs d'authentification Windows (Event ID 4625).

```xml
<rule id="100030" level="12" frequency="5" timeframe="60">
  <if_matched_sid>60122</if_matched_sid>
  <same_field>win.eventdata.ipAddress</same_field>
  <description>HAUT - Brute force RDP : 5 échecs en 60 secondes</description>
  <mitre>
    <id>T1110.001</id>
  </mitre>
  <group>brute_force,rdp,</group>
</rule>
```

---

### Règle 100050 — Création de compte suspect
**MITRE** : T1136.001 — Create Account / Local Account
**Niveau** : 12 (Haut)
**Event ID surveillé** : Windows Security Event ID 4720

**Raisonnement** : La création d'un nouveau compte utilisateur en dehors
des procédures normales est un indicateur classique de persistance.
Un attaquant crée souvent un compte backdoor après avoir obtenu des
privilèges élevés pour maintenir son accès même si ses credentials
initiaux sont révoqués.

```xml
<rule id="100050" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4720$</field>
  <description>HAUT - Nouveau compte utilisateur créé (persistance possible)</description>
  <mitre>
    <id>T1136.001</id>
  </mitre>
  <group>persistence,account_creation,</group>
</rule>
```

Note: La règle 100050 s'appuie sur le même Event ID 4720 que la règle native Wazuh 60109, mais remonte la criticité à niveau 12 et ajoute le mapping MITRE ATT&CK T1136.001 pour faciliter la corrélation et le triage SOC.

---

### Règle 100060 — PowerShell encodé
**MITRE** : T1059.001 — Command and Scripting Interpreter / PowerShell
**Niveau** : 12 (Haut)
**Event ID surveillé** : Sysmon Event ID 1 (création de processus)

**Raisonnement** : L'encodage base64 des commandes PowerShell est une technique
d'obfuscation courante pour bypasser les solutions de détection basées sur les
signatures. Un usage légitime de `-EncodedCommand` existe dans certains scripts
d'administration, ce qui peut générer des faux positifs dans des environnements
avec une gestion automatisée importante.

```xml
<rule id="100060" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^1$</field>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(-enc|-encodedcommand|-ec\s)</field>
  <description>HAUT - PowerShell avec commande encodée détecté (obfuscation possible)</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
  <group>execution,powershell,obfuscation,</group>
</rule>
```


---

### Règle 100092 — Suppression des shadow copies
**MITRE** : T1490 — Inhibit System Recovery
**Niveau** : 15 (Critique)
**Event ID surveillé** : Sysmon Event ID 1 (création de processus)

**Raisonnement** : La suppression des shadow copies est la signature
caractéristique d'un ransomware — elle empêche la restauration du système
via les points de restauration Windows. Cette technique est utilisée par
la quasi-totalité des ransomwares modernes (Ryuk, LockBit, BlackCat).

```xml
<rule id="100092" level="15">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^1$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(vssadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled)</field>
  <description>CRITIQUE - Suppression des shadow copies détectée (comportement ransomware)</description>
  <mitre>
    <id>T1490</id>
  </mitre>
  <group>impact,ransomware,</group>
</rule>
```


---

### Règle 100094 — Exécution depuis dossier suspect
**MITRE** : T1059 — Command and Scripting Interpreter
**Niveau** : 10 (Moyen)
**Event ID surveillé** : Sysmon Event ID 1 (création de processus)

**Raisonnement** : Les malwares et outils offensifs sont fréquemment déposés
dans des dossiers temporaires (`%TEMP%`, `Downloads`, `AppData`) avant exécution.
Un exécutable lancé depuis ces chemins est anormal dans un environnement
d'entreprise sain.

```xml
<rule id="100094" level="10">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^1$</field>
  <field name="win.eventdata.image" type="pcre2">(?i)(\\temp\\|\\downloads\\|\\appdata\\local\\temp\\)</field>
  <description>MOYEN - Exécution depuis un dossier temporaire suspect</description>
  <mitre>
    <id>T1059</id>
  </mitre>
  <group>execution,suspicious_path,</group>
</rule>
```


---


## 4. Récapitulatif des règles

| Rule ID | Attaque | MITRE | Niveau | Event ID | OS |
|---|---|---|---|---|---|
| 100001 | Mimikatz — nom de processus | T1003.001 | 15 — Critique | Sysmon 1 | Windows |
| 100003 | Accès mémoire LSASS | T1003.001 | 15 — Critique | Sysmon 10 | Windows |
| 100010 | Authentification NTLM réseau | T1550.002 | 12 — Haut | 4624 | Windows |
| 100030 | Brute force RDP | T1110.001 | 12 — Haut | 4625 | Windows |
| 100050 | Création de compte (Event) | T1136.001 | 12 — Haut | 4720 | Windows |
| 100060 | PowerShell encodé | T1059.001 | 12 — Haut | Sysmon 1 | Windows |
| 100091 | Création compte via CLI | T1136.001 | 12 — Haut | Sysmon 1 | Windows |
| 100092 | Shadow copies supprimées | T1490 | 15 — Critique | Sysmon 1 | Windows |
| 100094 | Exécution dossier suspect | T1059 | 10 — Moyen | Sysmon 1 | Windows |

---

## 5. Tactiques MITRE ATT&CK couvertes

| Tactique | Règles |
|---|---|
| Credential Access | 100001, 100003 |
| Lateral Movement | 100010 |
| Initial Access | 100030 |
| Persistence | 100050, 100091 |
| Execution | 100060, 100090, 100094 |
| Impact | 100092 |
| Defense Evasion | 100060 |
| Discovery | 100090 |

---

## 6. Limites des règles

| Règle | Limite |
|---|---|
| 100001 | Contournable par renommage de l'exécutable |
| 100003 | Dépend de Sysmon Event ID 10 — nécessite une config Sysmon adaptée |
| 100010 | Peut générer des faux positifs — l'authentification NTLM réseau est légitime dans certains contextes |
| 100060 | Certaines solutions d'administration utilisent `-EncodedCommand` légitimement |
| 100092 | Ne couvre pas toutes les variantes de suppression de sauvegardes |
| 100094 | Peut générer des faux positifs sur des postes de développeurs |

---

## 7. Vérification dans le Dashboard

**Wazuh Dashboard → Rules → Manage rules → chercher `100001`**

> ![Rule_wazuh](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-5/Rule_Mimikatz.PNG) : Dashboard Wazuh affichant la règle 100001 dans la liste des règles chargées.
