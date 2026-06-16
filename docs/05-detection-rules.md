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
son nom de processus. Elle peut être contournée par le renommage de l'exécutable,
c'est pourquoi elle est combinée avec la règle 100003 pour une détection en profondeur.

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

Note : En production, cette règle nécessiterait une liste d'exclusion pour
les outils de sécurité autorisés (antivirus, EDR) afin de réduire les faux positifs.

```xml
<rule id="100003" level="15">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^10$</field>
  <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe</field>
  <description>CRITIQUE - Accès mémoire LSASS détecté (credential dumping)</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
  <group>credential_access,lsass,</group>
</rule>
```

---

### Règle 100010 — Pass-the-Hash
**MITRE** : T1550.002 — Use Alternate Authentication Material / Pass the Hash
**Niveau** : 12 (Haut)
**Event ID surveillé** : Windows Security Event ID 4624 (ouverture de session)

**Raisonnement** : Le Pass-the-Hash génère une authentification réseau
(Logon Type 3) via NTLM. Une authentification NTLM de type réseau est légitime
dans certains cas, mais devient suspecte combinée à d'autres indicateurs
(heure inhabituelle, compte sensible, corrélation avec d'autres alertes).

Cette règle est volontairement large et doit être corrélée avec d'autres
indicateurs pour confirmer un véritable Pass-the-Hash.

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

---

## 4. Récapitulatif des règles

| Rule ID | Attaque | MITRE | Niveau | Event ID |
|---|---|---|---|---|
| 100001 | Mimikatz — nom de processus | T1003.001 | 15 — Critique | Sysmon 1 |
| 100003 | Accès mémoire LSASS | T1003.001 | 15 — Critique | Sysmon 10 |
| 100010 | Pass-the-Hash NTLM | T1550.002 | 12 — Haut | 4624 |
| 100030 | Brute force RDP | T1110.001 | 12 — Haut | 4625 |
| 100050 | Création de compte suspect | T1136.001 | 12 — Haut | 4720 |

---

## 5. Vérification dans le Dashboard

**Wazuh Dashboard → Rules → Manage rules → chercher `100001`**

> ![Rule_wazuh](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/etape-5/Rule_Mimikatz.PNG) : Dashboard Wazuh affichant la règle 100001 dans la liste des règles chargées.
