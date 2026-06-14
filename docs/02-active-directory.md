# 02 — Active Directory : Installation & Configuration

## Objectif
Déployer un contrôleur de domaine Active Directory sur DC01 avec une structure
d'OUs, des utilisateurs de test et des GPOs d'audit adaptées à la détection SOC.

---

## Environnement

| Paramètre | Valeur |
|---|---|
| Serveur | DC01 — 192.168.100.10 |
| OS | Windows Server 2022 Standard Evaluation |
| Domaine | lab.local |
| NetBIOS | LAB |

---

## 1. Renommage du serveur

```powershell
Rename-Computer -NewName "DC01" -Restart
```

Après reboot, reconnexion en Administrateur local.

---

## 2. Installation du rôle AD DS

Exécuté en **Windows PowerShell 64 bits Administrateur** :

```powershell
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
```

Résultat attendu :

```
Success  Restart Needed  Exit Code  Feature Result
-------  --------------  ---------  --------------
True     No              Success    {Active Directory Domain Services, ...}
```


## 3. Promotion en Domain Controller

```powershell
Install-ADDSForest `
  -DomainName "lab.local" `
  -DomainNetbiosName "LAB" `
  -ForestMode "WinThreshold" `
  -DomainMode "WinThreshold" `
  -InstallDns:$true `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "Lab@Admin2024!" -AsPlainText -Force) `
  -Force:$true
```

> Le serveur redémarre automatiquement à la fin — comportement normal.
> Après reboot, connexion avec `LAB\Administrator`.

### Vérification

```powershell
Get-ADDomain
Get-ADForest
```

> ![ADDomain](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/AD_domain.PNG) : Output de `Get-ADDomain` montrant `lab.local`
> dans PowerShell sur DC01 après le reboot.

---

## 4. Structure Organisationnelle (OUs)

```powershell
New-ADOrganizationalUnit -Name "SOC-Lab" -Path "DC=lab,DC=local"
New-ADOrganizationalUnit -Name "Users" -Path "OU=SOC-Lab,DC=lab,DC=local"
New-ADOrganizationalUnit -Name "Servers" -Path "OU=SOC-Lab,DC=lab,DC=local"
New-ADOrganizationalUnit -Name "Workstations" -Path "OU=SOC-Lab,DC=lab,DC=local"
```

Structure créée :

```
lab.local
└── SOC-Lab
    ├── Users
    ├── Servers
    └── Workstations
```

---

## 5. Groupes de sécurité

```powershell
New-ADGroup -Name "SOC-Analysts" -GroupScope Global -Path "OU=Users,OU=SOC-Lab,DC=lab,DC=local"
New-ADGroup -Name "IT-Admins" -GroupScope Global -Path "OU=Users,OU=SOC-Lab,DC=lab,DC=local"
```

---

## 6. Comptes utilisateurs

```powershell
$password = ConvertTo-SecureString "Lab@User2024!" -AsPlainText -Force

New-ADUser -Name "John Smith" -GivenName "John" -Surname "Smith" `
  -SamAccountName "jsmith" -UserPrincipalName "jsmith@lab.local" `
  -Path "OU=Users,OU=SOC-Lab,DC=lab,DC=local" `
  -AccountPassword $password -Enabled $true

New-ADUser -Name "Alice Martin" -GivenName "Alice" -Surname "Martin" `
  -SamAccountName "amartin" -UserPrincipalName "amartin@lab.local" `
  -Path "OU=Users,OU=SOC-Lab,DC=lab,DC=local" `
  -AccountPassword $password -Enabled $true

New-ADUser -Name "Bob Admin" -GivenName "Bob" -Surname "Admin" `
  -SamAccountName "badmin" -UserPrincipalName "badmin@lab.local" `
  -Path "OU=Users,OU=SOC-Lab,DC=lab,DC=local" `
  -AccountPassword $password -Enabled $true
```

### Membres des groupes

```powershell
# Note : groupes en français sur Windows FR
Add-ADGroupMember -Identity "Admins du domaine" -Members "badmin"
Add-ADGroupMember -Identity "IT-Admins" -Members "badmin"
Add-ADGroupMember -Identity "SOC-Analysts" -Members "jsmith","amartin"
```


### Tableau récapitulatif des comptes

| Utilisateur | Login | Rôle | Groupe |
|---|---|---|---|
| John Smith | jsmith | Analyste SOC | SOC-Analysts |
| Alice Martin | amartin | Analyste SOC | SOC-Analysts |
| Bob Admin | badmin | Admin IT | IT-Admins + **Admins du domaine** |

> ![ADUsers](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/AD_users.PNG) : Output de la commande suivante dans PowerShell :
> `Get-ADUser -Filter * -SearchBase "OU=SOC-Lab,DC=lab,DC=local" -Properties Enabled | Select Name, SamAccountName, Enabled`
> montrant les 3 utilisateurs avec Enabled = True.

---

## 7. GPO d'audit (Stratégie d'audit avancée)

Les audits Windows sont essentiels pour alimenter Wazuh en logs exploitables.

```powershell
auditpol /set /subcategory:"Création du processus" /success:enable /failure:enable
auditpol /set /subcategory:"Fin du processus" /success:enable /failure:enable
auditpol /set /subcategory:"Ouvrir la session" /success:enable /failure:enable
auditpol /set /subcategory:"Fermer la session" /success:enable /failure:enable
auditpol /set /subcategory:"Verrouillage du compte" /success:enable /failure:enable
auditpol /set /subcategory:"Utilisation de privilèges sensibles" /success:enable /failure:enable
auditpol /set /subcategory:"Gestion des comptes d'utilisateur" /success:enable /failure:enable
auditpol /set /subcategory:"Modification du service d'annuaire" /success:enable /failure:enable
auditpol /set /subcategory:"Partage de fichiers" /success:enable /failure:enable
```

### Vérification

```powershell
auditpol /get /subcategory:"Création du processus"
auditpol /get /subcategory:"Ouvrir la session"
```

Résultat attendu : **Succès et échec** sur les deux sous-catégories.

> ![ADDomain](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/auditpol.PNG) : Output de `auditpol /get /category:*` dans PowerShell
> montrant les sous-catégories clés avec "Succès et échec".

### Événements Windows générés (référence)

| Event ID | Description | Utilité SOC |
|---|---|---|
| 4624 | Ouverture de session réussie | Détection PTH, accès suspects |
| 4625 | Échec d'ouverture de session | Brute force |
| 4648 | Ouverture de session avec credentials explicites | Lateral movement |
| 4672 | Privilèges spéciaux assignés | Escalade de privilèges |
| 4688 | Création de processus | Exécution Mimikatz |
| 4720 | Création de compte utilisateur | Persistance |
| 4768 | Demande de ticket Kerberos (TGT) | Kerberoasting |

---

## 8. Vérification finale

```powershell
# Utilisateurs
Get-ADUser -Filter * -SearchBase "OU=SOC-Lab,DC=lab,DC=local" | Select Name, SamAccountName, Enabled

# OUs
Get-ADOrganizationalUnit -Filter * | Select Name, DistinguishedName

# Membres Admins du domaine
Get-ADGroupMember -Identity "Admins du domaine" | Select Name, SamAccountName
```

> ![ADDomain](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/console_users_soclab.PNG) : Console "Utilisateurs et ordinateurs Active Directory"
> (DSA.msc) montrant l'arborescence SOC-Lab avec les OUs et utilisateurs.
> Ouvrir avec : touche Windows → taper `dsa.msc` → Entrée.
