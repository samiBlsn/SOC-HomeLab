# 01 — Lab Setup : VMware & Configuration Réseau

## Objectif
Déployer l'infrastructure réseau virtuelle du lab SOC avec 5 VMs interconnectées
sur un réseau isolé VMware NAT.

---

## Environnement hôte

| Composant | Détail |
|---|---|
| CPU | AMD Ryzen 5 5700X (8c/16t) |
| RAM | 32 Go |
| Hyperviseur | VMware Workstation Pro 17+ |
| OS Hôte | Windows 11 |

---

## 1. Configuration du réseau VMware

### Création du réseau NAT dédié (VMnet2)

**Edit → Virtual Network Editor → Add Network → VMnet2**

| Paramètre | Valeur |
|---|---|
| Type | NAT |
| Subnet | 192.168.100.0 |
| Masque | 255.255.255.0 |
| DHCP | Désactivé (IPs statiques) |
| Gateway VMware | 192.168.100.2 (auto) |

> ![Virtual Network Editor - VMnet2](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/virtual_network.PNG) : Fenêtre Virtual Network Editor avec VMnet2 configuré
> (Edit → Virtual Network Editor)

---

## 2. VMs déployées

| VM | OS | RAM | CPU | Disque | IP |
|---|---|---|---|---|---|
| `DC01` | Windows Server 2022 Std Eval | 4 Go | 2 cœurs | 60 Go | 192.168.100.10 |
| `win10-client` | Windows 10 Pro | 2 Go | 2 cœurs | 40 Go | 192.168.100.20 |
| `ubuntu-endpoint` | Ubuntu 22.04 LTS Server | 2 Go | 1 cœur | 30 Go | 192.168.100.30 |
| `wazuh-server` | Ubuntu 22.04 LTS Server | 6 Go | 4 cœurs | 80 Go | 192.168.100.50 |
| `kali` | Kali Linux Rolling | 2 Go | 2 cœurs | 40 Go | 192.168.100.40 |

**Total alloué** : 16 Go RAM / ~11 vCPUs / ~250 Go stockage

> ![VMWare VMS](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/vmware_vms.PNG) : Liste des 5 VMs dans VMware Workstation (panneau gauche)

---

## 3. Configuration IP statique — Windows

### DC01 (Windows Server 2022)

Exécuté en PowerShell 64 bits **Administrateur** :

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.100.10 -PrefixLength 24 -DefaultGateway 192.168.100.2
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 127.0.0.1
```

### win10-client (Windows 10 Pro)

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.100.20 -PrefixLength 24 -DefaultGateway 192.168.100.2
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 192.168.100.10
```

## 4. Configuration IP statique — Ubuntu

### Fix cloud-init (obligatoire)

Par défaut, cloud-init réinitialise la config réseau à chaque reboot.
Pour le désactiver sur **chaque VM Ubuntu** :

```bash
sudo bash -c 'echo "network: {config: disabled}" > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg'
```

### Fichier Netplan — `/etc/netplan/50-cloud-init.yaml`

**ubuntu-endpoint (192.168.100.30) :**

```yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: no
      addresses:
        - 192.168.100.30/24
      routes:
        - to: default
          via: 192.168.100.2
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
```

**wazuh-server (192.168.100.50) :**

```yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: no
      addresses:
        - 192.168.100.50/24
      routes:
        - to: default
          via: 192.168.100.2
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
```

Appliquer la configuration :

```bash
sudo netplan apply
```

## 5. Fix pare-feu Windows (ICMP)

Par défaut, Windows bloque les pings. Commande à exécuter sur **DC01 et win10-client** :

```powershell
Set-NetFirewallRule -DisplayName "Partage de fichiers et d'imprimantes (Demande d'écho - Trafic entrant ICMPv4)" -Enabled True
```

---

## 6. Vérification de la connectivité

Test depuis DC01 :

```powershell
ping 192.168.100.20
ping 192.168.100.30
ping 192.168.100.50
ping 8.8.8.8
```

> ![Ping_DC01](https://raw.githubusercontent.com/samiBlsn/SOC-HomeLab/main/screenshots/ping_dc01.PNG) : Terminal montrant les pings réussis entre les VMs
> (depuis DC01 vers les autres IPs)

**Résultat attendu** : 0% packet loss sur toutes les destinations.

---

## Schéma réseau

```
VMware Workstation — Host (192.168.100.0/24 — VMnet2 NAT)
│
├── 192.168.100.10   DC01              Windows Server 2022   AD DS · DNS
├── 192.168.100.20   win10-client      Windows 10 Pro        Endpoint
├── 192.168.100.30   ubuntu-endpoint   Ubuntu 22.04          Endpoint
├── 192.168.100.40   kali              Kali Linux            Attacker
└── 192.168.100.50   wazuh-server      Ubuntu 22.04          Wazuh Stack
```
