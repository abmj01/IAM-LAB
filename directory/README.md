# Directory: Samba Active Directory Domain Controller

The company "phone book": one server holding every user and group for `greenfield.lab`.
Keycloak reads from it (Phase 2) and midPoint writes to it (Phase 6).

| Setting | Value |
|---|---|
| VM name / hostname | `dc1` / `dc1.greenfield.lab` |
| OS | Ubuntu Server 24.04 LTS |
| IP (host-only network) | `192.168.56.10` |
| Kerberos realm / NetBIOS domain | `GREENFIELD.LAB` / `GREENFIELD` |
| LDAP base DN | `DC=greenfield,DC=lab` |

The VM has two network cards:
- **NIC 1 (NAT):** internet access for `apt`, plus SSH via port forward `127.0.0.1:2222`
- **NIC 2 (host-only):** fixed IP `192.168.56.10`, reachable from Windows, WSL and Docker

Each block below says **where** to run it: `[Windows PowerShell]`, `[VM]` or `[WSL]`.

---

## Step 1: Install VirtualBox and download Ubuntu `[Windows PowerShell]`

```powershell
winget install Oracle.VirtualBox
```

Download the **Ubuntu Server 24.04 LTS** ISO (`ubuntu-24.04.x-live-server-amd64.iso`) from
https://releases.ubuntu.com/24.04/ into your `Downloads` folder.

> VirtualBox runs alongside WSL2 (it uses Hyper-V underneath). It works but can be a bit slow.

## Step 2: Create the VM `[Windows PowerShell]`

```powershell
$vbox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$iso  = (Get-ChildItem "$HOME\Downloads\ubuntu-24.04*-live-server-amd64.iso" | Select-Object -First 1).FullName
$disk = "$HOME\VirtualBox VMs\dc1\dc1.vdi"

# Find the host-only adapter name (usually "VirtualBox Host-Only Ethernet Adapter", IP 192.168.56.1).
# If the list is empty, create one first with:  & $vbox hostonlyif create
& $vbox list hostonlyifs
$hostonly = "VirtualBox Host-Only Ethernet Adapter"

& $vbox createvm --name dc1 --ostype Ubuntu_64 --register
& $vbox modifyvm dc1 --memory 2048 --cpus 2 `
    --nic1 nat --natpf1 "ssh,tcp,127.0.0.1,2222,,22" `
    --nic2 hostonly --hostonlyadapter2 $hostonly
& $vbox createmedium disk --filename $disk --size 20480
& $vbox storagectl dc1 --name SATA --add sata --controller IntelAhci
& $vbox storageattach dc1 --storagectl SATA --port 0 --device 0 --type hdd --medium $disk
& $vbox storageattach dc1 --storagectl SATA --port 1 --device 0 --type dvddrive --medium $iso
& $vbox startvm dc1
```

## Step 3: Install Ubuntu (in the VM window)

Go through the installer with the defaults, except:
- **Your name / server name:** server name = `dc1`, pick your own username and password
- **SSH:** tick **Install OpenSSH server**
- **Featured snaps:** select nothing

When it says "Reboot now", press Enter. Then eject the ISO `[Windows PowerShell]`:

```powershell
& $vbox storageattach dc1 --storagectl SATA --port 1 --device 0 --medium emptydrive
```

## Step 4: SSH in so you can copy-paste `[Windows PowerShell]`

The VM window doesn't support paste, so work over SSH from now on:

```powershell
ssh -p 2222 YOURUSER@127.0.0.1
```

Everything in Steps 5–10 runs **inside this SSH session** `[VM]`.

## Step 5: Install packages `[VM]`

```bash
sudo apt update && sudo apt full-upgrade -y
sudo DEBIAN_FRONTEND=noninteractive apt install -y \
  acl attr samba samba-ad-dc samba-dsdb-modules samba-vfs-modules smbclient winbind \
  libpam-winbind libnss-winbind krb5-config krb5-user dnsutils ldap-utils chrony
```

## Step 6: Hostname and fixed IP `[VM]`

```bash
sudo hostnamectl set-hostname dc1
sudo sed -i '/127.0.1.1/d' /etc/hosts
echo '192.168.56.10 dc1.greenfield.lab dc1' | sudo tee -a /etc/hosts

# Stop cloud-init from overwriting our network config
echo 'network: {config: disabled}' | sudo tee /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg

# Check your interface names: usually enp0s3 (NAT) and enp0s8 (host-only)
ip -br link

sudo rm -f /etc/netplan/*.yaml
sudo tee /etc/netplan/01-greenfield.yaml >/dev/null <<'EOF'
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
      dhcp4-overrides:
        use-dns: false
    enp0s8:
      addresses: [192.168.56.10/24]
EOF
sudo chmod 600 /etc/netplan/01-greenfield.yaml
sudo netplan apply
ip -br addr   # enp0s8 should show 192.168.56.10
```

## Step 7: Hand DNS over to Samba `[VM]`

A domain controller is also the DNS server for its domain, so Ubuntu's own DNS service must step aside.

```bash
sudo systemctl disable --now smbd nmbd winbind systemd-resolved
sudo systemctl mask smbd nmbd winbind
sudo unlink /etc/resolv.conf
printf 'nameserver 127.0.0.1\nsearch greenfield.lab\n' | sudo tee /etc/resolv.conf
```

(Internet name lookups stop working until Samba starts in Step 8. That's expected.)

## Step 8: Create the domain `[VM]`

```bash
sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.orig

sudo samba-tool domain provision \
  --use-rfc2307 \
  --realm=GREENFIELD.LAB \
  --domain=GREENFIELD \
  --server-role=dc \
  --dns-backend=SAMBA_INTERNAL \
  --host-ip=192.168.56.10 \
  --option="interfaces = lo enp0s8" \
  --option="bind interfaces only = yes" \
  --option="dns forwarder = 1.1.1.1"

sudo cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
sudo systemctl unmask samba-ad-dc
sudo systemctl enable --now samba-ad-dc

# Set the domain Administrator password (min. 12 chars; store it in your password manager, NOT in Git)
sudo samba-tool user setpassword administrator
```

## Step 9: Check it works `[VM]`

```bash
sudo systemctl status samba-ad-dc --no-pager   # active (running)
sudo samba-tool domain level show              # shows the domain function level
host -t SRV _ldap._tcp.greenfield.lab          # -> dc1.greenfield.lab
host -t A dc1.greenfield.lab                   # -> 192.168.56.10
host ubuntu.com                                # internet DNS works again (via forwarder)
kinit administrator && klist                   # Kerberos ticket for administrator@GREENFIELD.LAB
sudo samba-tool user list                      # Administrator, Guest, krbtgt
```

## Step 10: Reach it from WSL `[WSL]`

```bash
ping -c 2 192.168.56.10

sudo apt install -y ldap-utils
# Samba refuses plain-text passwords over unencrypted LDAP, so use LDAPS (port 636).
# LDAPTLS_REQCERT=never accepts Samba's self-signed certificate. Fine for this lab only.
LDAPTLS_REQCERT=never ldapsearch -H ldaps://192.168.56.10 -x \
  -D 'administrator@greenfield.lab' -W \
  -b 'DC=greenfield,DC=lab' '(sAMAccountName=administrator)' dn
```

If `ping` fails from WSL but works from PowerShell (`ping 192.168.56.10`), switch WSL to mirrored
networking: add the following to `C:\Users\<you>\.wslconfig`, then run `wsl --shutdown` in PowerShell and reopen WSL.

```ini
[wsl2]
networkingMode=mirrored
```

---

## Day-to-day

```powershell
# [Windows PowerShell]
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm dc1 --type headless   # start without a window
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm dc1 acpipowerbutton  # clean shutdown
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" snapshot dc1 take "fresh-dc"   # save a restore point
```

Take a snapshot now, so you can roll back if you break something later.

## Next

- Create the OUs and groups (Phase 1, steps 2–3)
- Import users from `../data/employees.csv` (Phase 1, step 4)
- Set the password policy (Phase 1, step 5)
