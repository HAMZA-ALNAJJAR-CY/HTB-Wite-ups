# HTB Writeups — Z3R0

Personal collection of Hack The Box machine writeups, written while preparing for the CPTS certification. Only retired machines are included, per [HTB's writeup policy](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines).

| Machine | Difficulty | OS | Key Techniques |
|---|---|---|---|
| [Facts](machines/medium/facts.md) | Medium | Linux | CVE-2024-46987, CVE-2025-2304, MinIO/S3, sudo `facter` RCE |
| [Support](machines/easy/support.md) | Easy | Windows AD | .NET reversing, LDAP, RBCD |
| [TwoMillion](machines/easy/twomillion.md) | Easy | Linux | Broken Access Control, Command Injection, CVE-2023-0386 |

## Structure

```
HTB-writeups/
├── machines/
│   ├── easy/
│   └── medium/
└── README.md
```

---

**Author:** Hamza Al-Najjar (Z3R0) — Offensive Security Practitioner
**Portfolio:** hamza-alnajjar-cy.github.io
