# DFIR Artifact Checklist (Windows / Linux / Network)

This checklist helps SOC Analysts and DFIR practitioners quickly identify **what evidence to collect** during:
- Live Response (system still running)
- Post-Incident / Disk analysis
- Threat hunting & scoping

> ✅ Tip: Always preserve timestamps, document hash values, and keep a clear chain of custody.

---

## 0) Collection Principles (Quick)
- Record: system time, timezone, hostname, IPs, logged-in users
- Prefer read-only collection (avoid modifying artifacts)
- Hash evidence (SHA256) and store hashes separately
- Collect volatile data first (RAM, network connections)
- Document everything (who/when/how)

---

## 1) Windows Artifacts

### A) Volatile / Live Response (collect first)
- Running processes + command lines
- Network connections (established/listening)
- Logged-on users & sessions
- Scheduled tasks running now
- Loaded DLLs (if possible)
- Clipboard (optional), mapped drives
- Memory dump (if allowed)

### B) Logs
- Windows Event Logs:
  - Security.evtx
  - System.evtx
  - Application.evtx
  - Microsoft-Windows-Sysmon/Operational (if Sysmon exists)
  - PowerShell logs (if enabled)
- Windows Defender / AV logs (if available)

### C) Persistence & Execution
- Startup folders
- Registry Run keys:
  - HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  - HKLM\Software\Microsoft\Windows\CurrentVersion\Run
- Services:
  - service config, image paths
- Scheduled Tasks:
  - Task Scheduler XMLs
- WMI persistence (subscription filters/consumers)

### D) File Execution & Program Traces
- Prefetch (*.pf)
- Amcache.hve
- ShimCache / AppCompatCache
- SRUM (network/app usage timeline)
- Jump Lists
- Recent files / LNK files
- Recycle Bin

### E) Registry Hives (for offline analysis)
- SAM
- SYSTEM
- SECURITY
- SOFTWARE
- NTUSER.DAT (per-user)
- UsrClass.dat (per-user)

### F) Browser / User Activity
- Chrome/Edge/Firefox history + downloads + cookies (where permitted)
- Saved credentials (handle carefully and legally)
- Email clients artifacts (Outlook PST/OST if in scope)

---

## 2) Linux Artifacts

### A) Volatile / Live Response (collect first)
- `ps aux`, process tree
- Open files/sockets (lsof)
- Active connections (ss/netstat)
- Logged-in users (who, w)
- Loaded kernel modules
- Running services (systemd)
- Memory dump (if allowed)

### B) Logs
- Authentication:
  - /var/log/auth.log (Debian/Ubuntu)
  - /var/log/secure (RHEL/CentOS)
- Syslog:
  - /var/log/syslog
  - /var/log/messages
- systemd journal:
  - journalctl output / persistent journal files
- Web logs (if server):
  - /var/log/apache2/access.log / error.log
  - /var/log/nginx/access.log / error.log

### C) Persistence & Scheduled Execution
- Cron:
  - /etc/crontab
  - /etc/cron.*/*
  - user crontabs
- systemd services/timers:
  - /etc/systemd/system/
  - systemctl list-timers
- SSH:
  - ~/.ssh/authorized_keys
  - /etc/ssh/sshd_config
- Shell profiles:
  - ~/.bashrc, ~/.profile, ~/.zshrc

### D) Accounts & Access
- /etc/passwd, /etc/shadow, /etc/group
- sudo configuration:
  - /etc/sudoers, /etc/sudoers.d/
- SSH login history:
  - /var/log/wtmp, /var/log/btmp, lastlog

### E) Command History & User Activity
- ~/.bash_history, ~/.zsh_history
- .viminfo, recent files (if relevant)
- Downloads directory (user context)

---

## 3) Network Artifacts

### A) Packet & Flow Data
- PCAP (full packet capture) if available
- NetFlow / sFlow (if enabled)
- IDS/IPS logs (Suricata/Snort)

### B) DNS
- DNS resolver logs
- DNS query logs from:
  - firewall / proxy
  - endpoint agents
  - AD DNS (Windows)
- Suspicious patterns:
  - DGA-like domains
  - high NXDOMAIN rate
  - unusual TLDs

### C) Web / Proxy
- Proxy logs (URLs, user agents, response codes)
- Web gateway logs
- TLS inspection logs (if present)

### D) Firewall / VPN
- Firewall allow/deny events
- NAT logs (mapping internal to public)
- VPN connection logs (user, source IP, duration)

---

## 4) Cloud (Optional but Valuable)

### A) Identity & Auth
- Azure AD / Entra sign-in logs
- MFA events & changes
- Risky sign-ins / impossible travel alerts

### B) Activity Logs
- Azure Activity Logs
- AWS CloudTrail
- GCP Audit Logs

### C) Email / Collaboration
- O365 audit logs (mailbox access, forwarding rules)
- Suspicious inbox rules, OAuth app consents
- SharePoint/OneDrive file access logs

---

## 5) Quick Triage Questions (Analyst Checklist)
- What is the initial access vector?
- Which accounts were used?
- Any persistence created?
- Any lateral movement signs?
- Any exfiltration indicators?
- What is the timeline of key events?
- What IOCs should be blocked / detected?

---

## 6) Output & Documentation
- Preserve evidence with hashes (SHA256)
- Maintain chain-of-custody notes
- Create a short incident summary:
  - Impact
  - Timeline
  - Root cause (if known)
  - Containment actions
  - Recommended detections & hardening
