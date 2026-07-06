# IOC Extractor Tool

A lightweight **Incident Response & DFIR utility** that extracts Indicators of Compromise (IOCs) from raw logs and text files to speed up investigation and threat hunting.

---

## 🎯 Purpose
During an incident, analysts often deal with unstructured data.  
This tool helps SOC Analysts quickly extract actionable IOCs for:

- Threat hunting
- SIEM detection rules
- Firewall / EDR blocking
- Incident reporting
- Timeline correlation

---

## 🔍 Supported IOC Types
- IPv4 addresses
- Domains
- URLs
- File hashes:
  - MD5
  - SHA1
  - SHA256

---

## 🚀 Usage

### Basic
```bash
python3 ioc_extractor.py suspicious.log
