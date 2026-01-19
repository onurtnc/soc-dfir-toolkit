# Timeline Analyzer Tool

Build a single **incident investigation timeline** from multiple log sources.  
This tool helps SOC Analysts and DFIR practitioners correlate events across systems and quickly understand what happened, when, and in what order.

---

## 🎯 Purpose
During incident response, logs are scattered across different sources.  
This tool merges them into one **chronological timeline** for:

- Incident triage & scoping
- Brute-force / suspicious login correlation
- Web access + authentication correlation
- Evidence collection & reporting
- IOC-driven timeline marking

---

## ✅ Supported Inputs (auto-detected best-effort)

### 1) Parsed JSONL events  
Output from **Log Parser Tool**:
- `*.parsed.jsonl`

### 2) Raw Linux auth.log (sshd)
- `/var/log/auth.log`

### 3) Raw Apache access.log
- Common / combined formats

### 4) Optional IOC file (JSON)
Output from **IOC Extractor Tool**:
- `*.iocs.json`

---

## 🚀 Usage

### Basic timeline from raw logs
> `auth.log` usually has no year → use `--year`
```bash
python3 timeline.py --inputs auth.log access.log --year 2026 --out timeline.jsonl
