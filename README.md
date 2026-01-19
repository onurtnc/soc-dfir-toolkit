# 🛡️ SOC & DFIR Toolkit

A practical **Digital Forensics & Incident Response toolkit** built for SOC Analysts, DFIR practitioners, and Blue Team operations.  
This repository contains custom scripts and checklists used for log analysis, IOC extraction, timeline creation, and incident investigation.

---

## 🎯 Purpose
This toolkit is designed to help SOC Analysts and DFIR teams:
- Quickly analyze logs during incidents
- Extract IOCs from raw data
- Build investigation timelines
- Standardize forensic artifact collection
- Improve response time in real-world incidents

---

## 📦 Toolkit Structure

🔄 How to Run the Full DFIR Workflow

This section demonstrates how to use the toolkit end-to-end during a real incident investigation.

1️⃣ Parse Raw Logs

Convert raw logs into structured events for analysis.

Komutlar:
python3 log_parser/log_parser.py /var/log/auth.log --year 2026 --out auth.parsed.jsonl
python3 log_parser/log_parser.py /var/log/apache2/access.log --out access.parsed.jsonl

2️⃣ Extract Indicators of Compromise (IOCs)

Extract actionable indicators from logs or any investigation notes.

Komut:
python3 ioc_extractor/ioc_extractor.py auth.parsed.jsonl --out iocs.json

3️⃣ Build the Investigation Timeline

Merge all events into a single chronological timeline and mark suspicious activity.

Komut:
python3 timeline_analysis/timeline.py --inputs auth.parsed.jsonl access.parsed.jsonl --ioc-file iocs.json --out timeline.jsonl

4️⃣ Review & Investigate

After generating the timeline:

Review timeline for suspicious patterns

Validate IOCs (VirusTotal, MISP, OTX)

Identify persistence and lateral movement

Collect artifacts using the DFIR checklist

Write the incident report

📈 Example Analyst Workflow

Raw Logs → Log Parser → Structured Events → IOC Extractor → Validated IOCs → Timeline Analyzer → Incident Report & Detections

✅ Result

You now have a complete DFIR investigation pipeline that can be used for:

SOC alert triage

Incident response

Threat hunting

Detection engineering

Post-incident reporting
