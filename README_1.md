# 🛡️ Threat Intelligence Aggregator (Non-AI)

A real-world, rule-based Python tool that ingests IOC (Indicators of Compromise) threat feeds, parses indicators, normalizes data, correlates across feeds, generates blocklists, and produces a final threat intelligence report — with a full Streamlit web dashboard.

> ⚡ No AI or ML used — 100% deterministic, rule-based logic.

---

## 🚀 Live Demo

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://your-username-threat-intelligence-aggregator.streamlit.app)

---

## 📌 Pipeline (6 Steps)

| Step | What it does |
|------|-------------|
| 1. Load Feeds | Import IOC feeds from URLs, local files, or built-in samples |
| 2. Parse Indicators | Extract IPs, URLs, domains, MD5/SHA256 hashes, emails via regex |
| 3. Normalize Data | Drop private IPs, whitelisted entries, clean and standardize values |
| 4. Correlation Engine | Merge duplicates across feeds, boost risk score for multi-feed IOCs |
| 5. Blocklist Generation | Write category-based blocklist .txt files |
| 6. Final Reporting | Generate JSON + text summary report with risk scores |

---

## 📁 Project Structure

```
threat-intelligence-aggregator/
├── app.py              ← Streamlit web dashboard
├── ioc_engine.py       ← Core pipeline engine (all 6 steps)
├── requirements.txt    ← Python dependencies
└── README.md           ← This file
```

---

## ⚙️ How to Run Locally

**1. Clone the repository**
```bash
git clone https://github.com/your-username/threat-intelligence-aggregator.git
cd threat-intelligence-aggregator
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

**3. Launch the dashboard**
```bash
streamlit run app.py
```

**4. Open in browser**
```
http://localhost:8501
```

---

## 💻 CLI Usage (without dashboard)

```bash
# Demo mode — built-in sample feeds (works offline)
python run.py

# Live threat feeds (requires internet)
python run.py --urls

# Your own feed files
python run.py --files feed1.txt feed2.txt
```

---

## 📊 Dashboard Features

- ✅ Pipeline progress bar (all 6 steps live)
- ✅ Metric cards — Total IOCs, Critical, High, Medium, Low
- ✅ Risk distribution bar chart
- ✅ IOC types pie chart
- ✅ Full IOC table with risk score bars and filters
- ✅ Feed status panel
- ✅ Download buttons — TXT report, JSON report, blocklists
- ✅ Sidebar filters — by risk score and IOC type
- ✅ 3 feed modes — Sample, Live URLs, Upload your own

---

## 🔍 IOC Types Detected

| Type | Example |
|------|---------|
| IPv4 Address | `185.220.101.47` |
| Domain | `evil-domain.ru` |
| URL | `http://malicious-payload.xyz/shell.php` |
| MD5 Hash | `D41D8CD98F00B204E9800998ECF8427E` |
| SHA256 Hash | `A3F5B2C1D4E6F708...` |
| Email | `attacker@phishme.net` |

---

## ⚠️ Risk Scoring Model

| IOC Type | Base Score | +per extra feed |
|----------|-----------|-----------------|
| SHA-256  | 65        | +15             |
| MD5      | 60        | +15             |
| URL      | 50        | +15             |
| IP       | 40        | +15             |
| Domain   | 35        | +15             |
| Email    | 25        | +15             |

- Max score: **100**
- IOCs seen in 3+ feeds → tagged `HIGH_CONFIDENCE`
- Score ≥ 80 → `CRITICAL`
- Score 60–79 → `HIGH`
- Score 40–59 → `MEDIUM`
- Score < 40 → `LOW`

---

## 🌐 Live Threat Feed Sources

- [AlienVault OTX](https://reputation.alienvault.com/)
- [Abuse.ch URLhaus](https://urlhaus.abuse.ch/)
- [Emerging Threats](https://rules.emergingthreats.net/)
- [PhishTank](https://www.phishtank.com/)

---

## 🛠️ Tech Stack

| Tool | Purpose |
|------|---------|
| Python 3.7+ | Core language |
| Streamlit | Web dashboard |
| Plotly | Charts and visualizations |
| Pandas | Data handling |
| Regex | IOC extraction |

---

## 📄 Output Files

| File | Description |
|------|-------------|
| `output/blocklist_ip_*.txt` | IP blocklist |
| `output/blocklist_domain_*.txt` | Domain blocklist |
| `output/blocklist_url_*.txt` | URL blocklist |
| `output/blocklist_hash_md5_*.txt` | MD5 hash blocklist |
| `output/blocklist_hash_sha256_*.txt` | SHA256 hash blocklist |
| `output/blocklist_email_*.txt` | Email blocklist |
| `reports/ti_report_*.json` | Full JSON report |
| `reports/ti_report_*.txt` | Human-readable summary |

---

## 👤 Author

**Yashas**
- 🎓 VTU Graduate (2023)
- 🔐 Cybersecurity & Digital Forensics Enthusiast
- 📜 ISC2 CC | CHFI | CEH

---

## 📜 License

MIT License — free to use, modify, and share.
