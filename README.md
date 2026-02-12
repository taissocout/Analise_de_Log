# 🛡️ LogSentinel

**LogSentinel** is an **interactive SOC-style Apache access.log analyzer** designed for **controlled labs** (e.g., DESEC training).  
It identifies the **top source IP by request volume**, extracts an **attack timeline**, detects common **automation/scanning tools via User-Agent**, and generates a **Mini SOC Report** in Markdown.

> ⚠️ **For educational use in authorized environments only.**

---

## ✨ Features

- ✅ **Interactive mode (Y/N prompts)**: detects if you already have `access.log` or downloads it
- ✅ **Download support**: tries `wget`, falls back to **Python urllib** (works on Windows too)
- ✅ Finds **top IPs** by request count
- ✅ Extracts **attack window (start/end)** for the top IP
- ✅ Detects tools by User-Agent (e.g., **Nmap, Nikto, sqlmap, ffuf, Gobuster**)
- ✅ Calculates **peak requests/min**
- ✅ Produces:
  - `SOC_REPORT.md` (Mini SOC report)
  - `data.json` (raw structured output)

---

## 🖥️ Demo Flow (Interactive)

1) Ask if you already have an `access.log`  
2) If not, asks for a URL and downloads it  
3) Asks if you want to analyze immediately  
4) Generates the report folder automatically

---

## ✅ Requirements

- Python 3.x
- (Optional) `wget` on Linux/Kali — not required on Windows

No external Python dependencies.

---

## 🚀 Usage

### Windows (PowerShell)
```powershell
py .\logsentinel.py
Kali / Linux
python3 logsentinel.py
⚙️ CLI Mode (Optional)
Analyze a local file
python3 logsentinel.py --file access.log --out soc_report --json
Download and analyze via URL
python3 logsentinel.py --url "http://example.com/access.log" --out soc_report --json
📄 Output
Default output folder: soc_report/

soc_report/SOC_REPORT.md

soc_report/data.json

If you used --url, it also stores the downloaded:

soc_report/access.log