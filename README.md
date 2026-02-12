# 🛡️ LogSentinel – Advanced SOC Log Analyzer

LogSentinel is an **interactive Apache access.log analyzer** designed for cybersecurity labs and controlled environments.

It simulates a SOC-style investigation by identifying:

- 🔍 Top attacking IP
- ⏱ Attack timeline (start / end)
- 📈 Peak requests per minute
- 🛠 Tool detection via User-Agent (Nmap, Nikto, sqlmap, ffuf, Gobuster, etc.)
- 📄 Automatic SOC-style report generation (Markdown + JSON)
- 🎮 Interactive terminal UI with animation and status LEDs

---

## ⚠️ Disclaimer

This tool is intended **only for authorized environments and cybersecurity labs**.

Do NOT use against systems without permission.

---

# 🚀 Installation

Repository:

https://github.com/taissocout/Analise_de_Log


---

# 🐉 Installing on Kali Linux

### 1️⃣ Clone the repository

```bash
git clone https://github.com/taissocout/Analise_de_Log.git
2️⃣ Enter the directory
cd Analise_de_Log
3️⃣ Run the tool
python3 logsentinel.py
Optional: Make executable
chmod +x logsentinel.py
./logsentinel.py
🪟 Running on Windows
Open PowerShell inside the project folder:

py .\logsentinel.py
or

python .\logsentinel.py
🧠 Interactive Mode (Default)
When executed without parameters:

python3 logsentinel.py
The tool will:

Ask if you already have an access.log

If not, request a URL

Download using:

wget (if available)

Python fallback (urllib)

Ask if you want to analyze immediately

Generate a report automatically

📂 Output
By default, results are stored in:

soc_report/
Generated files:

SOC_REPORT.md

data.json

access.log (if downloaded)

⚙️ CLI Mode (Advanced Usage)
Analyze local file
python3 logsentinel.py --file access.log --out report --json
Download and analyze
python3 logsentinel.py --url "http://example.com/access.log" --out report --json
📊 What the Report Includes
The generated SOC_REPORT.md contains:

Executive Summary

Top IPs by volume

Main IOC

Attack timeline

Tool fingerprinting

HTTP Status breakdown

Most targeted paths

Blue Team recommendations

🎮 Terminal UI Features
LogSentinel includes:

🕵️ Hooded character animation

🔎 Hunting animation

🟥🟨🟩 Status LEDs (red / yellow / green)

🔄 Live progress spinner

📊 Visual progress bars

Inspired by embedded security devices like Flipper Zero.

📁 Project Structure
Analise_de_Log/
├── logsentinel.py
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
├── examples/
│   └── access_sample.log
└── soc_report/   (generated output)
🔍 Tool Detection (User-Agent Based)
LogSentinel detects common tools such as:

Nmap

Nikto

sqlmap

Gobuster

ffuf

dirb

masscan

Burp Suite

OWASP ZAP

curl / wget

python-requests

🛠 Requirements
Python 3.x

(Optional) wget (Linux only)

No external Python libraries required

🧯 Troubleshooting
Windows says “python3 not found”
Use:

py .\logsentinel.py
URL error: unknown url type
Make sure the URL includes:

http://
Example:

http://www.example.com/access.log
📜 License
MIT License.

👨‍💻 Author
Taisso Cout
Cybersecurity Research • Blue Team • Offensive Security Labs

GitHub: https://github.com/taissocout