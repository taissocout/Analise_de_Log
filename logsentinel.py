def banner():
    print(r"""
██╗      ██████╗  ██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██║     ██╔═══██╗██╔════╝ ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
██║     ██║   ██║██║  ███╗█████╗  █████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
██║     ██║   ██║██║   ██║██╔══╝  ██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
███████╗╚██████╔╝╚██████╔╝███████╗███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

        LogSentinel - Advanced SOC Log Analyzer
        Author: Cout | Controlled Lab Use
""")
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import collections
import datetime as dt
import json
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3}git)\s+(?P<size>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

# Heurística de ferramentas comuns (User-Agent)
TOOL_SIGNATURES = [
    ("Nikto", re.compile(r"nikto", re.I)),
    ("Nmap", re.compile(r"\bnmap\b", re.I)),
    ("sqlmap", re.compile(r"sqlmap", re.I)),
    ("Gobuster", re.compile(r"gobuster", re.I)),
    ("ffuf", re.compile(r"\bffuf\b", re.I)),
    ("dirb/dirbuster", re.compile(r"\bdirb\b|\bdirbuster\b", re.I)),
    ("Wfuzz", re.compile(r"wfuzz", re.I)),
    ("masscan", re.compile(r"masscan", re.I)),
    ("curl", re.compile(r"\bcurl\b", re.I)),
    ("wget", re.compile(r"\bwget\b", re.I)),
    ("python-requests", re.compile(r"python-requests", re.I)),
    ("java", re.compile(r"\bjava\b", re.I)),
    ("Go-http-client", re.compile(r"go-http-client", re.I)),
    ("Burp Suite", re.compile(r"burp", re.I)),
    ("ZAP", re.compile(r"\bzap\b|owasp\s*zap", re.I)),
]

MONTHS = {
    "Jan":"01","Feb":"02","Mar":"03","Apr":"04","May":"05","Jun":"06",
    "Jul":"07","Aug":"08","Sep":"09","Oct":"10","Nov":"11","Dec":"12"
}

def parse_apache_time(ts: str) -> Optional[dt.datetime]:
    """
    Ex: 13/Feb/2026:00:21:34 -0300
    """
    try:
        return dt.datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
    except Exception:
        # fallback sem timezone
        try:
            return dt.datetime.strptime(ts.split(" ")[0], "%d/%b/%Y:%H:%M:%S")
        except Exception:
            return None

def detect_tool(user_agent: str) -> str:
    for name, rx in TOOL_SIGNATURES:
        if rx.search(user_agent or ""):
            return name
    return "Browser/Unknown"

def wget_download(url: str, out_path: str) -> None:
    # Usa wget se existir; senão tenta curl
    if shutil_which("wget"):
        cmd = ["wget", "-q", "-O", out_path, url]
    elif shutil_which("curl"):
        cmd = ["curl", "-sSL", "-o", out_path, url]
    else:
        raise RuntimeError("Nem wget nem curl encontrados no sistema.")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"Falha ao baixar log.\nSTDERR:\n{r.stderr}")

def shutil_which(cmd: str) -> Optional[str]:
    for p in os.environ.get("PATH", "").split(os.pathsep):
        full = os.path.join(p, cmd)
        if os.path.isfile(full) and os.access(full, os.X_OK):
            return full
    return None

def analyze_log(path: str, top_n: int = 10) -> Dict:
    ip_counts = collections.Counter()

    # Para análise detalhada do top IP, vamos precisar re-ler depois
    total_lines = 0
    parse_errors = 0

    with open(path, "r", errors="replace") as f:
        for line in f:
            total_lines += 1
            m = APACHE_RE.match(line)
            if not m:
                parse_errors += 1
                continue
            ip_counts[m.group("ip")] += 1

    if not ip_counts:
        raise RuntimeError("Não consegui extrair nenhum IP. O log está em formato diferente do Apache combinado?")

    top_ips = ip_counts.most_common(top_n)
    top_ip, top_ip_hits = top_ips[0]

    # Agora análise focada no top_ip
    status_counts = collections.Counter()
    tool_counts = collections.Counter()
    path_counts = collections.Counter()
    method_counts = collections.Counter()
    minute_buckets = collections.Counter()

    first_seen = None
    last_seen = None

    # timeline por ferramenta (início/fim)
    tool_first_last: Dict[str, Tuple[Optional[dt.datetime], Optional[dt.datetime]]] = {}

    with open(path, "r", errors="replace") as f:
        for line in f:
            m = APACHE_RE.match(line)
            if not m:
                continue

            ip = m.group("ip")
            if ip != top_ip:
                continue

            ts = parse_apache_time(m.group("ts"))
            ua = m.group("ua") or ""
            tool = detect_tool(ua)
            status = m.group("status")
            method = m.group("method")
            req_path = m.group("path")

            status_counts[status] += 1
            tool_counts[tool] += 1
            method_counts[method] += 1
            path_counts[req_path] += 1

            if ts:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

                minute_key = ts.strftime("%Y-%m-%d %H:%M")
                minute_buckets[minute_key] += 1

                cur_first, cur_last = tool_first_last.get(tool, (None, None))
                if cur_first is None or ts < cur_first:
                    cur_first = ts
                if cur_last is None or ts > cur_last:
                    cur_last = ts
                tool_first_last[tool] = (cur_first, cur_last)

    # pico de req/min
    peak_minute, peak_rpm = (None, 0)
    if minute_buckets:
        peak_minute, peak_rpm = max(minute_buckets.items(), key=lambda x: x[1])

    # Top paths suspeitos (muitos 404 normalmente)
    top_paths = path_counts.most_common(15)

    def fmt_ts(x: Optional[dt.datetime]) -> Optional[str]:
        if not x:
            return None
        try:
            return x.isoformat()
        except Exception:
            return str(x)

    tool_timeline = []
    for tool, (a, b) in sorted(tool_first_last.items(), key=lambda kv: tool_counts[kv[0]], reverse=True):
        tool_timeline.append({
            "tool": tool,
            "hits": tool_counts[tool],
            "first_seen": fmt_ts(a),
            "last_seen": fmt_ts(b),
        })

    result = {
        "meta": {
            "log_path": os.path.abspath(path),
            "total_lines": total_lines,
            "parse_errors": parse_errors,
            "unique_ips": len(ip_counts),
        },
        "top_ips": [{"ip": ip, "hits": hits} for ip, hits in top_ips],
        "primary_suspect": {
            "ip": top_ip,
            "hits": top_ip_hits,
            "first_seen": fmt_ts(first_seen),
            "last_seen": fmt_ts(last_seen),
            "peak_minute": peak_minute,
            "peak_requests_per_minute": peak_rpm,
            "status_codes": dict(status_counts),
            "methods": dict(method_counts),
            "tools": dict(tool_counts),
            "tool_timeline": tool_timeline,
            "top_paths": [{"path": p, "hits": h} for p, h in top_paths],
        }
    }
    return result

def render_soc_report_md(data: Dict) -> str:
    meta = data["meta"]
    suspect = data["primary_suspect"]
    top_ips = data["top_ips"]

    def pct(part: int, whole: int) -> str:
        if whole <= 0:
            return "0%"
        return f"{(part/whole)*100:.2f}%"

    total_lines = meta["total_lines"]
    suspect_hits = suspect["hits"]

    # Heurística simples de severidade
    # - muito volume + scanners conhecidos => HIGH
    tools = suspect.get("tools", {})
    scanners = sum(tools.get(k, 0) for k in ["Nmap", "Nikto", "sqlmap", "Gobuster", "ffuf", "dirb/dirbuster", "Wfuzz", "masscan"])
    sev = "LOW"
    if suspect_hits > 5000 or scanners > 1000:
        sev = "MEDIUM"
    if suspect_hits > 15000 or (tools.get("Nikto", 0) + tools.get("Nmap", 0) + tools.get("sqlmap", 0)) > 2000:
        sev = "HIGH"

    lines = []
    lines.append("# Mini SOC Report — Análise de Access Log (Apache)")
    lines.append("")
    lines.append(f"**Arquivo:** `{meta['log_path']}`  ")
    lines.append(f"**Total de linhas:** {total_lines}  ")
    lines.append(f"**IPs únicos:** {meta['unique_ips']}  ")
    lines.append(f"**Linhas com erro de parse:** {meta['parse_errors']}  ")
    lines.append("")
    lines.append("## 1) Executive Summary")
    lines.append("")
    lines.append(f"Foi identificado um **IP com comportamento fortemente automatizado**: **`{suspect['ip']}`**, responsável por **{suspect_hits} requisições** ({pct(suspect_hits, total_lines)} do log).")
    lines.append(f"O período observado para este IP vai de **{suspect['first_seen']}** até **{suspect['last_seen']}**.")
    lines.append(f"Ferramentas e padrões compatíveis com varredura foram encontrados (ex.: **Nmap/Nikto/sqlmap/dir brute** quando aplicável).")
    lines.append(f"**Severidade (heurística): {sev}**")
    lines.append("")
    lines.append("## 2) Principais IPs por volume")
    lines.append("")
    lines.append("| Rank | IP | Requisições |")
    lines.append("|---:|---|---:|")
    for i, item in enumerate(top_ips, start=1):
        lines.append(f"| {i} | `{item['ip']}` | {item['hits']} |")
    lines.append("")
    lines.append("## 3) IOC Principal")
    lines.append("")
    lines.append(f"- **IP:** `{suspect['ip']}`")
    lines.append(f"- **Janela temporal:** {suspect['first_seen']} → {suspect['last_seen']}")
    lines.append(f"- **Pico de volume:** {suspect.get('peak_requests_per_minute', 0)} req/min em `{suspect.get('peak_minute')}`")
    lines.append("")
    lines.append("## 4) Indicadores de Ferramentas (User-Agent)")
    lines.append("")
    lines.append("| Ferramenta/Classe | Hits | Primeiro visto | Último visto |")
    lines.append("|---|---:|---|---|")
    for t in suspect.get("tool_timeline", []):
        lines.append(f"| {t['tool']} | {t['hits']} | {t['first_seen']} | {t['last_seen']} |")
    lines.append("")
    lines.append("## 5) Status Codes (para inferir enumeração/exploração)")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(suspect.get("status_codes", {}), indent=2, ensure_ascii=False))
    lines.append("```")
    lines.append("")
    lines.append("## 6) Top Alvos (Paths mais requisitados)")
    lines.append("")
    lines.append("| Path | Hits |")
    lines.append("|---|---:|")
    for p in suspect.get("top_paths", []):
        lines.append(f"| `{p['path']}` | {p['hits']} |")
    lines.append("")
    lines.append("## 7) Recomendações (Blue Team / Hardening)")
    lines.append("")
    lines.append("- Bloquear/mitigar o IP via firewall/WAF (em ambiente real).")
    lines.append("- Habilitar **rate limiting** e regras contra varredura (ex.: limites por IP/UA).")
    lines.append("- Revisar `error.log` e logs de autenticação para sinais de exploração bem-sucedida.")
    lines.append("- Aplicar baseline de headers e hardening do servidor web.")
    lines.append("- Monitorar novos picos com alertas (req/min, 404 spike, UA scanner).")
    lines.append("")
    lines.append("## 8) Observações")
    lines.append("")
    lines.append("> Este relatório foi gerado automaticamente por heurísticas e contagens. Em SOC real, a validação cruza: WAF/IDS, DNS, Netflow, EDR e integridade do host.")
    lines.append("")
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser(
        description="SOCLog — analisador automatizado de access.log (Apache) + mini SOC report"
    )
    ap.add_argument("--url", help="URL para baixar o access.log (usa wget/curl)")
    ap.add_argument("--file", help="Caminho do log local (access.log)")
    ap.add_argument("--out", default="soc_report", help="Diretório de saída (default: soc_report)")
    ap.add_argument("--top", type=int, default=10, help="Top N IPs (default: 10)")
    ap.add_argument("--json", action="store_true", help="Salvar também JSON com dados brutos")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)

    log_path = None
    if args.url:
        log_path = os.path.join(args.out, "access.log")
        print(f"[+] Baixando log: {args.url}")
        # download
        if shutil_which("wget"):
            r = subprocess.run(["wget", "-q", "-O", log_path, args.url])
            if r.returncode != 0:
                print("[-] wget falhou. Tentando curl...")
                if not shutil_which("curl"):
                    raise SystemExit("Nem wget nem curl disponíveis.")
                r2 = subprocess.run(["curl", "-sSL", "-o", log_path, args.url])
                if r2.returncode != 0:
                    raise SystemExit("Falha ao baixar log via curl.")
        else:
            if not shutil_which("curl"):
                raise SystemExit("Nem wget nem curl disponíveis.")
            r = subprocess.run(["curl", "-sSL", "-o", log_path, args.url])
            if r.returncode != 0:
                raise SystemExit("Falha ao baixar log via curl.")
    elif args.file:
        if not os.path.isfile(args.file):
            raise SystemExit(f"Arquivo não encontrado: {args.file}")
        log_path = args.file
    else:
        raise SystemExit("Use --url OU --file")

    print(f"[+] Analisando: {log_path}")
    data = analyze_log(log_path, top_n=args.top)

    md = render_soc_report_md(data)

    md_path = os.path.join(args.out, "SOC_REPORT.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)

    print(f"[+] Report gerado: {md_path}")

    if args.json:
        js_path = os.path.join(args.out, "data.json")
        with open(js_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[+] JSON gerado: {js_path}")

    # Resumo rápido no terminal
    suspect = data["primary_suspect"]
    print("\n=== RESUMO ===")
    print(f"IP suspeito: {suspect['ip']}")
    print(f"Hits: {suspect['hits']}")
    print(f"Início: {suspect['first_seen']}")
    print(f"Fim:    {suspect['last_seen']}")
    print(f"Pico:   {suspect.get('peak_requests_per_minute', 0)} req/min em {suspect.get('peak_minute')}")

if __name__ == "__main__":
    main()
