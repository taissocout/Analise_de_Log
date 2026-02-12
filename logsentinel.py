#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import collections
import datetime as dt
import json
import os
import re
import sys
import subprocess
import urllib.request
import urllib.error
from typing import Dict, Optional, Tuple

APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

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


def banner() -> None:
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


def ask_yes_no(prompt: str, default: Optional[bool] = None) -> bool:
    """
    Pergunta Y/N. Retorna True para Y, False para N.
    default:
      - True  => Enter vira Y
      - False => Enter vira N
      - None  => Enter repete pergunta
    """
    while True:
        suffix = " [Y/N]: "
        if default is True:
            suffix = " [Y/n]: "
        elif default is False:
            suffix = " [y/N]: "

        ans = input(prompt + suffix).strip().lower()
        if ans == "" and default is not None:
            return default
        if ans in ("y", "yes", "s", "sim"):
            return True
        if ans in ("n", "no", "nao", "não"):
            return False
        print("[-] Responda com Y para sim ou N para não.")


def parse_apache_time(ts: str) -> Optional[dt.datetime]:
    try:
        return dt.datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
    except Exception:
        try:
            return dt.datetime.strptime(ts.split(" ")[0], "%d/%b/%Y:%H:%M:%S")
        except Exception:
            return None


def detect_tool(user_agent: str) -> str:
    for name, rx in TOOL_SIGNATURES:
        if rx.search(user_agent or ""):
            return name
    return "Browser/Unknown"


def which(cmd: str) -> Optional[str]:
    for p in os.environ.get("PATH", "").split(os.pathsep):
        full = os.path.join(p, cmd)
        if os.path.isfile(full) and os.access(full, os.X_OK):
            return full
    return None


def download_via_wget(url: str, out_path: str) -> bool:
    """
    Tenta baixar via wget. Retorna True se conseguiu, False se não tem wget ou falhou.
    """
    if not which("wget"):
        return False
    r = subprocess.run(["wget", "-q", "-O", out_path, url])
    return r.returncode == 0


def download_via_python(url: str, out_path: str) -> None:
    """
    Fallback cross-platform sem depender de wget/curl.
    """
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
    with open(out_path, "wb") as f:
        f.write(data)


def download_log(url: str, out_path: str) -> None:
    """
    Primeiro tenta wget. Se não der, usa Python.
    """
    print("[*] Tentando baixar via wget...")
    if download_via_wget(url, out_path):
        print("[+] Download feito via wget.")
        return

    print("[*] wget indisponível ou falhou. Usando download via Python...")
    try:
        download_via_python(url, out_path)
        print("[+] Download feito via Python (urllib).")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP error ao baixar log: {e.code} {e.reason}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Erro de rede ao baixar log: {e.reason}") from e
    except Exception as e:
        raise RuntimeError(f"Falha inesperada ao baixar log: {e}") from e


def analyze_log(path: str, top_n: int = 10) -> Dict:
    ip_counts = collections.Counter()
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

    status_counts = collections.Counter()
    tool_counts = collections.Counter()
    path_counts = collections.Counter()
    method_counts = collections.Counter()
    minute_buckets = collections.Counter()

    first_seen = None
    last_seen = None

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

    peak_minute, peak_rpm = (None, 0)
    if minute_buckets:
        peak_minute, peak_rpm = max(minute_buckets.items(), key=lambda x: x[1])

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

    return {
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
    lines.append("Ferramentas e padrões compatíveis com varredura foram encontrados via User-Agent.")
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
    lines.append("## 5) Status Codes")
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
    lines.append("## 7) Recomendações")
    lines.append("")
    lines.append("- Implementar rate limiting e proteção contra varredura (WAF).")
    lines.append("- Correlacionar com `error.log` e logs de autenticação.")
    lines.append("- Criar alertas para picos de req/min e spikes de 404/403.")
    lines.append("")
    lines.append("## 8) Observações")
    lines.append("")
    lines.append("> Relatório gerado automaticamente (heurísticas). Uso recomendado em ambiente controlado/lab.")
    lines.append("")
    return "\n".join(lines)


def interactive_flow() -> Tuple[str, str, int, bool]:
    """
    Retorna: (log_path, out_dir, top_n, save_json)
    """
    print("\n=== MODO INTERATIVO ===")
    have_log = ask_yes_no("Você já tem um access.log para analisar?", default=True)

    out_dir = "soc_report"
    top_n = 10
    save_json = True

    if have_log:
        # assume access.log no diretório atual
        cwd = os.getcwd()
        default_path = os.path.join(cwd, "access.log")
        custom = ask_yes_no(f"O arquivo está em `{default_path}`?", default=True)
        if custom:
            log_path = default_path
        else:
            log_path = input("Digite o caminho do access.log: ").strip().strip('"').strip("'")

        return log_path, out_dir, top_n, save_json

    # Não tem log -> baixar
    url = input("Cole a URL do access.log para baixar: ").strip().strip('"').strip("'")
    os.makedirs(out_dir, exist_ok=True)
    log_path = os.path.join(out_dir, "access.log")

    print(f"[+] Baixando log para: {log_path}")
    download_log(url, log_path)

    analyze_now = ask_yes_no("Download concluído. Deseja analisar agora?", default=True)
    if not analyze_now:
        print(f"[i] Ok. O arquivo foi salvo em: {log_path}")
        sys.exit(0)

    return log_path, out_dir, top_n, save_json


def main() -> None:
    banner()

    ap = argparse.ArgumentParser(
        description="LogSentinel — analisador automatizado de access.log (Apache) + mini SOC report"
    )
    ap.add_argument("--interactive", action="store_true", help="Modo interativo (perguntas Y/N)")
    ap.add_argument("--url", help="URL para baixar o access.log (tenta wget, fallback Python)")
    ap.add_argument("--file", help="Caminho do log local (access.log)")
    ap.add_argument("--out", default="soc_report", help="Diretório de saída (default: soc_report)")
    ap.add_argument("--top", type=int, default=10, help="Top N IPs (default: 10)")
    ap.add_argument("--json", action="store_true", help="Salvar também JSON com dados brutos")
    args = ap.parse_args()

    # Se não passar nada, cai no modo interativo automaticamente
    use_interactive = args.interactive or (not args.url and not args.file)

    if use_interactive:
        log_path, out_dir, top_n, save_json = interactive_flow()
    else:
        out_dir = args.out
        top_n = args.top
        save_json = args.json

        os.makedirs(out_dir, exist_ok=True)

        if args.url:
            log_path = os.path.join(out_dir, "access.log")
            print(f"[+] Baixando log: {args.url}")
            download_log(args.url, log_path)
        elif args.file:
            if not os.path.isfile(args.file):
                print(f"[-] Arquivo não encontrado: {args.file}")
                sys.exit(1)
            log_path = args.file
        else:
            print("[-] Use --url OU --file OU --interactive")
            sys.exit(1)

    if not os.path.isfile(log_path):
        print(f"[-] access.log não encontrado em: {log_path}")
        sys.exit(1)

    print(f"[+] Analisando: {log_path}")
    data = analyze_log(log_path, top_n=top_n)

    md = render_soc_report_md(data)

    md_path = os.path.join(out_dir, "SOC_REPORT.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)

    print(f"[+] Report gerado: {md_path}")

    if save_json:
        js_path = os.path.join(out_dir, "data.json")
        with open(js_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[+] JSON gerado: {js_path}")

    suspect = data["primary_suspect"]
    print("\n=== RESUMO ===")
    print(f"IP suspeito: {suspect['ip']}")
    print(f"Hits: {suspect['hits']}")
    print(f"Início: {suspect['first_seen']}")
    print(f"Fim:    {suspect['last_seen']}")
    print(f"Pico:   {suspect.get('peak_requests_per_minute', 0)} req/min em {suspect.get('peak_minute')}")


if __name__ == "__main__":
    main()
