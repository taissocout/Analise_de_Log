#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LogSentinel - Advanced SOC Log Analyzer (Controlled Lab Use)

✅ Interativo (Y/N): tem access.log? se não, baixa via wget (se existir) ou via Python (urllib)
✅ UI estilo "Flipper-like": personagem com capuz + lupa + LEDs (🟥🟨🟩) no terminal
✅ Gera relatório SOC em Markdown + JSON opcional
✅ Cross-platform: Windows (py) e Linux/Kali (python3)
"""

import argparse
import collections
import datetime as dt
import json
import os
import re
import sys
import subprocess
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

# =========================
#  UI (Flipper-like) - Terminal
# =========================

def supports_ansi() -> bool:
    if os.name != "nt":
        return True
    return bool(os.environ.get("WT_SESSION") or os.environ.get("TERM_PROGRAM") or os.environ.get("VSCODE_PID"))

def c(text: str, code: str) -> str:
    if not supports_ansi():
        return text
    return f"\x1b[{code}m{text}\x1b[0m"

def clear_screen():
    if supports_ansi():
        sys.stdout.write("\x1b[2J\x1b[H")
        sys.stdout.flush()
    else:
        os.system("cls" if os.name == "nt" else "clear")

def hide_cursor():
    if supports_ansi():
        sys.stdout.write("\x1b[?25l")
        sys.stdout.flush()

def show_cursor():
    if supports_ansi():
        sys.stdout.write("\x1b[?25h")
        sys.stdout.flush()

def move_home():
    if supports_ansi():
        sys.stdout.write("\x1b[H")
        sys.stdout.flush()

def led_red(on=True):    return c("●", "31;1") if on else c("○", "31")
def led_yellow(on=True): return c("●", "33;1") if on else c("○", "33")
def led_green(on=True):  return c("●", "32;1") if on else c("○", "32")

@dataclass
class UiState:
    phase: str = "idle"       # idle, download, parse, hunt, report, done, error
    message: str = ""
    sub: str = ""
    progress: float = 0.0     # 0..1

FRAMES = [
r"""
       ____  
     _/____\_         {LEDS}   LogSentinel UI
    /  (.. ) \        Phase: {PHASE}
   /|   __   |\       {MSG}
    |  /  \  |        {SUB}
    |  \__/  |
     \  __  /
      \/  \/
       /\/\     🔎
""",
r"""
       ____  
     _/____\_         {LEDS}   LogSentinel UI
    /  (.. ) \        Phase: {PHASE}
   /|   __   |\       {MSG}
    |  /  \  |        {SUB}
    |  \__/  |
     \  __  /
      \/  \/
       /\/\    🔎
""",
r"""
       ____  
     _/____\_         {LEDS}   LogSentinel UI
    /  (.. ) \        Phase: {PHASE}
   /|   __   |\       {MSG}
    |  /  \  |        {SUB}
    |  \__/  |
     \  __  /
      \/  \/
       /\/\       🔎
""",
r"""
       ____  
     _/____\_         {LEDS}   LogSentinel UI
    /  (.. ) \        Phase: {PHASE}
   /|   __   |\       {MSG}
    |  /  \  |        {SUB}
    |  \__/  |
     \  __  /
      \/  \/
       /\/\      🔎
""",
]

SPINNER = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

def leds_for_phase(phase: str) -> str:
    if phase == "error":
        return f"{led_red(True)} {led_yellow(False)} {led_green(False)}"
    if phase in ("download", "parse", "hunt", "report"):
        return f"{led_red(False)} {led_yellow(True)} {led_green(False)}"
    if phase == "done":
        return f"{led_red(False)} {led_yellow(False)} {led_green(True)}"
    return f"{led_red(False)} {led_yellow(False)} {led_green(False)}"

def render(state: UiState, frame_i: int, spin_i: int):
    ledline = leds_for_phase(state.phase)
    phase_label = state.phase.upper()
    msg = state.message
    sub = state.sub

    spin = SPINNER[spin_i % len(SPINNER)]

    # Barra opcional
    if state.progress > 0:
        bar_w = 26
        filled = int(bar_w * max(0.0, min(1.0, state.progress)))
        bar = "█"*filled + "░"*(bar_w-filled)
        sub = f"{sub}\n    [{bar}] {int(state.progress*100):>3}% {spin}"
    else:
        sub = f"{sub}\n    {spin}"

    frame = FRAMES[frame_i % len(FRAMES)].format(
        LEDS=ledline,
        PHASE=phase_label,
        MSG=msg,
        SUB=sub
    )
    move_home()
    sys.stdout.write(frame)
    sys.stdout.flush()

class TerminalUI:
    def __init__(self):
        self.state = UiState()
        self._frame_i = 0
        self._spin_i = 0
        self._running = False

    def start(self):
        self._running = True
        hide_cursor()
        clear_screen()

    def stop(self):
        self._running = False
        show_cursor()

    def update(self, phase=None, message=None, sub=None, progress=None):
        if phase is not None:
            self.state.phase = phase
        if message is not None:
            self.state.message = message
        if sub is not None:
            self.state.sub = sub
        if progress is not None:
            self.state.progress = progress

    def tick(self):
        if not self._running:
            return
        render(self.state, self._frame_i, self._spin_i)
        self._frame_i += 1
        self._spin_i += 1

    def run_for(self, seconds: float, fps: float = 10.0):
        interval = 1.0 / fps
        end = time.time() + seconds
        while time.time() < end:
            self.tick()
            time.sleep(interval)

# =========================
#  Core - LogSentinel
# =========================

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

def banner():
    print(r"""
██╗      ██████╗  ██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██║     ██╔═══██╗██╔════╝ ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
██║     ██║   ██║██║  ███╗█████╗  █████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
██║     ██║   ██║██║   ██║██╔══╝  ██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
███████╗╚██████╔╝╚██████╔╝███████╗███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

        LogSentinel - Advanced SOC Log Analyzer
        Author:Taisso Cout | Controlled Lab Use
""")

def ask_yes_no(prompt: str, default: Optional[bool] = None) -> bool:
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

def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return url
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    return url

def which(cmd: str) -> Optional[str]:
    for p in os.environ.get("PATH", "").split(os.pathsep):
        full = os.path.join(p, cmd)
        if os.path.isfile(full) and os.access(full, os.X_OK):
            return full
    return None

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

def download_via_wget(url: str, out_path: str, ui: Optional[TerminalUI] = None) -> bool:
    if not which("wget"):
        return False
    if ui:
        ui.update(sub="Usando wget (se disponível)...", progress=0.15)
        ui.tick()
    r = subprocess.run(["wget", "-q", "-O", out_path, url])
    return r.returncode == 0

def download_via_python(url: str, out_path: str, ui: Optional[TerminalUI] = None) -> None:
    url = normalize_url(url)
    if ui:
        ui.update(sub="Fallback Python (urllib)...", progress=0.25)
        ui.tick()
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
        if ui:
            ui.update(progress=0.6)
            ui.tick()
    with open(out_path, "wb") as f:
        f.write(data)
        if ui:
            ui.update(progress=0.9)
            ui.tick()

def download_log(url: str, out_path: str, ui: Optional[TerminalUI] = None) -> None:
    url = normalize_url(url)
    if ui:
        ui.update(phase="download", message="Baixando access.log...", sub=url, progress=0.05)
        ui.tick()

    # tenta wget
    if ui:
        ui.update(sub="Tentando baixar via wget...", progress=0.1)
        ui.tick()

    if download_via_wget(url, out_path, ui=ui):
        if ui:
            ui.update(sub="Download via wget concluído.", progress=1.0)
            ui.tick()
        return

    # fallback python
    if ui:
        ui.update(sub="wget indisponível ou falhou. Usando Python...", progress=0.2)
        ui.tick()

    try:
        download_via_python(url, out_path, ui=ui)
        if ui:
            ui.update(sub="Download via Python concluído.", progress=1.0)
            ui.tick()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP error ao baixar log: {e.code} {e.reason}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Erro de rede ao baixar log: {e.reason}") from e
    except Exception as e:
        raise RuntimeError(f"Falha inesperada ao baixar log: {e}") from e

def analyze_log(path: str, top_n: int = 10, ui: Optional[TerminalUI] = None) -> Dict:
    # Passo 1: contar linhas (para progresso real)
    try:
        with open(path, "r", errors="replace") as f:
            total_est = sum(1 for _ in f) or 1
    except Exception:
        total_est = 1

    ip_counts = collections.Counter()
    total_lines = 0
    parse_errors = 0

    if ui:
        ui.update(phase="parse", message="Parseando log / extraindo IPs...", sub="Contando requisições por IP", progress=0.0)
        ui.tick()

    # Passo 2: contar IPs
    with open(path, "r", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            total_lines += 1
            m = APACHE_RE.match(line)
            if not m:
                parse_errors += 1
            else:
                ip_counts[m.group("ip")] += 1

            if ui and (i % 600 == 0):
                ui.update(progress=min(0.98, i / total_est))
                ui.tick()

    if not ip_counts:
        raise RuntimeError("Não consegui extrair nenhum IP. O log está em formato diferente do Apache combinado?")

    top_ips = ip_counts.most_common(top_n)
    top_ip, top_ip_hits = top_ips[0]

    # Passo 3: análise focada no top_ip
    status_counts = collections.Counter()
    tool_counts = collections.Counter()
    path_counts = collections.Counter()
    method_counts = collections.Counter()
    minute_buckets = collections.Counter()
    first_seen = None
    last_seen = None
    tool_first_last: Dict[str, Tuple[Optional[dt.datetime], Optional[dt.datetime]]] = {}

    if ui:
        ui.update(phase="hunt", message="Hunting no IP suspeito...", sub=f"Foco: {top_ip}", progress=0.0)
        ui.tick()

    # progresso novamente
    with open(path, "r", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            m = APACHE_RE.match(line)
            if not m:
                continue
            if m.group("ip") != top_ip:
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

            if ui and (i % 1200 == 0):
                ui.update(progress=min(0.98, i / total_est), sub=f"Foco: {top_ip} | Ferramenta: {tool}")
                ui.tick()

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

    # tool_timeline ordenado por hits
    tool_timeline = []
    for tool, (a, b) in sorted(tool_first_last.items(), key=lambda kv: tool_counts[kv[0]], reverse=True):
        tool_timeline.append({
            "tool": tool,
            "hits": tool_counts[tool],
            "first_seen": fmt_ts(a),
            "last_seen": fmt_ts(b),
        })

    if ui:
        ui.update(progress=1.0)
        ui.tick()

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
    lines.append("# Mini SOC Report — LogSentinel (Apache Access Log)")
    lines.append("")
    lines.append(f"**Arquivo:** `{meta['log_path']}`  ")
    lines.append(f"**Total de linhas:** {total_lines}  ")
    lines.append(f"**IPs únicos:** {meta['unique_ips']}  ")
    lines.append(f"**Linhas com erro de parse:** {meta['parse_errors']}  ")
    lines.append("")
    lines.append("## 1) Executive Summary")
    lines.append("")
    lines.append(f"Foi identificado um **IP com comportamento automatizado**: **`{suspect['ip']}`**, responsável por **{suspect_hits} requisições** ({pct(suspect_hits, total_lines)} do log).")
    lines.append(f"Janela temporal observada: **{suspect['first_seen']}** → **{suspect['last_seen']}**.")
    lines.append("Assinaturas de ferramentas foram inferidas via **User-Agent**.")
    lines.append(f"**Severidade (heurística): {sev}**")
    lines.append("")
    lines.append("## 2) Top IPs por volume")
    lines.append("")
    lines.append("| Rank | IP | Requisições |")
    lines.append("|---:|---|---:|")
    for i, item in enumerate(top_ips, start=1):
        lines.append(f"| {i} | `{item['ip']}` | {item['hits']} |")
    lines.append("")
    lines.append("## 3) IOC principal")
    lines.append("")
    lines.append(f"- **IP:** `{suspect['ip']}`")
    lines.append(f"- **Janela temporal:** {suspect['first_seen']} → {suspect['last_seen']}")
    lines.append(f"- **Pico de volume:** {suspect.get('peak_requests_per_minute', 0)} req/min em `{suspect.get('peak_minute')}`")
    lines.append("")
    lines.append("## 4) Ferramentas detectadas (User-Agent)")
    lines.append("")
    lines.append("| Ferramenta | Hits | Primeiro visto | Último visto |")
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
    lines.append("## 6) Top paths alvos")
    lines.append("")
    lines.append("| Path | Hits |")
    lines.append("|---|---:|")
    for p in suspect.get("top_paths", []):
        lines.append(f"| `{p['path']}` | {p['hits']} |")
    lines.append("")
    lines.append("## 7) Recomendações (Blue Team / Hardening)")
    lines.append("")
    lines.append("- Implementar **rate limiting** e proteção contra varredura (WAF).")
    lines.append("- Correlacionar com `error.log` e logs de autenticação.")
    lines.append("- Criar alertas para picos de req/min e spikes de 404/403.")
    lines.append("")
    lines.append("## 8) Observações")
    lines.append("")
    lines.append("> Relatório gerado automaticamente (heurísticas). Uso recomendado em ambiente controlado/lab.")
    lines.append("")
    return "\n".join(lines)

def interactive_flow(ui: TerminalUI) -> Tuple[str, str, int, bool]:
    ui.update(phase="idle", message="Modo interativo", sub="Responda Y/N para prosseguir", progress=0.0)
    ui.tick()

    have_log = ask_yes_no("Você já tem um access.log para analisar?", default=True)
    out_dir = "soc_report"
    top_n = 10
    save_json = True

    if have_log:
        cwd = os.getcwd()
        default_path = os.path.join(cwd, "access.log")
        custom = ask_yes_no(f"O arquivo está em `{default_path}`?", default=True)
        if custom:
            log_path = default_path
        else:
            log_path = input("Digite o caminho do access.log: ").strip().strip('"').strip("'")

        return log_path, out_dir, top_n, save_json

    # Não tem log -> baixar
    url = normalize_url(input("Cole a URL do access.log para baixar: ").strip().strip('"').strip("'"))
    os.makedirs(out_dir, exist_ok=True)
    log_path = os.path.join(out_dir, "access.log")

    download_log(url, log_path, ui=ui)

    analyze_now = ask_yes_no("Download concluído. Deseja analisar agora?", default=True)
    if not analyze_now:
        ui.update(phase="done", message="Ok! Arquivo baixado.", sub=f"Salvo em: {log_path}", progress=1.0)
        ui.run_for(0.8)
        ui.stop()
        print(f"\n[i] Log salvo em: {log_path}")
        sys.exit(0)

    return log_path, out_dir, top_n, save_json

def main() -> None:
    banner()

    ui = TerminalUI()
    ui.start()

    ap = argparse.ArgumentParser(
        description="LogSentinel — analisador automatizado de access.log (Apache) + mini SOC report"
    )
    ap.add_argument("--interactive", action="store_true", help="Modo interativo (perguntas Y/N)")
    ap.add_argument("--url", help="URL para baixar o access.log (tenta wget, fallback Python)")
    ap.add_argument("--file", help="Caminho do log local (access.log)")
    ap.add_argument("--out", default="soc_report", help="Diretório de saída (default: soc_report)")
    ap.add_argument("--top", type=int, default=10, help="Top N IPs (default: 10)")
    ap.add_argument("--json", action="store_true", help="Salvar também JSON com dados brutos (modo CLI)")
    args = ap.parse_args()

    use_interactive = args.interactive or (not args.url and not args.file)

    try:
        if use_interactive:
            log_path, out_dir, top_n, save_json = interactive_flow(ui)
        else:
            out_dir = args.out
            top_n = args.top
            save_json = args.json

            os.makedirs(out_dir, exist_ok=True)

            if args.url:
                log_path = os.path.join(out_dir, "access.log")
                download_log(args.url, log_path, ui=ui)
            elif args.file:
                if not os.path.isfile(args.file):
                    ui.update(phase="error", message="Arquivo não encontrado!", sub=args.file, progress=0.0)
                    ui.run_for(1.0)
                    ui.stop()
                    print(f"[-] Arquivo não encontrado: {args.file}")
                    sys.exit(1)
                log_path = args.file
            else:
                ui.update(phase="error", message="Parâmetros inválidos", sub="Use --url ou --file", progress=0.0)
                ui.run_for(1.0)
                ui.stop()
                print("[-] Use --url OU --file OU --interactive")
                sys.exit(1)

        if not os.path.isfile(log_path):
            ui.update(phase="error", message="access.log não encontrado!", sub=log_path, progress=0.0)
            ui.run_for(1.0)
            ui.stop()
            print(f"[-] access.log não encontrado em: {log_path}")
            sys.exit(1)

        # Análise
        data = analyze_log(log_path, top_n=top_n, ui=ui)

        # Report
        ui.update(phase="report", message="Gerando SOC_REPORT.md...", sub="Montando evidências e recomendações", progress=0.2)
        ui.tick()

        md = render_soc_report_md(data)

        md_path = os.path.join(out_dir, "SOC_REPORT.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)

        if save_json:
            js_path = os.path.join(out_dir, "data.json")
            with open(js_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

        ui.update(phase="done", message="Finalizado!", sub=f"Relatório: {md_path}", progress=1.0)
        ui.run_for(0.8)
        ui.stop()

        # Saída final “limpa”
        suspect = data["primary_suspect"]
        print(f"\n[+] Report gerado: {md_path}")
        if save_json:
            print(f"[+] JSON gerado: {os.path.join(out_dir, 'data.json')}")
        print("\n=== RESUMO ===")
        print(f"IP suspeito: {suspect['ip']}")
        print(f"Hits: {suspect['hits']}")
        print(f"Início: {suspect['first_seen']}")
        print(f"Fim:    {suspect['last_seen']}")
        print(f"Pico:   {suspect.get('peak_requests_per_minute', 0)} req/min em {suspect.get('peak_minute')}")

    except Exception as e:
        try:
            ui.update(phase="error", message="Erro!", sub=str(e), progress=0.0)
            ui.run_for(1.2)
            ui.stop()
        except Exception:
            pass
        raise

if __name__ == "__main__":
    main()
