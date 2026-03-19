"""
=============================================================
LAB 20 — Network Zone Mapper
Security+ SY0-701 — Domínio 3 — Infraestrutura Segura
=============================================================
Autor: Luiz Otavio Gonçalves Gilio
GitHub: github.com/LuizGilio

CONCEITO:
    Mapeia a rede local identificando dispositivos por zona
    de segurança (Trusted, Untrusted, DMZ). Detecta portas
    abertas por zona, calcula a superfície de ataque e
    sugere segmentação. Simula o trabalho de um arquiteto
    de segurança de rede.

    Conceitos: Security Zones, Attack Surface, VLANs,
    Segmentação, IPS/IDS, Firewall, DMZ, Port Management.

COMO USAR:
    python network_zone_mapper.py --scan
    python network_zone_mapper.py --scan --range 192.168.1
    python network_zone_mapper.py --report
=============================================================
"""

import socket
import json
import os
import datetime
import argparse
import platform
import ipaddress
import concurrent.futures

OUTPUT_HTML = "./relatorio_zonas.html"
OUTPUT_JSON = "./zone_map_log.json"

# ══════════════════════════════════════════════════════════
# DEFINIÇÕES DE ZONAS E PORTAS
# ══════════════════════════════════════════════════════════

# Zonas de segurança com seus critérios
SECURITY_ZONES = {
    "TRUSTED":   {"color": "#166534", "bg": "#F0FDF4", "border": "#86EFAC", "desc": "Rede interna corporativa — dispositivos confiáveis"},
    "DMZ":       {"color": "#92400E", "bg": "#FFFBEB", "border": "#FCD34D", "desc": "Zona desmilitarizada — serviços públicos expostos"},
    "UNTRUSTED": {"color": "#B91C1C", "bg": "#FEF2F2", "border": "#FCA5A5", "desc": "Rede externa ou não gerenciada — não confiável"},
    "UNKNOWN":   {"color": "#374151", "bg": "#F9FAFB", "border": "#D1D5DB", "desc": "Zona indeterminada — requer investigação"},
}

# Portas e seus perfis de risco
PORT_PROFILES = {
    21:   {"service": "FTP",          "risk": "HIGH",     "zone_hint": "DMZ",     "desc": "Transferência de arquivos sem criptografia"},
    22:   {"service": "SSH",          "risk": "MEDIUM",   "zone_hint": "TRUSTED", "desc": "Acesso remoto seguro — restringir por IP"},
    23:   {"service": "Telnet",       "risk": "CRITICAL", "zone_hint": "UNKNOWN", "desc": "Protocolo inseguro — substituir por SSH"},
    25:   {"service": "SMTP",         "risk": "MEDIUM",   "zone_hint": "DMZ",     "desc": "Servidor de e-mail — verificar relay aberto"},
    53:   {"service": "DNS",          "risk": "MEDIUM",   "zone_hint": "DMZ",     "desc": "DNS — verificar se é open resolver"},
    80:   {"service": "HTTP",         "risk": "MEDIUM",   "zone_hint": "DMZ",     "desc": "Web sem criptografia — migrar para HTTPS"},
    135:  {"service": "RPC",          "risk": "HIGH",     "zone_hint": "TRUSTED", "desc": "RPC Windows — vetor comum de ataques"},
    139:  {"service": "NetBIOS",      "risk": "HIGH",     "zone_hint": "TRUSTED", "desc": "NetBIOS — relacionado ao EternalBlue"},
    443:  {"service": "HTTPS",        "risk": "LOW",      "zone_hint": "DMZ",     "desc": "Web criptografado — verificar certificado"},
    445:  {"service": "SMB",          "risk": "CRITICAL", "zone_hint": "TRUSTED", "desc": "SMB — vetor do WannaCry (EternalBlue)"},
    3389: {"service": "RDP",          "risk": "HIGH",     "zone_hint": "TRUSTED", "desc": "Remote Desktop — alvo frequente de brute force"},
    8080: {"service": "HTTP-Alt",     "risk": "MEDIUM",   "zone_hint": "DMZ",     "desc": "HTTP alternativo — verificar serviço"},
    8443: {"service": "HTTPS-Alt",    "risk": "LOW",      "zone_hint": "DMZ",     "desc": "HTTPS alternativo"},
}

# Portas que indicam que o host é um servidor público (DMZ)
DMZ_INDICATOR_PORTS = {80, 443, 25, 53, 8080, 8443}
# Portas que indicam rede interna confiável
TRUSTED_INDICATOR_PORTS = {22, 3389, 445, 139, 135}


# ══════════════════════════════════════════════════════════
# DESCOBERTA DE REDE
# ══════════════════════════════════════════════════════════

def get_local_network():
    """Detecta a rede local automaticamente."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        network_base = ".".join(parts[:3])
        return local_ip, network_base
    except Exception:
        return "127.0.0.1", "127.0.0"


def check_port(host, port, timeout=0.4):
    """Verifica se uma porta está aberta."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception:
        return False


def resolve_hostname(ip):
    """Tenta resolver o hostname do IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def scan_host(ip, ports=None):
    """Varre um host e retorna suas portas abertas."""
    if ports is None:
        ports = list(PORT_PROFILES.keys())

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ports)) as executor:
        futures = {executor.submit(check_port, ip, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append(port)
    return sorted(open_ports)


def determine_zone(ip, open_ports, local_ip):
    """Determina a zona de segurança do host."""
    if ip == local_ip:
        return "TRUSTED"

    port_set = set(open_ports)

    if port_set & DMZ_INDICATOR_PORTS and not (port_set & TRUSTED_INDICATOR_PORTS):
        return "DMZ"
    if port_set & TRUSTED_INDICATOR_PORTS:
        return "TRUSTED"
    if open_ports:
        return "UNKNOWN"
    return "TRUSTED"  # Host ativo mas sem portas abertas = provavelmente interno


def calculate_attack_surface(hosts):
    """Calcula métricas de superfície de ataque."""
    total_open    = sum(len(h["open_ports"]) for h in hosts)
    critical_ports= sum(
        1 for h in hosts
        for p in h["open_ports"]
        if PORT_PROFILES.get(p, {}).get("risk") == "CRITICAL"
    )
    dmz_hosts    = sum(1 for h in hosts if h["zone"] == "DMZ")
    unknown_hosts= sum(1 for h in hosts if h["zone"] == "UNKNOWN")

    if critical_ports >= 3 or unknown_hosts >= 2:
        risk = "CRITICAL"
    elif critical_ports >= 1 or dmz_hosts >= 3:
        risk = "HIGH"
    elif total_open >= 10:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "total_open_ports":  total_open,
        "critical_ports":    critical_ports,
        "dmz_hosts":         dmz_hosts,
        "unknown_hosts":     unknown_hosts,
        "overall_risk":      risk,
    }


# ══════════════════════════════════════════════════════════
# SCAN PRINCIPAL
# ══════════════════════════════════════════════════════════

def run_scan(network_base=None, host_range=20):
    """Executa varredura da rede local."""
    local_ip, auto_base = get_local_network()
    base = network_base or auto_base

    print(f"\n  Rede detectada:  {base}.0/24")
    print(f"  IP local:        {local_ip}")
    print(f"  Hosts a varrer:  {base}.1 — {base}.{host_range}")
    print(f"  Portas:          {len(PORT_PROFILES)} serviços monitorados\n")

    hosts = []
    active = 0

    for i in range(1, host_range + 1):
        ip = f"{base}.{i}"
        sys.stdout.write(f"\r  Varrendo {ip}...   ")
        sys.stdout.flush()

        open_ports = scan_host(ip)

        # Testa ping simples (porta 80 ou 445 ou 22)
        is_active = len(open_ports) > 0 or check_port(ip, 80, 0.3) or check_port(ip, 443, 0.3)

        if not is_active and ip != local_ip:
            continue

        active += 1
        hostname = resolve_hostname(ip)
        zone     = determine_zone(ip, open_ports, local_ip)
        is_local = ip == local_ip

        port_details = []
        for p in open_ports:
            prof = PORT_PROFILES.get(p, {})
            port_details.append({
                "port":    p,
                "service": prof.get("service", "Unknown"),
                "risk":    prof.get("risk",    "UNKNOWN"),
                "desc":    prof.get("desc",    ""),
            })

        hosts.append({
            "ip":          ip,
            "hostname":    hostname or ip,
            "zone":        zone,
            "is_local":    is_local,
            "open_ports":  open_ports,
            "port_details":port_details,
        })

        zone_label = f"[{zone}]"
        ports_str  = ", ".join(f"{p}({PORT_PROFILES.get(p,{}).get('service','?')})" for p in open_ports) or "nenhuma"
        print(f"\r  {ip:16} {zone_label:12} Portas: {ports_str}")

    print(f"\n\n  Hosts ativos encontrados: {active}")
    return hosts, local_ip


# ══════════════════════════════════════════════════════════
# RELATÓRIO HTML — ESTILO ENTERPRISE
# ══════════════════════════════════════════════════════════

def gerar_relatorio(hosts, local_ip, network_base):
    agora    = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    hostname = socket.gethostname()
    sistema  = platform.system() + " " + platform.release()
    metrics  = calculate_attack_surface(hosts)

    risk_colors = {
        "CRITICAL": "#B91C1C", "HIGH": "#92400E",
        "MEDIUM":   "#1E3A5F", "LOW":  "#166534", "CLEAN": "#166534"
    }
    overall_color = risk_colors.get(metrics["overall_risk"], "#374151")

    # Contagem por zona
    zone_counts = {}
    for h in hosts:
        z = h["zone"]
        zone_counts[z] = zone_counts.get(z, 0) + 1

    # Tabela de hosts
    rows_hosts = ""
    for h in sorted(hosts, key=lambda x: (x["zone"] != "UNKNOWN", x["zone"] != "DMZ", x["ip"])):
        zc = SECURITY_ZONES.get(h["zone"], SECURITY_ZONES["UNKNOWN"])
        local_badge = ' <span style="font-size:0.68rem;color:#1E3A5F;border:1px solid #1E3A5F;padding:1px 5px;border-radius:2px">THIS HOST</span>' if h["is_local"] else ""
        ports_html = ""
        for pd in h["port_details"]:
            rc = risk_colors.get(pd["risk"], "#374151")
            ports_html += f'<span style="font-size:0.72rem;font-family:monospace;color:{rc};margin-right:6px" title="{pd["desc"]}">{pd["port"]}/{pd["service"]}</span>'
        if not ports_html:
            ports_html = '<span class="muted small">—</span>'

        rows_hosts += f"""
        <tr>
          <td class="mono">{h['ip']}{local_badge}</td>
          <td class="mono small muted">{h['hostname'] if h['hostname'] != h['ip'] else '—'}</td>
          <td><span style="font-size:0.72rem;font-weight:700;color:{zc['color']};border:1px solid {zc['border']};padding:2px 7px;border-radius:2px;background:{zc['bg']}">{h['zone']}</span></td>
          <td>{ports_html}</td>
          <td class="center">{len(h['open_ports'])}</td>
        </tr>"""

    if not rows_hosts:
        rows_hosts = '<tr><td colspan="5" class="center muted">Nenhum host ativo encontrado.</td></tr>'

    # Tabela de portas críticas
    rows_ports = ""
    seen_ports = {}
    for h in hosts:
        for pd in h["port_details"]:
            if pd["risk"] in ("CRITICAL", "HIGH"):
                key = (h["ip"], pd["port"])
                if key not in seen_ports:
                    seen_ports[key] = True
                    rc = risk_colors.get(pd["risk"], "#374151")
                    zc = SECURITY_ZONES.get(h["zone"], SECURITY_ZONES["UNKNOWN"])
                    rows_ports += f"""
                    <tr>
                      <td class="mono">{h['ip']}</td>
                      <td class="mono">{pd['port']}</td>
                      <td class="mono">{pd['service']}</td>
                      <td><span style="font-size:0.72rem;font-weight:700;color:{rc};border:1px solid {rc};padding:2px 7px;border-radius:2px">{pd['risk']}</span></td>
                      <td><span style="font-size:0.72rem;font-weight:700;color:{zc['color']};border:1px solid {zc['border']};padding:2px 7px;border-radius:2px;background:{zc['bg']}">{h['zone']}</span></td>
                      <td class="small muted">{pd['desc']}</td>
                    </tr>"""

    if not rows_ports:
        rows_ports = '<tr><td colspan="6" class="center muted">Nenhuma porta crítica ou alta detectada.</td></tr>'

    # Recomendações
    recs = []
    has_smb = any(445 in h["open_ports"] for h in hosts)
    has_telnet = any(23 in h["open_ports"] for h in hosts)
    has_unknown = any(h["zone"] == "UNKNOWN" for h in hosts)
    has_rdp = any(3389 in h["open_ports"] for h in hosts)

    if has_telnet:
        recs.append(("CRITICAL", "Desabilitar Telnet (23) em todos os hosts", "Protocolo sem criptografia — substituir por SSH (22) imediatamente"))
    if has_smb:
        recs.append(("CRITICAL", "Avaliar exposição do SMB (445)", "Vetor do WannaCry via EternalBlue — garantir patch MS17-010 aplicado e acesso restrito"))
    if has_unknown:
        recs.append(("HIGH", "Investigar hosts com zona UNKNOWN", "Hosts com portas abertas não classificadas — podem ser dispositivos não gerenciados"))
    if has_rdp:
        recs.append(("HIGH", "Restringir RDP (3389) por endereço IP", "RDP exposto é alvo constante de brute force — usar VPN ou IP allowlist"))
    if metrics["dmz_hosts"] == 0 and len(hosts) > 2:
        recs.append(("MEDIUM", "Considerar criação de DMZ para serviços públicos", "Serviços web e DNS devem estar em zona separada da rede interna"))
    if not recs:
        recs.append(("LOW", "Manter monitoramento periódico da superfície de ataque", "Executar varredura regularmente para detectar novos dispositivos"))

    rows_recs = ""
    for i, (sev, acao, motivo) in enumerate(recs, 1):
        sc = risk_colors.get(sev, "#374151")
        rows_recs += f"""
        <tr>
          <td class="center muted">{i}</td>
          <td><span style="font-size:0.72rem;font-weight:700;color:{sc};border:1px solid {sc};padding:2px 7px;border-radius:2px">{sev}</span></td>
          <td>{acao}</td>
          <td class="small muted">{motivo}</td>
        </tr>"""

    # Legenda de zonas
    zone_legend = ""
    for zname, zinfo in SECURITY_ZONES.items():
        count = zone_counts.get(zname, 0)
        zone_legend += f"""
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
          <span style="font-size:0.72rem;font-weight:700;color:{zinfo['color']};border:1px solid {zinfo['border']};
                padding:2px 8px;border-radius:2px;background:{zinfo['bg']};white-space:nowrap">{zname}</span>
          <span style="font-size:0.82rem;color:#475569">{zinfo['desc']}</span>
          <span style="font-size:0.78rem;color:#94A3B8;margin-left:auto">({count} hosts)</span>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Network Zone Map Report — Lab 20</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, 'Segoe UI', Arial, sans-serif; background: #F0F2F5; color: #1E293B; font-size: 13px; line-height: 1.5; padding: 2rem; }}
  .page {{ max-width: 1200px; margin: 0 auto; }}
  .report-header {{ background: #FFFFFF; border: 1px solid #CBD5E1; border-top: 3px solid #1E3A5F; padding: 1.2rem 1.5rem; margin-bottom: 1.2rem; display: flex; justify-content: space-between; align-items: flex-start; }}
  .report-header h1 {{ font-size: 1.1rem; font-weight: 700; color: #1E293B; }}
  .report-header p {{ font-size: 0.78rem; color: #64748B; margin-top: 2px; }}
  .meta {{ font-size: 0.75rem; color: #64748B; text-align: right; line-height: 1.8; }}
  .meta strong {{ color: #374151; }}
  .risk-banner {{ background: #FFFFFF; border: 1px solid #CBD5E1; border-left: 4px solid {overall_color}; padding: 0.9rem 1.2rem; margin-bottom: 1.2rem; display: flex; align-items: center; gap: 1.5rem; }}
  .risk-label {{ font-size: 0.68rem; font-weight: 600; color: #64748B; text-transform: uppercase; letter-spacing: 0.8px; }}
  .risk-value {{ font-size: 1.3rem; font-weight: 700; color: {overall_color}; }}
  .risk-desc {{ font-size: 0.82rem; color: #475569; }}
  .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.2rem; }}
  .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.8rem; margin-bottom: 1.2rem; }}
  .stat {{ background: #FFFFFF; border: 1px solid #CBD5E1; padding: 0.8rem 1rem; }}
  .stat .num {{ font-size: 1.6rem; font-weight: 700; color: #1E293B; }}
  .stat .lbl {{ font-size: 0.7rem; color: #64748B; margin-top: 2px; text-transform: uppercase; letter-spacing: 0.5px; }}
  .panel {{ background: #FFFFFF; border: 1px solid #CBD5E1; padding: 1rem 1.2rem; }}
  .section-label {{ font-size: 0.7rem; font-weight: 700; color: #64748B; text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 0.5rem; padding-bottom: 0.4rem; border-bottom: 1px solid #E2E8F0; }}
  .table-wrap {{ overflow-x: auto; margin-bottom: 1.2rem; }}
  table {{ width: 100%; border-collapse: collapse; background: #FFFFFF; border: 1px solid #CBD5E1; font-size: 0.82rem; }}
  thead tr {{ background: #F8FAFC; border-bottom: 2px solid #CBD5E1; }}
  th {{ padding: 8px 12px; text-align: left; font-size: 0.7rem; font-weight: 600; color: #475569; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #F1F5F9; vertical-align: middle; color: #334155; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #F8FAFC; }}
  .center {{ text-align: center; }}
  .mono {{ font-family: 'Consolas', 'Courier New', monospace; font-size: 0.78rem; }}
  .small {{ font-size: 0.78rem; }}
  .muted {{ color: #94A3B8; }}
  .concept {{ background: #FFFFFF; border: 1px solid #CBD5E1; border-left: 3px solid #1E3A5F; padding: 1rem 1.2rem; margin-bottom: 1.2rem; }}
  .concept h3 {{ font-size: 0.8rem; font-weight: 700; color: #1E3A5F; margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 0.5px; }}
  .concept p {{ font-size: 0.82rem; color: #475569; line-height: 1.7; }}
  .concept p + p {{ margin-top: 0.4rem; }}
  .footer {{ text-align: center; font-size: 0.72rem; color: #94A3B8; padding-top: 1rem; border-top: 1px solid #E2E8F0; margin-top: 1rem; }}
</style>
</head>
<body>
<div class="page">

  <div class="report-header">
    <div>
      <h1>Network Zone Map Report</h1>
      <p>Security+ SY0-701 — Lab 20 — Domínio 3 &nbsp;·&nbsp; Luiz Otavio Gonçalves Gilio</p>
    </div>
    <div class="meta">
      <strong>Host:</strong> {hostname}<br>
      <strong>Sistema:</strong> {sistema}<br>
      <strong>Rede varrida:</strong> {network_base}.0/24<br>
      <strong>Gerado em:</strong> {agora}
    </div>
  </div>

  <div class="risk-banner">
    <div>
      <div class="risk-label">Superfície de Ataque</div>
      <div class="risk-value">{metrics['overall_risk']}</div>
    </div>
    <div style="width:1px;height:40px;background:#E2E8F0;margin:0 0.5rem"></div>
    <div class="risk-desc">
      {len(hosts)} host(s) ativo(s) &nbsp;·&nbsp;
      {metrics['total_open_ports']} porta(s) abertas &nbsp;·&nbsp;
      {metrics['critical_ports']} porta(s) crítica(s) &nbsp;·&nbsp;
      {metrics['unknown_hosts']} host(s) não classificado(s)
    </div>
  </div>

  <div class="stats">
    <div class="stat"><div class="num">{len(hosts)}</div><div class="lbl">Hosts Ativos</div></div>
    <div class="stat"><div class="num" style="color:#166534">{zone_counts.get('TRUSTED',0)}</div><div class="lbl">Trusted</div></div>
    <div class="stat"><div class="num" style="color:#92400E">{zone_counts.get('DMZ',0)}</div><div class="lbl">DMZ</div></div>
    <div class="stat"><div class="num" style="color:#B91C1C">{zone_counts.get('UNKNOWN',0)}</div><div class="lbl">Unknown</div></div>
    <div class="stat"><div class="num" style="color:#B91C1C">{metrics['critical_ports']}</div><div class="lbl">Portas Críticas</div></div>
  </div>

  <div class="two-col">
    <div class="panel">
      <div class="section-label">Legenda de Zonas de Segurança</div>
      {zone_legend}
    </div>
    <div class="panel">
      <div class="section-label">Distribuição por Zona</div>
      {''.join(f'<div style="margin-bottom:10px"><div style="display:flex;justify-content:space-between;margin-bottom:3px"><span style="font-size:0.8rem;font-weight:600;color:{SECURITY_ZONES.get(z,SECURITY_ZONES["UNKNOWN"])["color"]}">{z}</span><span class="muted small">{c} host(s)</span></div><div style="background:#F1F5F9;height:8px;border-radius:2px"><div style="background:{SECURITY_ZONES.get(z,SECURITY_ZONES["UNKNOWN"])["color"]};height:8px;border-radius:2px;width:{min(100, c/max(len(hosts),1)*100):.0f}%"></div></div></div>' for z, c in zone_counts.items())}
    </div>
  </div>

  <div class="section-label">Recomendações Priorizadas</div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>#</th><th>Severidade</th><th>Ação</th><th>Justificativa</th></tr></thead>
      <tbody>{rows_recs}</tbody>
    </table>
  </div>

  <div class="section-label">Mapa de Hosts por Zona</div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Endereço IP</th><th>Hostname</th><th>Zona</th><th>Portas Abertas</th><th>Total</th></tr></thead>
      <tbody>{rows_hosts}</tbody>
    </table>
  </div>

  <div class="section-label">Portas Críticas e Altas Detectadas</div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>IP</th><th>Porta</th><th>Serviço</th><th>Risco</th><th>Zona</th><th>Descrição</th></tr></thead>
      <tbody>{rows_ports}</tbody>
    </table>
  </div>

  <div class="concept">
    <h3>Conceitos demonstrados neste lab</h3>
    <p>
      <strong>Security Zones</strong> separam a rede por nível de confiança — Trusted (interna), DMZ (serviços públicos)
      e Untrusted (internet). Esta separação é fundamental: um atacante que comprometa um servidor DMZ não deve
      conseguir acessar diretamente a rede interna.
    </p>
    <p>
      A <strong>Attack Surface</strong> é calculada pelo número de portas abertas e serviços expostos. Cada porta
      desnecessária aberta é um vetor potencial de ataque. O <strong>SMB (445)</strong> aberto foi o vetor do
      WannaCry — o patch MS17-010 corrige a vulnerabilidade mas não remove o risco de exposição.
      <strong>VLANs</strong> implementam o isolamento de zonas no mesmo hardware físico.
    </p>
  </div>

  <div class="footer">
    github.com/LuizGilio/security-plus-studies &nbsp;·&nbsp; CompTIA Security+ SY0-701 — Domínio 3
  </div>

</div>
</body>
</html>"""

    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(html)

    log = {
        "timestamp":    datetime.datetime.now().isoformat(),
        "hostname":     hostname,
        "network_base": network_base,
        "local_ip":     local_ip,
        "hosts":        hosts,
        "metrics":      metrics,
        "zone_counts":  zone_counts,
    }
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2, ensure_ascii=False)

    print(f"\n  Relatorio: {OUTPUT_HTML}")
    print(f"  Log JSON:  {OUTPUT_JSON}")


# ══════════════════════════════════════════════════════════
# PONTO DE ENTRADA
# ══════════════════════════════════════════════════════════

import sys

def main():
    parser = argparse.ArgumentParser(
        description="Network Zone Mapper — Lab 20 Security+",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--scan",   action="store_true", help="Executa varredura da rede local")
    parser.add_argument("--range",  metavar="BASE", help="Base da rede (ex: 192.168.1)")
    parser.add_argument("--hosts",  type=int, default=20, help="Numero de hosts a varrer (padrao: 20)")
    parser.add_argument("--report", action="store_true", help="Gera relatorio do ultimo scan")
    args = parser.parse_args()

    print("\n" + "="*60)
    print("  NETWORK ZONE MAPPER — Lab 20")
    print("  Security+ SY0-701 — Dominio 3")
    print("="*60)

    if args.report:
        if not os.path.exists(OUTPUT_JSON):
            print("\n  Log nao encontrado. Execute primeiro: --scan\n")
            return
        with open(OUTPUT_JSON) as f:
            log = json.load(f)
        gerar_relatorio(log["hosts"], log["local_ip"], log["network_base"])
        print(f"\n  Abra: start {OUTPUT_HTML}\n")
        return

    if args.scan:
        hosts, local_ip = run_scan(args.range, args.hosts)
        if not hosts:
            print("\n  Nenhum host ativo encontrado.\n")
            return
        local_ip_obj, base = get_local_network()
        network_base = args.range or base
        gerar_relatorio(hosts, local_ip, network_base)
        print(f"\n  Abra: start {OUTPUT_HTML}\n")
        return

    print("""
  Uso:
    python network_zone_mapper.py --scan
    python network_zone_mapper.py --scan --range 192.168.1 --hosts 30
    python network_zone_mapper.py --report
    """)

if __name__ == "__main__":
    main()
