"""
=============================================================
LAB 22 — Security Architecture Dashboard — Domínio 3
Security+ SY0-701 — Visão Consolidada SOC
=============================================================
Autor: Luiz Otavio Gonçalves Gilio
GitHub: github.com/LuizGilio

CONCEITO:
    Consolida os resultados dos Labs 20 (Network Zone Mapper)
    e 21 (Data Classification Auditor) num painel SOC
    unificado — correlacionando ameaças de rede com risco
    de exposição de dados.

COMO USAR:
    python dashboard_d3.py         → lê logs reais dos labs
    python dashboard_d3.py --demo  → dados de demonstração
=============================================================
"""

import json
import os
import datetime
import argparse
import socket
import platform

OUTPUT_FILE = "./security_dashboard_d3.html"

ZONE_LOG = "../lab-20-network-zone-mapper/zone_map_log.json"
DATA_LOG  = "../lab-21-data-classification-auditor/classification_log.json"


# ══════════════════════════════════════════════════════════
# COLETA DE DADOS
# ══════════════════════════════════════════════════════════

def load_zone(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_data(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def demo_data():
    zone = {
        "network_base": "192.168.15",
        "local_ip":     "192.168.15.5",
        "metrics": {
            "overall_risk":     "HIGH",
            "total_open_ports": 5,
            "critical_ports":   1,
            "unknown_hosts":    0,
            "dmz_hosts":        0,
        },
        "zone_counts": {"TRUSTED": 2, "DMZ": 0, "UNKNOWN": 0},
        "hosts": [
            {"ip":"192.168.15.1","hostname":"menuvivofibra","zone":"TRUSTED","is_local":False,
             "open_ports":[22,80],"port_details":[
                {"port":22,"service":"SSH","risk":"MEDIUM","desc":"Acesso remoto seguro"},
                {"port":80,"service":"HTTP","risk":"MEDIUM","desc":"Web sem criptografia"},
             ]},
            {"ip":"192.168.15.5","hostname":"DESKTOP-K5E630E","zone":"TRUSTED","is_local":True,
             "open_ports":[135,139,445],"port_details":[
                {"port":135,"service":"RPC",    "risk":"HIGH",    "desc":"RPC Windows — vetor comum de ataques"},
                {"port":139,"service":"NetBIOS","risk":"HIGH",    "desc":"NetBIOS — relacionado ao EternalBlue"},
                {"port":445,"service":"SMB",    "risk":"CRITICAL","desc":"SMB — vetor do WannaCry (EternalBlue)"},
             ]},
        ],
    }
    data = {
        "scan_path":      "./demo_files",
        "total_scanned":  6,
        "total_flagged":  5,
        "total_critical": 0,
        "total_high":     5,
        "overall_risk":   "HIGH",
        "category_counts":{"PII":8,"PHI":4,"Financial":5,"Credentials":2},
        "files": [
            {"path":"config.env",          "risk":"HIGH","total_matches":3,"critical_count":0,"findings":[{"category":"Credentials","severity":"CRITICAL","count":2},{"category":"PII","severity":"HIGH","count":1}]},
            {"path":"pagamentos.json",     "risk":"HIGH","total_matches":3,"critical_count":0,"findings":[{"category":"Financial","severity":"CRITICAL","count":3}]},
            {"path":"relatorio_medico.txt","risk":"HIGH","total_matches":4,"critical_count":0,"findings":[{"category":"PHI","severity":"CRITICAL","count":4}]},
            {"path":"clientes.csv",        "risk":"HIGH","total_matches":6,"critical_count":0,"findings":[{"category":"PII","severity":"CRITICAL","count":6}]},
            {"path":"logs_sistema.log",    "risk":"HIGH","total_matches":5,"critical_count":0,"findings":[{"category":"Financial","severity":"HIGH","count":3},{"category":"PII","severity":"HIGH","count":2}]},
        ],
    }
    return zone, data


def calc_overall(zone, data):
    pts = 0
    if zone:
        pts += zone["metrics"]["critical_ports"] * 5
        pts += zone["metrics"]["unknown_hosts"]  * 3
        pts += zone["metrics"]["total_open_ports"]
    if data:
        pts += data["total_critical"] * 4
        pts += data["total_high"]     * 2
    if pts >= 15: return "CRITICAL", "#B91C1C"
    if pts >= 8:  return "HIGH",     "#92400E"
    if pts >= 3:  return "MEDIUM",   "#1E3A5F"
    return             "LOW",       "#166534"


# ══════════════════════════════════════════════════════════
# GERADOR HTML
# ══════════════════════════════════════════════════════════

def gerar_html(zone, data, demo=False):
    agora    = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    hostname = socket.gethostname()
    sistema  = platform.system() + " " + platform.release()

    overall_risk, overall_color = calc_overall(zone, data)

    rc = {"CRITICAL":"#B91C1C","HIGH":"#92400E","MEDIUM":"#1E3A5F","LOW":"#166534","CLEAN":"#166534"}

    # ── Métricas de rede ──────────────────────────────
    z_hosts      = len(zone["hosts"])           if zone else 0
    z_critical   = zone["metrics"]["critical_ports"] if zone else 0
    z_open       = zone["metrics"]["total_open_ports"] if zone else 0
    z_risk       = zone["metrics"]["overall_risk"]  if zone else "N/A"
    z_network    = zone.get("network_base","—") if zone else "—"
    z_counts     = zone.get("zone_counts",{})   if zone else {}

    # ── Métricas de dados ─────────────────────────────
    d_scanned    = data["total_scanned"]  if data else 0
    d_flagged    = data["total_flagged"]  if data else 0
    d_critical   = data["total_critical"] if data else 0
    d_high       = data["total_high"]     if data else 0
    d_risk       = data["overall_risk"]   if data else "N/A"
    d_cats       = data.get("category_counts",{}) if data else {}

    # ── Cards de zona ─────────────────────────────────
    zone_colors = {"TRUSTED":"#166534","DMZ":"#92400E","UNKNOWN":"#B91C1C","UNTRUSTED":"#B91C1C"}
    cards_zone = ""
    for zname, zcount in z_counts.items():
        zc = zone_colors.get(zname,"#374151")
        cards_zone += f"""
        <div style="background:#FFFFFF;border:1px solid #CBD5E1;border-top:2px solid {zc};padding:0.8rem 1rem;text-align:center">
          <div style="font-size:1.4rem;font-weight:700;color:{zc}">{zcount}</div>
          <div style="font-size:0.7rem;color:#64748B;margin-top:2px;text-transform:uppercase;letter-spacing:0.5px">{zname}</div>
        </div>"""

    # ── Cards de categoria de dados ───────────────────
    cat_colors = {"PII":"#B91C1C","PHI":"#B91C1C","Financial":"#92400E","Credentials":"#B91C1C"}
    cards_data = ""
    for cat, count in d_cats.items():
        cc = cat_colors.get(cat,"#1E3A5F")
        cards_data += f"""
        <div style="background:#FFFFFF;border:1px solid #CBD5E1;border-top:2px solid {cc};padding:0.8rem 1rem;text-align:center">
          <div style="font-size:1.4rem;font-weight:700;color:{cc}">{count}</div>
          <div style="font-size:0.7rem;color:#64748B;margin-top:2px;text-transform:uppercase;letter-spacing:0.5px">{cat}</div>
        </div>"""

    # ── Tabela hosts ──────────────────────────────────
    rows_hosts = ""
    if zone:
        for h in zone["hosts"]:
            zc = zone_colors.get(h["zone"],"#374151")
            zb = {"TRUSTED":"#F0FDF4","DMZ":"#FFFBEB","UNKNOWN":"#FEF2F2"}.get(h["zone"],"#F9FAFB")
            zbd= {"TRUSTED":"#86EFAC","DMZ":"#FCD34D","UNKNOWN":"#FCA5A5"}.get(h["zone"],"#D1D5DB")
            local_tag = ' <span style="font-size:0.68rem;color:#1E3A5F;border:1px solid #1E3A5F;padding:1px 4px">THIS HOST</span>' if h["is_local"] else ""
            ports_html = ""
            for pd in h.get("port_details",[]):
                prc = rc.get(pd["risk"],"#374151")
                ports_html += f'<span style="font-size:0.72rem;font-family:monospace;color:{prc};margin-right:5px">{pd["port"]}/{pd["service"]}</span>'
            rows_hosts += f"""
            <tr>
              <td style="font-family:monospace;font-size:0.78rem">{h['ip']}{local_tag}</td>
              <td style="font-size:0.78rem;color:#64748B">{h['hostname'] if h['hostname']!=h['ip'] else '—'}</td>
              <td><span style="font-size:0.7rem;font-weight:700;color:{zc};border:1px solid {zbd};padding:2px 6px;background:{zb}">{h['zone']}</span></td>
              <td>{ports_html or '<span style="color:#94A3B8">—</span>'}</td>
              <td style="text-align:center;font-size:0.82rem">{len(h['open_ports'])}</td>
            </tr>"""

    # ── Tabela arquivos ───────────────────────────────
    rows_files = ""
    if data:
        for f in sorted(data["files"], key=lambda x: x["total_matches"], reverse=True)[:8]:
            frc = rc.get(f["risk"],"#374151")
            cats = ", ".join(set(x["category"] for x in f.get("findings",[])))
            rows_files += f"""
            <tr>
              <td style="font-family:monospace;font-size:0.78rem">{f['path']}</td>
              <td style="text-align:center"><span style="font-size:0.7rem;font-weight:700;color:{frc};border:1px solid {frc};padding:2px 6px">{f['risk']}</span></td>
              <td style="text-align:center;font-size:0.82rem">{f['total_matches']}</td>
              <td style="font-size:0.78rem;color:#475569">{cats}</td>
            </tr>"""

    # ── Correlação de risco ───────────────────────────
    correlations = []
    if zone and data:
        has_smb = any(445 in h["open_ports"] for h in zone["hosts"])
        has_creds = "Credentials" in d_cats
        has_pii = "PII" in d_cats
        has_phi = "PHI" in d_cats

        if has_smb and has_creds:
            correlations.append({
                "risk":"CRITICAL",
                "finding":"SMB (445) aberto + credenciais em texto claro detectadas",
                "impact":"Credenciais expostas podem ser usadas para autenticar via SMB e comprometer a rede",
                "action":"Fechar SMB externamente e remover credenciais de arquivos — usar cofre de senhas",
            })
        if has_smb and has_pii:
            correlations.append({
                "risk":"HIGH",
                "finding":"SMB (445) aberto + dados PII armazenados sem proteção",
                "impact":"Acesso via SMB pode expor arquivos com dados pessoais — violação da LGPD",
                "action":"Criptografar arquivos com PII (BitLocker/EFS) e restringir acesso SMB por IP",
            })
        if has_phi:
            correlations.append({
                "risk":"CRITICAL",
                "finding":"Dados PHI detectados sem controles de acesso verificados",
                "impact":"Dados de saúde exigem isolamento em área restrita — regulamentação específica",
                "action":"Mover arquivos PHI para servidor dedicado com acesso mínimo (Least Privilege)",
            })
        if not correlations:
            correlations.append({
                "risk":"LOW",
                "finding":"Nenhuma correlação crítica identificada",
                "impact":"Ambiente com controles básicos adequados",
                "action":"Manter monitoramento periódico — executar labs regularmente",
            })

    rows_corr = ""
    for i, c in enumerate(correlations, 1):
        crc = rc.get(c["risk"],"#374151")
        rows_corr += f"""
        <tr>
          <td style="text-align:center;color:#94A3B8;font-size:0.82rem">{i}</td>
          <td><span style="font-size:0.7rem;font-weight:700;color:{crc};border:1px solid {crc};padding:2px 6px">{c['risk']}</span></td>
          <td style="font-size:0.82rem">{c['finding']}</td>
          <td style="font-size:0.78rem;color:#475569">{c['impact']}</td>
          <td style="font-size:0.78rem;color:#166534">{c['action']}</td>
        </tr>"""

    demo_banner = ""
    if demo:
        demo_banner = '<div style="background:#FFFBEB;border:1px solid #FCD34D;padding:0.6rem 1rem;font-size:0.8rem;color:#92400E;margin-bottom:1rem">Modo demonstracao — dados simulados dos Labs 20 e 21</div>'

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Security Architecture Dashboard D3 — Lab 22</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, 'Segoe UI', Arial, sans-serif; background: #F0F2F5; color: #1E293B; font-size: 13px; line-height: 1.5; padding: 2rem; }}
  .page {{ max-width: 1280px; margin: 0 auto; }}
  .report-header {{ background: #FFFFFF; border: 1px solid #CBD5E1; border-top: 3px solid #1E3A5F; padding: 1.2rem 1.5rem; margin-bottom: 1rem; display: flex; justify-content: space-between; align-items: flex-start; }}
  .report-header h1 {{ font-size: 1.1rem; font-weight: 700; color: #1E293B; }}
  .report-header p {{ font-size: 0.78rem; color: #64748B; margin-top: 2px; }}
  .meta {{ font-size: 0.75rem; color: #64748B; text-align: right; line-height: 1.8; }}
  .meta strong {{ color: #374151; }}
  .risk-banner {{ background: #FFFFFF; border: 1px solid #CBD5E1; border-left: 4px solid {overall_color}; padding: 0.9rem 1.2rem; margin-bottom: 1rem; display: flex; align-items: center; gap: 1.5rem; }}
  .risk-label {{ font-size: 0.68rem; font-weight: 600; color: #64748B; text-transform: uppercase; letter-spacing: 0.8px; }}
  .risk-value {{ font-size: 1.3rem; font-weight: 700; color: {overall_color}; }}
  .risk-desc {{ font-size: 0.82rem; color: #475569; }}
  .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem; }}
  .panel {{ background: #FFFFFF; border: 1px solid #CBD5E1; padding: 1rem 1.2rem; }}
  .panel-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.8rem; padding-bottom: 0.5rem; border-bottom: 1px solid #F1F5F9; }}
  .panel-title {{ font-size: 0.82rem; font-weight: 600; color: #1E293B; }}
  .panel-sub {{ font-size: 0.72rem; color: #64748B; }}
  .mini-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.6rem; margin-top: 0.6rem; }}
  .section-label {{ font-size: 0.7rem; font-weight: 700; color: #64748B; text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 0.5rem; padding-bottom: 0.4rem; border-bottom: 1px solid #E2E8F0; }}
  .table-wrap {{ overflow-x: auto; margin-bottom: 1rem; }}
  table {{ width: 100%; border-collapse: collapse; background: #FFFFFF; border: 1px solid #CBD5E1; font-size: 0.82rem; }}
  thead tr {{ background: #F8FAFC; border-bottom: 2px solid #CBD5E1; }}
  th {{ padding: 8px 12px; text-align: left; font-size: 0.7rem; font-weight: 600; color: #475569; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #F1F5F9; vertical-align: middle; color: #334155; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #F8FAFC; }}
  .concept {{ background: #FFFFFF; border: 1px solid #CBD5E1; border-left: 3px solid #1E3A5F; padding: 1rem 1.2rem; margin-bottom: 1rem; }}
  .concept h3 {{ font-size: 0.8rem; font-weight: 700; color: #1E3A5F; margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 0.5px; }}
  .concept p {{ font-size: 0.82rem; color: #475569; line-height: 1.7; }}
  .concept p + p {{ margin-top: 0.4rem; }}
  .footer {{ text-align: center; font-size: 0.72rem; color: #94A3B8; padding-top: 1rem; border-top: 1px solid #E2E8F0; }}
</style>
</head>
<body>
<div class="page">

  <div class="report-header">
    <div>
      <h1>Security Architecture Dashboard</h1>
      <p>Security+ SY0-701 — Lab 22 — Domínio 3 &nbsp;·&nbsp; Luiz Otavio Gonçalves Gilio</p>
    </div>
    <div class="meta">
      <strong>Host:</strong> {hostname}<br>
      <strong>Sistema:</strong> {sistema}<br>
      <strong>Ultima atualizacao:</strong> {agora}
    </div>
  </div>

  {demo_banner}

  <div class="risk-banner">
    <div>
      <div class="risk-label">Risco Consolidado</div>
      <div class="risk-value">{overall_risk}</div>
    </div>
    <div style="width:1px;height:40px;background:#E2E8F0;margin:0 0.5rem"></div>
    <div class="risk-desc">
      Rede {z_network}.0/24 &nbsp;·&nbsp;
      {z_hosts} host(s) ativo(s) &nbsp;·&nbsp;
      {z_critical} porta(s) critica(s) &nbsp;·&nbsp;
      {d_flagged} arquivo(s) com dados sensiveis &nbsp;·&nbsp;
      {d_critical + d_high} ocorrencias de risco
    </div>
  </div>

  <div class="two-col">
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Lab 20 — Network Zone Mapper</span>
        <span class="panel-sub" style="color:{rc.get(z_risk,'#374151')};font-weight:600">{z_risk}</span>
      </div>
      <div style="font-size:0.82rem;color:#475569;margin-bottom:0.8rem">
        {z_hosts} hosts ativos &nbsp;·&nbsp; {z_open} portas abertas &nbsp;·&nbsp; {z_critical} criticas
      </div>
      <div style="display:grid;grid-template-columns:repeat({max(len(z_counts),1)},1fr);gap:0.6rem">
        {cards_zone}
      </div>
    </div>
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Lab 21 — Data Classification Auditor</span>
        <span class="panel-sub" style="color:{rc.get(d_risk,'#374151')};font-weight:600">{d_risk}</span>
      </div>
      <div style="font-size:0.82rem;color:#475569;margin-bottom:0.8rem">
        {d_scanned} arquivos varridos &nbsp;·&nbsp; {d_flagged} flagados &nbsp;·&nbsp; {d_critical} criticos
      </div>
      <div style="display:grid;grid-template-columns:repeat({max(len(d_cats),1)},1fr);gap:0.6rem">
        {cards_data}
      </div>
    </div>
  </div>

  <div class="section-label">Correlacao de Riscos — Rede + Dados</div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>#</th><th>Risco</th><th>Correlacao</th><th>Impacto</th><th>Acao Recomendada</th></tr></thead>
      <tbody>{rows_corr}</tbody>
    </table>
  </div>

  <div class="two-col">
    <div>
      <div class="section-label">Hosts por Zona — Lab 20</div>
      <div class="table-wrap" style="margin-bottom:0">
        <table>
          <thead><tr><th>IP</th><th>Hostname</th><th>Zona</th><th>Portas</th><th>#</th></tr></thead>
          <tbody>{rows_hosts or '<tr><td colspan="5" style="text-align:center;color:#94A3B8">Sem dados</td></tr>'}</tbody>
        </table>
      </div>
    </div>
    <div>
      <div class="section-label">Arquivos Sensiveis — Lab 21</div>
      <div class="table-wrap" style="margin-bottom:0">
        <table>
          <thead><tr><th>Arquivo</th><th>Risco</th><th>Ocorr.</th><th>Categorias</th></tr></thead>
          <tbody>{rows_files or '<tr><td colspan="4" style="text-align:center;color:#94A3B8">Sem dados</td></tr>'}</tbody>
        </table>
      </div>
    </div>
  </div>

  <br>
  <div class="concept">
    <h3>Conceitos consolidados neste projeto</h3>
    <p>
      O <strong>Lab 20</strong> mapeou a topologia de segurança da rede — identificando zonas (Trusted, DMZ, Unknown),
      superfície de ataque e portas críticas. O <strong>SMB (445)</strong> aberto no host local representa o mesmo
      vetor explorado pelo WannaCry via EternalBlue — presente nos Labs 17 e 18 do Domínio 2.
    </p>
    <p>
      O <strong>Lab 21</strong> auditou os dados armazenados em disco — detectando PII, PHI e credenciais em texto
      claro. A correlação entre ambos revela o risco real: dados sensíveis expostos em uma máquina com portas
      críticas abertas aumentam drasticamente o impacto de um comprometimento.
    </p>
    <p>
      Este dashboard demonstra como um analista SOC correlaciona <strong>riscos de rede</strong> com
      <strong>riscos de dados</strong> para priorizar remediações — o núcleo do trabalho de Security Architecture.
    </p>
  </div>

  <div class="footer">
    github.com/LuizGilio/security-plus-studies &nbsp;·&nbsp; CompTIA Security+ SY0-701 — Domínio 3
  </div>

</div>
</body>
</html>"""

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n  Dashboard gerado: {OUTPUT_FILE}")
    print(f"  Abra: start {OUTPUT_FILE}\n")


# ══════════════════════════════════════════════════════════
# PONTO DE ENTRADA
# ══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Security Architecture Dashboard D3 — Lab 22")
    parser.add_argument("--demo", action="store_true", help="Usa dados de demonstracao")
    args = parser.parse_args()

    print("\n" + "="*60)
    print("  SECURITY ARCHITECTURE DASHBOARD — Lab 22")
    print("  Security+ SY0-701 — Dominio 3")
    print("="*60)

    if args.demo:
        zone, data = demo_data()
        gerar_html(zone, data, demo=True)
        return

    zone = load_zone(ZONE_LOG)
    data = load_data(DATA_LOG)

    if not zone and not data:
        print("\n  Logs nao encontrados — rodando em modo demo.\n")
        zone, data = demo_data()
        gerar_html(zone, data, demo=True)
    else:
        gerar_html(zone, data, demo=False)


if __name__ == "__main__":
    main()
