"""
=============================================================
LAB 19 — Security Operations Dashboard — Domínio 2
Security+ SY0-701 — Visão Consolidada SOC
=============================================================
Autor: Luiz Otavio Gonçalves Gilio
GitHub: github.com/LuizGilio

CONCEITO:
    Consolida os resultados dos Labs 17 (Malware Simulator)
    e 18 (Hardening Auditor) num painel SOC unificado —
    simulando o que um analista veria no dia a dia.

COMO USAR:
    python dashboard_d2.py         → lê logs reais dos labs
    python dashboard_d2.py --demo  → dados de demonstração
=============================================================
"""

import json
import os
import datetime
import argparse

# ── Caminhos dos logs dos labs ─────────────────────────
MALWARE_LOG  = "../lab-17-malware-behavior-simulator/malware_iocs.json"
HARDENING_LOG= "../lab-18-hardening-auditor/hardening_log.json"
OUTPUT_FILE  = "./security_dashboard_d2.html"


# ══════════════════════════════════════════════════════════
# COLETA DE DADOS
# ══════════════════════════════════════════════════════════

def carregar_malware(caminho):
    if not os.path.exists(caminho):
        return None
    with open(caminho, "r", encoding="utf-8") as f:
        iocs = json.load(f)

    total    = len(iocs)
    criticos = sum(1 for i in iocs if i["severidade"] == "CRÍTICO")
    altos    = sum(1 for i in iocs if i["severidade"] == "ALTO")

    por_malware = {}
    for ioc in iocs:
        m = ioc["malware"]
        por_malware[m] = por_malware.get(m, 0) + 1

    return {
        "total":       total,
        "criticos":    criticos,
        "altos":       altos,
        "por_malware": por_malware,
        "iocs":        iocs[-20:],
    }


def carregar_hardening(caminho):
    if not os.path.exists(caminho):
        return None
    with open(caminho, "r", encoding="utf-8") as f:
        return json.load(f)


def dados_demo():
    malware = {
        "total": 24, "criticos": 16, "altos": 6,
        "por_malware": {
            "Virus": 6, "Ransomware": 6,
            "Worm": 2, "Keylogger": 4, "Logic Bomb": 6
        },
        "iocs": [
            {"timestamp":"2026-03-19T13:28:25","malware":"Virus","ioc_tipo":"Hash de Arquivo Alterado","descricao":"sistema_config.exe modificado","severidade":"ALTO"},
            {"timestamp":"2026-03-19T13:28:25","malware":"Virus","ioc_tipo":"Tentativa de Replicacao","descricao":"Tentativa de escrita em C:\\Windows\\System32","severidade":"CRÍTICO"},
            {"timestamp":"2026-03-19T13:28:26","malware":"Ransomware","ioc_tipo":"Arquivo Criptografado","descricao":"relatorio_financeiro_2026.xlsx → .LOCKED_WNCRY","severidade":"CRÍTICO"},
            {"timestamp":"2026-03-19T13:28:27","malware":"Ransomware","ioc_tipo":"Nota de Resgate Criada","descricao":"!!!_LEIA_ISTO_!!!.txt criado","severidade":"CRÍTICO"},
            {"timestamp":"2026-03-19T13:28:30","malware":"Worm","ioc_tipo":"Varredura de Rede","descricao":"Varredura SMB em 8 hosts da rede 192.168.15.0/24","severidade":"ALTO"},
            {"timestamp":"2026-03-19T13:28:31","malware":"Worm","ioc_tipo":"Tentativa de Propagacao","descricao":"Infeccao via SMB em 192.168.15.5 (EternalBlue)","severidade":"CRÍTICO"},
            {"timestamp":"2026-03-19T13:28:32","malware":"Keylogger","ioc_tipo":"Credencial Capturada","descricao":"Credencial Bancaria capturada em chrome.exe","severidade":"CRÍTICO"},
            {"timestamp":"2026-03-19T13:28:33","malware":"Keylogger","ioc_tipo":"Exfiltracao de Dados","descricao":"Log enviado para C2: 185.125.71.76:443","severidade":"CRÍTICO"},
            {"timestamp":"2026-03-19T13:28:34","malware":"Logic Bomb","ioc_tipo":"Gatilho Ativado","descricao":"Ativa no dia 19 de cada mes","severidade":"ALTO"},
            {"timestamp":"2026-03-19T13:28:35","malware":"Logic Bomb","ioc_tipo":"Payload: Overwrite de MBR","descricao":"Tentativa de sobrescrita do Master Boot Record","severidade":"CRÍTICO"},
        ],
    }
    hardening = {
        "score": 62, "nivel": "REGULAR",
        "portas_abertas": 2, "portas_criticas": 1, "configs_falha": 2,
        "portas": [
            {"porta":445,"servico":"SMB","risco":"CRÍTICO","descricao":"Vetor do WannaCry (EternalBlue)"},
            {"porta":135,"servico":"RPC","risco":"ALTO","descricao":"Remote Procedure Call — comum em ataques Windows"},
        ],
        "configs": [
            {"nome":"Windows Defender","categoria":"Endpoint","ok":True,"risco":"BAIXO","rec":"Configuracao adequada"},
            {"nome":"Windows Firewall","categoria":"Host Firewall","ok":True,"risco":"BAIXO","rec":"Configuracao adequada"},
            {"nome":"UAC","categoria":"Least Privilege","ok":True,"risco":"BAIXO","rec":"Configuracao adequada"},
            {"nome":"Conta Guest desabilitada","categoria":"Controle de Acesso","ok":False,"risco":"MÉDIO","rec":"Desabilitar conta Guest"},
            {"nome":"Atualizacoes automaticas","categoria":"Patching","ok":False,"risco":"ALTO","rec":"Habilitar atualizacoes automaticas"},
        ],
        "recomendacoes": [
            {"prioridade":"CRÍTICO","acao":"Fechar porta 445 (SMB)","motivo":"Vetor do WannaCry via EternalBlue"},
            {"prioridade":"ALTO","acao":"Habilitar atualizacoes automaticas","motivo":"Patching"},
            {"prioridade":"ALTO","acao":"Avaliar necessidade da porta 135 (RPC)","motivo":"Vetor de ataques Windows"},
        ],
    }
    return malware, hardening


def calcular_risco_geral(malware, hardening):
    pts = 0
    if malware:
        pts += malware["criticos"] * 3
        pts += malware["altos"]
    if hardening:
        pts += hardening["portas_criticas"] * 5
        pts += hardening["configs_falha"] * 3
    if pts == 0:   return "BAIXO",   "22C55E"
    if pts <= 10:  return "MÉDIO",   "F59E0B"
    if pts <= 25:  return "ALTO",    "EF4444"
    return               "CRÍTICO", "EF4444"


# ══════════════════════════════════════════════════════════
# GERADOR HTML
# ══════════════════════════════════════════════════════════

def gerar_html(malware, hardening, demo=False):
    agora = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    risco, risco_cor = calcular_risco_geral(malware, hardening)

    # ── Métricas ───────────────────────────────────────
    ioc_total    = malware["total"]    if malware else 0
    ioc_criticos = malware["criticos"] if malware else 0
    hs_score     = hardening["score"]  if hardening else 0
    hs_nivel     = hardening["nivel"]  if hardening else "N/A"
    portas_crit  = hardening["portas_criticas"] if hardening else 0
    configs_falha= hardening["configs_falha"]   if hardening else 0

    hs_cor = "22C55E" if hs_score >= 80 else "F59E0B" if hs_score >= 60 else "EF4444"

    # ── Cards de malware ───────────────────────────────
    cores_mal = {
        "Virus":"EF4444","Ransomware":"8B5CF6",
        "Worm":"F59E0B","Keylogger":"06B6D4","Logic Bomb":"22C55E"
    }
    cards_mal = ""
    if malware:
        for nome, qtd in malware["por_malware"].items():
            cor = cores_mal.get(nome, "94A3B8")
            cards_mal += f"""
            <div class="mal-card">
              <div class="mal-num" style="color:#{cor}">{qtd}</div>
              <div class="mal-lbl">{nome}</div>
            </div>"""

    # ── Tabela de IOCs ─────────────────────────────────
    linhas_iocs = ""
    if malware and malware["iocs"]:
        for ioc in malware["iocs"]:
            cor_sev = {"CRÍTICO":"#EF4444","ALTO":"#F59E0B",
                       "MÉDIO":"#06B6D4","BAIXO":"#22C55E"}.get(ioc["severidade"],"#94A3B8")
            cor_mal = "#" + cores_mal.get(ioc["malware"], "94A3B8")
            ts = ioc["timestamp"][11:19] if len(ioc["timestamp"]) > 11 else ioc["timestamp"]
            linhas_iocs += f"""
            <tr>
              <td style="color:#64748B;font-family:monospace;font-size:0.82rem">{ts}</td>
              <td><span style="color:{cor_mal};font-weight:600">{ioc['malware']}</span></td>
              <td style="color:#E2E8F0;font-size:0.85rem">{ioc['ioc_tipo']}</td>
              <td style="color:#94A3B8;font-size:0.83rem">{ioc['descricao']}</td>
              <td><span style="color:{cor_sev};font-weight:700">{ioc['severidade']}</span></td>
            </tr>"""

    # ── Tabela de portas ───────────────────────────────
    linhas_portas = ""
    if hardening and hardening.get("portas"):
        for p in hardening["portas"]:
            cor = {"CRÍTICO":"#EF4444","ALTO":"#F59E0B",
                   "MÉDIO":"#06B6D4","BAIXO":"#22C55E"}.get(p["risco"],"#94A3B8")
            linhas_portas += f"""
            <tr>
              <td><strong style="color:#E2E8F0">{p['porta']}</strong></td>
              <td style="color:#06B6D4">{p['servico']}</td>
              <td><span style="color:{cor};font-weight:700">{p['risco']}</span></td>
              <td style="color:#94A3B8;font-size:0.83rem">{p['descricao']}</td>
            </tr>"""
    if not linhas_portas:
        linhas_portas = '<tr><td colspan="4" style="text-align:center;color:#22C55E;padding:12px">Nenhuma porta de risco aberta</td></tr>'

    # ── Recomendações ──────────────────────────────────
    linhas_recs = ""
    if hardening and hardening.get("recomendacoes"):
        for i, r in enumerate(hardening["recomendacoes"], 1):
            cor = {"CRÍTICO":"#EF4444","ALTO":"#F59E0B","MÉDIO":"#06B6D4"}.get(r["prioridade"],"#94A3B8")
            linhas_recs += f"""
            <tr>
              <td style="color:#64748B;text-align:center">{i}</td>
              <td><span style="color:{cor};font-weight:700">{r['prioridade']}</span></td>
              <td style="color:#E2E8F0">{r['acao']}</td>
              <td style="color:#94A3B8;font-size:0.83rem">{r['motivo']}</td>
            </tr>"""

    # ── Configs ────────────────────────────────────────
    linhas_cfg = ""
    if hardening and hardening.get("configs"):
        for c in hardening["configs"]:
            cor_s = "#22C55E" if c["ok"] else "#EF4444"
            txt_s = "OK" if c["ok"] else "ATENCAO"
            linhas_cfg += f"""
            <tr>
              <td style="color:#E2E8F0">{c['nome']}</td>
              <td style="color:#94A3B8">{c['categoria']}</td>
              <td><span style="color:{cor_s};font-weight:600">{txt_s}</span></td>
              <td style="color:#94A3B8;font-size:0.83rem">{c['rec']}</td>
            </tr>"""

    demo_banner = ""
    if demo:
        demo_banner = '<div class="demo-banner">Modo demonstracao — dados simulados dos Labs 17 e 18</div>'

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Security Dashboard D2 — Lab 19</title>
<style>
  *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0F1117;color:#E2E8F0;font-size:14px;line-height:1.5;padding:2rem}}
  .page{{max-width:1280px;margin:0 auto}}
  .header{{display:flex;justify-content:space-between;align-items:flex-end;padding-bottom:1.2rem;border-bottom:1px solid #1E2837;margin-bottom:1.5rem}}
  .header-left h1{{font-size:1.4rem;font-weight:700;color:#F1F5F9;letter-spacing:-0.3px}}
  .header-left p{{font-size:0.8rem;color:#64748B;margin-top:3px}}
  .header-right{{font-size:0.78rem;color:#64748B;text-align:right}}
  .header-right strong{{color:#94A3B8}}
  .demo-banner{{background:#1C1608;border:1px solid #78350F;border-radius:6px;padding:0.6rem 1rem;font-size:0.82rem;color:#D97706;margin-bottom:1.5rem}}
  .risk-bar{{background:#161B27;border:1px solid #1E2837;border-radius:8px;padding:1rem 1.5rem;margin-bottom:1.5rem;display:flex;align-items:center;gap:1.5rem}}
  .risk-num{{font-size:1.5rem;font-weight:700;color:#{risco_cor}}}
  .risk-label{{font-size:0.72rem;color:#64748B;text-transform:uppercase;letter-spacing:0.8px;margin-bottom:3px}}
  .risk-div{{width:1px;height:40px;background:#1E2837;margin:0 0.5rem}}
  .risk-desc{{font-size:0.85rem;color:#94A3B8}}
  .stats{{display:grid;grid-template-columns:repeat(6,1fr);gap:1rem;margin-bottom:1.5rem}}
  .stat{{background:#161B27;border:1px solid #1E2837;border-radius:8px;padding:0.9rem 1rem}}
  .stat .num{{font-size:1.8rem;font-weight:700;color:#F1F5F9}}
  .stat .lbl{{font-size:0.72rem;color:#64748B;margin-top:3px}}
  .two-col{{display:grid;grid-template-columns:1fr 1fr;gap:1.2rem;margin-bottom:1.5rem}}
  .panel{{background:#161B27;border:1px solid #1E2837;border-radius:8px;padding:1.2rem}}
  .panel-header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;padding-bottom:0.7rem;border-bottom:1px solid #1E2837}}
  .panel-title{{font-size:0.88rem;font-weight:600;color:#E2E8F0}}
  .badge{{font-size:0.72rem;font-weight:700;padding:3px 8px;border-radius:4px;text-transform:uppercase;letter-spacing:0.5px}}
  .badge-ok{{background:#052E16;color:#22C55E}}
  .badge-warn{{background:#431407;color:#EF4444}}
  .badge-neutral{{background:#1E2837;color:#94A3B8}}
  .mal-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:0.7rem}}
  .mal-card{{background:#0F1117;border:1px solid #1E2837;border-radius:6px;padding:0.8rem;text-align:center}}
  .mal-num{{font-size:1.6rem;font-weight:700}}
  .mal-lbl{{font-size:0.75rem;color:#64748B;margin-top:3px}}
  .score-big{{font-size:2.5rem;font-weight:800;color:#{hs_cor}}}
  .score-nivel{{font-size:1rem;font-weight:600;color:#{hs_cor};margin-top:2px}}
  .section-title{{font-size:0.72rem;font-weight:700;color:#64748B;text-transform:uppercase;letter-spacing:1px;margin-bottom:0.8rem}}
  .table-wrap{{overflow-x:auto;margin-bottom:1.5rem}}
  table{{width:100%;border-collapse:collapse;background:#161B27;border-radius:8px;overflow:hidden;font-size:0.88rem}}
  thead tr{{background:#1E2837}}
  th{{padding:9px 12px;text-align:left;font-size:0.72rem;font-weight:600;color:#64748B;text-transform:uppercase;letter-spacing:0.6px;white-space:nowrap}}
  td{{padding:9px 12px;border-bottom:1px solid #1A2030;vertical-align:top}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#1A2030}}
  .concept{{background:#161B27;border:1px solid #1E2837;border-left:3px solid #3B82F6;border-radius:8px;padding:1.2rem 1.4rem;margin-bottom:1.5rem}}
  .concept h3{{font-size:0.85rem;font-weight:600;color:#93C5FD;margin-bottom:0.5rem}}
  .concept p{{font-size:0.85rem;color:#94A3B8;line-height:1.7}}
  .concept p+p{{margin-top:0.5rem}}
  .footer{{text-align:center;font-size:0.75rem;color:#374151;padding-top:1.5rem;border-top:1px solid #1E2837}}
</style>
</head>
<body>
<div class="page">

  <div class="header">
    <div class="header-left">
      <h1>Security Operations Dashboard</h1>
      <p>Security+ SY0-701 — Lab 19 — Dominio 2 &nbsp;·&nbsp; Luiz Otavio Gonçalves Gilio</p>
    </div>
    <div class="header-right"><strong>Ultima atualizacao:</strong><br>{agora}</div>
  </div>

  {demo_banner}

  <div class="risk-bar">
    <div>
      <div class="risk-label">Risco Geral do Ambiente</div>
      <div class="risk-num">{risco}</div>
    </div>
    <div class="risk-div"></div>
    <div class="risk-desc">
      Calculado com base em {ioc_criticos} IOCs criticos do Malware Simulator
      e {portas_crit} porta(s) critica(s) + {configs_falha} configuracao(oes) inadequada(s) do Hardening Auditor.
    </div>
  </div>

  <div class="stats">
    <div class="stat"><div class="num" style="color:#06B6D4">{ioc_total}</div><div class="lbl">IOCs Detectados</div></div>
    <div class="stat"><div class="num" style="color:#EF4444">{ioc_criticos}</div><div class="lbl">IOCs Criticos</div></div>
    <div class="stat"><div class="num" style="color:#8B5CF6">{len(malware['por_malware']) if malware else 0}</div><div class="lbl">Tipos de Malware</div></div>
    <div class="stat"><div class="num" style="color:#{hs_cor}">{hs_score}</div><div class="lbl">Score Hardening</div></div>
    <div class="stat"><div class="num" style="color:#EF4444">{portas_crit}</div><div class="lbl">Portas Criticas</div></div>
    <div class="stat"><div class="num" style="color:#F59E0B">{configs_falha}</div><div class="lbl">Config. Falhas</div></div>
  </div>

  <div class="two-col">
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Malware Behavior Simulator — IOCs por Tipo</span>
        <span class="badge badge-warn">{ioc_total} IOCs</span>
      </div>
      <div class="mal-grid">{cards_mal}</div>
    </div>
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Hardening Auditor — Score do Sistema</span>
        <span class="badge badge-neutral">Lab 18</span>
      </div>
      <div style="display:flex;align-items:center;gap:2rem;padding:0.5rem 0">
        <div>
          <div class="score-big">{hs_score}</div>
          <div class="score-nivel">{hs_nivel}</div>
        </div>
        <div style="font-size:0.85rem;color:#94A3B8;line-height:1.8">
          <span style="color:#EF4444;font-weight:600">{portas_crit}</span> porta(s) critica(s) aberta(s)<br>
          <span style="color:#F59E0B;font-weight:600">{hardening['portas_abertas'] if hardening else 0}</span> porta(s) abertas no total<br>
          <span style="color:#F59E0B;font-weight:600">{configs_falha}</span> configuracao(oes) inadequada(s)
        </div>
      </div>
    </div>
  </div>

  <div class="section-title">Recomendacoes Priorizadas — Hardening</div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>#</th><th>Prioridade</th><th>Acao Recomendada</th><th>Motivo</th></tr></thead>
      <tbody>{linhas_recs}</tbody>
    </table>
  </div>

  <div class="section-title">Log de IOCs — Malware Simulator (ultimos eventos)</div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Hora</th><th>Malware</th><th>Tipo de IOC</th><th>Descricao</th><th>Severidade</th></tr></thead>
      <tbody>{linhas_iocs}</tbody>
    </table>
  </div>

  <div class="two-col">
    <div>
      <div class="section-title">Portas Abertas — Hardening Auditor</div>
      <div class="table-wrap" style="margin-bottom:0">
        <table>
          <thead><tr><th>Porta</th><th>Servico</th><th>Risco</th><th>Descricao</th></tr></thead>
          <tbody>{linhas_portas}</tbody>
        </table>
      </div>
    </div>
    <div>
      <div class="section-title">Configuracoes do Sistema</div>
      <div class="table-wrap" style="margin-bottom:0">
        <table>
          <thead><tr><th>Verificacao</th><th>Categoria</th><th>Status</th><th>Recomendacao</th></tr></thead>
          <tbody>{linhas_cfg}</tbody>
        </table>
      </div>
    </div>
  </div>

  <br>
  <div class="concept">
    <h3>Conceitos consolidados neste projeto</h3>
    <p>
      O <strong>Lab 17</strong> simulou 5 tipos de malware gerando IOCs reais — cada um atacando
      um pilar diferente do CIA Triad. Ransomware ataca Disponibilidade. Keylogger ataca
      Confidencialidade. Virus e Worm atacam Integridade. Logic Bomb ataca todos.
    </p>
    <p>
      O <strong>Lab 18</strong> auditou o sistema real identificando portas abertas e configuracoes
      inadequadas — calculando um score de hardening baseado nos mesmos criterios usados por
      ferramentas como CIS-CAT e Nessus em ambientes corporativos.
    </p>
    <p>
      Este dashboard consolida ambos num painel SOC unico — demonstrando como um analista
      correlaciona ameacas ativas com vulnerabilidades do ambiente para priorizar remediacoes.
    </p>
  </div>

  <div class="footer">
    github.com/LuizGilio/security-plus-studies &nbsp;·&nbsp; CompTIA Security+ SY0-701 — Dominio 2
  </div>

</div>
</body>
</html>"""

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n✅ Dashboard gerado: {OUTPUT_FILE}")
    print("   Abra security_dashboard_d2.html no navegador.\n")


# ══════════════════════════════════════════════════════════
# PONTO DE ENTRADA
# ══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Security Dashboard D2 — Lab 19")
    parser.add_argument("--demo", action="store_true", help="Usa dados de demonstracao")
    args = parser.parse_args()

    if args.demo:
        malware, hardening = dados_demo()
        gerar_html(malware, hardening, demo=True)
        return

    malware  = carregar_malware(MALWARE_LOG)
    hardening= carregar_hardening(HARDENING_LOG)

    if not malware and not hardening:
        print("Logs nao encontrados — rodando em modo demo.")
        malware, hardening = dados_demo()
        gerar_html(malware, hardening, demo=True)
    else:
        gerar_html(malware, hardening, demo=False)

if __name__ == "__main__":
    main()
