"""
=============================================================
LAB 12 — Security Dashboard
Security+ SY0-701 — Domínio 1 — Visão Consolidada
=============================================================
Autor: Luiz Otavio Gonçalves Gilio
GitHub: github.com/LuizGilio

CONCEITO:
    Consolida os resultados dos Labs 05 (FIM) e 10 (Zero Trust)
    num painel unificado — simulando o que um analista SOC
    veria no dia a dia.

COMO USAR:
    python dashboard.py         → lê logs reais dos labs
    python dashboard.py --demo  → gera com dados de demonstração
=============================================================
"""

import json
import os
import datetime
import argparse

FIM_LOG_PATH = "../lab-05-file-integrity-monitor/fim_log.txt"
ZT_LOG_PATH  = "../lab-10-zero-trust-simulator/zt_log.json"
OUTPUT_FILE  = "./security_dashboard.html"


# ══════════════════════════════════════════════════════════
# COLETA DE DADOS
# ══════════════════════════════════════════════════════════

def carregar_fim(caminho):
    if not os.path.exists(caminho):
        return None
    alterados = deletados = novos = 0
    eventos = []
    with open(caminho, "r", encoding="utf-8") as f:
        for linha in f:
            if "ALTERADO:" in linha:
                alterados += 1
                eventos.append({"tipo": "ALTERADO", "msg": linha.split("ALTERADO:")[-1].strip()})
            elif "DELETADO:" in linha:
                deletados += 1
                eventos.append({"tipo": "DELETADO", "msg": linha.split("DELETADO:")[-1].strip()})
            elif "NOVO ARQUIVO:" in linha:
                novos += 1
                eventos.append({"tipo": "NOVO", "msg": linha.split("NOVO ARQUIVO:")[-1].strip()})
    return {
        "integro":       (alterados + deletados + novos) == 0,
        "alterados":     alterados,
        "deletados":     deletados,
        "novos":         novos,
        "total_alertas": alterados + deletados + novos,
        "eventos":       eventos[-8:],
    }


def carregar_zt(caminho):
    if not os.path.exists(caminho):
        return None
    with open(caminho, "r", encoding="utf-8") as f:
        entries = json.load(f)
    total      = len(entries)
    permitidos = sum(1 for e in entries if e["resultado"] == "PERMITIDO")
    negados    = total - permitidos
    criticos   = sum(1 for e in entries if e["risco"] == "CRÍTICO")
    bloqueados = list(set(e["usuario"] for e in entries if e["resultado"] == "NEGADO"))
    return {
        "total":       total,
        "permitidos":  permitidos,
        "negados":     negados,
        "criticos":    criticos,
        "bloqueados":  bloqueados,
        "entries":     entries,
    }


def dados_demo():
    """Dados de demonstração quando os logs reais não existem."""
    fim = {
        "integro": False, "alterados": 1, "deletados": 1, "novos": 0,
        "total_alertas": 2,
        "eventos": [
            {"tipo": "ALTERADO", "msg": "config_sistema.txt"},
            {"tipo": "DELETADO", "msg": "chaves_api.txt"},
        ],
    }
    zt = {
        "total": 6, "permitidos": 2, "negados": 4, "criticos": 3,
        "bloqueados": ["visitante", "joao.souza", "hacker123"],
        "entries": [
            {"timestamp": "2026-03-18T13:45:04", "usuario": "luiz.gilio",
             "recurso": "servidor_producao", "dispositivo": "notebook-corp-001",
             "localizacao": "sede", "resultado": "PERMITIDO", "risco": "BAIXO",
             "motivos": ["Nível adequado", "MFA ativo", "Dispositivo confiável"]},
            {"timestamp": "2026-03-18T13:45:04", "usuario": "visitante",
             "recurso": "banco_dados_financeiro", "dispositivo": "notebook-pessoal-xyz",
             "localizacao": "remoto", "resultado": "NEGADO", "risco": "CRÍTICO",
             "motivos": ["Nível insuficiente", "Sem MFA", "Dispositivo não confiável"]},
            {"timestamp": "2026-03-18T13:45:04", "usuario": "joao.souza",
             "recurso": "servidor_producao", "dispositivo": "notebook-corp-002",
             "localizacao": "sede", "resultado": "NEGADO", "risco": "CRÍTICO",
             "motivos": ["Nível insuficiente", "Sem MFA"]},
            {"timestamp": "2026-03-18T13:45:04", "usuario": "luiz.gilio",
             "recurso": "banco_dados_financeiro", "dispositivo": "notebook-corp-001",
             "localizacao": "sede", "resultado": "NEGADO", "risco": "MÉDIO",
             "motivos": ["Fora do horário permitido"]},
            {"timestamp": "2026-03-18T13:45:04", "usuario": "hacker123",
             "recurso": "servidor_producao", "dispositivo": "notebook-desconhecido",
             "localizacao": "pais_estrangeiro", "resultado": "NEGADO", "risco": "CRÍTICO",
             "motivos": ["Identidade desconhecida"]},
            {"timestamp": "2026-03-18T13:45:04", "usuario": "luiz.gilio",
             "recurso": "intranet", "dispositivo": "notebook-corp-001",
             "localizacao": "remoto", "resultado": "PERMITIDO", "risco": "BAIXO",
             "motivos": ["Todos os critérios atendidos"]},
        ],
    }
    return fim, zt


def calcular_risco(fim, zt):
    pts = 0
    if fim and not fim["integro"]:
        pts += fim["alterados"] * 3 + fim["deletados"] * 4
    if zt:
        pts += zt["criticos"] * 3
        if zt["total"] > 0 and zt["negados"] / zt["total"] > 0.5:
            pts += 2
    if pts == 0:   return "BAIXO",    "#22C55E"
    if pts <= 4:   return "MÉDIO",    "#F59E0B"
    if pts <= 9:   return "ALTO",     "#EF4444"
    return          "CRÍTICO",        "#EF4444"


# ══════════════════════════════════════════════════════════
# GERADOR HTML
# ══════════════════════════════════════════════════════════

def gerar_html(fim, zt, demo=False):
    agora       = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    risco, _    = calcular_risco(fim, zt)

    risco_cor = {
        "BAIXO":   "#22C55E",
        "MÉDIO":   "#F59E0B",
        "ALTO":    "#EF4444",
        "CRÍTICO": "#EF4444",
    }.get(risco, "#94A3B8")

    # ── Status FIM ────────────────────────────────────────
    fim_status     = "ÍNTEGRO"    if fim and fim["integro"] else "COMPROMETIDO"
    fim_status_cor = "#22C55E"    if fim and fim["integro"] else "#EF4444"
    fim_alertas    = fim["total_alertas"] if fim else 0

    fim_eventos_html = ""
    if fim and fim["eventos"]:
        for ev in fim["eventos"]:
            cor = {"ALTERADO": "#F59E0B", "DELETADO": "#EF4444", "NOVO": "#60A5FA"}.get(ev["tipo"], "#94A3B8")
            fim_eventos_html += f'<li><span style="color:{cor};font-weight:600">{ev["tipo"]}</span> — <code>{ev["msg"]}</code></li>'
    else:
        fim_eventos_html = '<li style="color:#6B7280">Nenhum evento registrado</li>'

    # ── Status Zero Trust ─────────────────────────────────
    zt_total     = zt["total"]     if zt else 0
    zt_permitidos= zt["permitidos"]if zt else 0
    zt_negados   = zt["negados"]   if zt else 0
    zt_criticos  = zt["criticos"]  if zt else 0
    zt_bloqueados= ", ".join(zt["bloqueados"]) if zt and zt["bloqueados"] else "—"

    # Tabela Zero Trust
    zt_rows = ""
    if zt and zt["entries"]:
        for e in zt["entries"]:
            res_cor  = "#22C55E" if e["resultado"] == "PERMITIDO" else "#EF4444"
            rsk_cor  = {"BAIXO":"#22C55E","MÉDIO":"#F59E0B","ALTO":"#EF4444","CRÍTICO":"#EF4444"}.get(e["risco"],"#94A3B8")
            motivos  = " · ".join(e["motivos"][:2])
            zt_rows += f"""
            <tr>
                <td>{e['timestamp'][11:19]}</td>
                <td><strong>{e['usuario']}</strong></td>
                <td>{e['recurso']}</td>
                <td>{e['localizacao']}</td>
                <td><span style="color:{res_cor};font-weight:700">{e['resultado']}</span></td>
                <td><span style="color:{rsk_cor};font-weight:600">{e['risco']}</span></td>
                <td style="color:#9CA3AF;font-size:0.82rem">{motivos}</td>
            </tr>"""

    demo_banner = ""
    if demo:
        demo_banner = '<div class="demo-banner">⚠️  Modo demonstração — dados simulados dos Labs 05 e 10</div>'

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Dashboard — Lab 12</title>
<style>
  /* ── Reset & Base ── */
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0F1117;
    color: #E2E8F0;
    font-size: 14px;
    line-height: 1.5;
  }}

  /* ── Layout ── */
  .page {{ max-width: 1280px; margin: 0 auto; padding: 2rem 1.5rem; }}

  /* ── Header ── */
  .header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    padding-bottom: 1.2rem;
    border-bottom: 1px solid #1E2837;
    margin-bottom: 1.8rem;
  }}
  .header-left h1 {{
    font-size: 1.4rem;
    font-weight: 700;
    color: #F1F5F9;
    letter-spacing: -0.3px;
  }}
  .header-left p {{
    font-size: 0.8rem;
    color: #64748B;
    margin-top: 3px;
  }}
  .header-right {{
    font-size: 0.78rem;
    color: #64748B;
    text-align: right;
  }}
  .header-right strong {{ color: #94A3B8; }}

  /* ── Demo Banner ── */
  .demo-banner {{
    background: #1C1608;
    border: 1px solid #78350F;
    border-radius: 6px;
    padding: 0.6rem 1rem;
    font-size: 0.82rem;
    color: #D97706;
    margin-bottom: 1.5rem;
  }}

  /* ── Risk Bar ── */
  .risk-bar {{
    display: flex;
    align-items: center;
    gap: 1rem;
    background: #161B27;
    border: 1px solid #1E2837;
    border-radius: 8px;
    padding: 1rem 1.4rem;
    margin-bottom: 1.8rem;
  }}
  .risk-label {{ font-size: 0.75rem; color: #64748B; text-transform: uppercase; letter-spacing: 0.8px; }}
  .risk-value {{ font-size: 1.5rem; font-weight: 700; color: {risco_cor}; margin-top: 2px; }}
  .risk-divider {{ width: 1px; height: 36px; background: #1E2837; margin: 0 0.5rem; }}
  .risk-desc {{ font-size: 0.85rem; color: #94A3B8; }}

  /* ── Section Title ── */
  .section-title {{
    font-size: 0.72rem;
    font-weight: 700;
    color: #64748B;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 0.8rem;
  }}

  /* ── Cards Grid ── */
  .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.8rem; }}
  .card {{
    background: #161B27;
    border: 1px solid #1E2837;
    border-radius: 8px;
    padding: 1rem 1.2rem;
  }}
  .card-label {{ font-size: 0.75rem; color: #64748B; margin-bottom: 6px; }}
  .card-value {{ font-size: 1.8rem; font-weight: 700; color: #F1F5F9; }}
  .card-value.green  {{ color: #22C55E; }}
  .card-value.red    {{ color: #EF4444; }}
  .card-value.amber  {{ color: #F59E0B; }}
  .card-value.purple {{ color: #A78BFA; }}
  .card-sub {{ font-size: 0.75rem; color: #64748B; margin-top: 4px; }}

  /* ── Two columns ── */
  .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.2rem; margin-bottom: 1.8rem; }}

  /* ── Panel ── */
  .panel {{
    background: #161B27;
    border: 1px solid #1E2837;
    border-radius: 8px;
    padding: 1.2rem;
  }}
  .panel-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
    padding-bottom: 0.7rem;
    border-bottom: 1px solid #1E2837;
  }}
  .panel-title {{ font-size: 0.88rem; font-weight: 600; color: #E2E8F0; }}
  .status-badge {{
    font-size: 0.72rem;
    font-weight: 700;
    padding: 3px 8px;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  .badge-ok      {{ background: #052E16; color: #22C55E; }}
  .badge-warn    {{ background: #431407; color: #EF4444; }}
  .badge-neutral {{ background: #1E2837; color: #94A3B8; }}

  /* ── Event List ── */
  .event-list {{ list-style: none; }}
  .event-list li {{
    padding: 6px 0;
    border-bottom: 1px solid #1E2837;
    font-size: 0.85rem;
    color: #CBD5E1;
  }}
  .event-list li:last-child {{ border-bottom: none; }}
  .event-list code {{
    font-family: 'Consolas', monospace;
    font-size: 0.82rem;
    color: #94A3B8;
  }}

  /* ── ZT Stats ── */
  .zt-mini {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.7rem; margin-bottom: 1rem; }}
  .zt-stat {{
    background: #0F1117;
    border: 1px solid #1E2837;
    border-radius: 6px;
    padding: 0.7rem;
    text-align: center;
  }}
  .zt-stat .n {{ font-size: 1.4rem; font-weight: 700; }}
  .zt-stat .l {{ font-size: 0.72rem; color: #64748B; margin-top: 2px; }}
  .blocked-list {{ font-size: 0.82rem; color: #94A3B8; }}
  .blocked-list strong {{ color: #E2E8F0; }}

  /* ── Table ── */
  .table-wrap {{ overflow-x: auto; margin-bottom: 1.8rem; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    background: #161B27;
    border-radius: 8px;
    overflow: hidden;
    font-size: 0.85rem;
  }}
  thead tr {{ background: #1E2837; }}
  th {{
    padding: 9px 12px;
    text-align: left;
    font-size: 0.72rem;
    font-weight: 600;
    color: #64748B;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    white-space: nowrap;
  }}
  td {{
    padding: 9px 12px;
    border-bottom: 1px solid #1A2030;
    color: #CBD5E1;
    vertical-align: top;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1A2030; }}
  code {{ font-family: 'Consolas', monospace; font-size: 0.82rem; color: #94A3B8; }}

  /* ── Concept Box ── */
  .concept {{
    background: #161B27;
    border: 1px solid #1E2837;
    border-left: 3px solid #3B82F6;
    border-radius: 8px;
    padding: 1.2rem 1.4rem;
    margin-bottom: 1.8rem;
  }}
  .concept h3 {{ font-size: 0.85rem; font-weight: 600; color: #93C5FD; margin-bottom: 0.6rem; }}
  .concept p  {{ font-size: 0.85rem; color: #94A3B8; line-height: 1.7; }}
  .concept p + p {{ margin-top: 0.5rem; }}

  /* ── Footer ── */
  .footer {{
    text-align: center;
    font-size: 0.75rem;
    color: #374151;
    padding-top: 1.5rem;
    border-top: 1px solid #1E2837;
  }}
</style>
</head>
<body>
<div class="page">

  <!-- Header -->
  <div class="header">
    <div class="header-left">
      <h1>Security Dashboard</h1>
      <p>Security+ SY0-701 — Lab 12 — Domínio 1 &nbsp;·&nbsp; Luiz Otavio Gonçalves Gilio</p>
    </div>
    <div class="header-right">
      <strong>Última atualização</strong><br>{agora}
    </div>
  </div>

  {demo_banner}

  <!-- Risco Geral -->
  <div class="risk-bar">
    <div>
      <div class="risk-label">Risco Geral do Ambiente</div>
      <div class="risk-value">{risco}</div>
    </div>
    <div class="risk-divider"></div>
    <div class="risk-desc">
      Calculado com base nos alertas do File Integrity Monitor e nas
      decisões de alto risco do Zero Trust Simulator.
    </div>
  </div>

  <!-- Cards de Resumo -->
  <div class="section-title">Resumo Executivo</div>
  <div class="cards">
    <div class="card">
      <div class="card-label">Integridade de Arquivos</div>
      <div class="card-value {'green' if fim and fim['integro'] else 'red'}">{fim_status}</div>
      <div class="card-sub">{fim_alertas} alerta(s) detectado(s)</div>
    </div>
    <div class="card">
      <div class="card-label">Acessos Avaliados (ZT)</div>
      <div class="card-value">{zt_total}</div>
      <div class="card-sub">pelo Zero Trust Simulator</div>
    </div>
    <div class="card">
      <div class="card-label">Acessos Negados</div>
      <div class="card-value {'red' if zt_negados > 0 else 'green'}">{zt_negados}</div>
      <div class="card-sub">{zt_criticos} com risco crítico</div>
    </div>
    <div class="card">
      <div class="card-label">Acessos Permitidos</div>
      <div class="card-value green">{zt_permitidos}</div>
      <div class="card-sub">de {zt_total} solicitações</div>
    </div>
  </div>

  <!-- FIM + ZT lado a lado -->
  <div class="two-col">

    <!-- FIM Panel -->
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">File Integrity Monitor</span>
        <span class="status-badge {'badge-ok' if fim and fim['integro'] else 'badge-warn'}">
          {fim_status}
        </span>
      </div>
      <ul class="event-list">
        {fim_eventos_html}
      </ul>
    </div>

    <!-- ZT Panel -->
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Zero Trust — Visão Geral</span>
        <span class="status-badge badge-neutral">AAA ATIVO</span>
      </div>
      <div class="zt-mini">
        <div class="zt-stat">
          <div class="n" style="color:#22C55E">{zt_permitidos}</div>
          <div class="l">Permitidos</div>
        </div>
        <div class="zt-stat">
          <div class="n" style="color:#EF4444">{zt_negados}</div>
          <div class="l">Negados</div>
        </div>
        <div class="zt-stat">
          <div class="n" style="color:#A78BFA">{zt_criticos}</div>
          <div class="l">Risco Crítico</div>
        </div>
      </div>
      <div class="blocked-list">
        <strong>Usuários bloqueados:</strong> {zt_bloqueados}
      </div>
    </div>

  </div>

  <!-- Tabela Zero Trust -->
  <div class="section-title">Log de Decisões — Zero Trust</div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Hora</th>
          <th>Usuário</th>
          <th>Recurso</th>
          <th>Localização</th>
          <th>Resultado</th>
          <th>Risco</th>
          <th>Motivo Principal</th>
        </tr>
      </thead>
      <tbody>
        {zt_rows}
      </tbody>
    </table>
  </div>

  <!-- Conceitos -->
  <div class="concept">
    <h3>Conceitos demonstrados neste projeto</h3>
    <p>
      O <strong>Lab 05</strong> implementa o princípio de <strong>Integridade</strong> do CIA Triad —
      qualquer alteração em arquivos monitorados gera um alerta via comparação de hashes SHA-256.
      Ferramentas reais equivalentes: Tripwire, OSSEC, Wazuh.
    </p>
    <p>
      O <strong>Lab 10</strong> simula um sistema <strong>Zero Trust</strong> completo com PEP, PDP
      e Identidade Adaptativa — avaliando identidade, dispositivo, localização e horário antes de
      cada decisão de acesso. Toda decisão é registrada (Accounting do AAA).
    </p>
    <p>
      Este dashboard consolida ambos num painel único — demonstrando como um analista SOC
      monitora integridade e controle de acesso em tempo real.
    </p>
  </div>

  <div class="footer">
    github.com/LuizGilio/security-plus-studies &nbsp;·&nbsp; CompTIA Security+ SY0-701
  </div>

</div>
</body>
</html>"""

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"✅ Dashboard gerado: {OUTPUT_FILE}")
    print("   Abra security_dashboard.html no navegador.\n")


# ══════════════════════════════════════════════════════════
# PONTO DE ENTRADA
# ══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Security Dashboard — Lab 12")
    parser.add_argument("--demo", action="store_true", help="Usa dados de demonstração")
    args = parser.parse_args()

    if args.demo:
        fim, zt = dados_demo()
        gerar_html(fim, zt, demo=True)
    else:
        fim = carregar_fim(FIM_LOG_PATH)
        zt  = carregar_zt(ZT_LOG_PATH)

        if not fim and not zt:
            print("⚠️  Logs dos labs não encontrados. Rodando em modo demo.")
            fim, zt = dados_demo()
            gerar_html(fim, zt, demo=True)
        else:
            gerar_html(fim, zt, demo=False)

if __name__ == "__main__":
    main()
