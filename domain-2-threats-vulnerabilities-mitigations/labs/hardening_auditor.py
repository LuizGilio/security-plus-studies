"""
=============================================================
LAB 18 — Network Hardening Auditor
Security+ SY0-701 — Domínio 2 — Mitigações e Hardening
=============================================================
Autor: Luiz Otavio Gonçalves Gilio
GitHub: github.com/LuizGilio

CONCEITO:
    Audita o próprio sistema simulando o trabalho de um analista
    de segurança — verifica portas abertas, protocolos inseguros,
    configurações do SO e calcula um score de hardening.

    Conceitos: Hardening, ACLs, Least Privilege, Port Management,
    Senhas Padrão, EDR, Host Firewall, Segmentação.

COMO USAR:
    python hardening_auditor.py --audit     → auditoria completa
    python hardening_auditor.py --ports     → só portas abertas
    python hardening_auditor.py --report    → gera relatório HTML
=============================================================
"""

import socket
import json
import os
import sys
import datetime
import argparse
import subprocess
import platform

OUTPUT_FILE  = "./relatorio_hardening.html"
LOG_FILE     = "./hardening_log.json"

# ══════════════════════════════════════════════════════════
# DEFINIÇÕES DE VERIFICAÇÕES
# ══════════════════════════════════════════════════════════

# Portas que serão verificadas e seu risco
PORTAS_VERIFICACAO = [
    # (porta, serviço, risco, descrição)
    (21,   "FTP",          "ALTO",   "Protocolo sem criptografia — transmite dados em texto claro"),
    (22,   "SSH",          "BAIXO",  "Protocolo seguro — mas deve ter acesso restrito"),
    (23,   "Telnet",       "CRÍTICO","Protocolo completamente inseguro — substituir por SSH"),
    (25,   "SMTP",         "MÉDIO",  "Servidor de e-mail — verificar se é necessário"),
    (53,   "DNS",          "MÉDIO",  "Serviço DNS — verificar se é Open Resolver"),
    (80,   "HTTP",         "MÉDIO",  "Web sem criptografia — migrar para HTTPS (443)"),
    (110,  "POP3",         "ALTO",   "E-mail sem criptografia"),
    (135,  "RPC",          "ALTO",   "Remote Procedure Call — comum em ataques Windows"),
    (137,  "NetBIOS-NS",   "ALTO",   "NetBIOS — vetor comum de ataques de rede"),
    (139,  "NetBIOS-SSN",  "ALTO",   "NetBIOS Session — relacionado ao EternalBlue/WannaCry"),
    (143,  "IMAP",         "ALTO",   "E-mail sem criptografia"),
    (443,  "HTTPS",        "BAIXO",  "Web com criptografia — verificar certificado"),
    (445,  "SMB",          "CRÍTICO","Server Message Block — vetor do WannaCry (EternalBlue)"),
    (1433, "MSSQL",        "ALTO",   "SQL Server — nunca deve estar exposto externamente"),
    (1521, "Oracle DB",    "ALTO",   "Oracle Database — nunca deve estar exposto externamente"),
    (3306, "MySQL",        "ALTO",   "MySQL — nunca deve estar exposto externamente"),
    (3389, "RDP",          "ALTO",   "Remote Desktop — alvo frequente de brute force"),
    (5432, "PostgreSQL",   "ALTO",   "PostgreSQL — nunca deve estar exposto externamente"),
    (5900, "VNC",          "ALTO",   "Virtual Network Computing — frequentemente sem autenticação forte"),
    (6379, "Redis",        "CRÍTICO","Redis — frequentemente sem autenticação — dados expostos"),
    (8080, "HTTP-Alt",     "MÉDIO",  "Porta HTTP alternativa — verificar serviço"),
    (8443, "HTTPS-Alt",    "BAIXO",  "Porta HTTPS alternativa"),
    (27017,"MongoDB",      "CRÍTICO","MongoDB — frequentemente configurado sem autenticação"),
]

# Credenciais padrão conhecidas por serviço
CREDENCIAIS_PADRAO = [
    {"servico": "Router/Switch padrão",  "usuario": "admin",       "senha": "admin"},
    {"servico": "Router/Switch padrão",  "usuario": "admin",       "senha": "password"},
    {"servico": "Router/Switch padrão",  "usuario": "admin",       "senha": ""},
    {"servico": "Cisco IOS padrão",      "usuario": "cisco",       "senha": "cisco"},
    {"servico": "Linux root padrão",     "usuario": "root",        "senha": "root"},
    {"servico": "Linux root padrão",     "usuario": "root",        "senha": "toor"},
    {"servico": "Aplicação web padrão",  "usuario": "admin",       "senha": "123456"},
    {"servico": "Aplicação web padrão",  "usuario": "admin",       "senha": "admin123"},
    {"servico": "MySQL padrão",          "usuario": "root",        "senha": ""},
    {"servico": "VMware padrão",         "usuario": "root",        "senha": "vmware"},
]

# Verificações de configuração do sistema
VERIFICACOES_SISTEMA = [
    "firewall_ativo",
    "atualizacoes_pendentes",
    "conta_guest",
    "usuarios_admin",
    "uac_windows",
]


# ══════════════════════════════════════════════════════════
# FUNÇÕES DE AUDITORIA
# ══════════════════════════════════════════════════════════

def verificar_porta(host, porta, timeout=0.5):
    """Verifica se uma porta está aberta."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        resultado = sock.connect_ex((host, porta))
        sock.close()
        return resultado == 0
    except Exception:
        return False


def auditar_portas():
    """Varre portas conhecidas e classifica o risco."""
    print("\n🔍 Verificando portas abertas...")
    resultado = []

    for porta, servico, risco, descricao in PORTAS_VERIFICACAO:
        aberta = verificar_porta("127.0.0.1", porta)
        status = "ABERTA" if aberta else "FECHADA"
        if aberta:
            print(f"  [{risco:8}] Porta {porta:5} ({servico}) — {status}")
        resultado.append({
            "porta":     porta,
            "servico":   servico,
            "status":    status,
            "risco":     risco,
            "descricao": descricao,
            "aberta":    aberta,
        })

    abertas = [r for r in resultado if r["aberta"]]
    criticas = [r for r in abertas if r["risco"] == "CRÍTICO"]
    altas    = [r for r in abertas if r["risco"] == "ALTO"]

    print(f"\n  Total verificado: {len(resultado)} portas")
    print(f"  Abertas: {len(abertas)} | Críticas: {len(criticas)} | Altas: {len(altas)}")
    return resultado


def auditar_configuracoes_sistema():
    """Verifica configurações de segurança do sistema operacional."""
    print("\n🔍 Verificando configurações do sistema...")
    sistema = platform.system()
    resultado = []

    if sistema == "Windows":
        checks = [
            {
                "nome":      "Windows Defender / Antivírus",
                "categoria": "Proteção de Endpoint",
                "cmd":       "powershell -Command \"Get-MpComputerStatus | Select-Object AntivirusEnabled\" 2>nul",
                "ok_if":     "True",
                "risco":     "ALTO",
                "rec":       "Habilitar Windows Defender ou instalar antivírus",
            },
            {
                "nome":      "Windows Firewall",
                "categoria": "Host Firewall",
                "cmd":       "powershell -Command \"(Get-NetFirewallProfile -Profile Domain,Public,Private | Where-Object Enabled -eq True).Count\" 2>nul",
                "ok_if":     "3",
                "risco":     "ALTO",
                "rec":       "Habilitar firewall em todos os perfis de rede",
            },
            {
                "nome":      "UAC (User Account Control)",
                "categoria": "Least Privilege",
                "cmd":       "powershell -Command \"(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System).EnableLUA\" 2>nul",
                "ok_if":     "1",
                "risco":     "MÉDIO",
                "rec":       "Habilitar UAC para controle de privilégios",
            },
            {
                "nome":      "Conta Guest desabilitada",
                "categoria": "Controle de Acesso",
                "cmd":       "powershell -Command \"(Get-LocalUser -Name 'Guest').Enabled\" 2>nul",
                "ok_if":     "False",
                "risco":     "MÉDIO",
                "rec":       "Desabilitar conta Guest",
            },
            {
                "nome":      "Atualizações automáticas",
                "categoria": "Patching",
                "cmd":       "powershell -Command \"(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update').AUOptions\" 2>nul",
                "ok_if":     "4",
                "risco":     "ALTO",
                "rec":       "Habilitar atualizações automáticas",
            },
        ]
    else:
        # Linux / macOS — verificações simplificadas
        checks = [
            {
                "nome":      "SSH root login",
                "categoria": "Controle de Acesso",
                "cmd":       "grep -i 'PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null",
                "ok_if":     "no",
                "risco":     "ALTO",
                "rec":       "Desabilitar login root via SSH (PermitRootLogin no)",
            },
            {
                "nome":      "Firewall ativo (ufw/iptables)",
                "categoria": "Host Firewall",
                "cmd":       "ufw status 2>/dev/null || iptables -L 2>/dev/null | head -1",
                "ok_if":     "active",
                "risco":     "ALTO",
                "rec":       "Habilitar ufw ou configurar iptables",
            },
        ]

    for check in checks:
        try:
            output = subprocess.check_output(
                check["cmd"], shell=True,
                stderr=subprocess.DEVNULL,
                timeout=5
            ).decode(errors="ignore").strip()
            ok = check["ok_if"].lower() in output.lower()
        except Exception:
            output = "N/A"
            ok = False

        status = "OK" if ok else "ATENÇÃO"
        print(f"  [{status:7}] {check['nome']}")
        resultado.append({
            "nome":      check["nome"],
            "categoria": check["categoria"],
            "status":    status,
            "ok":        ok,
            "risco":     check["risco"] if not ok else "BAIXO",
            "rec":       check["rec"] if not ok else "Configuração adequada",
        })

    return resultado


def calcular_score(portas, configs):
    """Calcula score de hardening de 0 a 100."""
    penalidades = 0

    for p in portas:
        if p["aberta"]:
            if p["risco"] == "CRÍTICO": penalidades += 15
            elif p["risco"] == "ALTO":  penalidades += 8
            elif p["risco"] == "MÉDIO": penalidades += 4
            elif p["risco"] == "BAIXO": penalidades += 1

    for c in configs:
        if not c["ok"]:
            if c["risco"] == "ALTO":  penalidades += 10
            elif c["risco"] == "MÉDIO": penalidades += 5

    score = max(0, 100 - penalidades)

    if score >= 80:   nivel = "BOM",      "22C55E"
    elif score >= 60: nivel = "REGULAR",  "F59E0B"
    elif score >= 40: nivel = "FRACO",    "EF4444"
    else:             nivel = "CRÍTICO",  "EF4444"

    return score, nivel[0], nivel[1]


# ══════════════════════════════════════════════════════════
# GERADOR DE RELATÓRIO HTML
# ══════════════════════════════════════════════════════════

def gerar_relatorio(portas, configs, score, nivel, cor_nivel):
    """Gera relatório HTML profissional de auditoria."""
    agora = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    hostname = socket.gethostname()
    sistema  = platform.system() + " " + platform.release()

    portas_abertas   = [p for p in portas if p["aberta"]]
    portas_criticas  = [p for p in portas_abertas if p["risco"] == "CRÍTICO"]
    portas_altas     = [p for p in portas_abertas if p["risco"] == "ALTO"]
    configs_falha    = [c for c in configs if not c["ok"]]

    # Linhas da tabela de portas
    linhas_portas = ""
    for p in portas:
        if not p["aberta"]:
            continue
        cor = {"CRÍTICO": "#EF4444", "ALTO": "#F59E0B",
               "MÉDIO": "#06B6D4", "BAIXO": "#22C55E"}.get(p["risco"], "#94A3B8")
        linhas_portas += f"""
        <tr>
            <td><strong style="color:#E2E8F0">{p['porta']}</strong></td>
            <td style="color:#06B6D4">{p['servico']}</td>
            <td><span style="color:{cor};font-weight:700">{p['risco']}</span></td>
            <td style="color:#94A3B8;font-size:0.85rem">{p['descricao']}</td>
        </tr>"""

    if not linhas_portas:
        linhas_portas = '<tr><td colspan="4" style="text-align:center;color:#22C55E;padding:16px">✅ Nenhuma porta de risco aberta detectada</td></tr>'

    # Linhas de configurações
    linhas_configs = ""
    for c in configs:
        cor_s = "#22C55E" if c["ok"] else "#EF4444"
        txt_s = "✅ OK" if c["ok"] else "⚠️ ATENÇÃO"
        linhas_configs += f"""
        <tr>
            <td style="color:#E2E8F0">{c['nome']}</td>
            <td style="color:#94A3B8">{c['categoria']}</td>
            <td><span style="color:{cor_s};font-weight:600">{txt_s}</span></td>
            <td style="color:#94A3B8;font-size:0.85rem">{c['rec']}</td>
        </tr>"""

    # Recomendações prioritárias
    recs = []
    for p in portas_criticas:
        recs.append({"prioridade": "CRÍTICO", "cor": "#EF4444",
                     "acao": f"Fechar porta {p['porta']} ({p['servico']})",
                     "motivo": p['descricao']})
    for c in configs_falha:
        if c["risco"] == "ALTO":
            recs.append({"prioridade": "ALTO", "cor": "#F59E0B",
                         "acao": c["rec"], "motivo": c["nome"]})
    for p in portas_altas:
        recs.append({"prioridade": "ALTO", "cor": "#F59E0B",
                     "acao": f"Avaliar necessidade da porta {p['porta']} ({p['servico']})",
                     "motivo": p['descricao']})

    linhas_recs = ""
    for i, r in enumerate(recs[:8], 1):
        linhas_recs += f"""
        <tr>
            <td style="color:#64748B;text-align:center">{i}</td>
            <td><span style="color:{r['cor']};font-weight:700">{r['prioridade']}</span></td>
            <td style="color:#E2E8F0">{r['acao']}</td>
            <td style="color:#94A3B8;font-size:0.85rem">{r['motivo']}</td>
        </tr>"""

    if not linhas_recs:
        linhas_recs = '<tr><td colspan="4" style="text-align:center;color:#22C55E;padding:16px">✅ Nenhuma recomendação crítica — sistema bem configurado</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Hardening Audit Report — Lab 18</title>
<style>
  *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0F1117;color:#E2E8F0;font-size:14px;line-height:1.5;padding:2rem}}
  .page{{max-width:1200px;margin:0 auto}}
  .header{{display:flex;justify-content:space-between;align-items:flex-end;padding-bottom:1.2rem;border-bottom:1px solid #1E2837;margin-bottom:1.5rem}}
  .header-left h1{{font-size:1.4rem;font-weight:700;color:#F1F5F9;letter-spacing:-0.3px}}
  .header-left p{{font-size:0.8rem;color:#64748B;margin-top:3px}}
  .header-right{{font-size:0.78rem;color:#64748B;text-align:right}}
  .header-right strong{{color:#94A3B8}}
  .score-bar{{background:#161B27;border:1px solid #1E2837;border-radius:8px;padding:1.2rem 1.5rem;margin-bottom:1.5rem;display:flex;align-items:center;gap:1.5rem}}
  .score-num{{font-size:3rem;font-weight:800;color:#{cor_nivel};line-height:1}}
  .score-label{{font-size:0.72rem;color:#64748B;text-transform:uppercase;letter-spacing:0.8px;margin-bottom:4px}}
  .score-nivel{{font-size:1.2rem;font-weight:700;color:#{cor_nivel}}}
  .score-divider{{width:1px;height:56px;background:#1E2837;margin:0 0.5rem}}
  .score-meta{{font-size:0.85rem;color:#94A3B8}}
  .score-meta strong{{color:#E2E8F0}}
  .stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:1.5rem}}
  .stat{{background:#161B27;border:1px solid #1E2837;border-radius:8px;padding:0.9rem 1rem}}
  .stat .num{{font-size:1.8rem;font-weight:700;color:#F1F5F9}}
  .stat .lbl{{font-size:0.72rem;color:#64748B;margin-top:3px}}
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
  .footer{{text-align:center;font-size:0.75rem;color:#374151;padding-top:1.5rem;border-top:1px solid #1E2837;margin-top:1.5rem}}
  code{{font-family:'Consolas',monospace;font-size:0.82rem;color:#94A3B8}}
</style>
</head>
<body>
<div class="page">

  <div class="header">
    <div class="header-left">
      <h1>Hardening Audit Report</h1>
      <p>Security+ SY0-701 — Lab 18 — Mitigações e Hardening &nbsp;·&nbsp; Luiz Otavio Gonçalves Gilio</p>
    </div>
    <div class="header-right">
      <strong>Host:</strong> {hostname}<br>
      <strong>Sistema:</strong> {sistema}<br>
      <strong>Auditado em:</strong> {agora}
    </div>
  </div>

  <div class="score-bar">
    <div>
      <div class="score-label">Score de Hardening</div>
      <div class="score-num">{score}</div>
    </div>
    <div class="score-divider"></div>
    <div>
      <div class="score-label">Classificação</div>
      <div class="score-nivel">{nivel}</div>
    </div>
    <div class="score-divider"></div>
    <div class="score-meta">
      <strong>{len(portas_abertas)}</strong> portas abertas detectadas<br>
      <strong>{len(portas_criticas)}</strong> portas de risco crítico<br>
      <strong>{len(configs_falha)}</strong> configurações inadequadas<br>
      <strong>{len(recs[:8])}</strong> recomendações priorizadas
    </div>
  </div>

  <div class="stats">
    <div class="stat"><div class="num">{len(portas)}</div><div class="lbl">Portas Verificadas</div></div>
    <div class="stat"><div class="num" style="color:#EF4444">{len(portas_abertas)}</div><div class="lbl">Portas Abertas</div></div>
    <div class="stat"><div class="num" style="color:#EF4444">{len(portas_criticas)}</div><div class="lbl">Risco Crítico</div></div>
    <div class="stat"><div class="num" style="color:#F59E0B">{len(portas_altas)}</div><div class="lbl">Risco Alto</div></div>
    <div class="stat"><div class="num" style="color:#F59E0B">{len(configs_falha)}</div><div class="lbl">Config. Inadequadas</div></div>
  </div>

  <div class="section-title">Recomendações Priorizadas</div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>#</th><th>Prioridade</th><th>Ação Recomendada</th><th>Motivo</th></tr></thead>
      <tbody>{linhas_recs}</tbody>
    </table>
  </div>

  <div class="section-title">Portas Abertas Detectadas</div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Porta</th><th>Serviço</th><th>Risco</th><th>Descrição</th></tr></thead>
      <tbody>{linhas_portas}</tbody>
    </table>
  </div>

  <div class="section-title">Verificações de Configuração do Sistema</div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Verificação</th><th>Categoria</th><th>Status</th><th>Recomendação</th></tr></thead>
      <tbody>{linhas_configs}</tbody>
    </table>
  </div>

  <div class="concept">
    <h3>Conceitos demonstrados neste lab</h3>
    <p>
      O <strong>Hardening</strong> reduz a superfície de ataque fechando portas desnecessárias,
      removendo serviços não utilizados e aplicando configurações seguras. Cada porta aberta
      é uma oportunidade para o atacante encontrar uma vulnerabilidade.
    </p>
    <p>
      <strong>Portas críticas identificadas:</strong> SMB (445) está associado ao WannaCry via EternalBlue.
      Telnet (23) transmite tudo em texto claro — substituir por SSH. MongoDB (27017) e Redis (6379)
      frequentemente ficam sem autenticação em configurações padrão.
    </p>
    <p>
      <strong>Least Privilege e Host Firewall</strong> são as mitigações mais eficazes —
      um usuário com privilégios mínimos e firewall ativo limita drasticamente o impacto
      de qualquer comprometimento.
    </p>
  </div>

  <div class="footer">
    github.com/LuizGilio/security-plus-studies &nbsp;·&nbsp; CompTIA Security+ SY0-701 — Domínio 2
  </div>

</div>
</body>
</html>"""

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(html)

    # Salva log JSON para o Dashboard (Lab 19)
    log = {
        "timestamp":      datetime.datetime.now().isoformat(),
        "hostname":       hostname,
        "sistema":        sistema,
        "score":          score,
        "nivel":          nivel,
        "portas_abertas": len(portas_abertas),
        "portas_criticas":len(portas_criticas),
        "configs_falha":  len(configs_falha),
        "portas":         [p for p in portas if p["aberta"]],
        "configs":        configs,
        "recomendacoes":  recs[:8],
    }
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Relatório gerado: {OUTPUT_FILE}")
    print(f"   Log salvo em:     {LOG_FILE}")
    print(f"   Abra o arquivo relatorio_hardening.html no navegador.\n")


# ══════════════════════════════════════════════════════════
# PONTO DE ENTRADA
# ══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Hardening Auditor — Lab 18 Security+",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--audit",  action="store_true", help="Auditoria completa do sistema")
    parser.add_argument("--ports",  action="store_true", help="Apenas verifica portas abertas")
    parser.add_argument("--report", action="store_true", help="Gera relatório HTML do último audit")
    args = parser.parse_args()

    if args.ports:
        portas = auditar_portas()
        return

    if args.report:
        if not os.path.exists(LOG_FILE):
            print("❌ Log não encontrado. Rode primeiro: python hardening_auditor.py --audit")
            sys.exit(1)
        with open(LOG_FILE) as f:
            log = json.load(f)
        print("📊 Gerando relatório a partir do último audit...")
        # Reconstrói objetos mínimos para o relatório
        portas  = log.get("portas", [])
        configs = log.get("configs", [])
        score   = log.get("score", 0)
        nivel   = log.get("nivel", "N/A")
        cor     = "22C55E" if score >= 80 else "F59E0B" if score >= 60 else "EF4444"
        gerar_relatorio(portas, configs, score, nivel, cor)
        return

    if args.audit:
        print("\n" + "="*60)
        print("  HARDENING AUDITOR — Lab 18 — Security+ SY0-701")
        print("="*60)
        print(f"  Host:    {socket.gethostname()}")
        print(f"  Sistema: {platform.system()} {platform.release()}")
        print(f"  Data:    {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}")
        print("="*60)

        portas  = auditar_portas()
        configs = auditar_configuracoes_sistema()
        score, nivel, cor = calcular_score(portas, configs)

        print(f"\n{'='*60}")
        print(f"  SCORE DE HARDENING: {score}/100 — {nivel}")
        print(f"{'='*60}")
        print(f"  Rode agora: python hardening_auditor.py --report")
        print(f"  Depois:     start relatorio_hardening.html\n")

        gerar_relatorio(portas, configs, score, nivel, cor)
        return

    # Sem argumento — mostra ajuda
    print("\n📋 Hardening Auditor — Lab 18")
    print("─" * 40)
    print("Uso:")
    print("  python hardening_auditor.py --audit    → auditoria completa")
    print("  python hardening_auditor.py --ports    → só portas abertas")
    print("  python hardening_auditor.py --report   → gera relatório HTML\n")

if __name__ == "__main__":
    main()
