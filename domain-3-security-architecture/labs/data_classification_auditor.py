"""
=============================================================
LAB 21 — Data Classification & Protection Auditor
Security+ SY0-701 — Domínio 3 — Proteção de Dados
=============================================================
Autor: Luiz Otavio Gonçalves Gilio
GitHub: github.com/LuizGilio

CONCEITO:
    Varre o sistema em busca de arquivos que podem conter
    dados sensíveis — PII, PHI e dados financeiros.
    Classifica por nível de sensibilidade e calcula risco
    de exposição. Simula o trabalho de um analista de
    privacidade e compliance.

    Conceitos: PII, PHI, Data Classification, Data at Rest,
    Data Sovereignty, Least Privilege, Encryption.

COMO USAR:
    python data_classification_auditor.py --scan PATH
    python data_classification_auditor.py --scan . --report
    python data_classification_auditor.py --demo
=============================================================
"""

import os
import re
import json
import hashlib
import datetime
import argparse
import platform
import socket
from pathlib import Path

OUTPUT_HTML = "./relatorio_classificacao.html"
OUTPUT_JSON = "./classification_log.json"

# ══════════════════════════════════════════════════════════
# PADRÕES DE DETECÇÃO
# ══════════════════════════════════════════════════════════

PATTERNS = {
    # PII — Personally Identifiable Information
    "CPF": {
        "regex": r'\b\d{3}[\.\-]?\d{3}[\.\-]?\d{3}[\-\.]?\d{2}\b',
        "category": "PII",
        "severity": "CRITICAL",
        "description": "CPF (Cadastro de Pessoa Fisica) — identificador pessoal brasileiro"
    },
    "Email": {
        "regex": r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
        "category": "PII",
        "severity": "HIGH",
        "description": "Endereco de email — dado pessoal identificavel"
    },
    "Phone_BR": {
        "regex": r'\b(\+55\s?)?\(?\d{2}\)?\s?\d{4,5}[\-\s]?\d{4}\b',
        "category": "PII",
        "severity": "HIGH",
        "description": "Numero de telefone brasileiro"
    },
    "IP_Address": {
        "regex": r'\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b',
        "category": "PII",
        "severity": "MEDIUM",
        "description": "Endereco IP — pode identificar localizacao e dispositivo"
    },
    # PHI — Protected Health Information
    "CRM_Doctor": {
        "regex": r'\bCRM[\s\-]?\d{4,6}[\s\-]?[A-Z]{2}\b',
        "category": "PHI",
        "severity": "CRITICAL",
        "description": "Numero CRM de medico — dado de saude regulamentado"
    },
    "Health_Keywords": {
        "regex": r'\b(diagnostico|prescricao|prontuario|CID[\s\-]\d|exame\s+medico|laudo\s+medico|receita\s+medica)\b',
        "category": "PHI",
        "severity": "CRITICAL",
        "description": "Termos de registros medicos — PHI regulamentado"
    },
    # Financial
    "Credit_Card": {
        "regex": r'\b(?:4\d{3}|5[1-5]\d{2}|6(?:011|5\d{2})|3[47]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b',
        "category": "Financial",
        "severity": "CRITICAL",
        "description": "Numero de cartao de credito — regulamentado pelo PCI DSS"
    },
    "Bank_Account_BR": {
        "regex": r'\b(?:conta|ag[eê]ncia|cc|corrente)[\s\:\-]+\d{4,12}[\-\s]?\d{1,2}\b',
        "category": "Financial",
        "severity": "CRITICAL",
        "description": "Dados bancarios — informacao financeira sensivel"
    },
    "Currency_BRL": {
        "regex": r'\bR\$\s?\d{1,3}(?:\.\d{3})*(?:,\d{2})?\b',
        "category": "Financial",
        "severity": "LOW",
        "description": "Valor monetario em reais"
    },
    # Credentials
    "Password_Pattern": {
        "regex": r'\b(?:senha|password|passwd|pwd|secret)[\s\=\:]+\S{6,}\b',
        "category": "Credentials",
        "severity": "CRITICAL",
        "description": "Possivel credencial em texto claro — nunca armazenar senhas em plain text"
    },
    "API_Key": {
        "regex": r'\b(?:api[_\-]?key|token|bearer|secret[_\-]?key)[\s\=\:]+[A-Za-z0-9\-_\.]{20,}\b',
        "category": "Credentials",
        "severity": "CRITICAL",
        "description": "Possivel chave de API ou token de autenticacao"
    },
}

# Extensões de arquivo para varrer
SCAN_EXTENSIONS = {
    '.txt', '.csv', '.json', '.xml', '.log', '.md',
    '.sql', '.py', '.js', '.ts', '.html', '.htm',
    '.yaml', '.yml', '.ini', '.cfg', '.conf', '.env',
    '.xlsx', '.xls', '.docx', '.doc',
}

# Diretórios a ignorar
IGNORE_DIRS = {
    '.git', '__pycache__', 'node_modules', '.venv', 'venv',
    '.env', 'dist', 'build', '.idea', '.vscode',
}

# Classificação por número de achados
def classify_risk(findings_count, critical_count):
    if critical_count >= 3 or findings_count >= 10:
        return "CRITICAL", "#B91C1C"
    if critical_count >= 1 or findings_count >= 5:
        return "HIGH",     "#92400E"
    if findings_count >= 2:
        return "MEDIUM",   "#1E3A5F"
    if findings_count >= 1:
        return "LOW",      "#166534"
    return "CLEAN",        "#374151"


# ══════════════════════════════════════════════════════════
# SCANNER
# ══════════════════════════════════════════════════════════

def scan_file(filepath):
    """Varre um arquivo em busca de padrões de dados sensíveis."""
    results = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        for pattern_name, pattern_info in PATTERNS.items():
            matches = re.findall(pattern_info["regex"], content, re.IGNORECASE)
            if matches:
                # Deduplica e limita para não expor dados reais
                unique = list(set(str(m) for m in matches))[:5]
                masked = [m[:4] + "****" + m[-2:] if len(m) > 8 else "****" for m in unique]
                results.append({
                    "pattern":     pattern_name,
                    "category":    pattern_info["category"],
                    "severity":    pattern_info["severity"],
                    "description": pattern_info["description"],
                    "count":       len(matches),
                    "samples":     masked,
                })
    except Exception:
        pass
    return results


def scan_directory(root_path, max_files=500):
    """Varre um diretório recursivamente."""
    print(f"\n  Varrendo: {root_path}")
    print(f"  Extensoes monitoradas: {len(SCAN_EXTENSIONS)}")
    print(f"  Limite de arquivos: {max_files}\n")

    scanned   = []
    total     = 0
    flagged   = 0

    for dirpath, dirnames, filenames in os.walk(root_path):
        # Remove diretórios ignorados
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]

        for filename in filenames:
            if total >= max_files:
                break

            ext = Path(filename).suffix.lower()
            if ext not in SCAN_EXTENSIONS:
                continue

            full_path = os.path.join(dirpath, filename)
            total += 1

            try:
                size = os.path.getsize(full_path)
                if size > 5 * 1024 * 1024:  # pula arquivos > 5MB
                    continue
            except Exception:
                continue

            findings = scan_file(full_path)

            if findings:
                flagged += 1
                crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
                risk, _ = classify_risk(len(findings), crit)
                rel_path = os.path.relpath(full_path, root_path)
                print(f"  [{risk:8}] {rel_path}")

                scanned.append({
                    "path":          rel_path,
                    "full_path":     full_path,
                    "size_kb":       round(size / 1024, 1),
                    "findings":      findings,
                    "total_matches": sum(f["count"] for f in findings),
                    "critical_count":crit,
                    "risk":          risk,
                    "hash_sha256":   _hash_file(full_path),
                })

    print(f"\n  Arquivos varridos: {total}")
    print(f"  Arquivos flagados: {flagged}")
    return scanned, total


def _hash_file(path):
    """Calcula SHA-256 do arquivo (para verificação de integridade)."""
    sha = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                sha.update(chunk)
        return sha.hexdigest()[:16] + "..."
    except Exception:
        return "N/A"


# ══════════════════════════════════════════════════════════
# DADOS DE DEMO
# ══════════════════════════════════════════════════════════

def gerar_arquivos_demo():
    """Cria arquivos de demonstração com dados simulados."""
    demo_dir = "./demo_files"
    os.makedirs(demo_dir, exist_ok=True)

    arquivos = {
        "clientes.csv": (
            "nome,cpf,email,telefone\n"
            "Joao Silva,123.456.789-00,joao@empresa.com,(11) 98765-4321\n"
            "Maria Santos,987.654.321-00,maria@empresa.com,(21) 91234-5678\n"
        ),
        "relatorio_medico.txt": (
            "Paciente: Carlos Souza\n"
            "CRM 54321-SP\n"
            "Diagnostico: Hipertensao arterial\n"
            "Prescricao: Losartana 50mg\n"
            "Prontuario 2026-003\n"
        ),
        "pagamentos.json": (
            '{"transacoes": ['
            '{"cartao": "4111 1111 1111 1111", "valor": "R$ 1.500,00"},'
            '{"conta": "corrente 1234-5", "agencia": "0001"}'
            ']}'
        ),
        "config.env": (
            "DB_HOST=192.168.1.100\n"
            "DB_USER=admin\n"
            "senha=MinhaSenh@Secreta123\n"
            "api_key=sk-abc123def456ghi789jkl012mno345pqr\n"
        ),
        "logs_sistema.log": (
            "[2026-03-19 10:00:01] Login: joao@empresa.com IP: 192.168.1.50\n"
            "[2026-03-19 10:05:33] Acesso negado: IP 203.0.113.45\n"
            "[2026-03-19 10:12:44] Transacao: R$ 25.000,00 conta 9876-1\n"
        ),
        "readme_limpo.txt": (
            "Este arquivo nao contem dados sensiveis.\n"
            "Documentacao do projeto de seguranca.\n"
            "Versao 1.0 - Uso interno.\n"
        ),
    }

    for nome, conteudo in arquivos.items():
        with open(os.path.join(demo_dir, nome), "w", encoding="utf-8") as f:
            f.write(conteudo)

    print(f"  Arquivos de demo criados em: {demo_dir}/")
    return demo_dir


# ══════════════════════════════════════════════════════════
# RELATÓRIO HTML — ESTILO ENTERPRISE
# ══════════════════════════════════════════════════════════

def gerar_relatorio(scanned_files, total_scanned, scan_path):
    agora    = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    hostname = socket.gethostname()
    sistema  = platform.system() + " " + platform.release()

    total_flagged  = len(scanned_files)
    total_critical = sum(1 for f in scanned_files if f["risk"] == "CRITICAL")
    total_high     = sum(1 for f in scanned_files if f["risk"] == "HIGH")
    total_matches  = sum(f["total_matches"] for f in scanned_files)

    # Contagem por categoria
    cat_counts = {}
    for f in scanned_files:
        for find in f["findings"]:
            cat = find["category"]
            cat_counts[cat] = cat_counts.get(cat, 0) + find["count"]

    # Risco geral
    if total_critical >= 3:
        overall_risk, risk_color = "CRITICAL", "#B91C1C"
    elif total_critical >= 1 or total_high >= 3:
        overall_risk, risk_color = "HIGH", "#92400E"
    elif total_flagged >= 3:
        overall_risk, risk_color = "MEDIUM", "#1E3A5F"
    elif total_flagged >= 1:
        overall_risk, risk_color = "LOW", "#166634"
    else:
        overall_risk, risk_color = "CLEAN", "#166634"

    # Linhas da tabela de arquivos
    rows_files = ""
    for f in sorted(scanned_files, key=lambda x: x["critical_count"], reverse=True):
        rc = {"CRITICAL":"#B91C1C","HIGH":"#92400E","MEDIUM":"#1E3A5F","LOW":"#166534","CLEAN":"#374151"}.get(f["risk"],"#374151")
        cats = ", ".join(set(x["category"] for x in f["findings"]))
        rows_files += f"""
        <tr>
          <td class="mono">{f['path']}</td>
          <td class="center">{f['size_kb']} KB</td>
          <td class="center"><span class="badge" style="color:{rc};border-color:{rc}">{f['risk']}</span></td>
          <td class="center">{f['total_matches']}</td>
          <td>{cats}</td>
          <td class="mono small">{f['hash_sha256']}</td>
        </tr>"""

    if not rows_files:
        rows_files = '<tr><td colspan="6" class="center muted">Nenhum arquivo com dados sensiveis detectado.</td></tr>'

    # Linhas de detalhes por padrão
    rows_patterns = ""
    pattern_summary = {}
    for f in scanned_files:
        for find in f["findings"]:
            key = find["pattern"]
            if key not in pattern_summary:
                pattern_summary[key] = {
                    "category":    find["category"],
                    "severity":    find["severity"],
                    "description": find["description"],
                    "total":       0,
                    "files":       0,
                }
            pattern_summary[key]["total"] += find["count"]
            pattern_summary[key]["files"] += 1

    for pname, pdata in sorted(pattern_summary.items(), key=lambda x: x[1]["total"], reverse=True):
        sc = {"CRITICAL":"#B91C1C","HIGH":"#92400E","MEDIUM":"#1E3A5F","LOW":"#166534"}.get(pdata["severity"],"#374151")
        rows_patterns += f"""
        <tr>
          <td><strong>{pname}</strong></td>
          <td><span class="badge" style="color:{sc};border-color:{sc}">{pdata['severity']}</span></td>
          <td>{pdata['category']}</td>
          <td class="center">{pdata['total']}</td>
          <td class="center">{pdata['files']}</td>
          <td class="small muted">{pdata['description']}</td>
        </tr>"""

    if not rows_patterns:
        rows_patterns = '<tr><td colspan="6" class="center muted">Nenhum padrao detectado.</td></tr>'

    # Recomendações
    recs = []
    if any(p in pattern_summary for p in ["Password_Pattern","API_Key"]):
        recs.append(("CRITICAL", "Remover credenciais em texto claro de arquivos", "Nunca armazenar senhas ou API keys em arquivos — usar variáveis de ambiente ou cofre de senhas"))
    if any(p in pattern_summary for p in ["Credit_Card","Bank_Account_BR"]):
        recs.append(("CRITICAL", "Criptografar ou tokenizar dados financeiros", "PCI DSS exige que dados de cartão sejam tokenizados ou criptografados — nunca em texto claro"))
    if any(p in pattern_summary for p in ["CPF","Email","Phone_BR"]):
        recs.append(("HIGH", "Aplicar Data Masking em arquivos com PII", "Exibir apenas dados parciais (ex: ***.***.789-00) — LGPD exige proteção de PII"))
    if any(p in pattern_summary for p in ["CRM_Doctor","Health_Keywords"]):
        recs.append(("CRITICAL", "Isolar arquivos PHI em área restrita da rede", "Dados de saúde exigem controles adicionais — acesso apenas por pessoal autorizado"))
    if not recs:
        recs.append(("LOW", "Manter monitoramento periódico", "Executar varredura regularmente para detectar novos arquivos sensíveis"))

    rows_recs = ""
    for i, (sev, acao, motivo) in enumerate(recs, 1):
        sc = {"CRITICAL":"#B91C1C","HIGH":"#92400E","MEDIUM":"#1E3A5F","LOW":"#166534"}.get(sev,"#374151")
        rows_recs += f"""
        <tr>
          <td class="center muted">{i}</td>
          <td><span class="badge" style="color:{sc};border-color:{sc}">{sev}</span></td>
          <td>{acao}</td>
          <td class="small muted">{motivo}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Data Classification Report — Lab 21</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, 'Segoe UI', Arial, sans-serif; background: #F0F2F5; color: #1E293B; font-size: 13px; line-height: 1.5; padding: 2rem; }}
  .page {{ max-width: 1200px; margin: 0 auto; }}

  /* Header */
  .report-header {{ background: #FFFFFF; border: 1px solid #CBD5E1; border-top: 3px solid #1E3A5F; padding: 1.2rem 1.5rem; margin-bottom: 1.2rem; display: flex; justify-content: space-between; align-items: flex-start; }}
  .report-header h1 {{ font-size: 1.1rem; font-weight: 700; color: #1E293B; letter-spacing: -0.2px; }}
  .report-header p {{ font-size: 0.78rem; color: #64748B; margin-top: 2px; }}
  .meta {{ font-size: 0.75rem; color: #64748B; text-align: right; line-height: 1.8; }}
  .meta strong {{ color: #374151; }}

  /* Risk banner */
  .risk-banner {{ background: #FFFFFF; border: 1px solid #CBD5E1; border-left: 4px solid {risk_color}; padding: 0.9rem 1.2rem; margin-bottom: 1.2rem; display: flex; align-items: center; gap: 1.5rem; }}
  .risk-label {{ font-size: 0.68rem; font-weight: 600; color: #64748B; text-transform: uppercase; letter-spacing: 0.8px; }}
  .risk-value {{ font-size: 1.3rem; font-weight: 700; color: {risk_color}; }}
  .risk-desc {{ font-size: 0.82rem; color: #475569; }}

  /* Stats */
  .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.8rem; margin-bottom: 1.2rem; }}
  .stat {{ background: #FFFFFF; border: 1px solid #CBD5E1; padding: 0.8rem 1rem; }}
  .stat .num {{ font-size: 1.6rem; font-weight: 700; color: #1E293B; }}
  .stat .lbl {{ font-size: 0.7rem; color: #64748B; margin-top: 2px; text-transform: uppercase; letter-spacing: 0.5px; }}

  /* Section */
  .section-label {{ font-size: 0.7rem; font-weight: 700; color: #64748B; text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 0.5rem; padding-bottom: 0.4rem; border-bottom: 1px solid #E2E8F0; }}

  /* Table */
  .table-wrap {{ overflow-x: auto; margin-bottom: 1.2rem; }}
  table {{ width: 100%; border-collapse: collapse; background: #FFFFFF; border: 1px solid #CBD5E1; font-size: 0.82rem; }}
  thead tr {{ background: #F8FAFC; border-bottom: 2px solid #CBD5E1; }}
  th {{ padding: 8px 12px; text-align: left; font-size: 0.7rem; font-weight: 600; color: #475569; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #F1F5F9; vertical-align: top; color: #334155; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #F8FAFC; }}

  /* Helpers */
  .badge {{ font-size: 0.7rem; font-weight: 700; padding: 2px 7px; border: 1px solid; border-radius: 2px; white-space: nowrap; }}
  .center {{ text-align: center; }}
  .mono {{ font-family: 'Consolas', 'Courier New', monospace; font-size: 0.78rem; }}
  .small {{ font-size: 0.78rem; }}
  .muted {{ color: #94A3B8; }}

  /* Concept box */
  .concept {{ background: #FFFFFF; border: 1px solid #CBD5E1; border-left: 3px solid #1E3A5F; padding: 1rem 1.2rem; margin-bottom: 1.2rem; }}
  .concept h3 {{ font-size: 0.8rem; font-weight: 700; color: #1E3A5F; margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 0.5px; }}
  .concept p {{ font-size: 0.82rem; color: #475569; line-height: 1.7; }}
  .concept p + p {{ margin-top: 0.4rem; }}

  /* Footer */
  .footer {{ text-align: center; font-size: 0.72rem; color: #94A3B8; padding-top: 1rem; border-top: 1px solid #E2E8F0; margin-top: 1rem; }}
</style>
</head>
<body>
<div class="page">

  <div class="report-header">
    <div>
      <h1>Data Classification &amp; Protection Audit Report</h1>
      <p>Security+ SY0-701 — Lab 21 — Dominío 3 &nbsp;·&nbsp; Luiz Otavio Gonçalves Gilio</p>
    </div>
    <div class="meta">
      <strong>Host:</strong> {hostname}<br>
      <strong>Sistema:</strong> {sistema}<br>
      <strong>Caminho varrido:</strong> {scan_path}<br>
      <strong>Gerado em:</strong> {agora}
    </div>
  </div>

  <div class="risk-banner">
    <div>
      <div class="risk-label">Risco Geral</div>
      <div class="risk-value">{overall_risk}</div>
    </div>
    <div style="width:1px;height:40px;background:#E2E8F0;margin:0 0.5rem"></div>
    <div class="risk-desc">
      {total_flagged} arquivo(s) com dados sensíveis de {total_scanned} varridos &nbsp;·&nbsp;
      {total_critical} arquivo(s) crítico(s) &nbsp;·&nbsp;
      {total_matches} ocorrência(s) total
    </div>
  </div>

  <div class="stats">
    <div class="stat"><div class="num">{total_scanned}</div><div class="lbl">Arquivos Varridos</div></div>
    <div class="stat"><div class="num" style="color:#B91C1C">{total_flagged}</div><div class="lbl">Arquivos Flagados</div></div>
    <div class="stat"><div class="num" style="color:#B91C1C">{total_critical}</div><div class="lbl">Risco Crítico</div></div>
    <div class="stat"><div class="num" style="color:#92400E">{total_high}</div><div class="lbl">Risco Alto</div></div>
    <div class="stat"><div class="num" style="color:#1E3A5F">{total_matches}</div><div class="lbl">Ocorrências</div></div>
  </div>

  <div class="section-label">Recomendações Priorizadas</div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>#</th><th>Severidade</th><th>Ação</th><th>Justificativa</th></tr></thead>
      <tbody>{rows_recs}</tbody>
    </table>
  </div>

  <div class="section-label">Arquivos com Dados Sensíveis Detectados</div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Arquivo</th><th>Tamanho</th><th>Risco</th><th>Ocorrências</th><th>Categorias</th><th>SHA-256 (parcial)</th></tr></thead>
      <tbody>{rows_files}</tbody>
    </table>
  </div>

  <div class="section-label">Padrões Detectados por Tipo</div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Padrão</th><th>Severidade</th><th>Categoria</th><th>Ocorrências</th><th>Arquivos</th><th>Descrição</th></tr></thead>
      <tbody>{rows_patterns}</tbody>
    </table>
  </div>

  <div class="concept">
    <h3>Conceitos demonstrados neste lab</h3>
    <p>
      <strong>PII (Personally Identifiable Information)</strong> inclui qualquer dado que identifique um indivíduo —
      CPF, email, telefone. <strong>PHI (Protected Health Information)</strong> abrange dados de saúde regulamentados.
      Ambos exigem controles específicos pela LGPD e regulamentações setoriais.
    </p>
    <p>
      <strong>Data at Rest</strong> deve ser protegido com criptografia (AES-256) e controles de acesso baseados
      em Least Privilege. Credenciais em texto claro são a falha mais crítica — usar cofres de senha ou
      variáveis de ambiente. <strong>Tokenização</strong> protege dados financeiros: token capturado não pode ser reutilizado.
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
        "timestamp":      datetime.datetime.now().isoformat(),
        "hostname":       hostname,
        "scan_path":      str(scan_path),
        "total_scanned":  total_scanned,
        "total_flagged":  total_flagged,
        "total_critical": total_critical,
        "total_high":     total_high,
        "overall_risk":   overall_risk,
        "files":          scanned_files,
        "category_counts":cat_counts,
    }
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2, ensure_ascii=False)

    print(f"\n  Relatorio: {OUTPUT_HTML}")
    print(f"  Log JSON:  {OUTPUT_JSON}")


# ══════════════════════════════════════════════════════════
# PONTO DE ENTRADA
# ══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Data Classification Auditor — Lab 21 Security+",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--scan",   metavar="PATH", help="Varre um diretorio em busca de dados sensiveis")
    parser.add_argument("--report", action="store_true", help="Gera relatorio HTML do ultimo scan")
    parser.add_argument("--demo",   action="store_true", help="Cria arquivos de demo e executa varredura")
    args = parser.parse_args()

    print("\n" + "="*60)
    print("  DATA CLASSIFICATION AUDITOR — Lab 21")
    print("  Security+ SY0-701 — Dominio 3")
    print("="*60)

    if args.demo:
        print("\n  Modo demonstracao — criando arquivos simulados...\n")
        demo_path = gerar_arquivos_demo()
        files, total = scan_directory(demo_path)
        gerar_relatorio(files, total, demo_path)
        print(f"\n  Abra: start {OUTPUT_HTML}\n")
        return

    if args.report:
        if not os.path.exists(OUTPUT_JSON):
            print("\n  Log nao encontrado. Execute primeiro: --scan PATH\n")
            return
        with open(OUTPUT_JSON) as f:
            log = json.load(f)
        gerar_relatorio(
            log["files"], log["total_scanned"], log["scan_path"]
        )
        print(f"\n  Abra: start {OUTPUT_HTML}\n")
        return

    if args.scan:
        path = os.path.abspath(args.scan)
        if not os.path.exists(path):
            print(f"\n  Caminho nao encontrado: {path}\n")
            return
        files, total = scan_directory(path)
        gerar_relatorio(files, total, path)
        print(f"\n  Abra: start {OUTPUT_HTML}\n")
        return

    print("""
  Uso:
    python data_classification_auditor.py --demo
    python data_classification_auditor.py --scan .
    python data_classification_auditor.py --scan C:\\Users\\Win\\Documents
    python data_classification_auditor.py --report
    """)

if __name__ == "__main__":
    main()
