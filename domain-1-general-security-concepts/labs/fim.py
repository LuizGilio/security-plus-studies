"""
=============================================================
LAB 05 — File Integrity Monitor (FIM)
Security+ SY0-701 — Domínio 1 — CIA Triad: Integridade
=============================================================
Autor: Luiz Otavio Gonçalves Gilio
GitHub: github.com/LuizGilio

CONCEITO:
    Um FIM monitora arquivos críticos gerando um hash (SHA-256)
    de cada um. Se o conteúdo mudar, o hash muda — alertando
    sobre alterações não autorizadas.

    Isso implementa o "I" do CIA Triad na prática.
    Ferramentas reais: Tripwire, OSSEC, Wazuh.

COMO USAR:
    1. python fim.py --baseline   → cria a linha de base
    2. python fim.py --check      → verifica se algo mudou
    3. python fim.py --report     → gera relatório em HTML
=============================================================
"""

import hashlib      # gera os hashes SHA-256
import json         # salva/lê a baseline em formato JSON
import os           # navega pelo sistema de arquivos
import argparse     # lê os argumentos da linha de comando
import datetime     # registra data/hora dos eventos
import sys

# ── Configurações ──────────────────────────────────────────
# Pasta que será monitorada (você pode mudar para qualquer pasta)
MONITOR_DIR   = "./arquivos_monitorados"
BASELINE_FILE = "./baseline.json"
LOG_FILE      = "./fim_log.txt"
REPORT_FILE   = "./relatorio_fim.html"


# ══════════════════════════════════════════════════════════
# FUNÇÕES PRINCIPAIS
# ══════════════════════════════════════════════════════════

def calcular_hash(filepath):
    """
    Lê o arquivo em blocos e calcula o hash SHA-256.
    Usar blocos evita carregar arquivos grandes na memória.
    """
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:          # abre em modo binário
            while chunk := f.read(8192):          # lê 8KB por vez
                sha256.update(chunk)              # alimenta o hash
        return sha256.hexdigest()                 # retorna o hash final
    except (PermissionError, FileNotFoundError) as e:
        return f"ERRO: {e}"


def escanear_diretorio(diretorio):
    """
    Percorre todos os arquivos do diretório e retorna
    um dicionário {caminho_arquivo: hash_sha256}.
    """
    hashes = {}
    for raiz, _, arquivos in os.walk(diretorio):
        for nome in arquivos:
            caminho = os.path.join(raiz, nome)
            hashes[caminho] = calcular_hash(caminho)
    return hashes


def registrar_log(mensagem):
    """Salva eventos no arquivo de log com timestamp."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    linha = f"[{timestamp}] {mensagem}"
    print(linha)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(linha + "\n")


# ══════════════════════════════════════════════════════════
# AÇÕES DO FIM
# ══════════════════════════════════════════════════════════

def criar_baseline():
    """
    Cria a 'foto' inicial dos arquivos.
    Esta é a linha de base com que tudo será comparado.
    """
    # Cria a pasta monitorada se não existir
    os.makedirs(MONITOR_DIR, exist_ok=True)

    # Cria arquivos de exemplo para monitorar
    exemplos = {
        "config_sistema.txt":  "usuario=admin\nsenha_hash=abc123\nnivel_acesso=root",
        "politica_acesso.txt": "Politica v1.0\nAcesso restrito a pessoal autorizado.",
        "chaves_api.txt":      "API_KEY=chave-super-secreta-fake-apenas-para-lab\nEXPIRES=2099-12-31",
    }
    for nome, conteudo in exemplos.items():
        caminho = os.path.join(MONITOR_DIR, nome)
        if not os.path.exists(caminho):
            with open(caminho, "w", encoding="utf-8") as f:
                f.write(conteudo)

    # Gera os hashes de todos os arquivos
    registrar_log("=" * 60)
    registrar_log("CRIANDO BASELINE — linha de base do sistema")
    hashes = escanear_diretorio(MONITOR_DIR)

    # Salva a baseline com metadados
    baseline = {
        "criado_em": datetime.datetime.now().isoformat(),
        "diretorio": MONITOR_DIR,
        "total_arquivos": len(hashes),
        "arquivos": hashes,
    }
    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2, ensure_ascii=False)

    registrar_log(f"Baseline criada com {len(hashes)} arquivo(s).")
    for caminho, hash_val in hashes.items():
        registrar_log(f"  [OK] {os.path.basename(caminho)} → {hash_val[:20]}...")
    registrar_log("Baseline salva em: baseline.json")
    print("\n✅ Baseline criada com sucesso!")
    print("   Agora modifique um arquivo e rode: python fim.py --check\n")


def verificar_integridade():
    """
    Compara o estado atual dos arquivos com a baseline.
    Detecta: arquivos alterados, deletados e novos.
    """
    # Verifica se a baseline existe
    if not os.path.exists(BASELINE_FILE):
        print("❌ Baseline não encontrada. Rode primeiro: python fim.py --baseline")
        sys.exit(1)

    # Carrega a baseline
    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        baseline = json.load(f)

    hashes_baseline  = baseline["arquivos"]
    hashes_atuais    = escanear_diretorio(MONITOR_DIR)

    # ── Comparação ─────────────────────────────────────────
    alterados = []
    deletados = []
    novos     = []

    # Verifica arquivos da baseline
    for caminho, hash_original in hashes_baseline.items():
        if caminho not in hashes_atuais:
            deletados.append(caminho)
        elif hashes_atuais[caminho] != hash_original:
            alterados.append({
                "arquivo":       caminho,
                "hash_original": hash_original,
                "hash_atual":    hashes_atuais[caminho],
            })

    # Verifica arquivos novos (não estavam na baseline)
    for caminho in hashes_atuais:
        if caminho not in hashes_baseline:
            novos.append(caminho)

    # ── Relatório no terminal ──────────────────────────────
    registrar_log("=" * 60)
    registrar_log("VERIFICAÇÃO DE INTEGRIDADE INICIADA")

    total_alertas = len(alterados) + len(deletados) + len(novos)

    if total_alertas == 0:
        registrar_log("✅ SISTEMA ÍNTEGRO — Nenhuma alteração detectada.")
    else:
        registrar_log(f"🚨 ALERTA — {total_alertas} problema(s) detectado(s)!")

        for item in alterados:
            registrar_log(f"  ⚠️  ALTERADO: {os.path.basename(item['arquivo'])}")
            registrar_log(f"       Hash original: {item['hash_original'][:32]}...")
            registrar_log(f"       Hash atual:    {item['hash_atual'][:32]}...")

        for caminho in deletados:
            registrar_log(f"  ❌ DELETADO: {os.path.basename(caminho)}")

        for caminho in novos:
            registrar_log(f"  🆕 NOVO ARQUIVO: {os.path.basename(caminho)}")

    registrar_log(f"Verificação concluída. Total monitorado: {len(hashes_atuais)} arquivo(s).")

    # Retorna os resultados para o relatório
    return {
        "verificado_em":  datetime.datetime.now().isoformat(),
        "baseline_criada": baseline["criado_em"],
        "total_monitorado": len(hashes_atuais),
        "alterados":  alterados,
        "deletados":  deletados,
        "novos":      novos,
        "integro":    total_alertas == 0,
    }


def gerar_relatorio(resultado=None):
    """
    Gera um relatório HTML visual com os resultados da verificação.
    """
    if resultado is None:
        resultado = verificar_integridade()

    status_cor   = "#10B981" if resultado["integro"] else "#EF4444"
    status_texto = "✅ SISTEMA ÍNTEGRO" if resultado["integro"] else "🚨 ALTERAÇÕES DETECTADAS"

    # Monta linhas de alertas
    linhas_alertas = ""
    for item in resultado["alterados"]:
        nome = os.path.basename(item["arquivo"])
        linhas_alertas += f"""
        <tr>
            <td><span class="badge badge-warn">⚠️ ALTERADO</span></td>
            <td><code>{nome}</code></td>
            <td><code style="color:#94A3B8">{item['hash_original'][:24]}...</code></td>
            <td><code style="color:#F59E0B">{item['hash_atual'][:24]}...</code></td>
        </tr>"""

    for caminho in resultado["deletados"]:
        nome = os.path.basename(caminho)
        linhas_alertas += f"""
        <tr>
            <td><span class="badge badge-danger">❌ DELETADO</span></td>
            <td><code>{nome}</code></td>
            <td colspan="2" style="color:#94A3B8">Arquivo removido do sistema</td>
        </tr>"""

    for caminho in resultado["novos"]:
        nome = os.path.basename(caminho)
        linhas_alertas += f"""
        <tr>
            <td><span class="badge badge-new">🆕 NOVO</span></td>
            <td><code>{nome}</code></td>
            <td colspan="2" style="color:#94A3B8">Arquivo não estava na baseline</td>
        </tr>"""

    if not linhas_alertas:
        linhas_alertas = """
        <tr>
            <td colspan="4" style="text-align:center; color:#10B981; padding:20px;">
                ✅ Nenhuma alteração detectada — todos os arquivos estão íntegros.
            </td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FIM Report — Lab 05</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', sans-serif;
            background: #0A0E1A;
            color: #E2E8F0;
            padding: 2rem;
        }}
        .header {{
            border-left: 4px solid #00D4FF;
            padding-left: 1rem;
            margin-bottom: 2rem;
        }}
        .header h1 {{ font-size: 1.8rem; color: #fff; }}
        .header p  {{ color: #94A3B8; font-size: 0.9rem; margin-top: 4px; }}
        .status-box {{
            background: #1E2A3A;
            border: 2px solid {status_cor};
            border-radius: 8px;
            padding: 1.2rem 1.5rem;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        .status-text {{ font-size: 1.3rem; font-weight: bold; color: {status_cor}; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-bottom: 1.5rem;
        }}
        .stat-card {{
            background: #1E2A3A;
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
            border-top: 3px solid #00D4FF;
        }}
        .stat-card .num {{ font-size: 2rem; font-weight: bold; color: #00D4FF; }}
        .stat-card .label {{ font-size: 0.8rem; color: #94A3B8; margin-top: 4px; }}
        .section-title {{
            font-size: 1rem;
            font-weight: bold;
            color: #00D4FF;
            margin-bottom: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #1E2A3A;
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 1.5rem;
        }}
        th {{
            background: #7C3AED;
            padding: 10px 14px;
            text-align: left;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        td {{
            padding: 10px 14px;
            border-bottom: 1px solid #243040;
            font-size: 0.9rem;
        }}
        tr:last-child td {{ border-bottom: none; }}
        .badge {{
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
        }}
        .badge-warn   {{ background: #78350F; color: #F59E0B; }}
        .badge-danger {{ background: #450A0A; color: #EF4444; }}
        .badge-new    {{ background: #0D3321; color: #10B981; }}
        .concept-box {{
            background: #1E2A3A;
            border: 1px solid #243040;
            border-radius: 8px;
            padding: 1.2rem;
            margin-bottom: 1.5rem;
        }}
        .concept-box h3 {{ color: #F59E0B; margin-bottom: 0.5rem; }}
        .concept-box p  {{ color: #94A3B8; font-size: 0.9rem; line-height: 1.6; }}
        .footer {{
            text-align: center;
            color: #4A5568;
            font-size: 0.8rem;
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid #1E2A3A;
        }}
        code {{
            font-family: 'Consolas', monospace;
            font-size: 0.85rem;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>File Integrity Monitor</h1>
        <p>Security+ SY0-701 — Lab 05 — CIA Triad: Integridade &nbsp;|&nbsp; Luiz Otavio Gonçalves Gilio</p>
    </div>

    <div class="status-box">
        <div class="status-text">{status_texto}</div>
    </div>

    <div class="stats">
        <div class="stat-card">
            <div class="num">{resultado['total_monitorado']}</div>
            <div class="label">Arquivos Monitorados</div>
        </div>
        <div class="stat-card">
            <div class="num" style="color:#F59E0B">{len(resultado['alterados'])}</div>
            <div class="label">Alterados</div>
        </div>
        <div class="stat-card">
            <div class="num" style="color:#EF4444">{len(resultado['deletados'])}</div>
            <div class="label">Deletados</div>
        </div>
        <div class="stat-card">
            <div class="num" style="color:#10B981">{len(resultado['novos'])}</div>
            <div class="label">Novos Arquivos</div>
        </div>
    </div>

    <div class="section-title">Detalhes da Verificação</div>
    <table>
        <thead>
            <tr>
                <th>Status</th>
                <th>Arquivo</th>
                <th>Hash Original (baseline)</th>
                <th>Hash Atual</th>
            </tr>
        </thead>
        <tbody>
            {linhas_alertas}
        </tbody>
    </table>

    <div class="concept-box">
        <h3>🧠 Conceito aplicado neste lab</h3>
        <p>
            Um <strong>File Integrity Monitor</strong> implementa o princípio de
            <strong>Integridade</strong> do CIA Triad. Ele gera um hash SHA-256 de cada arquivo
            monitorado e compara periodicamente com a baseline. Qualquer alteração — mesmo de
            1 único byte — muda completamente o hash, gerando um alerta. Ferramentas como
            <strong>Tripwire</strong>, <strong>OSSEC</strong> e <strong>Wazuh</strong> usam
            exatamente este princípio em ambientes corporativos.
        </p>
    </div>

    <div class="concept-box">
        <h3>📋 Metadados da Execução</h3>
        <p>
            Baseline criada em: <code>{resultado['baseline_criada']}</code><br>
            Verificação realizada em: <code>{resultado['verificado_em']}</code><br>
            Diretório monitorado: <code>{MONITOR_DIR}</code>
        </p>
    </div>

    <div class="footer">
        github.com/LuizGilio/security-plus-studies &nbsp;|&nbsp;
        CompTIA Security+ SY0-701 — Domínio 1
    </div>
</body>
</html>"""

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(html)

    registrar_log(f"Relatório HTML gerado: {REPORT_FILE}")
    print(f"\n✅ Relatório gerado: {REPORT_FILE}")
    print("   Abra o arquivo relatorio_fim.html no navegador para visualizar.\n")


# ══════════════════════════════════════════════════════════
# PONTO DE ENTRADA
# ══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="FIM — File Integrity Monitor | Lab 05 Security+",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--baseline", action="store_true",
        help="Cria a linha de base (primeira execução)")
    parser.add_argument("--check",    action="store_true",
        help="Verifica se algo foi alterado")
    parser.add_argument("--report",   action="store_true",
        help="Gera relatório HTML completo")

    args = parser.parse_args()

    if args.baseline:
        criar_baseline()
    elif args.check:
        verificar_integridade()
    elif args.report:
        gerar_relatorio()
    else:
        print("\n📋 File Integrity Monitor — Lab 05")
        print("─" * 40)
        print("Uso:")
        print("  python fim.py --baseline   → cria a linha de base")
        print("  python fim.py --check      → verifica alterações")
        print("  python fim.py --report     → gera relatório HTML\n")


if __name__ == "__main__":
    main()
