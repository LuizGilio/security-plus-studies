"""
=============================================================
LAB 10 — Zero Trust Policy Simulator
Security+ SY0-701 — Domínio 1 — Zero Trust: PEP, PDP, AAA
=============================================================
Autor: Luiz Otavio Gonçalves Gilio
GitHub: github.com/LuizGilio

CONCEITO:
    Simula o processo de decisão de um sistema Zero Trust.
    Toda solicitação de acesso passa pelo PEP (Ponto de
    Imposição de Política) que consulta o PDP (Ponto de
    Decisão de Política) antes de permitir ou negar acesso.

    Princípio: NUNCA confiar, SEMPRE verificar.

COMO USAR:
    1. python zero_trust.py --simular    → roda cenários de teste
    2. python zero_trust.py --interativo → você cria a solicitação
    3. python zero_trust.py --report     → gera relatório HTML
=============================================================
"""

import json
import datetime
import argparse
import sys
import os

# ── Arquivos de saída ──────────────────────────────────
LOG_FILE    = "./zt_log.json"
REPORT_FILE = "./relatorio_zero_trust.html"


# ══════════════════════════════════════════════════════════
# POLÍTICAS DO SISTEMA ZERO TRUST
# Aqui você define as regras que o PDP vai usar para decidir
# ══════════════════════════════════════════════════════════

POLITICAS = {
    # Usuários e seus níveis de confiança base
    "usuarios": {
        "luiz.gilio":    {"nivel": "alto",   "cargo": "analista_seguranca", "mfa": True},
        "maria.silva":   {"nivel": "medio",  "cargo": "desenvolvedor",      "mfa": True},
        "joao.souza":    {"nivel": "medio",  "cargo": "financeiro",         "mfa": False},
        "visitante":     {"nivel": "baixo",  "cargo": "externo",            "mfa": False},
        "desconhecido":  {"nivel": "zero",   "cargo": "desconhecido",       "mfa": False},
    },

    # Recursos e quem pode acessar
    "recursos": {
        "servidor_producao": {
            "nivel_minimo":    "alto",
            "requer_mfa":      True,
            "horario_permitido": (8, 20),   # das 8h às 20h
            "locais_permitidos": ["sede", "vpn"],
        },
        "banco_dados_financeiro": {
            "nivel_minimo":    "alto",
            "requer_mfa":      True,
            "horario_permitido": (9, 18),
            "locais_permitidos": ["sede"],
        },
        "sistema_rh": {
            "nivel_minimo":    "medio",
            "requer_mfa":      True,
            "horario_permitido": (7, 22),
            "locais_permitidos": ["sede", "vpn", "remoto"],
        },
        "intranet": {
            "nivel_minimo":    "baixo",
            "requer_mfa":      False,
            "horario_permitido": (0, 24),
            "locais_permitidos": ["sede", "vpn", "remoto"],
        },
    },

    # Dispositivos confiáveis
    "dispositivos_confiaveis": [
        "notebook-corp-001",
        "notebook-corp-002",
        "desktop-sede-010",
        "iphone-corp-luiz",
    ],

    # Localizações de risco (sempre negam acesso a recursos críticos)
    "locais_risco": ["pais_estrangeiro", "rede_publica", "desconhecido"],
}


# ══════════════════════════════════════════════════════════
# CLASSES PRINCIPAIS
# ══════════════════════════════════════════════════════════

class SolicitacaoAcesso:
    """
    Representa uma tentativa de acesso ao sistema.
    É o 'pacote de informações' que o PEP envia ao PDP.
    """
    def __init__(self, usuario, recurso, dispositivo, localizacao, horario=None):
        self.usuario      = usuario
        self.recurso      = recurso
        self.dispositivo  = dispositivo
        self.localizacao  = localizacao
        self.horario      = horario or datetime.datetime.now().hour
        self.timestamp    = datetime.datetime.now().isoformat()

    def __str__(self):
        return (f"Usuário: {self.usuario} | Recurso: {self.recurso} | "
                f"Dispositivo: {self.dispositivo} | Local: {self.localizacao} | "
                f"Horário: {self.horario}h")


class PEP:
    """
    Ponto de Imposição de Política (Policy Enforcement Point).
    Intercepta TODA solicitação de acesso e consulta o PDP.
    Não toma decisões — apenas aplica o que o PDP decide.
    """
    def __init__(self, pdp):
        self.pdp      = pdp        # referência ao PDP
        self.log      = []         # registro de todas as decisões (Accounting do AAA)

    def solicitar_acesso(self, solicitacao):
        """
        Ponto de entrada de toda solicitação.
        O PEP recebe, consulta o PDP e aplica a decisão.
        """
        print(f"\n{'='*60}")
        print(f"🔒 PEP — Solicitação de acesso interceptada")
        print(f"   {solicitacao}")
        print(f"{'='*60}")

        # Consulta o PDP para obter a decisão
        decisao = self.pdp.avaliar(solicitacao)

        # Aplica e registra a decisão (Accounting)
        self._registrar(solicitacao, decisao)
        self._exibir_decisao(decisao)

        return decisao

    def _exibir_decisao(self, decisao):
        """Exibe a decisão final no terminal."""
        icone = "✅" if decisao["resultado"] == "PERMITIDO" else "🚫"
        print(f"\n  {icone} DECISÃO FINAL: {decisao['resultado']}")
        print(f"  📋 Motivos:")
        for motivo in decisao["motivos"]:
            print(f"     • {motivo}")
        print(f"  ⚠️  Risco calculado: {decisao['risco']}")

    def _registrar(self, solicitacao, decisao):
        """Salva no log — implementa o A do AAA (Accounting)."""
        entrada = {
            "timestamp":   solicitacao.timestamp,
            "usuario":     solicitacao.usuario,
            "recurso":     solicitacao.recurso,
            "dispositivo": solicitacao.dispositivo,
            "localizacao": solicitacao.localizacao,
            "horario":     solicitacao.horario,
            "resultado":   decisao["resultado"],
            "risco":       decisao["risco"],
            "motivos":     decisao["motivos"],
        }
        self.log.append(entrada)

        # Salva no arquivo JSON
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(self.log, f, indent=2, ensure_ascii=False)


class PDP:
    """
    Ponto de Decisão de Política (Policy Decision Point).
    O 'cérebro' do Zero Trust — analisa o contexto e decide.

    Avalia 5 fatores para calcular o risco:
    1. Identidade do usuário
    2. Dispositivo
    3. Localização
    4. Horário
    5. Nível mínimo exigido pelo recurso
    """

    NIVEIS = {"zero": 0, "baixo": 1, "medio": 2, "alto": 3}

    def avaliar(self, solicitacao):
        """
        Análise completa da solicitação.
        Retorna decisão com resultado, motivos e nível de risco.
        """
        motivos    = []
        pontos_risco = 0
        resultado  = "PERMITIDO"

        usuario  = POLITICAS["usuarios"].get(solicitacao.usuario)
        recurso  = POLITICAS["recursos"].get(solicitacao.recurso)

        # ── Verificação 1: Usuário existe? ─────────────────
        if not usuario:
            return {
                "resultado": "NEGADO",
                "risco":     "CRÍTICO",
                "motivos":   ["Usuário não reconhecido no sistema — identidade desconhecida"],
            }

        if not recurso:
            return {
                "resultado": "NEGADO",
                "risco":     "CRÍTICO",
                "motivos":   ["Recurso não encontrado na política de acesso"],
            }

        # ── Verificação 2: Nível de confiança do usuário ───
        nivel_usuario  = self.NIVEIS.get(usuario["nivel"], 0)
        nivel_minimo   = self.NIVEIS.get(recurso["nivel_minimo"], 99)

        if nivel_usuario < nivel_minimo:
            resultado = "NEGADO"
            motivos.append(
                f"Nível de confiança insuficiente — usuário: '{usuario['nivel']}', "
                f"exigido: '{recurso['nivel_minimo']}'"
            )
            pontos_risco += 3
        else:
            motivos.append(f"✅ Nível de confiança adequado ({usuario['nivel']})")

        # ── Verificação 3: MFA ─────────────────────────────
        if recurso["requer_mfa"] and not usuario["mfa"]:
            resultado = "NEGADO"
            motivos.append("MFA obrigatório para este recurso — usuário sem MFA ativo")
            pontos_risco += 3
        elif recurso["requer_mfa"] and usuario["mfa"]:
            motivos.append("✅ MFA verificado e ativo")

        # ── Verificação 4: Dispositivo confiável ───────────
        dispositivos_confiaveis = POLITICAS["dispositivos_confiaveis"]
        if solicitacao.dispositivo not in dispositivos_confiaveis:
            resultado = "NEGADO"
            motivos.append(
                f"Dispositivo '{solicitacao.dispositivo}' não está na lista de dispositivos confiáveis"
            )
            pontos_risco += 2
        else:
            motivos.append(f"✅ Dispositivo confiável reconhecido")

        # ── Verificação 5: Localização ─────────────────────
        if solicitacao.localizacao in POLITICAS["locais_risco"]:
            resultado = "NEGADO"
            motivos.append(
                f"Localização de risco detectada: '{solicitacao.localizacao}'"
            )
            pontos_risco += 4
        elif solicitacao.localizacao not in recurso["locais_permitidos"]:
            resultado = "NEGADO"
            motivos.append(
                f"Localização '{solicitacao.localizacao}' não permitida para este recurso. "
                f"Permitidos: {', '.join(recurso['locais_permitidos'])}"
            )
            pontos_risco += 2
        else:
            motivos.append(f"✅ Localização permitida ({solicitacao.localizacao})")

        # ── Verificação 6: Horário ─────────────────────────
        hora_inicio, hora_fim = recurso["horario_permitido"]
        if not (hora_inicio <= solicitacao.horario < hora_fim):
            resultado = "NEGADO"
            motivos.append(
                f"Acesso fora do horário permitido — atual: {solicitacao.horario}h, "
                f"permitido: {hora_inicio}h às {hora_fim}h"
            )
            pontos_risco += 1
        else:
            motivos.append(f"✅ Acesso dentro do horário permitido")

        # ── Cálculo do risco ───────────────────────────────
        if pontos_risco == 0:
            risco = "BAIXO"
        elif pontos_risco <= 2:
            risco = "MÉDIO"
        elif pontos_risco <= 5:
            risco = "ALTO"
        else:
            risco = "CRÍTICO"

        return {
            "resultado": resultado,
            "risco":     risco,
            "motivos":   motivos,
        }


# ══════════════════════════════════════════════════════════
# CENÁRIOS DE TESTE
# ══════════════════════════════════════════════════════════

CENARIOS = [
    {
        "descricao": "Analista de segurança acessando servidor de produção durante horário comercial",
        "solicitacao": SolicitacaoAcesso(
            usuario="luiz.gilio",
            recurso="servidor_producao",
            dispositivo="notebook-corp-001",
            localizacao="sede",
            horario=14,
        ),
        "esperado": "PERMITIDO",
    },
    {
        "descricao": "Visitante externo tentando acessar banco de dados financeiro",
        "solicitacao": SolicitacaoAcesso(
            usuario="visitante",
            recurso="banco_dados_financeiro",
            dispositivo="notebook-pessoal-xyz",
            localizacao="remoto",
            horario=10,
        ),
        "esperado": "NEGADO",
    },
    {
        "descricao": "Desenvolvedor sem MFA tentando acessar servidor de produção",
        "solicitacao": SolicitacaoAcesso(
            usuario="joao.souza",
            recurso="servidor_producao",
            dispositivo="notebook-corp-002",
            localizacao="sede",
            horario=11,
        ),
        "esperado": "NEGADO",
    },
    {
        "descricao": "Acesso legítimo fora do horário permitido (madrugada)",
        "solicitacao": SolicitacaoAcesso(
            usuario="luiz.gilio",
            recurso="banco_dados_financeiro",
            dispositivo="notebook-corp-001",
            localizacao="sede",
            horario=2,
        ),
        "esperado": "NEGADO",
    },
    {
        "descricao": "Usuário desconhecido tentando acessar qualquer recurso",
        "solicitacao": SolicitacaoAcesso(
            usuario="hacker123",
            recurso="servidor_producao",
            dispositivo="notebook-desconhecido",
            localizacao="pais_estrangeiro",
            horario=3,
        ),
        "esperado": "NEGADO",
    },
    {
        "descricao": "Analista acessando intranet de localização remota",
        "solicitacao": SolicitacaoAcesso(
            usuario="luiz.gilio",
            recurso="intranet",
            dispositivo="notebook-corp-001",
            localizacao="remoto",
            horario=9,
        ),
        "esperado": "PERMITIDO",
    },
]


# ══════════════════════════════════════════════════════════
# GERADOR DE RELATÓRIO HTML
# ══════════════════════════════════════════════════════════

def gerar_relatorio(log_entries):
    """Gera relatório HTML visual com todos os resultados."""

    total      = len(log_entries)
    permitidos = sum(1 for e in log_entries if e["resultado"] == "PERMITIDO")
    negados    = total - permitidos
    criticos   = sum(1 for e in log_entries if e["risco"] == "CRÍTICO")

    linhas = ""
    for entry in log_entries:
        cor_resultado = "#10B981" if entry["resultado"] == "PERMITIDO" else "#EF4444"
        cor_risco = {
            "BAIXO": "#10B981", "MÉDIO": "#F59E0B",
            "ALTO": "#EF4444",  "CRÍTICO": "#7C3AED"
        }.get(entry["risco"], "#94A3B8")

        motivos_html = "".join(
            f'<li style="color:{"#10B981" if m.startswith("✅") else "#EF4444" if "não" in m.lower() or "negado" in m.lower() or "fora" in m.lower() or "risco" in m.lower() else "#94A3B8"}'
            f'; margin: 3px 0; font-size:0.82rem;">{m}</li>'
            for m in entry["motivos"]
        )

        linhas += f"""
        <tr>
            <td><code style="color:#94A3B8;font-size:0.8rem">{entry['timestamp'][:19]}</code></td>
            <td><strong style="color:#E2E8F0">{entry['usuario']}</strong></td>
            <td><code style="color:#00D4FF">{entry['recurso']}</code></td>
            <td><code style="color:#94A3B8">{entry['dispositivo']}</code></td>
            <td><span style="color:#94A3B8">{entry['localizacao']}</span></td>
            <td><strong style="color:{cor_resultado}">{entry['resultado']}</strong></td>
            <td><strong style="color:{cor_risco}">{entry['risco']}</strong></td>
            <td><ul style="margin:0;padding-left:16px">{motivos_html}</ul></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Zero Trust Simulator — Lab 10</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family:'Segoe UI',sans-serif; background:#0A0E1A; color:#E2E8F0; padding:2rem; }}
        .header {{ border-left:4px solid #7C3AED; padding-left:1rem; margin-bottom:1.5rem; }}
        .header h1 {{ font-size:1.8rem; color:#fff; }}
        .header p  {{ color:#94A3B8; font-size:0.9rem; margin-top:4px; }}
        .principle {{
            background:#1E2A3A; border:1px solid #7C3AED; border-radius:8px;
            padding:1rem 1.2rem; margin-bottom:1.5rem;
            font-style:italic; color:#94A3B8; font-size:0.9rem;
        }}
        .principle strong {{ color:#7C3AED; }}
        .stats {{
            display:grid; grid-template-columns:repeat(4,1fr);
            gap:1rem; margin-bottom:1.5rem;
        }}
        .stat {{ background:#1E2A3A; border-radius:8px; padding:1rem; text-align:center; }}
        .stat .num   {{ font-size:2rem; font-weight:bold; }}
        .stat .label {{ font-size:0.8rem; color:#94A3B8; margin-top:4px; }}
        .section-title {{
            font-size:0.85rem; font-weight:bold; color:#7C3AED;
            text-transform:uppercase; letter-spacing:1px; margin-bottom:0.8rem;
        }}
        .table-wrap {{ overflow-x:auto; margin-bottom:1.5rem; }}
        table {{ width:100%; border-collapse:collapse; background:#1E2A3A; border-radius:8px; overflow:hidden; }}
        th {{
            background:#7C3AED; padding:10px 12px; text-align:left;
            font-size:0.8rem; text-transform:uppercase; letter-spacing:0.5px; white-space:nowrap;
        }}
        td {{ padding:10px 12px; border-bottom:1px solid #243040; vertical-align:top; font-size:0.88rem; }}
        tr:last-child td {{ border-bottom:none; }}
        tr:nth-child(even) {{ background:#1A2535; }}
        .concept {{ background:#1E2A3A; border:1px solid #243040; border-radius:8px; padding:1.2rem; margin-bottom:1rem; }}
        .concept h3 {{ color:#F59E0B; margin-bottom:0.5rem; font-size:1rem; }}
        .concept p  {{ color:#94A3B8; font-size:0.9rem; line-height:1.6; }}
        .flow {{
            display:flex; align-items:center; gap:0.5rem;
            background:#111827; border-radius:8px; padding:1rem 1.2rem;
            margin:1rem 0; flex-wrap:wrap;
        }}
        .flow-step {{
            background:#243040; border:1px solid #7C3AED; border-radius:6px;
            padding:0.4rem 0.8rem; font-size:0.85rem; color:#E2E8F0; white-space:nowrap;
        }}
        .flow-arrow {{ color:#7C3AED; font-size:1.2rem; }}
        .footer {{ text-align:center; color:#4A5568; font-size:0.8rem; margin-top:2rem; padding-top:1rem; border-top:1px solid #1E2A3A; }}
    </style>
</head>
<body>

<div class="header">
    <h1>Zero Trust Policy Simulator</h1>
    <p>Security+ SY0-701 — Lab 10 — Zero Trust: PEP, PDP, AAA &nbsp;|&nbsp; Luiz Otavio Gonçalves Gilio</p>
</div>

<div class="principle">
    <strong>Princípio Zero Trust:</strong> "Nunca confiar, sempre verificar" —
    toda solicitação de acesso é avaliada independente de origem, usuário ou localização.
</div>

<div class="stats">
    <div class="stat">
        <div class="num" style="color:#00D4FF">{total}</div>
        <div class="label">Solicitações Avaliadas</div>
    </div>
    <div class="stat">
        <div class="num" style="color:#10B981">{permitidos}</div>
        <div class="label">Permitidas</div>
    </div>
    <div class="stat">
        <div class="num" style="color:#EF4444">{negados}</div>
        <div class="label">Negadas</div>
    </div>
    <div class="stat">
        <div class="num" style="color:#7C3AED">{criticos}</div>
        <div class="label">Risco Crítico</div>
    </div>
</div>

<div class="section-title">Fluxo Zero Trust</div>
<div class="flow">
    <div class="flow-step">👤 Usuário tenta acesso</div>
    <div class="flow-arrow">→</div>
    <div class="flow-step">🔒 PEP intercepta</div>
    <div class="flow-arrow">→</div>
    <div class="flow-step">🧠 PDP avalia contexto</div>
    <div class="flow-arrow">→</div>
    <div class="flow-step">⚖️ Decisão: PERMITIR / NEGAR</div>
    <div class="flow-arrow">→</div>
    <div class="flow-step">🔒 PEP aplica decisão</div>
    <div class="flow-arrow">→</div>
    <div class="flow-step">📋 Log registrado (AAA)</div>
</div>

<div class="section-title">Log de Decisões — Detalhado</div>
<div class="table-wrap">
<table>
    <thead>
        <tr>
            <th>Timestamp</th>
            <th>Usuário</th>
            <th>Recurso</th>
            <th>Dispositivo</th>
            <th>Localização</th>
            <th>Resultado</th>
            <th>Risco</th>
            <th>Motivos da Decisão</th>
        </tr>
    </thead>
    <tbody>{linhas}</tbody>
</table>
</div>

<div class="concept">
    <h3>🧠 Conceitos aplicados neste lab</h3>
    <p>
        O <strong>PEP (Ponto de Imposição de Política)</strong> intercepta toda solicitação e
        aplica a decisão do PDP — ele não pensa, só executa.<br><br>
        O <strong>PDP (Ponto de Decisão de Política)</strong> é o cérebro: avalia identidade,
        dispositivo, localização, horário e nível de risco antes de decidir.<br><br>
        A <strong>Identidade Adaptativa</strong> considera o contexto completo — não só quem você é,
        mas de onde, com qual dispositivo e quando você está acessando.<br><br>
        O <strong>Accounting (A do AAA)</strong> registra cada decisão com timestamp — garantindo
        rastreabilidade completa de todos os acessos.
    </p>
</div>

<div class="footer">
    github.com/LuizGilio/security-plus-studies &nbsp;|&nbsp; CompTIA Security+ SY0-701 — Domínio 1
</div>

</body>
</html>"""

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n✅ Relatório gerado: {REPORT_FILE}")
    print("   Abra o arquivo relatorio_zero_trust.html no navegador.\n")


# ══════════════════════════════════════════════════════════
# MODO INTERATIVO
# ══════════════════════════════════════════════════════════

def modo_interativo(pep):
    """Permite que o usuário crie sua própria solicitação."""
    print("\n" + "="*60)
    print("🎮 MODO INTERATIVO — Crie sua própria solicitação")
    print("="*60)

    print("\nUsuários disponíveis:")
    for nome, dados in POLITICAS["usuarios"].items():
        print(f"  • {nome} ({dados['cargo']}, nível: {dados['nivel']}, MFA: {dados['mfa']})")

    print("\nRecursos disponíveis:")
    for nome, dados in POLITICAS["recursos"].items():
        print(f"  • {nome} (nível mínimo: {dados['nivel_minimo']}, MFA: {dados['requer_mfa']})")

    print("\nDispositivos confiáveis:")
    for d in POLITICAS["dispositivos_confiaveis"]:
        print(f"  • {d}")

    print("\nLocalizações: sede, vpn, remoto, pais_estrangeiro, rede_publica")

    print("\n" + "-"*60)
    usuario     = input("Usuário: ").strip()
    recurso     = input("Recurso: ").strip()
    dispositivo = input("Dispositivo: ").strip()
    localizacao = input("Localização: ").strip()
    try:
        horario = int(input("Horário (0-23): ").strip())
    except ValueError:
        horario = datetime.datetime.now().hour

    solicitacao = SolicitacaoAcesso(usuario, recurso, dispositivo, localizacao, horario)
    pep.solicitar_acesso(solicitacao)


# ══════════════════════════════════════════════════════════
# PONTO DE ENTRADA
# ══════════════════════════════════════════════════════════

def main():
    pdp = PDP()
    pep = PEP(pdp)

    parser = argparse.ArgumentParser(
        description="Zero Trust Simulator — Lab 10 Security+",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--simular",     action="store_true", help="Roda todos os cenários de teste")
    parser.add_argument("--interativo",  action="store_true", help="Cria sua própria solicitação")
    parser.add_argument("--report",      action="store_true", help="Gera relatório HTML")

    args = parser.parse_args()

    if args.simular:
        print("\n🚀 Iniciando simulação Zero Trust — 6 cenários")
        acertos = 0
        for i, cenario in enumerate(CENARIOS, 1):
            print(f"\n📌 Cenário {i}: {cenario['descricao']}")
            decisao = pep.solicitar_acesso(cenario["solicitacao"])
            if decisao["resultado"] == cenario["esperado"]:
                acertos += 1
                print(f"  ✅ Resultado esperado: {cenario['esperado']} — CORRETO")
            else:
                print(f"  ❌ Esperado: {cenario['esperado']} | Obtido: {decisao['resultado']}")

        print(f"\n{'='*60}")
        print(f"📊 Resultado: {acertos}/{len(CENARIOS)} cenários corretos")
        print(f"   Log salvo em: {LOG_FILE}")
        print(f"   Rode agora: python zero_trust.py --report")

    elif args.interativo:
        modo_interativo(pep)
        if pep.log:
            gerar_relatorio(pep.log)

    elif args.report:
        if not os.path.exists(LOG_FILE):
            print("❌ Log não encontrado. Rode primeiro: python zero_trust.py --simular")
            sys.exit(1)
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            log_entries = json.load(f)
        gerar_relatorio(log_entries)

    else:
        print("\n📋 Zero Trust Policy Simulator — Lab 10")
        print("─" * 40)
        print("Uso:")
        print("  python zero_trust.py --simular     → roda 6 cenários de teste")
        print("  python zero_trust.py --interativo  → cria sua própria solicitação")
        print("  python zero_trust.py --report      → gera relatório HTML\n")


if __name__ == "__main__":
    main()
