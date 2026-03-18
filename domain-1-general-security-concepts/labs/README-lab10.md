# 🔐 Lab 10 — Zero Trust Policy Simulator

**Security+ SY0-701 — Domínio 1 — Zero Trust: PEP, PDP, AAA**

---

## 📌 Conceito aplicado

Este lab simula o processo de decisão de um sistema **Zero Trust** completo.

Toda solicitação de acesso passa pelo **PEP** (Ponto de Imposição de Política), que consulta o **PDP** (Ponto de Decisão de Política). O PDP avalia 6 fatores de contexto antes de decidir — e o PEP aplica a decisão sem questionar.

> **Princípio:** "Nunca confiar, sempre verificar" — independente de quem você é ou de onde você está.

---

## 🧠 O que este lab demonstra

| Conceito Security+ | Como aparece neste lab |
|---|---|
| Zero Trust — PEP | Classe `PEP` intercepta e aplica todas as decisões |
| Zero Trust — PDP | Classe `PDP` avalia contexto e decide o acesso |
| Identidade Adaptativa | Avalia: usuário + dispositivo + local + horário |
| AAA — Autenticação | Verificação de identidade e MFA |
| AAA — Autorização | Nível mínimo exigido pelo recurso |
| AAA — Accounting | Log JSON com timestamp de cada decisão |
| Controle Preventivo Técnico | Bloqueia acesso não autorizado antes de conceder |

---

## ⚙️ Pré-requisitos

- Python 3.8 ou superior
- Sem dependências externas

---

## 🚀 Como executar

### Passo 1 — Rodar os 6 cenários de teste
```powershell
python zero_trust.py --simular
```

### Passo 2 — Gerar relatório visual
```powershell
python zero_trust.py --report
start relatorio_zero_trust.html
```

### Passo 3 — Modo interativo (crie sua própria solicitação)
```powershell
python zero_trust.py --interativo
```

---

## 🎯 Os 6 Cenários Simulados

| # | Cenário | Resultado Esperado |
|---|---------|-------------------|
| 1 | Analista com MFA, dispositivo corporativo, sede, horário comercial | ✅ PERMITIDO |
| 2 | Visitante externo tentando acessar banco de dados financeiro | 🚫 NEGADO |
| 3 | Usuário sem MFA tentando acessar servidor de produção | 🚫 NEGADO |
| 4 | Acesso legítimo fora do horário permitido (2h da manhã) | 🚫 NEGADO |
| 5 | Usuário desconhecido de país estrangeiro | 🚫 NEGADO |
| 6 | Analista acessando intranet de localização remota | ✅ PERMITIDO |

---

## 📁 Estrutura de arquivos

```
lab-10-zero-trust-simulator/
├── zero_trust.py                → script principal (PEP + PDP + Políticas)
├── zt_log.json                  → log de decisões em JSON (criado ao simular)
├── relatorio_zero_trust.html    → relatório visual (criado ao rodar --report)
└── README.md
```

---

## 🔍 Entendendo o código

| Classe/Função | O que faz |
|---|---|
| `POLITICAS` | Dicionário com usuários, recursos, dispositivos e locais permitidos |
| `SolicitacaoAcesso` | Representa uma tentativa de acesso com todos os atributos de contexto |
| `PEP` | Intercepta solicitações, consulta o PDP e registra no log (Accounting) |
| `PDP.avaliar()` | Avalia 6 fatores e calcula o nível de risco da solicitação |
| `gerar_relatorio()` | Produz relatório HTML com todas as decisões |
| `modo_interativo()` | Permite criar solicitações personalizadas no terminal |

---

## 🔗 Referências

- [NIST SP 800-207 — Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [Professor Messer — Security+ SY0-701](https://www.professormesser.com)
- [CISA — Zero Trust Maturity Model](https://www.cisa.gov/zero-trust-maturity-model)

---

*Luiz Otavio Gonçalves Gilio — github.com/LuizGilio/security-plus-studies*
