# Lab 22 — Security Architecture Dashboard — Domínio 3

**Security+ SY0-701 — Domínio 3 — Visão Consolidada SOC**

---

## Conceito aplicado

Consolida os resultados dos Labs 20 e 21 num painel SOC unificado — correlacionando riscos de rede com risco de exposição de dados. Demonstra como um analista prioriza remediações cruzando informações de arquitetura e proteção de dados.

---

## O que este lab demonstra

| Conceito Security+ | Como aparece no dashboard |
|---|---|
| Security Zones | Visão consolidada de todos os hosts por zona |
| Attack Surface | Correlação entre portas abertas e dados expostos |
| Data Classification | Arquivos sensíveis lado a lado com a topologia de rede |
| Correlação de riscos | SMB aberto + credenciais em texto claro = risco combinado |
| Least Privilege | Recomendações baseadas nos dados encontrados |
| CIA Triad | Cada correlação mapeada ao pilar afetado |

---

## Como executar

### Com dados reais dos Labs 20 e 21
```powershell
python dashboard_d3.py
start security_dashboard_d3.html
```

### Com dados de demonstração
```powershell
python dashboard_d3.py --demo
start security_dashboard_d3.html
```

---

## Estrutura

```
lab-22-security-dashboard-d3/
├── dashboard_d3.py                  → script principal
├── security_dashboard_d3.html       → dashboard gerado
└── README.md
```

---

*Luiz Otavio Gonçalves Gilio — github.com/LuizGilio/security-plus-studies*
