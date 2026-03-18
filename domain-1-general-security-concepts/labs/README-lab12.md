# 🔐 Lab 12 — Security Dashboard

**Security+ SY0-701 — Domínio 1 — Visão Consolidada de Segurança**

---

## 📌 Conceito aplicado

Este lab consolida os resultados dos Labs 05 e 10 num painel unificado — simulando o que um analista SOC veria no dia a dia para monitorar integridade de arquivos e controle de acesso.

---

## 🧠 O que este lab demonstra

| Conceito Security+ | Como aparece no dashboard |
|---|---|
| CIA Triad — Integridade | Status do FIM com alertas de alteração |
| CIA Triad — Disponibilidade | Monitoramento contínuo do ambiente |
| Zero Trust — PEP/PDP | Log de decisões com motivos detalhados |
| AAA — Accounting | Registro completo de todos os acessos |
| Controle Detetivo | Alertas visuais de eventos anômalos |
| Gestão de Risco | Cálculo de risco geral do ambiente |

---

## 🚀 Como executar

### Com logs reais dos Labs 05 e 10
```powershell
python dashboard.py
start security_dashboard.html
```

### Com dados de demonstração
```powershell
python dashboard.py --demo
start security_dashboard.html
```

---

## 📁 Estrutura

```
lab-12-security-dashboard/
├── dashboard.py              → script principal
├── security_dashboard.html   → dashboard gerado
└── README.md
```

---

## 🔗 Referências

- [NIST SP 800-207 — Zero Trust](https://csrc.nist.gov)
- [Professor Messer — Security+ SY0-701](https://www.professormesser.com)

---

*Luiz Otavio Gonçalves Gilio — github.com/LuizGilio/security-plus-studies*
