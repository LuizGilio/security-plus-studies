# 🔐 Lab 19 — Security Operations Dashboard — Domínio 2

**Security+ SY0-701 — Domínio 2 — Visão Consolidada SOC**

---

## 📌 Conceito aplicado

Este lab consolida os resultados dos Labs 17 e 18 num painel SOC unificado — simulando o que um analista veria no dia a dia para correlacionar ameaças ativas com vulnerabilidades do ambiente.

---

## 🧠 O que este lab demonstra

| Conceito Security+ | Como aparece no dashboard |
|---|---|
| IOCs | Log completo de todos os eventos dos 5 malwares |
| CIA Triad | Cada malware mapeado ao pilar afetado |
| Hardening Score | Score calculado com base em portas e configurações |
| Correlação de ameaças | IOCs do Lab 17 + vulnerabilidades do Lab 18 juntos |
| Risco Geral | Calculado automaticamente combinando os dois labs |
| Recomendações | Priorizadas por criticidade para remediação |

---

## 🚀 Como executar

### Com dados reais dos Labs 17 e 18
```powershell
python dashboard_d2.py
start security_dashboard_d2.html
```

### Com dados de demonstração
```powershell
python dashboard_d2.py --demo
start security_dashboard_d2.html
```

---

## 📁 Estrutura

```
lab-19-security-dashboard/
├── dashboard_d2.py               → script principal
├── security_dashboard_d2.html    → dashboard gerado
└── README.md
```

---

## 🔗 Referências

- [MITRE ATT&CK](https://attack.mitre.org)
- [CIS Controls](https://www.cisecurity.org/controls)
- [Professor Messer — Security+ SY0-701](https://www.professormesser.com)

---

*Luiz Otavio Gonçalves Gilio — github.com/LuizGilio/security-plus-studies*
