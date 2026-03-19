# 🔐 Lab 17 — Malware Behavior Simulator

**Security+ SY0-701 — Domínio 2 — Malware, Ataques e IOCs**

---

## 📌 Conceito aplicado

Este lab simula o **comportamento** de 5 tipos de malware de forma segura e controlada — sem executar código malicioso real. Cada simulação gera **IOCs reais** que um analista SOC precisaria identificar e classificar.

> Nenhum código malicioso real é executado. Tudo acontece de forma controlada em uma pasta de simulação local.

---

## 🧠 O que este lab demonstra

| Malware | Comportamento Simulado | IOC Gerado | CIA Triad |
|---|---|---|---|
| Vírus | Modifica arquivos + tenta replicação | Hash alterado | Integridade |
| Ransomware | Criptografa arquivos + nota de resgate | Arquivo indisponível | Disponibilidade |
| Worm | Varre rede + tenta propagação via SMB | Tráfego de rede incomum | Disponibilidade |
| Keylogger | Captura credenciais + exfiltra para C2 | Dados enviados externamente | Confidencialidade |
| Logic Bomb | Avalia gatilhos + executa payload | Malware dormente ativado | Todos |

---

## 🚀 Como executar

### Simular todos os malwares de uma vez
```powershell
python malware_simulator.py --all
```

### Simular individualmente
```powershell
python malware_simulator.py --virus
python malware_simulator.py --ransomware
python malware_simulator.py --worm
python malware_simulator.py --keylogger
python malware_simulator.py --logicbomb
```

### Gerar relatório visual
```powershell
python malware_simulator.py --report
start relatorio_malware.html
```

### Limpar arquivos de simulação
```powershell
python malware_simulator.py --cleanup
```

---

## 📁 Estrutura de arquivos

```
lab-17-malware-behavior-simulator/
├── malware_simulator.py          → script principal
├── malware_iocs.json             → log de IOCs (alimenta o Lab 19)
├── relatorio_malware.html        → relatório visual
├── simulacao/
│   ├── infectados/               → arquivos modificados pelo vírus
│   ├── ransomware_target/        → arquivos "criptografados"
│   └── keylog_captured.txt       → captura simulada do keylogger
└── README.md
```

---

## 🔗 Referências

- [MITRE ATT&CK — Malware Behaviors](https://attack.mitre.org)
- [Professor Messer — Security+ SY0-701](https://www.professormesser.com)
- [CVE — WannaCry EternalBlue MS17-010](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144)

---

*Luiz Otavio Gonçalves Gilio — github.com/LuizGilio/security-plus-studies*
