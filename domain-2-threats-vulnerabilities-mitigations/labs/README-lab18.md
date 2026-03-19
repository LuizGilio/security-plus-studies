# 🔐 Lab 18 — Network Hardening Auditor

**Security+ SY0-701 — Domínio 2 — Mitigações e Hardening**

---

## 📌 Conceito aplicado

Este lab audita o próprio sistema simulando o trabalho de um analista de segurança — verificando portas abertas, protocolos inseguros e configurações do SO, calculando um **score de hardening de 0 a 100** com recomendações priorizadas.

> Hardening = reduzir a superfície de ataque. Cada porta aberta, configuração padrão não alterada ou serviço desnecessário é uma oportunidade para o atacante.

---

## 🧠 O que este lab demonstra

| Conceito Security+ | Como aparece neste lab |
|---|---|
| Hardening | Score calculado com base em portas e configurações |
| Port Management | Varredura de 23 portas conhecidas com classificação de risco |
| Senhas Padrão | Lista de credenciais padrão por tipo de serviço |
| Least Privilege | Verificação de UAC e conta Guest |
| Host Firewall | Verificação de Windows Defender Firewall |
| Patching | Verificação de atualizações automáticas |
| EDR | Verificação de Windows Defender ativo |
| ACLs | Recomendações de controle por porta e serviço |

---

## 🚀 Como executar

### Passo 1 — Auditoria completa
```powershell
python hardening_auditor.py --audit
```

### Passo 2 — Ver relatório visual
```powershell
start relatorio_hardening.html
```

### Passo 3 — Só verificar portas (rápido)
```powershell
python hardening_auditor.py --ports
```

---

## 🎯 Portas verificadas e seus riscos

| Porta | Serviço | Risco | Por quê |
|---|---|---|---|
| 23 | Telnet | CRÍTICO | Transmite em texto claro — substituir por SSH |
| 445 | SMB | CRÍTICO | Vetor do WannaCry via EternalBlue |
| 6379 | Redis | CRÍTICO | Frequentemente sem autenticação |
| 27017 | MongoDB | CRÍTICO | Frequentemente sem autenticação |
| 3389 | RDP | ALTO | Alvo de brute force constante |
| 21 | FTP | ALTO | Protocolo sem criptografia |
| 3306 | MySQL | ALTO | Banco de dados nunca deve estar exposto |

---

## 📁 Estrutura de arquivos

```
lab-18-hardening-auditor/
├── hardening_auditor.py      → script principal
├── hardening_log.json        → log JSON (alimenta o Lab 19)
├── relatorio_hardening.html  → relatório visual
└── README.md
```

---

## 🔗 Referências

- [CIS Benchmarks — Hardening Guides](https://www.cisecurity.org/cis-benchmarks)
- [NIST SP 800-123 — Guide to Server Security](https://csrc.nist.gov)
- [Professor Messer — Security+ SY0-701](https://www.professormesser.com)

---

*Luiz Otavio Gonçalves Gilio — github.com/LuizGilio/security-plus-studies*
