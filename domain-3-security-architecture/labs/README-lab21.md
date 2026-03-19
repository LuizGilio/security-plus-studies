# Lab 21 — Data Classification & Protection Auditor

**Security+ SY0-701 — Domínio 3 — Proteção de Dados**

---

## Conceito aplicado

Varre o sistema em busca de arquivos que contêm dados sensíveis — PII, PHI e dados financeiros. Classifica por nível de sensibilidade, calcula risco de exposição e gera recomendações priorizadas. Simula o trabalho de um analista de privacidade e compliance.

---

## O que este lab demonstra

| Conceito Security+ | Como aparece neste lab |
|---|---|
| PII | Detecção de CPF, email, telefone em arquivos |
| PHI | Detecção de dados de saúde e registros médicos |
| Data at Rest | Varredura de arquivos armazenados em disco |
| Data Classification | Classificação por CRITICAL / HIGH / MEDIUM / LOW |
| Credenciais em plain text | Detecção de senhas e API keys em texto claro |
| PCI DSS | Detecção de números de cartão de crédito |
| Least Privilege | Recomendações de controle de acesso por arquivo |
| Tokenização | Recomendação de tokenizar dados financeiros |

---

## Como executar

### Modo demonstração (recomendado para começar)
```powershell
python data_classification_auditor.py --demo
start relatorio_classificacao.html
```

### Varrer um diretório específico
```powershell
python data_classification_auditor.py --scan .
python data_classification_auditor.py --scan C:\Users\Win\Documents
start relatorio_classificacao.html
```

### Regenerar relatório do último scan
```powershell
python data_classification_auditor.py --report
```

---

## Padrões detectados

| Padrão | Categoria | Severidade |
|---|---|---|
| CPF | PII | CRITICAL |
| Email | PII | HIGH |
| Telefone BR | PII | HIGH |
| Endereço IP | PII | MEDIUM |
| CRM Médico | PHI | CRITICAL |
| Termos médicos | PHI | CRITICAL |
| Cartão de crédito | Financial | CRITICAL |
| Dados bancários | Financial | CRITICAL |
| Senha em plain text | Credentials | CRITICAL |
| API Key / Token | Credentials | CRITICAL |

---

## Estrutura de arquivos

```
lab-21-data-classification-auditor/
├── data_classification_auditor.py   → script principal
├── classification_log.json          → log JSON (alimenta Lab 22)
├── relatorio_classificacao.html     → relatório visual
├── demo_files/                      → arquivos criados pelo --demo
└── README.md
```

---

*Luiz Otavio Gonçalves Gilio — github.com/LuizGilio/security-plus-studies*
