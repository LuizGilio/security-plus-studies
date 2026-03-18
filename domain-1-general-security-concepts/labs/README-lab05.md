# 🔐 Lab 05 — File Integrity Monitor (FIM)

**Security+ SY0-701 — Domínio 1 — CIA Triad: Integridade**

---

## 📌 Conceito aplicado

Este lab implementa o princípio de **Integridade** do CIA Triad na prática.

Um File Integrity Monitor gera um hash SHA-256 de cada arquivo monitorado e compara periodicamente com uma linha de base (baseline). Se qualquer arquivo for alterado — mesmo que seja 1 único caractere — o hash muda completamente, gerando um alerta imediato.

> Ferramentas profissionais como **Tripwire**, **OSSEC** e **Wazuh** usam exatamente este princípio em ambientes corporativos.

---

## 🧠 O que este lab demonstra

| Conceito Security+ | Como aparece neste lab |
|---|---|
| CIA Triad — Integridade | Hash SHA-256 detecta qualquer alteração |
| Controle Detetivo | Alerta gerado após alteração detectada |
| Baseline | Linha de base criada na primeira execução |
| Hashing | SHA-256 aplicado a arquivos reais |
| Não-Repúdio | Log com timestamp de cada evento |

---

## ⚙️ Pré-requisitos

- Python 3.8 ou superior
- Sem dependências externas — usa apenas bibliotecas padrão do Python

---

## 🚀 Como executar

### Passo 1 — Criar a baseline
```powershell
python fim.py --baseline
```
Isso cria a "foto" inicial dos arquivos monitorados. O resultado é salvo em `baseline.json`.

### Passo 2 — Simular uma alteração
Abra qualquer arquivo dentro da pasta `arquivos_monitorados` e modifique algo — uma letra, um número, qualquer coisa.

### Passo 3 — Verificar a integridade
```powershell
python fim.py --check
```
O FIM compara o estado atual com a baseline e exibe o que mudou.

### Passo 4 — Gerar relatório visual
```powershell
python fim.py --report
```
Abre o arquivo `relatorio_fim.html` no navegador para ver o resultado completo.

---

## 📁 Estrutura de arquivos

```
lab-05-file-integrity-monitor/
├── fim.py                    → script principal
├── baseline.json             → linha de base gerada (criado ao rodar --baseline)
├── fim_log.txt               → log de todos os eventos (criado automaticamente)
├── relatorio_fim.html        → relatório visual (criado ao rodar --report)
├── arquivos_monitorados/     → pasta com arquivos sendo monitorados
│   ├── config_sistema.txt
│   ├── politica_acesso.txt
│   └── chaves_api.txt
└── README.md
```

---

## 🔍 Entendendo o código

O `fim.py` tem 4 funções principais — cada uma faz uma coisa específica:

| Função | O que faz |
|---|---|
| `calcular_hash()` | Lê o arquivo em blocos e gera o hash SHA-256 |
| `escanear_diretorio()` | Percorre todos os arquivos e retorna `{arquivo: hash}` |
| `criar_baseline()` | Salva o estado atual como linha de base em JSON |
| `verificar_integridade()` | Compara estado atual com baseline e lista divergências |
| `gerar_relatorio()` | Produz relatório HTML com os resultados |

---

## 📸 Resultado esperado

Após rodar `--baseline` e modificar um arquivo:

```
[2025-03-17 14:32:10] VERIFICAÇÃO DE INTEGRIDADE INICIADA
[2025-03-17 14:32:10] 🚨 ALERTA — 1 problema(s) detectado(s)!
[2025-03-17 14:32:10]   ⚠️  ALTERADO: config_sistema.txt
[2025-03-17 14:32:10]        Hash original: a3f5c2d1e8b4...
[2025-03-17 14:32:10]        Hash atual:    9d2e7f1a4c8b...
```

---

## 🔗 Referências

- [NIST — File Integrity Monitoring](https://csrc.nist.gov)
- [Tripwire — FIM comercial](https://www.tripwire.com)
- [OSSEC — FIM open source](https://www.ossec.net)
- [Professor Messer — Security+ SY0-701](https://www.professormesser.com)

---

*Luiz Otavio Gonçalves Gilio — github.com/LuizGilio/security-plus-studies*
