# Lab 20 — Network Zone Mapper

**Security+ SY0-701 — Domínio 3 — Infraestrutura Segura**

---

## Conceito aplicado

Mapeia a rede local identificando dispositivos por zona de segurança (Trusted, DMZ, Unknown). Detecta portas abertas, calcula a superfície de ataque e gera recomendações de segmentação. Simula o trabalho de um arquiteto de segurança de rede.

---

## O que este lab demonstra

| Conceito Security+ | Como aparece neste lab |
|---|---|
| Security Zones | Classificação automática de hosts em Trusted / DMZ / Unknown |
| Attack Surface | Cálculo baseado em portas abertas e serviços expostos |
| VLANs | Recomendação de segmentação por zona detectada |
| DMZ | Identificação de servidores com serviços públicos expostos |
| Port Management | Varredura e classificação de risco por porta |
| SMB / EternalBlue | Alerta crítico para porta 445 aberta |
| Firewall Rules | Recomendações baseadas em portas detectadas por zona |

---

## Como executar

### Varredura da rede local (detecção automática)
```powershell
python network_zone_mapper.py --scan
start relatorio_zonas.html
```

### Varredura com range específico
```powershell
python network_zone_mapper.py --scan --range 192.168.15 --hosts 30
```

### Regenerar relatório do último scan
```powershell
python network_zone_mapper.py --report
```

---

## Zonas de segurança

| Zona | Critério | Cor |
|---|---|---|
| TRUSTED | Portas internas (SSH, RDP, SMB) ou host local | Verde |
| DMZ | Portas públicas (HTTP, HTTPS, DNS, SMTP) sem portas internas | Amarelo |
| UNKNOWN | Portas abertas não classificadas — investigar | Vermelho |

---

## Estrutura de arquivos

```
lab-20-network-zone-mapper/
├── network_zone_mapper.py    → script principal
├── zone_map_log.json         → log JSON (alimenta Lab 22)
├── relatorio_zonas.html      → relatório visual
└── README.md
```

---

*Luiz Otavio Gonçalves Gilio — github.com/LuizGilio/security-plus-studies*
