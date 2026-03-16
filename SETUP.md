# ⚙️ SETUP — Como Configurar o Token no Windows

## 1. Gere seu token no GitHub
- GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
- Clique em **Generate new token (classic)**
- Marque a permissão: ✅ `repo`
- Copie o token gerado (ele só aparece uma vez!)

## 2. Configure a variável de ambiente no Windows

### Temporária (válida só para a sessão atual do PowerShell):
```powershell
$env:GITHUB_TOKEN="seu_token_aqui"
```

### Permanente (recomendado):
1. Pressione `Win + R` → digite `sysdm.cpl` → Enter
2. Aba **Avançado** → **Variáveis de Ambiente**
3. Em **Variáveis do usuário** → clique em **Novo**
4. Nome: `GITHUB_TOKEN`
5. Valor: `seu_token_aqui`
6. OK → OK → Reinicie o PowerShell

## 3. Uso do script

```powershell
# Upload de mapa mental
python github_upload.py --file mapa.opml --domain 1 --type maps

# Upload de lab
python github_upload.py --file lab_hashing.md --domain 1 --type labs

# Upload de notas
python github_upload.py --file resumo.md --domain 2 --type notes
```

## Domínios disponíveis:
- `1` → General Security Concepts
- `2` → Threats, Vulnerabilities & Mitigations
- `3` → Security Architecture
- `4` → Security Operations
- `5` → Security Program Management

## Tipos disponíveis:
- `notes` → Resumos e anotações
- `labs`  → Laboratórios práticos
- `maps`  → Mapas mentais (.opml)
- `quiz`  → Questões e revisão
