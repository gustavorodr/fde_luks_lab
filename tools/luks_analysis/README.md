# 🔧 Ferramentas LUKS2 - Scripts de Apoio

Este diretório contém scripts auxiliares especializados para análise e ataque de sistemas LUKS2.

## 📁 Estrutura

```
luks_analysis/
├── luks2_framework.py      # Framework principal de análise LUKS2
├── kdf_scanner.py          # Scanner de configurações KDF
├── luks_analyzer.py        # Analisador de metadados LUKS
└── README.md              # Este arquivo
```

## 🚀 Framework Principal: `luks2_framework.py`

### Características

- ✅ **Suporte nativo LUKS2** com parsing JSON de metadados
- ✅ **Análise automática de KDF** (Argon2id vs PBKDF2)
- ✅ **Extração otimizada** de cabeçalhos (16MB para LUKS2)
- ✅ **Compatibilidade múltipla** (Hashcat + John the Ripper)
- ✅ **Avaliação de segurança** e viabilidade de ataque
- ✅ **Geração automática** de wordlists
- ✅ **Relatórios detalhados** em texto

### Uso Básico

```bash
# Análise completa automatizada
sudo python3 luks2_framework.py /dev/sdX

# Com diretório customizado
sudo python3 luks2_framework.py /dev/sdX -o /tmp/luks2_results

# Apenas ataques (pular análise de segurança)
sudo python3 luks2_framework.py /dev/sdX --attack-only
```

### Saída Esperada

```
🔍 === RECONHECIMENTO LUKS2 ===
✅ Dispositivo LUKS confirmado: /dev/sdX
📋 Versão LUKS: 2
🔐 Tipo: ARGON2ID
🛡️  Segurança: HIGH
⚔️  Viabilidade de Ataque: ECONOMICALLY_INFEASIBLE

🟢 ARGON2 DETECTADO - ALTA SEGURANÇA
├─ Memória por tentativa: 1048576 KB
├─ Iterações: 4
├─ Paralelismo: 4
└─ ⚠️  ATAQUE DE FORÇA BRUTA ECONOMICAMENTE INVIÁVEL
```

## 🔍 Scanner KDF: `kdf_scanner.py`

Scanner especializado para identificar configurações de KDF em dispositivos LUKS.

### Recursos

- Detecção automática de versão LUKS
- Análise detalhada de parâmetros Argon2/PBKDF2
- Classificação de segurança
- Recomendações de melhoria

### Uso

```bash
python3 kdf_scanner.py /dev/sdX
python3 kdf_scanner.py --scan-all  # Escanear todos dispositivos
```

## 🔬 Analisador LUKS: `luks_analyzer.py`

Ferramenta de análise profunda de estruturas LUKS.

### Características

- Parse de metadados JSON LUKS2
- Análise de keyslots e algoritmos
- Verificação de integridade
- Exportação de dados estruturados

## 📊 Comparação: Framework vs Comandos Manuais

| Aspecto | Comandos Manuais | luks2_framework.py |
|---------|------------------|-------------------|
| **Suporte LUKS2** | Limitado | ✅ Nativo |
| **Análise KDF** | Manual | ✅ Automática |
| **Múltiplas ferramentas** | Separado | ✅ Integrado |
| **Relatórios** | Não | ✅ Completos |
| **Avaliação segurança** | Não | ✅ Automática |
| **Facilidade uso** | Complexo | ✅ Simples |

## 🎯 Casos de Uso

### 1. Auditoria de Segurança
```bash
# Verificar se sistemas usam Argon2id
sudo python3 luks2_framework.py /dev/sda2 | grep "KDF:"
```

### 2. Teste de Penetração
```bash
# Análise completa com tentativas de quebra
sudo python3 luks2_framework.py /dev/target --attack-only
```

### 3. Forense Digital
```bash
# Extração e análise para investigação
sudo python3 luks2_framework.py /dev/evidence -o /case/luks_analysis
```

### 4. Pesquisa de Segurança
```bash
# Benchmark de diferentes configurações
for device in /dev/sd*; do
    sudo python3 luks2_framework.py $device -o results_$(basename $device)
done
```

## 🛠️ Instalação de Dependências

### Ferramentas Obrigatórias
```bash
# Ubuntu/Debian
sudo apt install cryptsetup python3 python3-json

# Arch Linux
sudo pacman -S cryptsetup python

# CentOS/RHEL
sudo yum install cryptsetup python3
```

### Ferramentas Opcionais (Ataques)
```bash
# Hashcat
sudo apt install hashcat

# John the Ripper
sudo apt install john

# Crunch (geração wordlists)
sudo apt install crunch

# Ferramentas LUKS2 específicas
# luks2hashcat (compilar do source se necessário)
# luks2john (geralmente incluído com John)
```

## ⚠️ Considerações de Segurança

### Uso Ético
- ✅ Use apenas em sistemas próprios
- ✅ Obtenha autorização por escrito
- ✅ Documente todos os testes
- ❌ Nunca use sem permissão

### Limitações Técnicas
- **Argon2id**: Ataques economicamente inviáveis
- **PBKDF2**: Requer recursos GPU significativos
- **Senhas fortes**: Inviáveis independente da KDF

### Recomendações
1. **Foque na educação**: Use para demonstrar importância do Argon2id
2. **Auditoria preventiva**: Identifique sistemas PBKDF2 legados
3. **Testes controlados**: Ambiente isolado para pesquisa

## 📈 Interpretação de Resultados

### Alta Segurança (Argon2id)
```
🛡️  Segurança: HIGH
⚔️  Viabilidade: ECONOMICALLY_INFEASIBLE
💰 Custo: Bilhões USD
```
**Ação**: Sistema adequado, manter configuração

### Segurança Limitada (PBKDF2)
```
🛡️  Segurança: MEDIUM
⚔️  Viabilidade: FEASIBLE_WITH_RESOURCES
💰 Custo: $10K-500K USD
```
**Ação**: Migrar para Argon2id urgentemente

### Senha Encontrada
```
🎉 SENHA ENCONTRADA: password123
```
**Ação**: Recriar volume com senha forte + Argon2id

## 🔗 Links Úteis

- [LUKS2 Specification](https://gitlab.com/cryptsetup/LUKS2-docs)
- [Argon2 RFC 9106](https://tools.ietf.org/rfc/rfc9106.txt)
- [Hashcat LUKS Modes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [John the Ripper LUKS](https://www.openwall.com/john/)

---
*Desenvolvido para o FDE LUKS Lab - Dezembro 2025*