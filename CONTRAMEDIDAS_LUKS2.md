# 🛡️ Contramedidas e Defesas LUKS2

Este documento apresenta as melhores práticas e contramedidas para proteger sistemas LUKS2 contra ataques de força bruta e outros vetores de comprometimento.

## 📋 Sumário de Contramedidas

| Prioridade | Contramedida | Eficácia | Complexidade |
|------------|--------------|----------|--------------|
| 🔴 **CRÍTICA** | Migrar para Argon2id | ⭐⭐⭐⭐⭐ | Baixa |
| 🔴 **CRÍTICA** | Senhas ≥20 caracteres | ⭐⭐⭐⭐⭐ | Baixa |
| 🟡 **ALTA** | Maximizar parâmetros KDF | ⭐⭐⭐⭐ | Média |
| 🟡 **ALTA** | Keyfiles criptográficos | ⭐⭐⭐⭐⭐ | Média |
| 🟢 **MÉDIA** | Autenticação multifator | ⭐⭐⭐⭐ | Alta |
| 🟢 **MÉDIA** | Monitoramento boot | ⭐⭐⭐ | Alta |

---

## 🔴 Contramedidas Críticas

### 1. Migração para Argon2id

#### Problema
- PBKDF2 vulnerável à aceleração GPU massiva
- Custo de ataque: $10K-500K (viável)
- Milhões de H/s possíveis

#### Solução
```bash
# Verificar KDF atual
cryptsetup luksDump /dev/sdX | grep -A5 "PBKDF"

# Backup de dados (OBRIGATÓRIO)
sudo rsync -avHAXS /source/ /backup/

# Recriar volume com Argon2id
sudo cryptsetup luksFormat /dev/sdX \
    --pbkdf argon2id \
    --pbkdf-memory 2097152 \
    --iter-time 3000

# Verificar configuração
cryptsetup luksDump /dev/sdX --dump-json-metadata | \
    jq '.keyslots[].kdf'
```

#### Resultado
- **Custo de ataque**: $1B-4B (economicamente inviável)
- **Taxa de hash**: Redução de milhões para milhares H/s
- **Proteção**: Contra 99% dos adversários

### 2. Senhas de Alta Entropia

#### Problema
- Senhas humanas previsíveis
- Vulneráveis a ataques de dicionário
- Padrões linguísticos exploráveis

#### Soluções

##### A. Senhas Verdadeiramente Aleatórias
```bash
# Gerar senha de 24 caracteres
openssl rand -base64 32 | cut -c1-24

# Alternativa com caracteres especiais
tr -dc 'A-Za-z0-9!@#$%^&*()_+' < /dev/urandom | head -c 24
```

##### B. Passphrases com Diceware
```bash
# Método manual com dados
# 1. Baixar lista Diceware
wget https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt

# 2. Gerar números aleatórios (6 palavras)
for i in {1..6}; do 
    echo $((RANDOM % 7776 + 11111))
done

# 3. Mapear para palavras da lista
# Resultado: "correct horse battery staple monkey wrench"
```

##### C. Senhas Baseadas em Entropy Pools
```bash
# Usar /dev/urandom com filtros
head /dev/urandom | tr -dc A-Za-z0-9 | head -c 20
```

#### Validação de Entropia
```python
#!/usr/bin/env python3
import math
from collections import Counter

def calculate_entropy(password):
    """Calcula entropia de Shannon da senha"""
    char_freq = Counter(password)
    password_len = len(password)
    
    entropy = 0
    for count in char_freq.values():
        probability = count / password_len
        entropy -= probability * math.log2(probability)
    
    total_entropy = entropy * password_len
    return total_entropy

# Exemplo de uso
password = "MinhaSenh@Segura123!"
entropy = calculate_entropy(password)
print(f"Entropia: {entropy:.2f} bits")

# Meta: >80 bits para alta segurança
if entropy > 80:
    print("✅ Senha com alta entropia")
else:
    print("❌ Aumentar entropia da senha")
```

---

## 🟡 Contramedidas de Alta Prioridade

### 3. Maximização dos Parâmetros KDF

#### Configuração Otimizada

```bash
# Configuração agressiva para Argon2id
cryptsetup luksFormat /dev/sdX \
    --pbkdf argon2id \
    --pbkdf-memory 4194304 \    # 4 GiB (aumentar conforme RAM)
    --pbkdf-parallel 8 \        # Threads (cores CPU)
    --iter-time 5000           # 5 segundos

# Para sistemas com muita RAM (32GB+)
cryptsetup luksFormat /dev/sdX \
    --pbkdf argon2id \
    --pbkdf-memory 8388608 \    # 8 GiB
    --pbkdf-parallel 16 \
    --iter-time 10000          # 10 segundos
```

#### Script de Teste de Performance

```bash
#!/bin/bash
# benchmark_kdf.sh - Teste de parâmetros KDF

echo "🧪 Testando configurações KDF..."

# Criar dispositivo loop temporário
dd if=/dev/zero of=/tmp/test_luks.img bs=1M count=100
LOOP_DEV=$(losetup --find --show /tmp/test_luks.img)

# Testar diferentes configurações
configs=(
    "1048576 4 2000"    # 1GB, 4t, 2s
    "2097152 4 3000"    # 2GB, 4t, 3s  
    "4194304 8 5000"    # 4GB, 8t, 5s
)

for config in "${configs[@]}"; do
    read memory parallel time <<< "$config"
    
    echo "Testando: ${memory}KB, ${parallel}t, ${time}ms"
    
    time cryptsetup luksFormat "$LOOP_DEV" \
        --pbkdf argon2id \
        --pbkdf-memory "$memory" \
        --pbkdf-parallel "$parallel" \
        --iter-time "$time" \
        --batch-mode \
        --key-file <(echo "testpassword")
done

# Limpeza
losetup -d "$LOOP_DEV"
rm /tmp/test_luks.img
```

### 4. Keyfiles Criptográficos

#### Vantagens dos Keyfiles
- **Entropia máxima**: 4096 bytes = 32.768 bits
- **Elimina dicionário**: Impossível adivinhar
- **Não digitável**: Imune a keyloggers básicos

#### Implementação Segura

```bash
# 1. Gerar keyfile de alta entropia
dd if=/dev/urandom of=/secure/luks.keyfile bs=4096 count=1

# 2. Verificar qualidade
hexdump -C /secure/luks.keyfile | head -5

# 3. Proteger keyfile
chmod 600 /secure/luks.keyfile
chown root:root /secure/luks.keyfile

# 4. Adicionar ao LUKS
cryptsetup luksAddKey /dev/sdX /secure/luks.keyfile

# 5. Testar desbloqueio
cryptsetup luksOpen /dev/sdX encrypted_vol \
    --key-file /secure/luks.keyfile

# 6. Configurar automação (crypttab)
echo "encrypted_vol /dev/sdX /secure/luks.keyfile luks" >> /etc/crypttab
```

#### Armazenamento Seguro de Keyfiles

##### Opção 1: USB Separado
```bash
# Montar USB criptografado
cryptsetup luksOpen /dev/sdb1 usb_keys
mount /dev/mapper/usb_keys /mnt/keys

# Copiar keyfile
cp /secure/luks.keyfile /mnt/keys/system.key

# Configurar para montar automaticamente
echo "/dev/sdb1 /mnt/keys ext4 defaults,noauto 0 0" >> /etc/fstab
```

##### Opção 2: TPM 2.0 (Sistemas Modernos)
```bash
# Selar keyfile no TPM
tpm2_createprimary -C e -g sha256 -G rsa -c primary.ctx
tpm2_create -g sha256 -G keyedhash -u key.pub -r key.priv \
    -C primary.ctx -L policy.dat -i /secure/luks.keyfile

# Script de desbloqueio automático
#!/bin/bash
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
tmp2_unseal -c key.ctx -p pcr:sha256:0,1,2,3 | \
    cryptsetup luksOpen /dev/sdX encrypted_vol --key-file -
```

---

## 🟢 Contramedidas Avançadas

### 5. Autenticação Multifator

#### FIDO2/WebAuthn Integration

```bash
# Instalar suporte FIDO2
sudo apt install libfido2-dev fido2-tools

# Enrolar chave FIDO2
systemd-cryptenroll /dev/sdX --fido2-device=auto

# Verificar
systemd-cryptenroll /dev/sdX

# Boot automático com FIDO2
echo "encrypted_vol /dev/sdX - fido2-device=auto" >> /etc/crypttab
```

#### Yubikey Integration

```bash
# Configurar Yubikey como keyfile
ykpersonalize -2 -ochal-resp -ochal-hmac -ohmac-lt64 -oserial-api-visible

# Gerar challenge-response
ykchalresp -2 "challenge_string" > yubikey.response

# Usar como keyfile
cryptsetup luksAddKey /dev/sdX yubikey.response
```

### 6. Detecção de Ataques Evil Maid

#### Monitoramento de Integridade Boot

```bash
# 1. Script de verificação de integridade
#!/bin/bash
# check_boot_integrity.sh

BOOT_PATH="/boot"
HASH_FILE="/root/.boot_hashes"

echo "🔍 Verificando integridade do /boot..."

# Primeira execução: criar baseline
if [[ ! -f "$HASH_FILE" ]]; then
    echo "📝 Criando baseline de integridade..."
    find "$BOOT_PATH" -type f -exec sha256sum {} \; > "$HASH_FILE"
    echo "✅ Baseline criado: $HASH_FILE"
    exit 0
fi

# Verificação de mudanças
TEMP_HASH="/tmp/boot_check_$$"
find "$BOOT_PATH" -type f -exec sha256sum {} \; > "$TEMP_HASH"

if ! diff -q "$HASH_FILE" "$TEMP_HASH" > /dev/null; then
    echo "🚨 ALERTA: Arquivos alterados em /boot!"
    echo "Diferenças encontradas:"
    diff "$HASH_FILE" "$TEMP_HASH"
    
    # Log de segurança
    logger -p auth.warn "BOOT_INTEGRITY: Alterações detectadas em /boot"
    
    # Notificar administrador
    echo "ALERTA: Boot comprometido em $(hostname)" | \
        mail -s "SECURITY ALERT" admin@company.com
    
    exit 1
else
    echo "✅ Integridade do /boot verificada"
fi

rm "$TEMP_HASH"
```

#### Secure Boot com MOK (Machine Owner Key)

```bash
#!/bin/bash
# setup_secure_boot.sh - Configuração Secure Boot

echo "🔒 Configurando Secure Boot com MOK..."

# 1. Instalar ferramentas
sudo apt install mokutil shim-signed sbsigntool

# 2. Gerar chaves próprias
openssl req -new -x509 -newkey rsa:2048 \
    -keyout /etc/ssl/MOK.key \
    -out /etc/ssl/MOK.crt \
    -nodes -days 3650 \
    -subj "/CN=$(hostname) Secure Boot Key/"

# 3. Assinar kernel atual
sbsign --key /etc/ssl/MOK.key \
       --cert /etc/ssl/MOK.crt \
       /boot/vmlinuz-$(uname -r) \
       --output /boot/vmlinuz-$(uname -r).signed

# 4. Configurar GRUB para kernel assinado
cat >> /etc/grub.d/40_custom << EOF
menuentry 'Ubuntu Signed Kernel' {
    linux /vmlinuz-$(uname -r).signed root=UUID=$(findmnt -n -o UUID /) ro
    initrd /initrd.img-$(uname -r)
}
EOF

update-grub

# 5. Enrolar chave no firmware
mokutil --import /etc/ssl/MOK.crt

echo "✅ Secure Boot configurado!"
echo "🔄 REINICIE e enrole a chave no menu MOK"
echo "📋 Após reiniciar:"
echo "   mokutil --list-enrolled"
echo "   mokutil --test-key /etc/ssl/MOK.crt"
```

### 7. Proteção Contra Cold Boot Attacks

#### Configurações de Kernel

```bash
# /etc/sysctl.d/99-security.conf
# Limpar memória na inicialização
kernel.kptr_restrict=2
kernel.dmesg_restrict=1

# Desabilitar hibernação (protege chaves na RAM)
kernel.hibernate_disabled=1

# Configuração GRUB
# /etc/default/grub
GRUB_CMDLINE_LINUX="page_poison=1 slub_debug=P zero_on_free=1"
```

#### Script de Limpeza de Memória

```bash
#!/bin/bash
# memory_cleanup.sh - Limpeza segura de memória

echo "🧹 Iniciando limpeza segura de memória..."

# 1. Dropar caches
echo 3 > /proc/sys/vm/drop_caches
sync

# 2. Forçar compactação de memória
echo 1 > /proc/sys/vm/compact_memory

# 3. Limpar buffers de rede
ip route flush cache

# 4. Zerar swap (se seguro)
swapoff -a
swapon -a

echo "✅ Limpeza de memória concluída"
```

---

## 📊 Matriz de Eficácia das Contramedidas

### Contra Força Bruta

| Contramedida | vs PBKDF2 | vs Argon2id | Custo Impl. |
|--------------|-----------|-------------|-------------|
| Argon2id | ⭐⭐⭐⭐⭐ | N/A | Baixo |
| Senha 20+ chars | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Baixo |
| Keyfiles | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Médio |
| Parâmetros altos | ⭐⭐ | ⭐⭐⭐ | Baixo |

### Contra Outros Vetores

| Vetor | Contramedida Principal | Eficácia |
|-------|------------------------|----------|
| **Evil Maid** | Secure Boot + MOK | ⭐⭐⭐⭐ |
| **Cold Boot** | Configuração kernel | ⭐⭐⭐ |
| **Keylogger** | Keyfiles + FIDO2 | ⭐⭐⭐⭐⭐ |
| **Physical** | TPM + Monitoramento | ⭐⭐⭐ |

---

## 🎯 Plano de Implementação Recomendado

### Fase 1: Mitigações Críticas (1-2 semanas)

```bash
# Semana 1: Auditoria atual
./luks2_framework.py /dev/sdX > audit_report.txt

# Semana 2: Migração Argon2id
# 1. Backup completo
# 2. Recriar volumes com Argon2id
# 3. Validar migração
```

### Fase 2: Fortalecimento (2-4 semanas)

```bash
# Semanas 3-4: Implementar keyfiles
# 1. Gerar keyfiles seguros
# 2. Configurar armazenamento
# 3. Testar recuperação

# Semanas 5-6: Monitoramento
# 1. Scripts de integridade
# 2. Alertas automáticos
# 3. Procedimentos resposta
```

### Fase 3: Proteções Avançadas (1-2 meses)

```bash
# Mês 2: Secure Boot + TPM
# 1. Configurar Secure Boot
# 2. Integrar TPM 2.0
# 3. Autenticação multifator
```

---

## 📋 Checklist de Implementação

### ✅ Configuração Base
- [ ] LUKS2 com Argon2id verificado
- [ ] Senhas ≥20 caracteres implementadas
- [ ] Parâmetros KDF maximizados
- [ ] Backup seguro dos cabeçalhos LUKS

### ✅ Proteções Adicionais
- [ ] Keyfiles gerados e testados
- [ ] TPM 2.0 configurado (se disponível)
- [ ] FIDO2/WebAuthn implementado
- [ ] Secure Boot ativado

### ✅ Monitoramento
- [ ] Script verificação integridade /boot
- [ ] Alertas automáticos configurados
- [ ] Logs de auditoria ativados
- [ ] Procedimentos resposta documentados

### ✅ Documentação
- [ ] Procedimentos recuperação
- [ ] Contacts emergência
- [ ] Configurações backup
- [ ] Plano atualização regular

---

## 🚨 Procedimentos de Emergência

### Suspeita de Comprometimento

```bash
# 1. Isolamento imediato
systemctl isolate rescue.target

# 2. Análise forense
dd if=/dev/sdX of=/investigation/disk_image.dd bs=4M
./luks2_framework.py /dev/sdX -o /investigation/luks_analysis

# 3. Verificação integridade
./check_boot_integrity.sh
mokutil --list-enrolled

# 4. Recriar sistema se confirmado
# - Backup de dados
# - Format + reinstalação
# - Restauração dados verificados
```

### Recuperação de Keyfiles

```bash
# Se keyfile perdido mas senha conhecida
cryptsetup luksChangeKey /dev/sdX --key-slot 0
# Inserir senha atual e nova senha/keyfile
```

---

*Este documento deve ser atualizado regularmente conforme novas ameaças e contramedidas são descobertas.*