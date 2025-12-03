# Análise Forense da Viabilidade de Ataque de Força Bruta Contra Partições LUKS2

## Sumário Executivo

Este relatório apresenta uma análise detalhada da viabilidade de ataques de força bruta contra partições LUKS2, focando nos aspectos forenses e criptográficos que determinam o sucesso ou fracasso de tais ataques. A segurança do LUKS2 é fundamentalmente determinada pela Função de Derivação de Chave (KDF) utilizada.

### Principais Conclusões:
- **Argon2id**: Resistente a ataques massivos por GPU devido ao alto custo de memória (≥1 GiB por thread)
- **PBKDF2**: Vulnerável à paralelização por GPU, permitindo milhões de H/s
- **Custo de ataque contra Argon2id**: Bilhões de dólares para senhas de média entropia (12+ caracteres)
- **Recomendação**: Uso exclusivo do Argon2id com parâmetros de memória maximizados

---

## I. Fundamentos Criptográficos do LUKS2 e Definição do Vetor de Ataque

O ataque de força bruta contra dispositivos de armazenamento criptografados é uma tática de tentativa e erro, frequentemente auxiliada por software, buscando quebrar senhas ou chaves de criptografia. No contexto do Linux Unified Key Setup (LUKS), a viabilidade de tal ataque é definida, quase inteiramente, pela arquitetura de gerenciamento de chaves e, crucialmente, pela Função de Derivação de Chave (KDF) utilizada.

### I.A. Arquitetura LUKS (Linux Unified Key Setup)

LUKS é uma especificação de criptografia de disco robusta, implementada por meio do subsistema device mapper do kernel Linux (dm-crypt), que assegura um formato on-disk padrão e interoperável. A segurança do sistema reside em uma arquitetura de múltiplas camadas.

#### Chave Mestra (MK) e Criptografia de Dados

A criptografia a granel do dispositivo de bloco (partição ou disco inteiro) é realizada usando uma **Chave Mestra (MK)**. Esta MK é geralmente protegida por cifras robustas como AES-XTS-plain64, frequentemente configurada com um tamanho de chave de 512 bits.

> **Nota de Segurança**: A quebra direta da MK via força bruta é inviável; a complexidade de quebrar uma chave de 256 bits é estimada em custos que excedem o Produto Mundial Bruto (GWP) por ordens de magnitude astronômicas, requerendo cerca de $10^{44}$ vezes o GWP.

#### Gerenciamento de Chaves do Usuário

Em vez de atacar a chave mestra, o vetor de ataque visa o **gerenciamento de chaves do usuário**. O LUKS mantém um cabeçalho não criptografado que armazena:

- **Metadados**: Tipo de cifra, tamanho da chave, algoritmos utilizados
- **Keyslots**: O LUKS2 suporta até 32 keyslots, permitindo múltiplas formas de autenticação:
  - Senhas (passphrases)
  - Keyfiles (arquivos de chave)
  - Dispositivos de segurança (FIDO2/TPM)

#### Processo de Ataque

O ataque de força bruta segue esta sequência:

1. **Descobrir a passphrase** do usuário
2. **Transformar** a passphrase em chave de usuário via KDF
3. **Descriptografar** o keyslot correspondente
4. **Revelar** a Chave Mestra (MK) subjacente

> ⚠️ **Ponto Crítico**: A descoberta de qualquer passphrase válida em qualquer keyslot é suficiente para comprometer todo o volume criptografado.

### I.B. Esclarecimento Crítico sobre KDFs Suportadas

As implementações modernas do LUKS2 suportam duas KDFs principais:

| KDF | Tipo | Uso Recomendado | Resistência GPU |
|-----|------|-----------------|-----------------|
| **Argon2i/Argon2id** | Memory-hard | Padrão LUKS2 (cryptsetup ≥2.1) | **Alta** |
| **PBKDF2** | Time-based | Legado/Compatibilidade | **Baixa** |

A segurança de um volume LUKS2 contra força bruta depende **diretamente** da escolha e configuração dessas KDFs.

---

## II. Metodologia de Pré-Ataque: Extração e Preparação do Hash

Um ataque de força bruta contra o LUKS2 é, por definição, um **ataque offline**. O atacante deve primeiro obter o material criptográfico essencial—o cabeçalho LUKS—para poder testar senhas sem interagir com o sistema operacional criptografado.

### II.A. Acesso Físico e Exigências de Dados

**Pré-requisito absoluto**: Acesso físico e irrestrito ao dispositivo de bloco alvo.

- O atacante deve ser capaz de ler o disco em nível de bloco
- Alvo específico: cabeçalho LUKS2 + metadados + keyslots
- Conteúdo: Chave Mestra criptografada

### II.B. Extração Forense do Cabeçalho LUKS2

#### Limitações do Backup Simples

Para realizar o ataque offline, é **insuficiente** apenas ter uma cópia de backup do cabeçalho (obtida via `cryptsetup luksHeaderBackup`). As ferramentas de cracking de alto desempenho exigem:

- Cabeçalho LUKS2 completo
- **Primeiro setor do payload** (área de dados criptografados)

#### Comando de Extração Forense

```bash
# Extração padrão: ~2 MiB de dados
dd if=/dev/sdb3 of=header.raw bs=512 count=4097

# Alternativa com cryptsetup
cryptsetup luksHeaderBackup /dev/sdb3 --header-backup-file header.luks
```

**Resultado**: Exposição da configuração de todos os 32 keyslots possíveis.

### II.C. Preparação do Hash para Cracking Offline

#### Processamento do Cabeçalho

O arquivo binário extraído não pode ser usado diretamente em ferramentas como Hashcat ou John the Ripper. É necessário:

1. **Processar** o cabeçalho LUKS2 (formato JSON para metadados)
2. **Extrair** parâmetros críticos:
   - Salt (sal)
   - Identificador da KDF (Argon2id ou PBKDF2)
   - Parâmetros de custo (iterações, memória, paralelismo)

#### Ferramentas de Conversão

```bash
# Usando luks2john.py
python luks2john.py header.raw > hashfile.txt

# Verificar formato do hash extraído
cat hashfile.txt
```

A string resultante é o **alvo direto** do ataque de força bruta offline.

---

## III. Análise Criptográfica Detalhada: A Diferença Crítica da KDF

A diferença crítica na segurança do LUKS2 reside na **KDF**. A escolha da KDF atua como um mecanismo de **passphrase strengthening**, protegendo contra ataques de dicionário e força bruta ao aumentar artificialmente o tempo de verificação de cada tentativa.

### III.A. PBKDF2 (Password-Based Key Derivation Function 2)

#### Características Técnicas

- **Tipo**: KDF histórica (LUKS1) e compatibilidade (LUKS2)
- **Mecanismo**: Repetição sequencial de função hash criptográfica
- **Funções hash**: SHA-256, SHA-512
- **Custo**: Medido puramente pelo número de iterações

#### Configuração de Iterações

```bash
# Configuração por tempo alvo
cryptsetup luksFormat /dev/sdX --pbkdf pbkdf2 --iter-time 2000

# Configuração por iterações específicas  
cryptsetup luksFormat /dev/sdX --pbkdf pbkdf2 --pbkdf-force-iterations 100000
```

**Recomendações NIST**: Mínimo 10.000 iterações, até 10.000.000 para chaves críticas.

#### ⚠️ Vulnerabilidade à Paralelização por GPU

**Principal fraqueza**: Baixa exigência de memória por thread.

##### Características do Ataque GPU:
- **Hardware**: GPUs com milhares de núcleos CUDA
- **Paralelização**: Execução simultânea de milhões de iterações
- **Aceleração**: Quase linear com adição de poder computacional
- **Performance**: Dezenas de milhares de hashes por segundo (H/s)

##### Modo Hashcat para PBKDF2:
```bash
# Modo 14600 para LUKS1/PBKDF2
hashcat -m 14600 -a 0 -w 3 header.luks wordlist.txt
```

**Resultado**: Senhas de 10-12 caracteres vulneráveis em períodos factíveis.

### III.B. Argon2i/Argon2id (O Padrão LUKS2)

#### Histórico e Adoção

- **Origem**: Vencedor do Password Hashing Competition (PHC) de 2015
- **Implementação LUKS2**: Padrão desde cryptsetup 2.1
- **Variante**: Argon2id (híbrida, combina resistência a ataques side-channel e GPU)

#### Arquitetura Memory-Hard

Argon2 foi projetado como função **memory-hard**:
- Intensivo em CPU
- **Exige quantidade significativa de memória** de acesso rápido (RAM/VRAM)

#### As Três Dimensões de Custo

##### 1. Custo de Memória (m)
```bash
# Configuração de memória (em kB)
cryptsetup luksFormat /dev/sdX --pbkdf-memory 1048576  # 1 GiB
```

**Padrão LUKS2**: Tipicamente 1 GiB (1048576 kB) de RAM por derivação.

##### 2. Custo de Tempo (t)
```bash
# Número de iterações sobre a área de memória
cryptsetup luksFormat /dev/sdX --iter-time 2000  # 2 segundos
```

##### 3. Custo de Paralelismo (p)
```bash
# Threads paralelas durante derivação
cryptsetup luksFormat /dev/sdX --pbkdf-parallel 4
```

#### 🛡️ Resistência Superior à GPU

##### Limitação Fundamental: Memória

**Cálculo de limitação**:
- Cada tentativa requer: 1 GiB de VRAM
- GPU com 24 GiB VRAM: máximo 24 tentativas simultâneas
- **Resultado**: Taxa de hash drasticamente limitada

##### Inversão do Modelo de Ataque

| Aspecto | PBKDF2 | Argon2id |
|---------|---------|----------|
| **Limitação** | Tempo computacional | Memória disponível |
| **Escalabilidade** | Linear com cores | Limitada por VRAM |
| **Modelo de custo** | "Tempo vs. Processamento" | **"Custo vs. Hardware"** |

**Impacto**: Transforma ataque viável em **economicamente proibitivo**.

#### Tabela Comparativa: PBKDF2 vs. Argon2id

| KDF | Custo Primário | Resistência GPU | Config. Padrão LUKS2 | Taxa de Hash |
|-----|----------------|-----------------|----------------------|--------------|
| **PBKDF2** | Tempo (Iterações) | **Baixa** | ~2000ms, Sem custo memória | **Milhares a Milhões H/s** |
| **Argon2id** | Memória + Tempo | **Alta** | ~2000ms, 1 GiB, 4 threads | **Centenas a Milhares H/s** |

---

## IV. Execução do Ataque Offline com Ferramentas Especializadas

### IV.A. Ferramentas de Cracking: Hashcat e John the Ripper

#### Hashcat

**Características**:
- Ferramenta preferencial para ataques GPU-acelerados
- Amplamente usado em pentests e forense
- Suporte a múltiplos modos de ataque

**Modos de Ataque Suportados**:
```bash
# Ataque de dicionário
hashcat -m 14600 -a 0 hash.txt wordlist.txt

# Ataque de máscara (brute-force)
hashcat -m 14600 -a 3 hash.txt ?a?a?a?a?a?a?a?a

# Ataque híbrido
hashcat -m 14600 -a 6 hash.txt wordlist.txt ?d?d?d?d
```

**Modos LUKS**:
- **14600**: LUKS1 (tipicamente PBKDF2)
- **Argon2**: Suporte em versões recentes (performance reduzida)

#### John the Ripper (JtR)

**Características**:
- Cracker versátil, multiplataforma
- Eficaz para ataques baseados em CPU
- Excelente para listas de palavras e regras complexas

**Comandos Exemplo**:
```bash
# Listar dispositivos OpenCL
john --list=opencl-devices

# Ataque com GPU específica
john --format=LUKS2-opencl --dev=1 --wordlist=wordlist.txt hash_luks.txt

# Mostrar resultados
john --show hash_luks.txt
```

### IV.B. Técnicas de Ataque Ofensivo

#### 1. Ataque de Dicionário (Dictionary Attack)

**Método mais eficiente** contra senhas humanas:

```bash
# Wordlist básica
hashcat -m 14600 -a 0 hash.txt rockyou.txt

# Múltiplas wordlists
hashcat -m 14600 -a 0 hash.txt wordlist1.txt wordlist2.txt
```

**Características**:
- Compara hash alvo com hashes de listas massivas
- Explora palavras, frases, senhas vazadas
- Reduz drasticamente o espaço de busca

#### 2. Ataque Híbrido (Hybrid Attack)

Combina dicionário + regras de transformação:

```bash
# Dicionário + números no final
hashcat -m 14600 -a 6 hash.txt wordlist.txt ?d?d?d?d

# Dicionário + caracteres especiais
hashcat -m 14600 -a 7 ?d?d?d?d wordlist.txt
```

**Regras comuns**:
- Adicionar números (123, 2023, etc.)
- Substituições (a→@, s→$, e→3)
- Capitalização (primeira letra maiúscula)

#### 3. Ataque de Máscara/Força Bruta Pura

```bash
# Exemplo: 8 caracteres alfanuméricos
hashcat -m 14600 -a 3 hash.txt ?1?1?1?1?1?1?1?1
```

**Conjuntos de caracteres**:
- `?l`: Letras minúsculas
- `?u`: Letras maiúsculas  
- `?d`: Dígitos
- `?s`: Símbolos
- `?a`: Todos os caracteres

### IV.C. Desafios Específicos do Cracking Argon2

#### Mudança de Paradigma

A adoção do Argon2id representa **mudança fundamental**:

- Taxa de hash intencionalmente baixa
- Ataque de força bruta puro contra 12+ caracteres: **impraticável**
- Requer recursos computacionais maciços

#### Estratégias de Ataque Viáveis

Para sucesso contra LUKS2/Argon2id, o atacante deve:

1. **Explorar baixa entropia**: Senhas suscetíveis a dicionário
2. **Recursos estatais**: Poder computacional massivo (bilhões de dólares)

#### Foco na Defesa

A resistência do Argon2 **transfere responsabilidade** para:
- **Comprimento da passphrase** (≥20 caracteres)
- **Entropia da passphrase** (aleatoriedade real)
- **KDF já fornece proteção máxima** contra aceleração hardware

---

## V. Viabilidade Computacional: Modelagem de Custo e Tempo

### V.A. Benchmarking e Complexidade do Ataque

#### Métricas de Performance

**Quantificação**: Taxa de hashes por segundo (H/s)

#### Comparação PBKDF2 vs. Argon2

**PBKDF2**:
- Clusters GPU: taxas altíssimas (milhões H/s)
- Limitação: apenas tempo computacional

**Argon2**:
- Exigência: 1 GiB memória por thread
- Aceleração GPU vs. CPU: 158-350x (vs. milhares para PBKDF2)
- Taxa resultante: **milhares** (não milhões) H/s

### V.B. Modelagem de Custo para Quebra (Argon2id Padrão)

#### Estudo de Caso: 8 Caracteres

**Configuração**:
- KDF: Argon2id (configuração padrão LUKS2)
- Tempo de ataque: 10 anos
- Hardware necessário: ~1.085 GPUs Nvidia Tesla P100

**Custo estimado**: **$120 milhões USD**

#### Senhas Mais Complexas

**12+ caracteres ou configurações mais agressivas**:
- Hardware necessário: 75.000+ máquinas
- Custo: **$4+ bilhões USD** (10 anos)

#### Tabela de Viabilidade Computacional

| Cenário | KDF | Entropia | Hardware | Viabilidade |
|---------|-----|----------|----------|-------------|
| **8 caracteres** | Argon2id (1 GiB, 4t) | ~40 bits | 1.085 Tesla P100 | 10 anos, $120M USD |
| **12 caracteres** | Argon2id (1 GiB, 4t) | ~60 bits | Milhares RTX 4090 | Décadas, $Bilhões USD |
| **12 caracteres** | PBKDF2 (alta iter.) | ~60 bits | 10-20 GPUs | **Meses/Anos, Viável** |

### V.C. Análise do Modelo de Ameaça

#### Relatórios de Quebra de LUKS2

Apesar da resistência teórica, há **relatos de autoridades** quebrando volumes LUKS2 com senhas 20+ caracteres.

#### Três Implicações Principais

##### 1. Configuração Inadequada da KDF
- Uso de PBKDF2 em vez de Argon2id
- Compatibilidade com bootloaders (GRUB)
- Argon2id com parâmetros baixos

##### 2. Falha de OPSEC (Mais Comum)
- Comprometimento não-criptográfico:
  - Keylogger
  - Espionagem
  - Coação
- Senha previsível (dicionário disfarçado)

##### 3. Recursos Estatais Extremos
- Adversário com bilhões em poder computacional
- Milhares de GPUs alto desempenho
- Operação por longos períodos

#### Conclusão da Análise

**Força bruta pura** contra senha aleatória 12-14 caracteres + Argon2id: **matematicamente inviável**

**Mas**: Senhas longas baseadas em frases (menor entropia) permanecem vulneráveis a ataques de dicionário otimizados.

---

## VI. Recomendações e Medidas de Mitigação

### VI.A. Maximização da Entropia da Passphrase

#### Primeira Linha de Defesa

**Princípio**: Comprimento + aleatoriedade da passphrase

#### Recomendações Específicas

```bash
# Gerar passphrase de alta entropia
openssl rand -base64 32

# Alternativa com palavras aleatórias
shuf -n 6 /usr/share/dict/words | tr '\n' '-'
```

**Características recomendadas**:
- **≥20 caracteres**
- **Alta aleatoriedade**
- **Evitar padrões linguísticos**

### VI.B. Configuração Otimizada do LUKS2

#### 1. Uso Exclusivo do Argon2id

```bash
# Formatação com Argon2id (padrão)
cryptsetup luksFormat /dev/sdX

# Explícito (caso necessário)
cryptsetup luksFormat /dev/sdX --pbkdf argon2id
```

#### 2. Maximização dos Parâmetros da KDF

```bash
# Aumentar memória (exemplo: 2 GiB)
cryptsetup luksFormat /dev/sdX \
    --pbkdf argon2id \
    --pbkdf-memory 2097152 \
    --iter-time 3000

# Verificar configuração atual
cryptsetup luksDump /dev/sdX
```

**Parâmetros recomendados**:
- **Memória**: Máximo suportado pelo sistema
- **Tempo**: 2-5 segundos (balancear usabilidade)
- **Paralelismo**: Matching com cores CPU

#### 3. Mitigação da Restrição do GRUB

**Problema**: Partição `/boot` criptografada com LUKS1/PBKDF2

**Soluções**:
```bash
# Opção 1: Keyfile de alta entropia
dd if=/dev/urandom of=/root/boot.key bs=4096 count=1
cryptsetup luksAddKey /dev/boot_partition /root/boot.key

# Opção 2: Partição /boot não criptografada (configuração separada)
```

### VI.C. Fortalecimento Adicional da Chave

#### 1. Keyfiles Criptograficamente Gerados

```bash
# Gerar keyfile
dd if=/dev/urandom of=/secure/location/luks.key bs=4096 count=1

# Adicionar ao LUKS
cryptsetup luksAddKey /dev/sdX /secure/location/luks.key

# Usar keyfile no boot
cryptsetup luksOpen /dev/sdX encrypted_vol --key-file /secure/location/luks.key
```

**Vantagens**:
- **Elimina vulnerabilidade humana**
- **Torna ataque de dicionário impossível**
- **Entropia máxima garantida**

#### 2. Backup Seguro do Cabeçalho LUKS

```bash
# Criar backup
cryptsetup luksHeaderBackup /dev/sdX --header-backup-file luks_header.backup

# Criptografar o próprio backup
gpg --cipher-algo AES256 --compress-algo 1 --s2k-mode 3 \
    --s2k-digest-algo SHA512 --s2k-count 65536 --symmetric \
    luks_header.backup

# Armazenar em local físicamente separado e seguro
```

#### 3. Autenticação Multifator

```bash
# TPM 2.0 (se disponível)
systemd-cryptenroll /dev/sdX --tpm2-device=auto

# FIDO2/WebAuthn
systemd-cryptenroll /dev/sdX --fido2-device=auto
```

---

## VII. Conclusões

### Resumo da Análise de Viabilidade

#### ✅ Quando o Ataque é Viável

1. **KDF vulnerável**: PBKDF2 em uso
2. **Passphrase fraca**: Baixa entropia, baseada em dicionário
3. **Configuração inadequada**: Argon2id com parâmetros baixos
4. **Recursos extremos**: Orçamento estatal (bilhões USD)

#### ❌ Quando o Ataque é Inviável

1. **Argon2id padrão**: Configuração ≥1 GiB memória
2. **Passphrase forte**: ≥12 caracteres aleatórios
3. **Configuração otimizada**: Parâmetros maximizados
4. **Recursos limitados**: Atacantes sem recursos estatais

### Recomendações Finais

#### Para Profissionais de Segurança

1. **Garantir Argon2id**: Verificar KDF em volumes existentes
2. **Maximizar parâmetros**: Memória e tempo dentro do aceitável
3. **Educar usuários**: Senhas longas e aleatórias
4. **Implementar keyfiles**: Para sistemas críticos

#### Para Auditores e Forenses

1. **Verificar configuração KDF**: Primeira verificação em análise
2. **Avaliar entropia de senhas**: Susceptibilidade a dicionário
3. **Documentar recursos necessários**: Para quebra estimada
4. **Considerar vetores alternativos**: Evil maid, cold boot, etc.

### Declaração Final

**O LUKS2 com Argon2id adequadamente configurado torna a força bruta economicamente inviável para a maioria dos adversários**, transferindo a responsabilidade de segurança para a **qualidade da passphrase** e **configuração adequada dos parâmetros da KDF**.

A robustez criptográfica do Argon2id significa que **ataques bem-sucedidos contra configurações adequadas** indicam fortemente **comprometimento por métodos não-criptográficos** ou **configuração inadequada do sistema**.

---

## Anexos

### A. Comandos de Referência Rápida

#### Verificação de Configuração LUKS
```bash
# Verificar tipo KDF
cryptsetup luksDump /dev/sdX | grep -A 5 "PBKDF"

# Verificar parâmetros Argon2
cryptsetup luksDump /dev/sdX | grep -A 10 "argon2"

# Listar keyslots ativos
cryptsetup luksDump /dev/sdX | grep "Key Slot"
```

#### Extração para Análise Forense
```bash
# Extração do cabeçalho + dados
dd if=/dev/sdX of=luks_header.raw bs=512 count=4097

# Conversão para formato crackeable
python luks2john.py luks_header.raw > hash_file.txt

# Verificação do hash extraído
file luks_header.raw
hexdump -C luks_header.raw | head -10
```

#### Teste de Performance de Cracking
```bash
# Benchmark Hashcat
hashcat -b -m 14600

# Teste com wordlist pequena
hashcat -m 14600 -a 0 hash_file.txt small_wordlist.txt --show

# Estimativa de tempo
hashcat -m 14600 --keyspace -a 3 ?a?a?a?a?a?a?a?a
```

### B. Referências e Estudos

1. OWASP Testing Guide - Cryptographic Storage Testing
2. NIST SP 800-132 - Recommendation for Password-Based Key Derivation
3. RFC 2898 - PKCS #5: Password-Based Cryptography Specification
4. Argon2 Specification (RFC 9106)
5. LUKS2 On-Disk Format Specification
6. "The Password Hashing Competition" - Academic Papers
7. "GPU-based Password Cracking" - Research Studies
8. "Memory-Hard Functions" - Cryptographic Analysis

---

*Relatório gerado em: Dezembro 2025*  
*Versão: 1.0*  
*Classificação: Técnico/Forense*