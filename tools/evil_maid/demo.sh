#!/bin/bash

# Evil Maid Attack Framework - Demonstração Completa
# TSE 2025 Ballot-Box TPU System LUKS Penetration Testing
# 
# Script de demonstração das capacidades completas do framework
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

# Banner principal
print_main_banner() {
    clear
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    EVIL MAID ATTACK FRAMEWORK v2.0                          ║"
    echo "║                TSE 2025 Ballot-Box TPU System Penetration                   ║"
    echo "║                                                                              ║"
    echo "║  Framework completo para ataques Evil Maid contra sistemas LUKS FDE         ║"
    echo "║                                                                              ║"
    echo "║  COMPONENTES:                                                                ║"
    echo "║  • Framework Python principal (evil_maid_framework.py)                      ║"
    echo "║  • Reconnaissance avançado (reconnaissance.sh)                               ║"
    echo "║  • Ataque ao initramfs (initramfs_attack.sh)                               ║"
    echo "║  • Backdoor JVM (jvm_backdoor.sh)                                          ║"
    echo "║  • Keylogger em C (keylogger.c/keylogger)                                   ║"
    echo "║  • Gerenciador de persistência (persistence_manager.sh)                     ║"
    echo "║  • Coletor de resultados (results_collector.sh)                            ║"
    echo "║                                                                              ║"
    echo "║  AVISO: SOMENTE PARA TESTES AUTORIZADOS DE PENETRAÇÃO!                     ║"
    echo "║  USO NÃO AUTORIZADO É CRIME SEGUNDO A LEI BRASILEIRA!                      ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo
}

# Verificar dependências
check_dependencies() {
    local missing_deps=()
    local missing_tools=()
    
    echo -e "${CYAN}[VERIFICAÇÃO] Checando dependências...${NC}"
    
    # Verificar comandos básicos
    for cmd in python3 gcc bash; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    # Verificar ferramentas do framework
    local tools=(
        "evil_maid_framework.py"
        "reconnaissance.sh"
        "initramfs_attack.sh"
        "jvm_backdoor.sh"
        "keylogger.c"
        "persistence_manager.sh"
        "results_collector.sh"
    )
    
    for tool in "${tools[@]}"; do
        if [[ ! -f "$SCRIPT_DIR/$tool" ]]; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo -e "${RED}[ERROR] Dependências faltando: ${missing_deps[*]}${NC}"
        return 1
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo -e "${RED}[ERROR] Ferramentas faltando: ${missing_tools[*]}${NC}"
        return 1
    fi
    
    echo -e "${GREEN}[SUCCESS] Todas as dependências verificadas${NC}"
    return 0
}

# Compilar keylogger se necessário
compile_keylogger() {
    echo -e "\n${CYAN}[COMPILAÇÃO] Verificando keylogger...${NC}"
    
    if [[ -f "$SCRIPT_DIR/keylogger" ]]; then
        echo -e "${GREEN}[INFO] Keylogger já compilado${NC}"
        return 0
    fi
    
    if [[ ! -f "$SCRIPT_DIR/keylogger.c" ]]; then
        echo -e "${RED}[ERROR] Código fonte keylogger.c não encontrado${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}[INFO] Compilando keylogger...${NC}"
    cd "$SCRIPT_DIR"
    
    if gcc -o keylogger keylogger.c -lpthread -Wall -O2; then
        echo -e "${GREEN}[SUCCESS] Keylogger compilado com sucesso${NC}"
        chmod +x keylogger
        return 0
    else
        echo -e "${RED}[ERROR] Falha na compilação do keylogger${NC}"
        return 1
    fi
}

# Verificar permissões
check_permissions() {
    echo -e "\n${CYAN}[PERMISSÕES] Verificando privilégios...${NC}"
    
    if [[ $EUID -eq 0 ]]; then
        echo -e "${GREEN}[INFO] Executando como root - todos os recursos disponíveis${NC}"
        return 0
    else
        echo -e "${YELLOW}[WARNING] Executando sem privilégios root${NC}"
        echo -e "${YELLOW}[WARNING] Algumas funcionalidades podem estar limitadas${NC}"
        return 1
    fi
}

# Demonstrar reconnaissance
demo_reconnaissance() {
    echo -e "\n${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}                    DEMONSTRAÇÃO - RECONNAISSANCE                ${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "\nO script de reconnaissance coleta informações detalhadas do sistema:"
    echo "• Arquitetura do sistema e hardware"
    echo "• Dispositivos de armazenamento e partições"
    echo "• Detecção de LUKS e criptografia"
    echo "• Configuração de boot (GRUB, UEFI, etc.)"
    echo "• Análise de vulnerabilidades"
    
    read -p "Executar reconnaissance? [y/N]: " choice
    if [[ "$choice" =~ ^[Yy] ]]; then
        echo -e "\n${CYAN}[EXECUTANDO] Reconnaissance do sistema...${NC}"
        if bash "$SCRIPT_DIR/reconnaissance.sh"; then
            echo -e "\n${GREEN}[SUCCESS] Reconnaissance concluído${NC}"
        else
            echo -e "\n${RED}[ERROR] Falha no reconnaissance${NC}"
        fi
    fi
}

# Demonstrar análise de initramfs
demo_initramfs() {
    echo -e "\n${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}                   DEMONSTRAÇÃO - ATAQUE INITRAMFS              ${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "\nO ataque ao initramfs inclui:"
    echo "• Detecção automática de initramfs no sistema"
    echo "• Suporte para múltiplos formatos de compressão"
    echo "• Injeção de keylogger avançado"
    echo "• Modificação de scripts de boot"
    echo "• Reempacotamento e instalação"
    
    read -p "Demonstrar análise de initramfs (sem modificação)? [y/N]: " choice
    if [[ "$choice" =~ ^[Yy] ]]; then
        echo -e "\n${CYAN}[EXECUTANDO] Análise de initramfs...${NC}"
        echo -e "${YELLOW}[MODO SEGURO] Executando apenas análise, sem modificações${NC}"
        
        # Executar em modo de análise apenas
        export DEMO_MODE=1
        if bash "$SCRIPT_DIR/initramfs_attack.sh"; then
            echo -e "\n${GREEN}[SUCCESS] Análise de initramfs concluída${NC}"
        else
            echo -e "\n${RED}[ERROR] Falha na análise${NC}"
        fi
        unset DEMO_MODE
    fi
}

# Demonstrar keylogger
demo_keylogger() {
    echo -e "\n${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}                   DEMONSTRAÇÃO - KEYLOGGER AVANÇADO            ${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "\nO keylogger avançado em C oferece:"
    echo "• Captura de teclas em nível de kernel"
    echo "• Detecção automática de dispositivos de entrada"
    echo "• Análise de padrões de senha"
    echo "• Execução como daemon"
    echo "• Rotacionamento automático de logs"
    
    if [[ ! -f "$SCRIPT_DIR/keylogger" ]]; then
        echo -e "${YELLOW}[WARNING] Keylogger não compilado${NC}"
        return 1
    fi
    
    echo -e "\n${YELLOW}[INFO] Mostrando ajuda do keylogger:${NC}"
    "$SCRIPT_DIR/keylogger" --help 2>/dev/null || echo "Keylogger compilado e pronto para uso"
    
    read -p "Demonstrar captura de teclas (5 segundos)? [y/N]: " choice
    if [[ "$choice" =~ ^[Yy] ]] && [[ $EUID -eq 0 ]]; then
        echo -e "\n${CYAN}[EXECUTANDO] Teste de keylogger por 5 segundos...${NC}"
        echo -e "${YELLOW}[INFO] Digite algumas teclas para testar a captura${NC}"
        
        timeout 5s "$SCRIPT_DIR/keylogger" &
        keylogger_pid=$!
        sleep 6
        kill $keylogger_pid 2>/dev/null
        
        echo -e "\n${GREEN}[SUCCESS] Teste de keylogger concluído${NC}"
        if [[ -f "/tmp/.keylog" ]]; then
            echo -e "${CYAN}[INFO] Log de teste gerado em /tmp/.keylog${NC}"
        fi
    elif [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}[WARNING] Teste de keylogger requer privilégios root${NC}"
    fi
}

# Demonstrar backdoor JVM
demo_jvm_backdoor() {
    echo -e "\n${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}                   DEMONSTRAÇÃO - BACKDOOR JVM                  ${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "\nO sistema de backdoor JVM inclui:"
    echo "• Análise de segurança de arquivos JAR"
    echo "• Criação de payloads Java maliciosos"
    echo "• Injeção de código em aplicações existentes"
    echo "• Análise forense de aplicações Java"
    echo "• Suporte para múltiplos tipos de payload"
    
    read -p "Demonstrar análise de JAR (modo seguro)? [y/N]: " choice
    if [[ "$choice" =~ ^[Yy] ]]; then
        echo -e "\n${CYAN}[EXECUTANDO] Demonstração de análise JAR...${NC}"
        
        # Procurar por arquivos JAR no sistema
        echo -e "${YELLOW}[INFO] Procurando arquivos JAR no sistema...${NC}"
        jar_files=$(find /usr /opt -name "*.jar" 2>/dev/null | head -5)
        
        if [[ -n "$jar_files" ]]; then
            echo -e "${GREEN}[INFO] Arquivos JAR encontrados:${NC}"
            echo "$jar_files"
            echo -e "\n${YELLOW}[MODO SEGURO] Executando apenas análise, sem modificações${NC}"
            
            # Executar análise em modo seguro
            export DEMO_MODE=1
            echo "$jar_files" | head -1 | xargs bash "$SCRIPT_DIR/jvm_backdoor.sh" 2>/dev/null || true
            unset DEMO_MODE
        else
            echo -e "${YELLOW}[INFO] Nenhum arquivo JAR encontrado para análise${NC}"
        fi
    fi
}

# Demonstrar persistência
demo_persistence() {
    echo -e "\n${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}                   DEMONSTRAÇÃO - PERSISTÊNCIA                  ${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "\nO gerenciador de persistência oferece:"
    echo "• Instalação de serviços systemd"
    echo "• Configuração de cron jobs"
    echo "• Persistência de boot"
    echo "• Backdoor SSH opcional"
    echo "• Coleta automática de dados"
    
    read -p "Mostrar status da persistência? [y/N]: " choice
    if [[ "$choice" =~ ^[Yy] ]]; then
        echo -e "\n${CYAN}[EXECUTANDO] Verificação de status da persistência...${NC}"
        bash "$SCRIPT_DIR/persistence_manager.sh" status
    fi
}

# Demonstrar coleta de resultados
demo_results_collection() {
    echo -e "\n${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}                   DEMONSTRAÇÃO - COLETA DE RESULTADOS          ${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "\nO coletor de resultados inclui:"
    echo "• Análise automática de keylogs"
    echo "• Coleta de informações do sistema"
    echo "• Análise de persistência"
    echo "• Geração de relatórios executivos"
    echo "• Criação de pacotes de evidência"
    
    read -p "Demonstrar análise de sistema? [y/N]: " choice
    if [[ "$choice" =~ ^[Yy] ]]; then
        echo -e "\n${CYAN}[EXECUTANDO] Demonstração de coleta...${NC}"
        bash "$SCRIPT_DIR/results_collector.sh" system
    fi
}

# Demonstrar framework Python
demo_python_framework() {
    echo -e "\n${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}                   DEMONSTRAÇÃO - FRAMEWORK PYTHON              ${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "\nO framework principal em Python oferece:"
    echo "• Análise automática de boot chain"
    echo "• Orquestração de todos os ataques"
    echo "• Interface de linha de comando"
    echo "• Integração com todas as ferramentas"
    echo "• Relatórios detalhados"
    
    read -p "Executar análise de boot chain? [y/N]: " choice
    if [[ "$choice" =~ ^[Yy] ]]; then
        echo -e "\n${CYAN}[EXECUTANDO] Análise de boot chain...${NC}"
        python3 "$SCRIPT_DIR/evil_maid_framework.py" analyze
    fi
}

# Menu principal de demonstração
show_demo_menu() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                           MENU DE DEMONSTRAÇÃO                    ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo "1) Reconnaissance avançado"
    echo "2) Análise de initramfs (modo seguro)"
    echo "3) Keylogger avançado"
    echo "4) Backdoor JVM"
    echo "5) Gerenciador de persistência"
    echo "6) Coleta de resultados"
    echo "7) Framework Python principal"
    echo "8) Executar todas as demonstrações"
    echo "9) Mostrar estrutura do projeto"
    echo "0) Sair"
    echo
}

# Mostrar estrutura do projeto
show_project_structure() {
    echo -e "\n${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}                      ESTRUTURA DO PROJETO                      ${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "\n${YELLOW}Diretório atual: $SCRIPT_DIR${NC}"
    echo
    tree "$SCRIPT_DIR/../.." 2>/dev/null || find "$SCRIPT_DIR/../.." -type f -name "*.py" -o -name "*.sh" -o -name "*.c" | sort
    
    echo -e "\n${GREEN}Arquivos principais:${NC}"
    echo "• evil_maid_framework.py - Framework principal em Python"
    echo "• reconnaissance.sh - Script de reconhecimento"
    echo "• initramfs_attack.sh - Ataque ao initramfs"
    echo "• jvm_backdoor.sh - Backdoor para aplicações Java"
    echo "• keylogger.c - Keylogger avançado em C"
    echo "• persistence_manager.sh - Gerenciador de persistência"
    echo "• results_collector.sh - Coletor de resultados"
    echo "• demo.sh - Este script de demonstração"
}

# Executar todas as demonstrações
run_all_demos() {
    echo -e "\n${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}                    EXECUTANDO TODAS AS DEMONSTRAÇÕES           ${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
    
    demo_reconnaissance
    demo_initramfs
    demo_keylogger
    demo_jvm_backdoor
    demo_persistence
    demo_results_collection
    demo_python_framework
    
    echo -e "\n${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                    DEMONSTRAÇÃO COMPLETA FINALIZADA            ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
}

# Função principal
main() {
    print_main_banner
    
    # Verificações iniciais
    if ! check_dependencies; then
        exit 1
    fi
    
    compile_keylogger
    check_permissions
    
    # Menu interativo
    while true; do
        show_demo_menu
        read -p "Escolha uma opção [0-9]: " choice
        
        case $choice in
            1) demo_reconnaissance ;;
            2) demo_initramfs ;;
            3) demo_keylogger ;;
            4) demo_jvm_backdoor ;;
            5) demo_persistence ;;
            6) demo_results_collection ;;
            7) demo_python_framework ;;
            8) run_all_demos ;;
            9) show_project_structure ;;
            0) 
                echo -e "\n${CYAN}Obrigado por usar o Evil Maid Attack Framework!${NC}"
                echo -e "${YELLOW}Lembre-se: Use apenas em sistemas autorizados para teste.${NC}"
                exit 0
                ;;
            *) 
                echo -e "\n${RED}[ERROR] Opção inválida!${NC}"
                ;;
        esac
        
        echo -e "\nPressione Enter para continuar..."
        read
    done
}

# Executar função principal
main "$@"