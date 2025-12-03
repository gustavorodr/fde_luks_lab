#!/usr/bin/env bash
set -euo pipefail

# Offline LUKS cracking helper
# - Verifies LUKS2 on a device
# - Builds local Hashcat from tools/vendor/hashcat (no internet)
# - Installs/copies module_29500.so if missing
# - Runs Hashcat -m 29500 on header + wordlist
# - Falls back to John the Ripper Jumbo if Hashcat LUKS2 module missing
#
# Usage:
#   sudo bash tools/brute_force/offline_luks2_crack.sh /dev/sdb1 header.luks wordlist.txt
#   sudo bash tools/brute_force/offline_luks2_crack.sh /dev/sdb1   # uses defaults: header.luks, wordlist.txt
#
# Requirements:
# - Hashcat source present at tools/vendor/hashcat/
# - Optional JtR Jumbo built at john/run (or system john with luks2john)

DEVICE=${1:-/dev/sdb1}
HEADER=${2:-header.luks}
WORDLIST=${3:-wordlist.txt}
ROOT_DIR="$(cd "$(dirname "$0")"/../../.. && pwd)"
HC_SRC_DIR="$ROOT_DIR/tools/vendor/hashcat"
HC_TARBALL="$ROOT_DIR/tools/vendor/hashcat.tar.gz"
HC_SRC_ENV="${HASHCAT_SRC_PATH:-}"
HC_PREFIX_DIR="$HC_SRC_DIR/dist"
HC_LOCAL_BIN="$HC_PREFIX_DIR/bin/hashcat"
HC_LOCAL_MODULE_29500="$HC_SRC_DIR/modules/module_29500.so"
HC_SYSTEM_MODULE_DIR="/usr/share/hashcat/modules"
HC_SYSTEM_MODULE_29500="$HC_SYSTEM_MODULE_DIR/module_29500.so"

log() { echo "[+] $*"; }
warn() { echo "[!] $*"; }
err() { echo "[x] $*" >&2; exit 1; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || err "Comando requerido não encontrado: $1"; }

log "Dispositivo alvo: $DEVICE"
require_cmd cryptsetup

# 1) Dump LUKS info
log "Verificando cabeçalho LUKS em $DEVICE"
sudo cryptsetup luksDump "$DEVICE" || err "Falha ao ler cabeçalho LUKS em $DEVICE"

# 2) Backup header
log "Fazendo backup do cabeçalho para $HEADER"
sudo rm -f "$HEADER"
sudo cryptsetup luksHeaderBackup "$DEVICE" --header-backup-file "$HEADER" || err "Falha ao criar backup do cabeçalho"
sudo chown "$USER":"$USER" "$HEADER"
chmod 644 "$HEADER"

# 3) Ensure wordlist exists
if [[ ! -f "$WORDLIST" ]]; then
  warn "Wordlist não encontrada em $WORDLIST; criando exemplo com crunch (Admin%%%%)"
  require_cmd crunch
  crunch 9 9 -t Admin%%%% -o "$WORDLIST" >/dev/null
fi
sudo chown "$USER":"$USER" "$WORDLIST"
chmod 644 "$WORDLIST"

# 4) Try system Hashcat first
HC_BIN_SYSTEM=$(command -v hashcat || true)

has_mode_29500() {
  "$1" --help | grep -E "(^| )29500( |$)" >/dev/null 2>&1
}

run_hashcat() {
  local bin="$1"
  log "Executando Hashcat local: $bin"
  "$bin" -m 29500 -a 0 "$HEADER" "$WORDLIST" || return 1
}

# 5) If system Hashcat missing 29500, build local Hashcat from source
prepare_local_hashcat() {
  if [[ ! -d "$HC_SRC_DIR" ]]; then
    if [[ -n "$HC_SRC_ENV" && -d "$HC_SRC_ENV" ]]; then
      log "Copiando fonte Hashcat de $HC_SRC_ENV para $HC_SRC_DIR"
      mkdir -p "$HC_SRC_DIR"
      rsync -a --delete "$HC_SRC_ENV"/ "$HC_SRC_DIR"/
    elif [[ -f "$HC_TARBALL" ]]; then
      log "Extraindo tarball local $HC_TARBALL para $HC_SRC_DIR"
      mkdir -p "$HC_SRC_DIR"
      tar -xf "$HC_TARBALL" -C "$HC_SRC_DIR" --strip-components=1
    else
      err "Fonte do Hashcat não encontrada. Defina HASHCAT_SRC_PATH=/caminho/para/hashcat ou coloque tools/vendor/hashcat/ ou tools/vendor/hashcat.tar.gz."
    fi
  fi
  log "Compilando Hashcat a partir de $HC_SRC_DIR (offline)"
  pushd "$HC_SRC_DIR" >/dev/null
  make -j"$(nproc)"
  make PREFIX="$HC_PREFIX_DIR" install
  popd >/dev/null
}

install_module_to_system() {
  if [[ -f "$HC_LOCAL_MODULE_29500" ]]; then
    log "Instalando módulo LUKS2 em $HC_SYSTEM_MODULE_DIR"
    sudo mkdir -p "$HC_SYSTEM_MODULE_DIR"
    sudo install -m 644 "$HC_LOCAL_MODULE_29500" "$HC_SYSTEM_MODULE_29500"
  else
    warn "module_29500.so não encontrado em $HC_LOCAL_MODULE_29500"
  fi
}

# Try system hashcat with 29500
if [[ -n "$HC_BIN_SYSTEM" ]] && has_mode_29500 "$HC_BIN_SYSTEM"; then
  log "Hashcat do sistema suporta 29500. Tentando executar."
  if run_hashcat "$HC_BIN_SYSTEM"; then
    log "Hashcat concluído (modo 29500)."
    exit 0
  else
    warn "Falha ao executar Hashcat do sistema; prosseguindo com build local."
  fi
else
  warn "Hashcat do sistema não encontrado ou não suporta 29500."
fi

# Build local hashcat
prepare_local_hashcat

# Validate local module
if [[ -f "$HC_LOCAL_MODULE_29500" ]]; then
  log "Módulo local 29500 encontrado: $HC_LOCAL_MODULE_29500"
else
  warn "Módulo local 29500 não foi gerado; tentativa de execução pode falhar."
fi

# Try local binary first
if [[ -x "$HC_LOCAL_BIN" ]] && has_mode_29500 "$HC_LOCAL_BIN"; then
  if run_hashcat "$HC_LOCAL_BIN"; then
    log "Hashcat local concluído (modo 29500)."
    exit 0
  else
    warn "Falha ao executar Hashcat local."
  fi
else
  warn "Binário local do Hashcat não suporta 29500; tentando instalar módulo no sistema."
  install_module_to_system
fi

# Re-attempt system hashcat after module install
if [[ -n "$HC_BIN_SYSTEM" ]] && has_mode_29500 "$HC_BIN_SYSTEM"; then
  if run_hashcat "$HC_BIN_SYSTEM"; then
    log "Hashcat do sistema concluído após instalação de módulo (29500)."
    exit 0
  fi
fi

# 6) Fallback to John the Ripper Jumbo
log "Fallback: usando John the Ripper para LUKS2"
JTR_RUN_DIR="$ROOT_DIR/john/run"
LUKS2JOHN_BIN="$(command -v luks2john || true)"
if [[ -z "$LUKS2JOHN_BIN" && -x "$JTR_RUN_DIR/luks2john" ]]; then
  LUKS2JOHN_BIN="$JTR_RUN_DIR/luks2john"
fi

require_cmd john
[[ -n "$LUKS2JOHN_BIN" ]] || err "luks2john não encontrado (instale/compile JtR Jumbo)."

HASH_OUT="$ROOT_DIR/hash_luks2.txt"
log "Extraindo hash com luks2john para $HASH_OUT"
"$LUKS2JOHN_BIN" "$HEADER" > "$HASH_OUT"

log "Listando dispositivos OpenCL (opcional)"
john --list=opencl-devices || true

log "Executando JtR LUKS2-opencl"
john --format=LUKS2-opencl --wordlist="$WORDLIST" "$HASH_OUT" || err "JtR falhou para LUKS2-opencl"

log "Resultado:"
john --show "$HASH_OUT" || true

log "Concluído."
