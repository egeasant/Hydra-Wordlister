#!/usr/bin/env bash
#
# enum_scan.sh - Script de enumeração de portas/serviços com Nmap
#
# Uso:
#   ./enum_scan.sh <alvo> [diretorio_saida]
#
# Exemplo:
#   ./enum_scan.sh 192.168.1.10
#   ./enum_scan.sh scanme.nmap.org ./resultados
#
# IMPORTANTE: só execute contra alvos que você tem autorização explícita
# para testar (seus próprios sistemas, ou com permissão por escrito do dono).
# Escaneamento não autorizado pode ser crime em diversas jurisdições.

set -euo pipefail

TARGET="${1:-}"
OUTDIR="${2:-./nmap_$(date +%Y%m%d_%H%M%S)}"

if [[ -z "$TARGET" ]]; then
    echo "Uso: $0 <alvo> [diretorio_saida]"
    exit 1
fi

if ! command -v nmap &>/dev/null; then
    echo "[!] nmap não encontrado. Instale com: sudo apt install nmap"
    exit 1
fi

mkdir -p "$OUTDIR"
LOGFILE="$OUTDIR/scan.log"

log() {
    echo -e "[$(date +%H:%M:%S)] $*" | tee -a "$LOGFILE"
}

log "=== Iniciando enumeração contra: $TARGET ==="
log "Resultados serão salvos em: $OUTDIR"

# 1) Descoberta rápida de portas TCP abertas (top ports) - usada para acelerar
#    o scan completo em vez de rodar -p- com todos os scripts de uma vez
log "[1/4] Scan rápido (top 1000 portas TCP) para identificar portas abertas..."
nmap -Pn -T4 --top-ports 1000 -oA "$OUTDIR/01_quick_tcp" "$TARGET" | tee -a "$LOGFILE"

# Extrai as portas abertas encontradas no scan rápido
OPEN_PORTS=$(grep -oP '^\d+(?=/tcp\s+open)' "$OUTDIR/01_quick_tcp.gnmap" 2>/dev/null \
    || awk -F'/' '/open/{print $1}' "$OUTDIR/01_quick_tcp.nmap" 2>/dev/null || true)

# 2) Scan completo de todas as 65535 portas TCP (mais demorado, roda em paralelo
#    com detecção de versão desativada para ganhar velocidade)
log "[2/4] Scan completo TCP (todas as 65535 portas)..."
nmap -Pn -T4 -p- --min-rate=1000 -oA "$OUTDIR/02_full_tcp" "$TARGET" | tee -a "$LOGFILE"

ALL_OPEN=$(awk -F'/' '/open/{print $1}' "$OUTDIR/02_full_tcp.nmap" | sort -un | paste -sd, -)

if [[ -z "$ALL_OPEN" ]]; then
    log "[!] Nenhuma porta aberta encontrada. Encerrando."
    exit 0
fi

log "Portas abertas detectadas: $ALL_OPEN"

# 3) Detecção de versão de serviço + SO apenas nas portas abertas (mais preciso e rápido)
log "[3/4] Detecção de versão de serviços e sistema operacional..."
nmap -Pn -sV -O -T4 -p "$ALL_OPEN" -oA "$OUTDIR/03_service_version" "$TARGET" | tee -a "$LOGFILE"

# 4) Scripts padrão do NSE (safe) para enumeração adicional (banners, títulos http, etc)
log "[4/4] Scripts NSE padrão (categoria 'default' e 'safe')..."
nmap -Pn -sC -T4 -p "$ALL_OPEN" -oA "$OUTDIR/04_nse_default" "$TARGET" | tee -a "$LOGFILE"

log "=== Enumeração concluída ==="
log "Arquivos gerados em: $OUTDIR (.nmap, .xml, .gnmap para cada etapa)"

# --- Extração de domínios/SANs encontrados nos certificados SSL ---
DOMAINS_FILE="$OUTDIR/dominios_encontrados.txt"
{
    # commonName
    grep -oP 'commonName=\K\S+' "$OUTDIR/04_nse_default.nmap" 2>/dev/null
    # Subject Alternative Name (lista separada por vírgula, formato DNS:xxx)
    grep -oP 'DNS:\K[^,\s]+' "$OUTDIR/04_nse_default.nmap" 2>/dev/null
} | sort -u > "$DOMAINS_FILE"

DOMAIN_COUNT=$(wc -l < "$DOMAINS_FILE" 2>/dev/null || echo 0)

# --- Detecta serviços/tecnologias recorrentes (ex: HAProxy, OpenVPN, etc) ---
TECH_FILE="$OUTDIR/tecnologias_detectadas.txt"
grep -oP '(?<=VERSION\n|open\s{2,})\S.*' "$OUTDIR/03_service_version.nmap" 2>/dev/null > /dev/null || true
grep -E '^[0-9]+/tcp' "$OUTDIR/03_service_version.nmap" 2>/dev/null \
    | awk '{$1=$2=""; print $0}' | sed 's/^ *//' | sort -u > "$TECH_FILE"

# --- Certificados expirando em breve (próximos 30 dias) ---
CERT_EXPIRY_FILE="$OUTDIR/certificados_validade.txt"
grep -oP 'Not valid after:\s*\K[0-9T:-]+' "$OUTDIR/04_nse_default.nmap" 2>/dev/null | sort -u > "$CERT_EXPIRY_FILE"

# Resumo final consolidado
{
    echo ""
    echo "===== RESUMO ====="
    echo "Alvo: $TARGET"
    echo ""
    echo "-- Portas abertas (${ALL_OPEN//,/, }) --"
    echo "$ALL_OPEN"
    echo ""
    echo "-- Serviços/versões identificados por porta --"
    cat "$TECH_FILE" 2>/dev/null
    echo ""
    echo "-- Domínios/hostnames encontrados em certificados SSL ($DOMAIN_COUNT únicos) --"
    cat "$DOMAINS_FILE" 2>/dev/null
    echo ""
    echo "-- Datas de expiração de certificados encontradas --"
    cat "$CERT_EXPIRY_FILE" 2>/dev/null
    echo ""
    echo "Detalhes completos em: $OUTDIR/03_service_version.nmap"
    echo "Domínios salvos separadamente em: $DOMAINS_FILE"
} | tee -a "$LOGFILE"
