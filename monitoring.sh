#!/bin/bash
# script-version:02-003
# Required packages: vnstat sysstat bc dnsutils netcat-openbsd gzip

# Default configuration
CONFIG_DIR="/etc/monitoring"
VAR_DIR="/opt/monitoring/var"
RUN_DIR="/opt/monitoring/var"
PIDFILE="${RUN_DIR}/monitoring.pid"
IPFILE="${VAR_DIR}/myip"
HOSTIDFILE="${VAR_DIR}/hostid"
LOG_TAG="monitoring"

# Load configuration if exists
if [ -f "${CONFIG_DIR}/config" ]; then
    source "${CONFIG_DIR}/config"
fi

# Default values if not set in config
GRAYLOG_SERVER="${GRAYLOG_SERVER:-graylog.syushi.com}"
GRAYLOG_PORT="${GRAYLOG_PORT:-11514}"
INTERVAL="${MONITORING_INTERVAL:-5}"
DEBUG="${DEBUG:-false}"
HOST_NAME="${HOST_NAME:-$(hostname)}"

# Logging functions
log_error() {
    logger -t "$LOG_TAG" -p error "$1"
    echo "[ERROR] $1" >&2
}

log_info() {
    logger -t "$LOG_TAG" -p info "$1"
    [ "$DEBUG" = "true" ] && echo "[INFO] $1"
}

# Generate or load HOST_ID
init_host_id() {
    if [ ! -f "$HOSTIDFILE" ]; then
        # Generate UUID-like HOST_ID
        local host_id=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "$(hostname)-$(date +%s)")
        echo "$host_id" > "$HOSTIDFILE"
        log_info "Generated new HOST_ID: $host_id"
    fi
    HOST_ID=$(cat "$HOSTIDFILE")
}

# Initialize directories and check dependencies
init() {
    local dirs=("$CONFIG_DIR" "$VAR_DIR" "$RUN_DIR")
    for dir in "${dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir" || {
                log_error "Failed to create directory: $dir"
                exit 1
            }
        fi
    done

    local deps=(iostat free vnstat dig nc gzip bc)
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_error "Required command not found: $cmd"
            exit 1
        fi
    done

    # Initialize HOST_ID
    init_host_id
}

# Process command line options
process_options() {
    while getopts "d" opt; do
        case $opt in
            d)
                GRAYLOG_SERVER="127.0.0.1"
                log_info "Using localhost as Graylog server"
                ;;
            \?)
                log_error "Invalid option: -$OPTARG"
                exit 1
                ;;
        esac
    done
}

# Check and update IP address
update_ip() {
    local current_time=$(date +%s)
    local ip_update_interval=3600  # Update IP every hour

    if [ ! -f "$IPFILE" ] || [ $((current_time - $(stat -c %Y "$IPFILE" 2>/dev/null || echo 0))) -gt "$ip_update_interval" ]; then
        if ! dig +short myip.opendns.com @208.67.222.222 > "${IPFILE}.tmp" 2>/dev/null; then
            log_error "Failed to update IP address"
            return 1
        fi
        mv "${IPFILE}.tmp" "$IPFILE"
    fi
}

# Convert GiB to MiB
convert_gib_to_mib() {
    local input="$1"
    local output

    if [[ $input == *'GiB'* ]]; then
        local gib_value=$(echo "$input" | sed 's/[^0-9.]*//g')
        output=$(echo "scale=2; $gib_value * 1024" | bc)
    else
        output=$(echo "$input" | sed 's/[^0-9.]*//g')
    fi
    echo "${output:-0}"
}

# Send data to Graylog
convert_to_gelf() {
    local monitor_type="$1"
    local device="$2"
    local timestamp="$3"
    local utilization="${4:-0}"
    local rx="${5:-0}"
    local tx="${6:-0}"
    local group="$7"
    local rate="${8:-0}"
    local empt_size="${9:-0}"
    local load_1min="${10:-0}"
    local load_5min="${11:-0}"
    local load_15min="${12:-0}"
    local ip_g

    ip_g=$(cat "$IPFILE" 2>/dev/null || echo "unknown")

    local json=$(cat <<EOF
{
    "version": "1.1",
    "host": "$HOST_NAME",
    "short_message": "$monitor_type",
    "timestamp": $timestamp,
    "_host_id": "$HOST_ID",
    "_ip-g": "$ip_g",
    "_device": "$device",
    "_utilization": $utilization,
    "_rx": $rx,
    "_tx": $tx,
    "_group": "$group",
    "_rate": $rate,
    "_empt_size": $empt_size,
    "_load_1min": $load_1min,
    "_load_5min": $load_5min,
    "_load_15min": $load_15min
}
EOF
    )

    if ! echo -n "$json" | gzip | nc -w 1 -u "$GRAYLOG_SERVER" "$GRAYLOG_PORT" 2>/dev/null; then
        [ "$DEBUG" = "true" ] && log_error "Failed to send data to Graylog (type: $monitor_type)"
        return 1
    fi
}

# Collect and send monitoring data
collect_data() {
    local timestamp=$(date +%s)

    # ロードアベレージの取得
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | sed 's/,//g')
    local load_1min=$(echo "$load_avg" | awk '{print $1}')
    local load_5min=$(echo "$load_avg" | awk '{print $2}')
    local load_15min=$(echo "$load_avg" | awk '{print $3}')

    # CPU monitoring
    if iostat_output=$(iostat -c 1 2 | tail -n +4 | tail -1 2>/dev/null); then
        local utilization=$(echo "$iostat_output" | awk '{print 100 - $NF}')
        convert_to_gelf "iostat" "CPU" "$timestamp" "$utilization" "0" "0" "CPU" "0" "0" "$load_1min" "$load_5min" "$load_15min"
    else
        log_error "Failed to get CPU stats"
    fi

    # Memory monitoring (without Swap)
    if mem_output=$(free -m | grep Mem 2>/dev/null); then
        local total=$(echo "$mem_output" | awk '{print $2}')
        local used=$(echo "$mem_output" | awk '{print $3}')
        local utilization=$(echo "$mem_output" | awk '{print $3/$2 * 100.0}')
        convert_to_gelf "free" "Memory" "$timestamp" "$utilization" "$used" "$total" "Memory" "0" "0" "0" "0" "0"
    else
        log_error "Failed to get memory stats"
    fi

    # Swap monitoring
    if swap_output=$(free -m | grep Swap 2>/dev/null); then
        local total=$(echo "$swap_output" | awk '{print $2}')
        local used=$(echo "$swap_output" | awk '{print $3}')
        
        if [ "$total" -gt 0 ]; then
            local utilization=$(echo "scale=2; $used/$total * 100" | bc)
            convert_to_gelf "swap" "Swap" "$timestamp" "$utilization" "$used" "$total" "Swap" "0" "0" "0" "0" "0"
        else
            convert_to_gelf "swap" "Swap" "$timestamp" "0" "0" "0" "Swap" "0" "0" "0" "0" "0"
        fi
    else
        log_error "Failed to get swap stats"
    fi

    # Network monitoring
    if net_output=$(vnstat --oneline 2>/dev/null | cut -d ";" -f 11); then
        local rx=$(convert_gib_to_mib "$(echo "$net_output" | cut -d ";" -f 4)")
        local tx=$(convert_gib_to_mib "$(echo "$net_output" | cut -d ";" -f 5)")
        local rate=$(echo "$net_output" | cut -d ";" -f 7)
        local utilization=$(echo "$net_output" | awk '{print $1}')
        convert_to_gelf "vnstat" "Network" "$timestamp" "$utilization" "$rx" "$tx" "Network" "$rate" "0" "0" "0" "0"
    else
        log_error "Failed to get network stats"
    fi

    # Disk monitoring
    if df_output=$(df / -B m 2>/dev/null); then
        local utilization=$(echo "$df_output" | awk 'NR==2 {gsub(/[^0-9]/, "", $5); print $5}')
        local empt_size=$(echo "$df_output" | awk 'NR==2 {gsub(/[^0-9]/, "", $4); print $4}')
        convert_to_gelf "df" "Disk" "$timestamp" "$utilization" "0" "0" "Disk" "0" "$empt_size" "0" "0" "0"
    else
        log_error "Failed to get disk stats"
    fi
}

# Main monitoring loop
monitor_loop() {
    while true; do
        collect_data
        sleep "$INTERVAL"
    done
}

# Cleanup function
cleanup() {
    log_info "Stopping monitoring service"
    rm -f "$PIDFILE"
    exit 0
}

# Main function
main() {
    init
    process_options "$@"

    # Check if process is already running
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
        log_error "Process already running"
        exit 1
    fi

    # Set up trap for cleanup
    trap cleanup SIGTERM SIGINT SIGQUIT

    # Write PID file
    echo $$ > "$PIDFILE"

    # Initial IP update
    update_ip

    # Start monitoring
    log_info "Starting monitoring service (HOST_ID: ${HOST_ID}, sending to ${GRAYLOG_SERVER}:${GRAYLOG_PORT})"
    monitor_loop
}

# Run main function
main "$@"
