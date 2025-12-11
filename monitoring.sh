#!/bin/bash
# script-version:02-004
# Required packages: vnstat sysstat bc dnsutils netcat-openbsd gzip
#
# Changelog v02-004:
# - Fixed network monitoring data extraction from vnstat
# - Improved CPU sampling (1->3 iterations for stable average)
# - Added proper field naming: _used, _total, _free for memory/swap/disk
# - Enhanced error handling and logging
# - Fixed field assignments to prevent data confusion
# - Added network bandwidth calculation
# - Improved vnstat output parsing

# Default configuration
CONFIG_DIR="/etc/monitoring"
VAR_DIR="/opt/monitoring/var"
RUN_DIR="/opt/monitoring/var"
PIDFILE="${RUN_DIR}/monitoring.pid"
IPFILE="${VAR_DIR}/myip"
HOSTIDFILE="${VAR_DIR}/hostid"
NET_PREV_FILE="${VAR_DIR}/net_prev"
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

log_debug() {
    [ "$DEBUG" = "true" ] && echo "[DEBUG] $1"
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

    local deps=(iostat free vnstat dig nc gzip bc awk)
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

# Convert various units to MiB
convert_to_mib() {
    local input="$1"
    local value=$(echo "$input" | sed 's/[^0-9.]//g')
    local unit=$(echo "$input" | sed 's/[0-9.]//g' | tr -d ' ')
    local output

    case "$unit" in
        GiB|GB|G)
            output=$(echo "scale=2; $value * 1024" | bc)
            ;;
        MiB|MB|M|"")
            output="$value"
            ;;
        KiB|KB|K)
            output=$(echo "scale=2; $value / 1024" | bc)
            ;;
        *)
            log_debug "Unknown unit '$unit' in '$input', treating as MiB"
            output="$value"
            ;;
    esac
    
    echo "${output:-0}"
}

# Send data to Graylog (Enhanced GELF format)
convert_to_gelf() {
    local monitor_type="$1"
    local device="$2"
    local timestamp="$3"
    local utilization="${4:-0}"
    local group="$5"
    
    # Optional parameters with defaults
    local used="${6:-0}"
    local total="${7:-0}"
    local free="${8:-0}"
    local rx="${9:-0}"
    local tx="${10:-0}"
    local rate="${11:-0}"
    local load_1min="${12:-0}"
    local load_5min="${13:-0}"
    local load_15min="${14:-0}"
    local ip_g

    ip_g=$(cat "$IPFILE" 2>/dev/null || echo "unknown")

    local json=$(cat <<EOF
{
    "version": "1.1",
    "host": "$HOST_NAME",
    "short_message": "$monitor_type",
    "timestamp": $timestamp,
    "_host_id": "$HOST_ID",
    "_ip_g": "$ip_g",
    "_device": "$device",
    "_group": "$group",
    "_utilization": $utilization,
    "_used": $used,
    "_total": $total,
    "_free": $free,
    "_rx": $rx,
    "_tx": $tx,
    "_rate": $rate,
    "_load_1min": $load_1min,
    "_load_5min": $load_5min,
    "_load_15min": $load_15min
}
EOF
    )

    log_debug "Sending: $monitor_type - $device - utilization: $utilization%"

    if ! echo -n "$json" | gzip | nc -w 1 -u "$GRAYLOG_SERVER" "$GRAYLOG_PORT" 2>/dev/null; then
        [ "$DEBUG" = "true" ] && log_error "Failed to send data to Graylog (type: $monitor_type, device: $device)"
        return 1
    fi
}

# Calculate network bandwidth utilization
calculate_network_utilization() {
    local rx_mib="$1"
    local tx_mib="$2"
    local interval="$3"
    
    # Read previous values
    if [ -f "$NET_PREV_FILE" ]; then
        local prev_data=$(cat "$NET_PREV_FILE")
        local prev_time=$(echo "$prev_data" | cut -d',' -f1)
        local prev_rx=$(echo "$prev_data" | cut -d',' -f2)
        local prev_tx=$(echo "$prev_data" | cut -d',' -f3)
        
        local time_diff=$(($(date +%s) - prev_time))
        
        if [ "$time_diff" -gt 0 ]; then
            local rx_rate=$(echo "scale=2; ($rx_mib - $prev_rx) / $time_diff" | bc)
            local tx_rate=$(echo "scale=2; ($tx_mib - $prev_tx) / $time_diff" | bc)
            local total_rate=$(echo "scale=2; $rx_rate + $tx_rate" | bc)
            
            # Assume 1Gbps = 125 MB/s = 119.2 MiB/s
            # Adjust this value based on your network interface speed
            local bandwidth_mibps=119.2
            local utilization=$(echo "scale=2; ($total_rate / $bandwidth_mibps) * 100" | bc)
            
            # Cap at 100%
            utilization=$(echo "$utilization" | awk '{if($1>100) print 100; else print $1}')
            
            echo "$utilization,$rx_rate,$tx_rate"
        else
            echo "0,0,0"
        fi
    else
        echo "0,0,0"
    fi
    
    # Save current values
    echo "$(date +%s),$rx_mib,$tx_mib" > "$NET_PREV_FILE"
}

# Collect and send monitoring data
collect_data() {
    local timestamp=$(date +%s)

    # Load average
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | sed 's/,//g')
    local load_1min=$(echo "$load_avg" | awk '{print $1}')
    local load_5min=$(echo "$load_avg" | awk '{print $2}')
    local load_15min=$(echo "$load_avg" | awk '{print $3}')

    # CPU monitoring (improved: 3 samples for stable average)
    if iostat_output=$(iostat -c 1 3 2>/dev/null | tail -n +4 | tail -1); then
        local utilization=$(echo "$iostat_output" | awk '{printf "%.2f", 100 - $NF}')
        convert_to_gelf "iostat" "CPU" "$timestamp" "$utilization" "CPU" \
            "0" "0" "0" "0" "0" "0" "$load_1min" "$load_5min" "$load_15min"
    else
        log_error "Failed to get CPU stats"
    fi

    # Memory monitoring
    if mem_output=$(free -m 2>/dev/null | grep "^Mem:"); then
        local total=$(echo "$mem_output" | awk '{print $2}')
        local used=$(echo "$mem_output" | awk '{print $3}')
        local free=$(echo "$mem_output" | awk '{print $4}')
        local available=$(echo "$mem_output" | awk '{print $7}')
        
        # Use available memory for more accurate calculation
        local utilization=$(echo "scale=2; (($total - $available) / $total) * 100" | bc)
        
        convert_to_gelf "free" "Memory" "$timestamp" "$utilization" "Memory" \
            "$used" "$total" "$available" "0" "0" "0" "0" "0" "0"
    else
        log_error "Failed to get memory stats"
    fi

    # Swap monitoring
    if swap_output=$(free -m 2>/dev/null | grep "^Swap:"); then
        local total=$(echo "$swap_output" | awk '{print $2}')
        local used=$(echo "$swap_output" | awk '{print $3}')
        local free=$(echo "$swap_output" | awk '{print $4}')
        
        local utilization=0
        if [ "$total" -gt 0 ]; then
            utilization=$(echo "scale=2; ($used / $total) * 100" | bc)
        fi
        
        convert_to_gelf "swap" "Swap" "$timestamp" "$utilization" "Swap" \
            "$used" "$total" "$free" "0" "0" "0" "0" "0" "0"
    else
        log_error "Failed to get swap stats"
    fi

    # Network monitoring (FIXED)
    if net_output=$(vnstat --oneline 2>/dev/null); then
        local interface=$(echo "$net_output" | cut -d';' -f2 | tr -d ' ')
        
        # Extract today's traffic (fields 4 and 5)
        local rx_raw=$(echo "$net_output" | cut -d';' -f4 | tr -d ' ')
        local tx_raw=$(echo "$net_output" | cut -d';' -f5 | tr -d ' ')
        
        # Convert to MiB
        local rx_mib=$(convert_to_mib "$rx_raw")
        local tx_mib=$(convert_to_mib "$tx_raw")
        
        # Calculate bandwidth utilization and rate
        local net_calc=$(calculate_network_utilization "$rx_mib" "$tx_mib" "$INTERVAL")
        local utilization=$(echo "$net_calc" | cut -d',' -f1)
        local rx_rate=$(echo "$net_calc" | cut -d',' -f2)
        local tx_rate=$(echo "$net_calc" | cut -d',' -f3)
        local total_rate=$(echo "scale=2; $rx_rate + $tx_rate" | bc)
        
        convert_to_gelf "vnstat" "$interface" "$timestamp" "$utilization" "Network" \
            "0" "0" "0" "$rx_mib" "$tx_mib" "$total_rate" "0" "0" "0"
    else
        log_error "Failed to get network stats"
    fi

    # Disk monitoring (root filesystem)
    if df_output=$(df / -BM 2>/dev/null | tail -n1); then
        local total=$(echo "$df_output" | awk '{print $2}' | sed 's/M//g')
        local used=$(echo "$df_output" | awk '{print $3}' | sed 's/M//g')
        local free=$(echo "$df_output" | awk '{print $4}' | sed 's/M//g')
        local utilization=$(echo "$df_output" | awk '{print $5}' | sed 's/%//g')
        
        convert_to_gelf "df" "Disk" "$timestamp" "$utilization" "Disk" \
            "$used" "$total" "$free" "0" "0" "0" "0" "0" "0"
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
        log_error "Process already running (PID: $(cat "$PIDFILE"))"
        exit 1
    fi

    # Set up trap for cleanup
    trap cleanup SIGTERM SIGINT SIGQUIT

    # Write PID file
    echo $$ > "$PIDFILE"

    # Initial IP update
    update_ip

    # Start monitoring
    log_info "Starting monitoring service v02-004"
    log_info "HOST_ID: ${HOST_ID}"
    log_info "Target: ${GRAYLOG_SERVER}:${GRAYLOG_PORT}"
    log_info "Interval: ${INTERVAL}s"
    monitor_loop
}

# Run main function
main "$@"
