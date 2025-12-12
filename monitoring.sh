#!/bin/bash
# script-version:02-006-lxc-fix
# Required packages: vnstat sysstat bc dnsutils netcat-openbsd gzip
#
# Changelog v02-006-lxc-fix:
# - Fixed: LXC container interface name issue (eth0@if44 -> eth0)
# - Now correctly handles interface names with @ suffix in /proc/net/dev lookup
#
# Changelog v02-006:
# - Fixed: bc output formatting issue (.88 -> 0.88) for proper JSON/Graylog parsing
# - All numeric values now use printf for consistent formatting
#
# Changelog v02-005:
# - Added OS information detection and sending
# - Added network configuration in config file
# - Fixed vnstat field mapping for different environments
# - Added network interface and bandwidth configuration
# - Improved error handling

# Default configuration
CONFIG_DIR="/etc/monitoring"
VAR_DIR="/opt/monitoring/var"
RUN_DIR="/opt/monitoring/var"
PIDFILE="${RUN_DIR}/monitoring.pid"
IPFILE="${VAR_DIR}/myip"
HOSTIDFILE="${VAR_DIR}/hostid"
OSFILE="${VAR_DIR}/osinfo"
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

# Network configuration (can be overridden in config)
NETWORK_INTERFACE="${NETWORK_INTERFACE:-auto}"  # auto, eth0, ens3, etc.
NETWORK_BANDWIDTH_MBPS="${NETWORK_BANDWIDTH_MBPS:-1000}"  # Default 1Gbps
NETWORK_METHOD="${NETWORK_METHOD:-auto}"  # auto, vnstat, procnet
NETWORK_MODE="${NETWORK_MODE:-total}"  # total (合計), each (個別), both (両方)
VNSTAT_RX_FIELD="${VNSTAT_RX_FIELD:-4}"  # vnstat --oneline field number for RX
VNSTAT_TX_FIELD="${VNSTAT_TX_FIELD:-5}"  # vnstat --oneline field number for TX

# OS information (can be overridden in config)
OS_INFO="${OS_INFO:-auto}"  # auto, or specify like "Ubuntu 20.04"

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

# Format number to ensure proper JSON format (prevent .88 -> 0.88)
format_number() {
    local value="$1"
    local scale="${2:-2}"
    
    # If empty or invalid, return 0
    if [ -z "$value" ] || ! [[ "$value" =~ ^-?[0-9]*\.?[0-9]+$ ]]; then
        printf "%.${scale}f" "0"
        return
    fi
    
    printf "%.${scale}f" "$value"
}

# Detect OS information
detect_os_info() {
    if [ "$OS_INFO" != "auto" ]; then
        echo "$OS_INFO"
        return
    fi
    
    local os_info="unknown"
    
    # Try /etc/os-release (most modern systems)
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        os_info="${NAME:-unknown} ${VERSION_ID:-unknown}"
    # Try lsb_release
    elif command -v lsb_release >/dev/null 2>&1; then
        os_info=$(lsb_release -d | cut -f2-)
    # Try /etc/redhat-release
    elif [ -f /etc/redhat-release ]; then
        os_info=$(cat /etc/redhat-release)
    # Try /etc/debian_version
    elif [ -f /etc/debian_version ]; then
        os_info="Debian $(cat /etc/debian_version)"
    # Try uname as last resort
    else
        os_info="$(uname -s) $(uname -r)"
    fi
    
    echo "$os_info"
}

# Initialize OS info
init_os_info() {
    if [ ! -f "$OSFILE" ] || [ "$OS_INFO" = "auto" ]; then
        local detected_os=$(detect_os_info)
        echo "$detected_os" > "$OSFILE"
        log_info "Detected OS: $detected_os"
    fi
    OS_INFO_CURRENT=$(cat "$OSFILE")
}

# Detect network interface
detect_network_interface() {
    if [ "$NETWORK_INTERFACE" != "auto" ]; then
        echo "$NETWORK_INTERFACE"
        return
    fi
    
    # Try to get default interface
    local iface=$(ip route | grep default | awk '{print $5}' | head -1)
    
    if [ -z "$iface" ]; then
        # Fallback: try common names
        for name in eth0 ens3 ens33 enp0s3 eno1; do
            if [ -d "/sys/class/net/$name" ]; then
                iface="$name"
                break
            fi
        done
    fi
    
    echo "${iface:-eth0}"
}

# Detect network bandwidth
detect_network_bandwidth() {
    local interface="$1"
    
    if [ "$NETWORK_BANDWIDTH_MBPS" != "auto" ] && [ "$NETWORK_BANDWIDTH_MBPS" -gt 0 ]; then
        echo "$NETWORK_BANDWIDTH_MBPS"
        return
    fi
    
    # Try to read from sysfs
    local speed_file="/sys/class/net/$interface/speed"
    if [ -f "$speed_file" ]; then
        local speed=$(cat "$speed_file" 2>/dev/null)
        if [ -n "$speed" ] && [ "$speed" -gt 0 ] 2>/dev/null; then
            echo "$speed"
            return
        fi
    fi
    
    # Default to 1Gbps
    echo "1000"
}

# Generate or load HOST_ID
init_host_id() {
    if [ ! -f "$HOSTIDFILE" ]; then
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

    local deps=(free dig nc gzip bc awk)
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_error "Required command not found: $cmd"
            exit 1
        fi
    done
    
    # Optional dependencies
    if ! command -v iostat >/dev/null 2>&1; then
        log_info "iostat not found - CPU monitoring will use fallback method"
    fi
    if ! command -v vnstat >/dev/null 2>&1; then
        log_info "vnstat not found - network monitoring will use /proc/net/dev"
    fi

    # Initialize HOST_ID and OS info
    init_host_id
    init_os_info
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
    local ip_update_interval=3600

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
            output=$(echo "scale=4; $value * 1024" | bc)
            ;;
        MiB|MB|M|"")
            output="$value"
            ;;
        KiB|KB|K)
            output=$(echo "scale=4; $value / 1024" | bc)
            ;;
        *)
            log_debug "Unknown unit '$unit' in '$input', treating as MiB"
            output="$value"
            ;;
    esac
    
    format_number "${output:-0}" 2
}

# Send data to Graylog (Enhanced GELF format with OS info)
convert_to_gelf() {
    local monitor_type="$1"
    local device="$2"
    local timestamp="$3"
    local utilization="${4:-0}"
    local group="$5"
    
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
    
    # Format all numbers properly
    utilization=$(format_number "$utilization" 2)
    used=$(format_number "$used" 2)
    total=$(format_number "$total" 2)
    free=$(format_number "$free" 2)
    rx=$(format_number "$rx" 2)
    tx=$(format_number "$tx" 2)
    rate=$(format_number "$rate" 2)
    load_1min=$(format_number "$load_1min" 2)
    load_5min=$(format_number "$load_5min" 2)
    load_15min=$(format_number "$load_15min" 2)

    local json=$(cat <<EOF
{
    "version": "1.1",
    "host": "$HOST_NAME",
    "short_message": "$monitor_type",
    "timestamp": $timestamp,
    "_host_id": "$HOST_ID",
    "_ip_g": "$ip_g",
    "_os_info": "$OS_INFO_CURRENT",
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
    local bandwidth_mibps="$4"
    local prev_file="${5:-$NET_PREV_FILE}"  # Use custom prev file or default
    
    if [ -f "$prev_file" ]; then
        local prev_data=$(cat "$prev_file")
        local prev_time=$(echo "$prev_data" | cut -d',' -f1)
        local prev_rx=$(echo "$prev_data" | cut -d',' -f2)
        local prev_tx=$(echo "$prev_data" | cut -d',' -f3)
        
        local time_diff=$(($(date +%s) - prev_time))
        
        if [ "$time_diff" -gt 0 ]; then
            local rx_rate=$(echo "scale=4; ($rx_mib - $prev_rx) / $time_diff" | bc)
            local tx_rate=$(echo "scale=4; ($tx_mib - $prev_tx) / $time_diff" | bc)
            
            # Format properly
            rx_rate=$(format_number "$rx_rate" 2)
            tx_rate=$(format_number "$tx_rate" 2)
            
            # Handle negative values (counter reset)
            if [ $(echo "$rx_rate < 0" | bc) -eq 1 ]; then rx_rate="0.00"; fi
            if [ $(echo "$tx_rate < 0" | bc) -eq 1 ]; then tx_rate="0.00"; fi
            
            local total_rate=$(echo "scale=4; $rx_rate + $tx_rate" | bc)
            total_rate=$(format_number "$total_rate" 2)
            
            local utilization=$(echo "scale=4; ($total_rate / $bandwidth_mibps) * 100" | bc)
            utilization=$(format_number "$utilization" 2)
            
            # Cap at 100%
            if [ $(echo "$utilization < 0" | bc) -eq 1 ]; then
                utilization="0.00"
            elif [ $(echo "$utilization > 100" | bc) -eq 1 ]; then
                utilization="100.00"
            fi
            
            echo "$utilization,$rx_rate,$tx_rate"
        else
            echo "0.00,0.00,0.00"
        fi
    else
        echo "0.00,0.00,0.00"
    fi
    
    # Save current values
    echo "$(date +%s),$rx_mib,$tx_mib" > "$prev_file"
}

# Monitor CPU
monitor_cpu() {
    local timestamp="$1"
    local load_1min="$2"
    local load_5min="$3"
    local load_15min="$4"
    
    if command -v iostat >/dev/null 2>&1; then
        if iostat_output=$(iostat -c 1 3 2>/dev/null); then
            # Get the last set of CPU stats (after 3 second sampling)
            local idle=$(echo "$iostat_output" | awk '/^[[:space:]]*[0-9]/ {idle=$NF} END {print idle}')
            
            if [[ "$idle" =~ ^[0-9]+\.?[0-9]*$ ]]; then
                local utilization_raw=$(echo "scale=4; 100 - $idle" | bc)
                local utilization=$(format_number "$utilization_raw" 2)
                
                # Ensure range 0-100
                if [ $(echo "$utilization < 0" | bc) -eq 1 ]; then
                    utilization="0.00"
                elif [ $(echo "$utilization > 100" | bc) -eq 1 ]; then
                    utilization="100.00"
                fi
                
                convert_to_gelf "iostat" "CPU" "$timestamp" "$utilization" "CPU" \
                    "0" "0" "0" "0" "0" "0" "$load_1min" "$load_5min" "$load_15min"
                return 0
            fi
        fi
    fi
    
    log_error "Failed to get CPU stats"
}

# Get network stats for a single interface from /proc/net/dev
get_interface_stats() {
    local interface="$1"
    
    # Remove @ifXX suffix for LXC containers (e.g., eth0@if44 -> eth0)
    interface="${interface%%@*}"
    
    if [ ! -f "/proc/net/dev" ]; then
        echo "0.00,0.00"
        return 1
    fi
    
    local net_line=$(grep "^[[:space:]]*$interface:" /proc/net/dev | head -1)
    if [ -n "$net_line" ]; then
        local rx_bytes=$(echo "$net_line" | awk '{print $2}')
        local tx_bytes=$(echo "$net_line" | awk '{print $10}')
        local rx_mib_raw=$(echo "scale=4; $rx_bytes / 1048576" | bc)
        local tx_mib_raw=$(echo "scale=4; $tx_bytes / 1048576" | bc)
        local rx_mib=$(format_number "$rx_mib_raw" 2)
        local tx_mib=$(format_number "$tx_mib_raw" 2)
        echo "$rx_mib,$tx_mib"
        return 0
    fi
    
    echo "0.00,0.00"
    return 1
}

# Monitor single network interface
monitor_single_interface() {
    local timestamp="$1"
    local interface="$2"
    local bandwidth_mbps="$3"
    local prev_file="$4"
    
    local bandwidth_mibps_raw=$(echo "scale=4; $bandwidth_mbps / 8.388608" | bc)
    local bandwidth_mibps=$(format_number "$bandwidth_mibps_raw" 2)
    local rx_mib="0.00"
    local tx_mib="0.00"
    
    # Try vnstat first (if method is auto or vnstat)
    if [ "$NETWORK_METHOD" = "auto" ] || [ "$NETWORK_METHOD" = "vnstat" ]; then
        if command -v vnstat >/dev/null 2>&1; then
            if net_output=$(vnstat -i "$interface" --oneline 2>/dev/null); then
                log_debug "vnstat output for $interface: $net_output"
                
                local rx_raw=$(echo "$net_output" | cut -d';' -f"$VNSTAT_RX_FIELD" | tr -d ' ')
                local tx_raw=$(echo "$net_output" | cut -d';' -f"$VNSTAT_TX_FIELD" | tr -d ' ')
                
                if [ -n "$rx_raw" ] && [ -n "$tx_raw" ]; then
                    rx_mib=$(convert_to_mib "$rx_raw")
                    tx_mib=$(convert_to_mib "$tx_raw")
                    
                    local net_calc=$(calculate_network_utilization "$rx_mib" "$tx_mib" "$INTERVAL" "$bandwidth_mibps" "$prev_file")
                    local utilization=$(echo "$net_calc" | cut -d',' -f1)
                    local rx_rate=$(echo "$net_calc" | cut -d',' -f2)
                    local tx_rate=$(echo "$net_calc" | cut -d',' -f3)
                    local total_rate_raw=$(echo "scale=4; $rx_rate + $tx_rate" | bc)
                    local total_rate=$(format_number "$total_rate_raw" 2)
                    
                    convert_to_gelf "vnstat" "$interface" "$timestamp" "$utilization" "Network" \
                        "0" "0" "0" "$rx_mib" "$tx_mib" "$total_rate" "0" "0" "0"
                    return 0
                fi
            fi
        fi
    fi
    
    # Fallback to /proc/net/dev
    local stats=$(get_interface_stats "$interface")
    rx_mib=$(echo "$stats" | cut -d',' -f1)
    tx_mib=$(echo "$stats" | cut -d',' -f2)
    
    if [ "$rx_mib" != "0.00" ] || [ "$tx_mib" != "0.00" ]; then
        local net_calc=$(calculate_network_utilization "$rx_mib" "$tx_mib" "$INTERVAL" "$bandwidth_mibps" "$prev_file")
        local utilization=$(echo "$net_calc" | cut -d',' -f1)
        local rx_rate=$(echo "$net_calc" | cut -d',' -f2)
        local tx_rate=$(echo "$net_calc" | cut -d',' -f3)
        local total_rate_raw=$(echo "scale=4; $rx_rate + $tx_rate" | bc)
        local total_rate=$(format_number "$total_rate_raw" 2)
        
        convert_to_gelf "procnet" "$interface" "$timestamp" "$utilization" "Network" \
            "0" "0" "0" "$rx_mib" "$tx_mib" "$total_rate" "0" "0" "0"
        return 0
    fi
    
    return 1
}

# Monitor network with configurable mode (total/each/both)
monitor_network() {
    local timestamp="$1"
    
    case "$NETWORK_MODE" in
        total)
            # Monitor total of all interfaces
            monitor_network_total "$timestamp"
            ;;
        each)
            # Monitor each interface separately
            monitor_network_each "$timestamp"
            ;;
        both)
            # Monitor both total and each interface
            monitor_network_total "$timestamp"
            monitor_network_each "$timestamp"
            ;;
        *)
            log_error "Invalid NETWORK_MODE: $NETWORK_MODE"
            ;;
    esac
}

# Monitor total network usage (all interfaces combined)
monitor_network_total() {
    local timestamp="$1"
    
    # Get all active interfaces (excluding lo)
    local interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "^lo$")
    
    local total_rx_mib="0.00"
    local total_tx_mib="0.00"
    local interface_count=0
    
    # Sum up all interfaces
    for iface in $interfaces; do
        # Remove @ifXX suffix for LXC containers (e.g., eth0@if44 -> eth0)
        local clean_iface="${iface%%@*}"
        
        local stats=$(get_interface_stats "$clean_iface")
        local rx=$(echo "$stats" | cut -d',' -f1)
        local tx=$(echo "$stats" | cut -d',' -f2)
        
        if [ "$rx" != "0.00" ] || [ "$tx" != "0.00" ]; then
            local total_rx_raw=$(echo "scale=4; $total_rx_mib + $rx" | bc)
            local total_tx_raw=$(echo "scale=4; $total_tx_mib + $tx" | bc)
            total_rx_mib=$(format_number "$total_rx_raw" 2)
            total_tx_mib=$(format_number "$total_tx_raw" 2)
            interface_count=$((interface_count + 1))
        fi
    done
    
    if [ "$interface_count" -gt 0 ]; then
        # Use configured bandwidth or detect from primary interface
        local primary_interface=$(detect_network_interface)
        local bandwidth_mbps=$(detect_network_bandwidth "$primary_interface")
        
        # If multiple interfaces, multiply bandwidth
        if [ "$interface_count" -gt 1 ]; then
            bandwidth_mbps=$((bandwidth_mbps * interface_count))
        fi
        
        local bandwidth_mibps_raw=$(echo "scale=4; $bandwidth_mbps / 8.388608" | bc)
        local bandwidth_mibps=$(format_number "$bandwidth_mibps_raw" 2)
        
        local net_calc=$(calculate_network_utilization "$total_rx_mib" "$total_tx_mib" "$INTERVAL" "$bandwidth_mibps" "$NET_PREV_FILE")
        local utilization=$(echo "$net_calc" | cut -d',' -f1)
        local rx_rate=$(echo "$net_calc" | cut -d',' -f2)
        local tx_rate=$(echo "$net_calc" | cut -d',' -f3)
        local total_rate_raw=$(echo "scale=4; $rx_rate + $tx_rate" | bc)
        local total_rate=$(format_number "$total_rate_raw" 2)
        
        convert_to_gelf "procnet" "Total" "$timestamp" "$utilization" "Network" \
            "0" "0" "0" "$total_rx_mib" "$total_tx_mib" "$total_rate" "0" "0" "0"
        
        log_debug "Network Total: ${interface_count} interfaces, RX=${total_rx_mib}MiB, TX=${total_tx_mib}MiB"
    else
        log_error "No active network interfaces found"
    fi
}

# Monitor each network interface separately
monitor_network_each() {
    local timestamp="$1"
    
    # Get all active interfaces (excluding lo)
    local interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "^lo$")
    
    local interface_count=0
    for iface in $interfaces; do
        # Remove @ifXX suffix for LXC containers (e.g., eth0@if44 -> eth0)
        local clean_iface="${iface%%@*}"
        
        # Check if interface has traffic
        local stats=$(get_interface_stats "$clean_iface")
        local rx=$(echo "$stats" | cut -d',' -f1)
        local tx=$(echo "$stats" | cut -d',' -f2)
        
        if [ "$rx" != "0.00" ] || [ "$tx" != "0.00" ]; then
            local bandwidth_mbps=$(detect_network_bandwidth "$clean_iface")
            local prev_file="${NET_PREV_FILE}.${clean_iface}"
            
            monitor_single_interface "$timestamp" "$clean_iface" "$bandwidth_mbps" "$prev_file"
            interface_count=$((interface_count + 1))
        fi
    done
    
    if [ "$interface_count" -eq 0 ]; then
        log_error "No active network interfaces found"
    else
        log_debug "Monitored $interface_count network interfaces"
    fi
}

# Collect and send monitoring data
collect_data() {
    local timestamp=$(date +%s)

    # Load average
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | sed 's/,//g')
    local load_1min=$(echo "$load_avg" | awk '{print $1}')
    local load_5min=$(echo "$load_avg" | awk '{print $2}')
    local load_15min=$(echo "$load_avg" | awk '{print $3}')

    # CPU monitoring
    monitor_cpu "$timestamp" "$load_1min" "$load_5min" "$load_15min"

    # Memory monitoring
    if mem_output=$(free -m 2>/dev/null | grep "^Mem:"); then
        local total=$(echo "$mem_output" | awk '{print $2}')
        local available=$(echo "$mem_output" | awk '{print $7}')
        
        if [ -z "$available" ] || [ "$available" = "0" ]; then
            local used=$(echo "$mem_output" | awk '{print $3}')
            local free=$(echo "$mem_output" | awk '{print $4}')
            local buff_cache=$(echo "$mem_output" | awk '{print $6}')
            available=$((free + buff_cache))
        fi
        
        local utilization_raw=$(echo "scale=4; (($total - $available) / $total) * 100" | bc)
        local utilization=$(format_number "$utilization_raw" 2)
        local used=$((total - available))
        
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
        
        local utilization="0.00"
        if [ "$total" -gt 0 ]; then
            local utilization_raw=$(echo "scale=4; ($used / $total) * 100" | bc)
            utilization=$(format_number "$utilization_raw" 2)
        fi
        
        convert_to_gelf "swap" "Swap" "$timestamp" "$utilization" "Swap" \
            "$used" "$total" "$free" "0" "0" "0" "0" "0" "0"
    else
        log_error "Failed to get swap stats"
    fi

    # Network monitoring
    monitor_network "$timestamp"

    # Disk monitoring
    if df_output=$(df / -BM 2>/dev/null | tail -n1); then
        local total=$(echo "$df_output" | awk '{print $2}' | sed 's/M//g')
        local used=$(echo "$df_output" | awk '{print $3}' | sed 's/M//g')
        local free=$(echo "$df_output" | awk '{print $4}' | sed 's/M//g')
        local utilization=$(echo "$df_output" | awk '{print $5}' | sed 's/%//g')
        
        if [[ "$utilization" =~ ^[0-9]+$ ]]; then
            utilization=$(format_number "$utilization" 0)
            
            convert_to_gelf "df" "Disk" "$timestamp" "$utilization" "Disk" \
                "$used" "$total" "$free" "0" "0" "0" "0" "0" "0"
        else
            log_error "Invalid disk utilization: $utilization"
        fi
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

    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
        log_error "Process already running (PID: $(cat "$PIDFILE"))"
        exit 1
    fi

    trap cleanup SIGTERM SIGINT SIGQUIT

    echo $$ > "$PIDFILE"
    update_ip

    log_info "Starting monitoring service v02-006-lxc-fix"
    log_info "HOST_ID: ${HOST_ID}"
    log_info "OS: ${OS_INFO_CURRENT}"
    log_info "Target: ${GRAYLOG_SERVER}:${GRAYLOG_PORT}"
    log_info "Interval: ${INTERVAL}s"
    log_info "Network: mode=${NETWORK_MODE}, interface=${NETWORK_INTERFACE}, bandwidth=${NETWORK_BANDWIDTH_MBPS}Mbps, method=${NETWORK_METHOD}"
    
    monitor_loop
}

main "$@"
