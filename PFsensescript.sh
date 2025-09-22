#!/usr/bin/env bash
# pfSense Performance Diagnostic Script  
# Validates system tunables, hardware acceleration, and network configuration
# Version: 1.0

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="${SCRIPT_DIR}/pfsense_diagnostic_$(date +%Y%m%d_%H%M%S).log"
readonly VERBOSE=${VERBOSE:-false}

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# Logging functions
setup_logging() {
    exec 3>&1 1>"$LOG_FILE" 2>&1
    trap "echo -e '${RED}ERROR: Check log file for details: $LOG_FILE${NC}' >&3" ERR
    trap cleanup EXIT
}

cleanup() {
    trap - EXIT
}

log_info() {
    echo "INFO: $1"
    [[ "$VERBOSE" == "true" ]] && echo "INFO: $1" >&3
}

log_warning() {
    echo -e "${YELLOW}WARNING: $1${NC}"
    echo -e "${YELLOW}WARNING: $1${NC}" >&3
}

log_error() {
    echo -e "${RED}ERROR: $1${NC}"
    echo -e "${RED}ERROR: $1${NC}" >&3
}

log_success() {
    echo -e "${GREEN}SUCCESS: $1${NC}"
    echo -e "${GREEN}SUCCESS: $1${NC}" >&3
}

print_header() {
    echo "==================" >&3
    echo "$1" >&3
    echo "==================" >&3
}

print_section() {
    echo "" >&3
    echo "--- $1 ---" >&3
}

# Check if running on pfSense
verify_pfsense() {
    if [[ ! -f /etc/version ]] || ! grep -q "pfSense" /etc/version 2>/dev/null; then
        log_error "This script must be run on a pfSense system"
        exit 1
    fi
    
    if ! command -v pfctl >/dev/null 2>&1; then
        log_error "pfctl command not found. Is this a pfSense system?"
        exit 1
    fi
    
    log_success "pfSense environment detected"
}

# System Tunables Validation
check_system_tunables() {
    print_section "System Tunables Analysis"
    
    # Check kern.ipc.nmbclusters
    local nmbclusters
    nmbclusters=$(sysctl -n kern.ipc.nmbclusters 2>/dev/null || echo "0")
    
    local total_mem_mb
    total_mem_mb=$(sysctl -n hw.physmem | awk '{print int($1/1024/1024)}')
    
    # Calculate recommended nmbclusters based on memory
    local recommended_nmbclusters
    if [[ $total_mem_mb -le 4096 ]]; then
        recommended_nmbclusters=262144
    elif [[ $total_mem_mb -le 16384 ]]; then
        recommended_nmbclusters=524288
    else
        recommended_nmbclusters=1000000
    fi
    
    log_info "Current nmbclusters: $nmbclusters"
    log_info "Recommended nmbclusters for ${total_mem_mb}MB RAM: $recommended_nmbclusters"
    
    if [[ $nmbclusters -lt $recommended_nmbclusters ]]; then
        log_warning "nmbclusters may be too low - consider increasing to $recommended_nmbclusters"
    else
        log_success "nmbclusters properly configured"
    fi
    
    # Check mbuf usage
    log_info "Checking current mbuf utilization..."
    netstat -m | grep -E "(mbufs in use|mbuf clusters)" >&3
    
    local mbufs_denied
    mbufs_denied=$(netstat -m | grep "denied" | wc -l)
    
    if [[ $mbufs_denied -gt 0 ]]; then
        log_warning "mbuf allocation denials detected - increase nmbclusters"
        netstat -m | grep "denied" >&3
    else
        log_success "No mbuf allocation denials"
    fi
    
    # Check other important tunables
    local maxsockbuf
    maxsockbuf=$(sysctl -n kern.ipc.maxsockbuf 2>/dev/null || echo "0")
    
    if [[ $maxsockbuf -lt 16777216 ]]; then
        log_warning "kern.ipc.maxsockbuf ($maxsockbuf) may be too low - consider 16777216"
    else
        log_success "Socket buffer size properly configured: $maxsockbuf"
    fi
    
    local somaxconn
    somaxconn=$(sysctl -n kern.ipc.somaxconn 2>/dev/null || echo "0")
    
    if [[ $somaxconn -lt 4096 ]]; then
        log_warning "kern.ipc.somaxconn ($somaxconn) may be too low for high-connection loads"
    else
        log_success "Connection backlog properly configured: $somaxconn"
    fi
}

# Hardware Acceleration Check
check_hardware_acceleration() {
    print_section "Hardware Acceleration Analysis"
    
    # Check AES-NI support
    if dmesg | grep -i "aes" | head -5 >&3; then
        log_success "AES-NI hardware acceleration available"
    else
        log_warning "AES-NI acceleration not detected"
    fi
    
    # Check current crypto acceleration setting
    if kldstat | grep -q "aesni"; then
        log_success "AES-NI kernel module loaded"
    else
        log_warning "AES-NI kernel module not loaded"
    fi
    
    # Check crypto performance
    log_info "Testing crypto performance..."
    if command -v openssl >/dev/null 2>&1; then
        openssl speed -evp aes-128-cbc 2>/dev/null | tail -5 >&3 || true
    fi
    
    # Check for Intel QuickAssist Technology
    if dmesg | grep -i "quickassist\|qat" >/dev/null 2>&1; then
        log_success "Intel QuickAssist Technology detected"
    fi
}

# Network Interface Configuration
check_network_interfaces() {
    print_section "Network Interface Configuration"
    
    # Get list of network interfaces (exclude lo)
    local interfaces
    interfaces=$(ifconfig -l | tr ' ' '\n' | grep -v "lo0\|pflog\|pfsync" | sort)
    
    while read -r interface; do
        [[ -z "$interface" ]] && continue
        
        log_info "Analyzing interface: $interface"
        
        # Check interface status
        if ifconfig "$interface" | grep -q "status: active"; then
            log_success "Interface $interface: ACTIVE"
        else
            log_warning "Interface $interface: Not active"
            continue
        fi
        
        # Check MTU settings
        local mtu
        mtu=$(ifconfig "$interface" | grep "mtu" | grep -o "mtu [0-9]*" | awk '{print $2}')
        
        case "$mtu" in
            "1500")
                log_info "Interface $interface: Standard MTU (1500)"
                ;;
            "1492")
                log_info "Interface $interface: PPPoE MTU (1492)"
                ;;
            "9000")
                log_success "Interface $interface: Jumbo frames (9000)"
                ;;
            *)
                log_info "Interface $interface: Custom MTU ($mtu)"
                ;;
        esac
        
        # Check interface options (hardware offloading)
        local options
        options=$(ifconfig "$interface" | grep "options=" | cut -d'=' -f2 | cut -d'<' -f2 | cut -d'>' -f1)
        
        if echo "$options" | grep -q "RXCSUM"; then
            log_info "Interface $interface: RX checksum offload enabled"
        fi
        
        if echo "$options" | grep -q "TXCSUM"; then
            log_info "Interface $interface: TX checksum offload enabled"
        fi
        
        if echo "$options" | grep -q "TSO4\|TSO6"; then
            log_info "Interface $interface: TCP segmentation offload enabled"
        fi
        
        if echo "$options" | grep -q "LRO"; then
            log_info "Interface $interface: Large receive offload enabled"
        fi
        
        # Check for multiqueue support
        if ifconfig "$interface" | grep -q "queues"; then
            log_success "Interface $interface: Multiqueue supported"
        fi
        
        # Interface statistics
        local rx_errors
        rx_errors=$(netstat -i | grep "$interface" | awk '{print $5}')
        
        local tx_errors  
        tx_errors=$(netstat -i | grep "$interface" | awk '{print $8}')
        
        if [[ $rx_errors -gt 0 || $tx_errors -gt 0 ]]; then
            log_warning "Interface $interface: Errors detected (RX: $rx_errors, TX: $tx_errors)"
        else
            log_success "Interface $interface: No errors"
        fi
        
    done <<< "$interfaces"
    
    # Check interrupt distribution
    log_info "Checking interrupt distribution..."
    vmstat -i | head -10 >&3
    
    # Check for high interrupt load
    local total_interrupts
    total_interrupts=$(vmstat -i | tail -1 | awk '{print $3}')
    
    log_info "Total interrupt rate: $total_interrupts/sec"
}

# Traffic Shaping and QoS Analysis  
check_traffic_shaping() {
    print_section "Traffic Shaping and QoS Analysis"
    
    # Check for ALTQ configuration
    if pfctl -s queue >/dev/null 2>&1; then
        log_info "ALTQ traffic shaping configuration:"
        pfctl -s queue >&3
        
        # Check queue statistics
        local queue_stats
        queue_stats=$(pfctl -s queue -v 2>/dev/null | grep -c "queue" || echo "0")
        
        if [[ $queue_stats -gt 0 ]]; then
            log_success "Traffic shaping queues configured: $queue_stats"
            
            # Check for drops
            if pfctl -s queue -v | grep -q "drops"; then
                log_warning "Queue drops detected - may indicate insufficient bandwidth allocation"
                pfctl -s queue -v | grep "drops" >&3
            fi
        else
            log_info "No traffic shaping queues configured"
        fi
    else
        log_info "ALTQ traffic shaping not configured"
    fi
    
    # Check limiter configuration (if any)
    if dummynet show config >/dev/null 2>&1; then
        log_info "Dummynet limiters configured"
        dummynet show config >&3
    fi
    
    # Check for buffer bloat indicators
    log_info "Checking for potential buffer bloat indicators..."
    
    local tcp_sendspace
    tcp_sendspace=$(sysctl -n net.inet.tcp.sendspace 2>/dev/null || echo "0")
    
    local tcp_recvspace
    tcp_recvspace=$(sysctl -n net.inet.tcp.recvspace 2>/dev/null || echo "0")
    
    log_info "TCP send buffer: $tcp_sendspace"
    log_info "TCP receive buffer: $tcp_recvspace"
}

# FreeBSD sysctl Performance Parameters
check_freebsd_tunables() {
    print_section "FreeBSD Performance Tunables"
    
    # TCP Performance settings
    log_info "TCP Configuration:"
    
    local tcp_cc
    tcp_cc=$(sysctl -n net.inet.tcp.cc.algorithm 2>/dev/null || echo "unknown")
    log_info "TCP congestion control: $tcp_cc"
    
    if [[ "$tcp_cc" != "cubic" ]]; then
        log_warning "Consider using CUBIC congestion control for better performance"
    fi
    
    # TCP window scaling
    local tcp_rfc1323
    tcp_rfc1323=$(sysctl -n net.inet.tcp.rfc1323 2>/dev/null || echo "0")
    
    if [[ $tcp_rfc1323 -eq 1 ]]; then
        log_success "TCP window scaling enabled"
    else
        log_warning "TCP window scaling disabled - may limit throughput"
    fi
    
    # TCP auto-tuning
    local sendbuf_auto
    sendbuf_auto=$(sysctl -n net.inet.tcp.sendbuf_auto 2>/dev/null || echo "0")
    
    local recvbuf_auto
    recvbuf_auto=$(sysctl -n net.inet.tcp.recvbuf_auto 2>/dev/null || echo "0")
    
    if [[ $sendbuf_auto -eq 1 && $recvbuf_auto -eq 1 ]]; then
        log_success "TCP buffer auto-tuning enabled"
    else
        log_warning "TCP buffer auto-tuning not fully enabled"
    fi
    
    # Security settings
    log_info "Security Configuration:"
    
    local tcp_blackhole
    tcp_blackhole=$(sysctl -n net.inet.tcp.blackhole 2>/dev/null || echo "0")
    
    local udp_blackhole
    udp_blackhole=$(sysctl -n net.inet.udp.blackhole 2>/dev/null || echo "0")
    
    if [[ $tcp_blackhole -eq 2 ]]; then
        log_success "TCP blackhole enabled (optimal)"
    else
        log_info "TCP blackhole: $tcp_blackhole"
    fi
    
    if [[ $udp_blackhole -eq 1 ]]; then
        log_success "UDP blackhole enabled"
    else
        log_info "UDP blackhole: $udp_blackhole"
    fi
    
    # Network performance settings
    log_info "Network Performance Settings:"
    
    local maxthreads
    maxthreads=$(sysctl -n net.isr.maxthreads 2>/dev/null || echo "unknown")
    log_info "Network ISR threads: $maxthreads"
    
    local bindthreads
    bindthreads=$(sysctl -n net.isr.bindthreads 2>/dev/null || echo "unknown")
    log_info "Network ISR thread binding: $bindthreads"
    
    local dispatch
    dispatch=$(sysctl -n net.isr.dispatch 2>/dev/null || echo "unknown")
    log_info "Network ISR dispatch: $dispatch"
    
    if [[ "$dispatch" != "deferred" ]]; then
        log_warning "Consider setting net.isr.dispatch=deferred for multi-queue performance"
    fi
}

# Performance Monitoring and Bottleneck Detection
check_performance_metrics() {
    print_section "Performance Metrics and Bottleneck Analysis"
    
    # System load analysis
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | xargs)
    
    local cpu_count
    cpu_count=$(sysctl -n hw.ncpu)
    
    log_info "System load: $load_avg (CPUs: $cpu_count)"
    
    if (( $(echo "$load_avg > $cpu_count" | bc -l) 2>/dev/null )); then
        log_warning "High system load detected - may indicate CPU bottleneck"
    fi
    
    # Memory usage
    local memory_stats
    memory_stats=$(vmstat -s | head -10)
    echo "$memory_stats" >&3
    
    # Check swap usage
    local swap_usage
    swap_usage=$(swapinfo -h | tail -n +2 | awk '{if($2!="0B") print $1": "$5}' || echo "No swap")
    
    if [[ "$swap_usage" != "No swap" ]]; then
        log_warning "Swap usage detected: $swap_usage"
    else
        log_success "No swap usage"
    fi
    
    # PF state table analysis
    local pf_states
    pf_states=$(pfctl -s info | grep "current entries" | awk '{print $3}')
    
    local pf_limit
    pf_limit=$(pfctl -s info | grep "limit" | head -1 | awk '{print $3}')
    
    log_info "PF state table: $pf_states/$pf_limit entries"
    
    local pf_utilization
    pf_utilization=$(echo "scale=1; $pf_states * 100 / $pf_limit" | bc -l 2>/dev/null || echo "0")
    
    if (( $(echo "$pf_utilization > 80" | bc -l) 2>/dev/null )); then
        log_warning "High PF state table utilization (${pf_utilization}%)"
    else
        log_success "PF state table utilization: ${pf_utilization}%"
    fi
    
    # Network throughput test capabilities
    if command -v iperf3 >/dev/null 2>&1; then
        log_success "iperf3 available for throughput testing"
    else
        log_info "iperf3 not available - install for network performance testing"
    fi
    
    # Interface utilization
    log_info "Interface utilization (packets/sec):"
    netstat -i | awk 'NR>1 && $1!~/lo0|pflog|pfsync/ {print $1": RX "$5" TX "$8}' >&3
}

# Generate Performance Recommendations
generate_recommendations() {
    print_section "Performance Optimization Recommendations"
    
    local recommendations=()
    
    # Analyze current configuration and suggest improvements
    local nmbclusters
    nmbclusters=$(sysctl -n kern.ipc.nmbclusters)
    
    local total_mem_mb
    total_mem_mb=$(sysctl -n hw.physmem | awk '{print int($1/1024/1024)}')
    
    # Memory-based recommendations
    if [[ $total_mem_mb -ge 8192 && $nmbclusters -lt 524288 ]]; then
        recommendations+=("Increase kern.ipc.nmbclusters to 524288 or higher for your ${total_mem_mb}MB system")
    fi
    
    # Check for common performance issues
    local tcp_cc
    tcp_cc=$(sysctl -n net.inet.tcp.cc.algorithm 2>/dev/null || echo "newreno")
    
    if [[ "$tcp_cc" != "cubic" ]]; then
        recommendations+=("Change TCP congestion control to CUBIC: sysctl net.inet.tcp.cc.algorithm=cubic")
    fi
    
    local dispatch
    dispatch=$(sysctl -n net.isr.dispatch 2>/dev/null || echo "direct")
    
    if [[ "$dispatch" != "deferred" ]]; then
        recommendations+=("Enable deferred network processing: sysctl net.isr.dispatch=deferred")
    fi
    
    # Hardware acceleration recommendations
    if ! kldstat | grep -q "aesni"; then
        recommendations+=("Load AES-NI module for crypto acceleration: kldload aesni")
    fi
    
    # Interface-specific recommendations
    local high_error_interfaces
    high_error_interfaces=$(netstat -i | awk 'NR>1 && ($5>0 || $8>0) && $1!~/lo0|pflog|pfsync/ {print $1}')
    
    if [[ -n "$high_error_interfaces" ]]; then
        while read -r iface; do
            [[ -z "$iface" ]] && continue
            recommendations+=("Interface $iface has errors - check cabling and driver settings")
        done <<< "$high_error_interfaces"
    fi
    
    # System load recommendations
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | xargs)
    
    local cpu_count
    cpu_count=$(sysctl -n hw.ncpu)
    
    if (( $(echo "$load_avg > $cpu_count" | bc -l) 2>/dev/null )); then
        recommendations+=("High CPU load detected - consider enabling hardware acceleration or upgrading CPU")
    fi
    
    # Output recommendations
    if [[ ${#recommendations[@]} -gt 0 ]]; then
        echo "Optimization opportunities found:" >&3
        for rec in "${recommendations[@]}"; do
            echo "- $rec" >&3
        done
    else
        echo "System appears to be well-optimized. No critical issues detected." >&3
    fi
    
    # Configuration examples
    echo "" >&3
    echo "Example high-performance sysctl settings:" >&3
    cat << 'EOF' >&3
# Network performance
net.inet.tcp.cc.algorithm=cubic
net.inet.tcp.sendbuf_auto=1
net.inet.tcp.recvbuf_auto=1
net.inet.tcp.sendbuf_max=16777216
net.inet.tcp.recvbuf_max=16777216
net.isr.dispatch=deferred
net.isr.bindthreads=1

# Security
net.inet.tcp.blackhole=2
net.inet.udp.blackhole=1
net.inet.ip.random_id=1

# Memory
kern.ipc.maxsockbuf=16777216
kern.ipc.somaxconn=4096
EOF
}

# Main execution function
main() {
    print_header "pfSense Performance Diagnostic Report"
    echo "Generated: $(date)" >&3
    echo "Hostname: $(hostname)" >&3
    echo "pfSense Version: $(cat /etc/version)" >&3
    echo "FreeBSD Version: $(uname -r)" >&3
    echo "" >&3
    
    verify_pfsense
    check_system_tunables
    check_hardware_acceleration
    check_network_interfaces
    check_traffic_shaping
    check_freebsd_tunables
    check_performance_metrics
    generate_recommendations
    
    echo "" >&3
    print_header "Diagnostic Complete"
    echo "Full log saved to: $LOG_FILE" >&3
}

# Script initialization
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    setup_logging
    main
    log_success "pfSense diagnostic completed. Check $LOG_FILE for full details."
fi