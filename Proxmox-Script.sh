
#bash -c "$(curl -fsSL https://raw.githubusercontent.com/eSENTIRE-AUSTRALIA/ProxmoxPerfTuning/refs/heads/main/Proxmox-Script.sh)"
#curl -fsSL https://raw.githubusercontent.com/eSENTIRE-AUSTRALIA/ProxmoxPerfTuning/refs/heads/main/Proxmox-Script.sh -o Proxmox-Script.sh

#!/usr/bin/env bash
# Proxmox Performance Diagnostic Script
# Validates VM configuration, network, storage, and system tunables
# Version: 2.0 - Fixed hanging issues with timeouts and error handling

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="${SCRIPT_DIR}/proxmox_diagnostic_$(date +%Y%m%d_%H%M%S).log"
readonly VERBOSE=${VERBOSE:-false}

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m' 
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging and error handling
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

log_progress() {
    echo -e "${BLUE}PROGRESS: $1${NC}" >&3
}

print_header() {
    local header="$1"
    echo "==================" >&3
    echo "$header" >&3
    echo "==================" >&3
}

print_section() {
    echo "" >&3
    echo "--- $1 ---" >&3
}

# Check if running on Proxmox
verify_proxmox() {
    if [[ ! -f /etc/pve/storage.cfg ]]; then
        log_error "This script must be run on a Proxmox VE host"
        exit 1
    fi
    
    if ! command -v qm >/dev/null 2>&1; then
        log_error "Proxmox qm command not found. Is this a Proxmox VE node?"
        exit 1
    fi
    
    log_success "Proxmox VE environment detected"
}

# Helper function to safely execute qm commands with timeout and error handling
safe_qm_cmd() {
    local cmd="$1"
    local vmid="$2"
    local timeout_seconds="${3:-15}"
    
    if timeout "$timeout_seconds" qm "$cmd" "$vmid" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Clear any problematic VM locks before starting
clear_vm_locks() {
    log_progress "Checking for stale VM locks..."
    
    local lock_files
    lock_files=$(find /var/lock/qemu-server/ -name "lock-*.conf" 2>/dev/null || true)
    
    if [[ -n "$lock_files" ]]; then
        while read -r lock_file; do
            [[ -z "$lock_file" ]] && continue
            
            local vmid
            vmid=$(basename "$lock_file" | grep -o '[0-9]*')
            
            if [[ -n "$vmid" ]]; then
                log_info "Found stale lock for VM $vmid - attempting to clear"
                qm unlock "$vmid" 2>/dev/null || true
                
                # Remove empty lock files
                if [[ ! -s "$lock_file" ]]; then
                    rm -f "$lock_file" 2>/dev/null || true
                    log_success "Cleared empty lock file for VM $vmid"
                fi
            fi
        done <<< "$lock_files"
    else
        log_success "No stale VM locks found"
    fi
}

# Enhanced VM Configuration Analysis for pfSense Optimization
check_vm_configurations() {
    print_section "VM Configuration Analysis (pfSense Optimized)"
    
    local vm_list
    log_progress "Getting VM list..."
    if ! vm_list=$(timeout 30 qm list 2>/dev/null | awk 'NR>1 {print $1}'); then
        log_error "Failed to get VM list or command timed out"
        return 1
    fi
    
    if [[ -z "$vm_list" ]]; then
        log_info "No VMs found on this host"
        return
    fi
    
    local total_vms=0
    local cpu_issues=0
    local memory_issues=0
    local storage_issues=0
    local network_issues=0
    local failed_vms=0
    local analyzed_vms=0
    local pfsense_vms=0
    
    # Count total VMs first
    total_vms=$(echo "$vm_list" | wc -l)
    log_progress "Found $total_vms VMs to analyze"
    
    while read -r vmid; do
        [[ -z "$vmid" ]] && continue
        
        log_progress "Analyzing VM $vmid... ($((analyzed_vms + failed_vms + 1))/$total_vms)"
        
        # Check if VM is accessible and not locked
        local vm_status
        if ! vm_status=$(timeout 10 qm status "$vmid" 2>/dev/null); then
            log_warning "VM $vmid: Cannot get status (may be locked or inaccessible) - skipping"
            failed_vms=$((failed_vms + 1))
            continue
        fi
        
        # Check if VM is locked by examining status output
        if echo "$vm_status" | grep -q "lock"; then
            log_warning "VM $vmid: VM appears to be locked - attempting unlock"
            qm unlock "$vmid" 2>/dev/null || true
            sleep 1
        fi
        
        # Get VM configuration with timeout and error handling
        local vm_config
        if ! vm_config=$(timeout 15 qm config "$vmid" 2>/dev/null); then
            log_warning "VM $vmid: Cannot get configuration (timeout or error) - skipping"
            failed_vms=$((failed_vms + 1))
            continue
        fi
        
        analyzed_vms=$((analyzed_vms + 1))
        
        # Detect if this is likely a pfSense/router VM
        local vm_name
        vm_name=$(echo "$vm_config" | grep "^name:" | cut -d' ' -f2 || echo "")
        local is_pfsense=false
        
        if echo "$vm_name" | grep -qi "pfsense\|opnsense\|router\|firewall\|gateway"; then
            is_pfsense=true
            pfsense_vms=$((pfsense_vms + 1))
            log_success "VM $vmid ($vm_name): Detected as pfSense/router VM - applying enhanced checks"
        fi
        
        # Enhanced CPU configuration analysis
        local cpu_config
        cpu_config=$(echo "$vm_config" | grep "^cpu:" | cut -d' ' -f2 || echo "kvm64")
        
        case "$cpu_config" in
            "host")
                if $is_pfsense; then
                    log_success "VM $vmid: Optimal CPU type (host) - excellent for pfSense performance"
                else
                    log_success "VM $vmid: Optimal CPU type (host)"
                fi
                ;;
            "kvm64")
                if $is_pfsense; then
                    log_warning "VM $vmid: Using default CPU type - CRITICAL: pfSense needs 'host' CPU type for optimal performance"
                else
                    log_warning "VM $vmid: Using default CPU type - consider 'host' for better performance"
                fi
                cpu_issues=$((cpu_issues + 1))
                ;;
            *)
                log_info "VM $vmid: Using CPU type $cpu_config"
                if $is_pfsense; then
                    log_warning "VM $vmid: pfSense performs best with 'host' CPU type"
                    cpu_issues=$((cpu_issues + 1))
                fi
                ;;
        esac
        
        # Check CPU cores for pfSense
        local cores
        cores=$(echo "$vm_config" | grep "^cores:" | awk '{print $2}' || echo "1")
        if $is_pfsense; then
            if [[ $cores -ge 4 ]]; then
                log_success "VM $vmid: Good CPU allocation ($cores cores) for pfSense"
            elif [[ $cores -eq 2 ]]; then
                log_info "VM $vmid: Adequate CPU allocation ($cores cores) for basic pfSense usage"
            else
                log_warning "VM $vmid: Low CPU allocation ($cores cores) - consider 2-4 cores for pfSense"
            fi
        fi
        
        # Enhanced memory configuration analysis
        local memory_mb
        memory_mb=$(echo "$vm_config" | grep "^memory:" | awk '{print $2}' || echo "0")
        
        # Check for memory ballooning (bad for pfSense)
        local balloon
        balloon=$(echo "$vm_config" | grep "^balloon:" | awk '{print $2}' || echo "")
        
        if [[ -n "$balloon" && "$balloon" != "0" ]]; then
            if $is_pfsense; then
                log_error "VM $vmid: Memory ballooning enabled ($balloon MB) - DISABLE for pfSense stability!"
            else
                log_warning "VM $vmid: Memory ballooning enabled ($balloon MB)"
            fi
            memory_issues=$((memory_issues + 1))
        elif $is_pfsense; then
            log_success "VM $vmid: Memory ballooning properly disabled for pfSense"
        fi
        
        if [[ $memory_mb -gt 0 ]]; then
            if $is_pfsense; then
                if [[ $memory_mb -ge 4096 ]]; then
                    log_success "VM $vmid: Excellent memory allocation (${memory_mb}MB) for pfSense"
                elif [[ $memory_mb -ge 2048 ]]; then
                    log_success "VM $vmid: Good memory allocation (${memory_mb}MB) for pfSense"
                else
                    log_warning "VM $vmid: Low memory allocation (${memory_mb}MB) - consider 2GB+ for pfSense"
                fi
            fi
            
            local hugepages
            hugepages=$(echo "$vm_config" | grep "hugepages" | cut -d'=' -f2 || echo "none")
            
            if [[ "$hugepages" == "none" && $memory_mb -ge 4096 ]]; then
                log_warning "VM $vmid: Large VM (${memory_mb}MB) without hugepages - consider enabling"
                memory_issues=$((memory_issues + 1))
            elif [[ "$hugepages" != "none" ]]; then
                log_success "VM $vmid: Hugepages enabled (${hugepages}) - good for performance"
            fi
        fi
        
        # Enhanced storage configuration analysis
        local storage_config
        storage_config=$(echo "$vm_config" | grep -E "^(virtio|scsi|ide|sata)" || echo "")
        
        if echo "$storage_config" | grep -q "ide\|sata"; then
            if $is_pfsense; then
                log_error "VM $vmid: Using IDE/SATA storage - pfSense needs VirtIO for optimal performance"
            else
                log_warning "VM $vmid: Using IDE/SATA storage - consider VirtIO for better performance"
            fi
            storage_issues=$((storage_issues + 1))
        fi
        
        # Check VirtIO storage settings
        while IFS= read -r storage_line; do
            if [[ -z "$storage_line" ]]; then
                continue
            fi
            
            local disk_name
            disk_name=$(echo "$storage_line" | cut -d':' -f1)
            
            if echo "$storage_line" | grep -q "virtio.*iothread=1"; then
                log_success "VM $vmid ($disk_name): VirtIO with iothread enabled - optimal for pfSense"
            elif echo "$storage_line" | grep -q "virtio"; then
                if $is_pfsense; then
                    log_warning "VM $vmid ($disk_name): VirtIO without iothread - enable iothread for pfSense performance"
                else
                    log_warning "VM $vmid ($disk_name): VirtIO without iothread - consider enabling"
                fi
                storage_issues=$((storage_issues + 1))
            fi
            
            # Check cache settings
            if echo "$storage_line" | grep -q "cache=writeback"; then
                if $is_pfsense; then
                    log_success "VM $vmid ($disk_name): Writeback caching - optimal for pfSense performance"
                else
                    log_success "VM $vmid ($disk_name): Writeback caching enabled"
                fi
            elif echo "$storage_line" | grep -q "cache=writethrough"; then
                log_info "VM $vmid ($disk_name): Writethrough caching - safe but slower"
                if $is_pfsense; then
                    log_warning "VM $vmid ($disk_name): Consider writeback caching for pfSense (with UPS protection)"
                fi
            elif echo "$storage_line" | grep -q "cache=none"; then
                log_info "VM $vmid ($disk_name): No caching - direct I/O"
                if $is_pfsense; then
                    log_warning "VM $vmid ($disk_name): Consider writeback caching for pfSense performance"
                fi
            else
                log_warning "VM $vmid ($disk_name): No explicit cache setting - consider 'cache=writeback'"
                storage_issues=$((storage_issues + 1))
            fi
            
            # Check AIO settings
            if echo "$storage_line" | grep -q "aio=io_uring"; then
                log_success "VM $vmid ($disk_name): Using io_uring AIO - optimal for modern systems"
            elif echo "$storage_line" | grep -q "aio=native"; then
                log_info "VM $vmid ($disk_name): Using native AIO - good performance"
            else
                log_info "VM $vmid ($disk_name): Default AIO - consider io_uring for better performance"
            fi
            
        done <<< "$storage_config"
        
        # Enhanced network configuration analysis
        local net_config
        net_config=$(echo "$vm_config" | grep "^net" || echo "")
        
        if [[ -z "$net_config" ]] && $is_pfsense; then
            log_error "VM $vmid: No network interfaces found - pfSense requires network interfaces!"
            network_issues=$((network_issues + 1))
        fi
        
        local net_count=0
        while IFS= read -r net_line; do
            if [[ -z "$net_line" ]]; then
                continue
            fi
            
            net_count=$((net_count + 1))
            local net_name
            net_name=$(echo "$net_line" | cut -d':' -f1)
            
            # Check for VirtIO network
            if echo "$net_line" | grep -q "virtio"; then
                log_success "VM $vmid ($net_name): Using VirtIO network - optimal for pfSense"
            else
                if $is_pfsense; then
                    log_error "VM $vmid ($net_name): Not using VirtIO network - critical for pfSense performance"
                else
                    log_warning "VM $vmid ($net_name): Not using VirtIO network"
                fi
                network_issues=$((network_issues + 1))
            fi
            
            # Check multiqueue settings
            if echo "$net_line" | grep -q "queues="; then
                local queues
                queues=$(echo "$net_line" | grep -o "queues=[0-9]*" | cut -d'=' -f2 | head -1)
                
                if [[ $queues -eq $cores ]]; then
                    log_success "VM $vmid ($net_name): Network multiqueue matches CPU cores ($queues)"
                elif [[ $queues -gt $cores ]]; then
                    log_warning "VM $vmid ($net_name): More network queues ($queues) than CPU cores ($cores)"
                    network_issues=$((network_issues + 1))
                else
                    log_warning "VM $vmid ($net_name): Fewer network queues ($queues) than CPU cores ($cores) - consider matching"
                    network_issues=$((network_issues + 1))
                fi
            elif echo "$net_line" | grep -q "virtio" && $cores -gt 1; then
                if $is_pfsense; then
                    log_warning "VM $vmid ($net_name): VirtIO without multiqueue - add queues=$cores for pfSense performance"
                else
                    log_info "VM $vmid ($net_name): VirtIO without multiqueue - consider adding queues=$cores"
                fi
                network_issues=$((network_issues + 1))
            fi
            
            # Check network model and advanced settings
            if echo "$net_line" | grep -q "model=virtio"; then
                if echo "$net_line" | grep -q "rx_queue_size="; then
                    local rx_queue_size
                    rx_queue_size=$(echo "$net_line" | grep -o "rx_queue_size=[0-9]*" | cut -d'=' -f2)
                    if [[ $rx_queue_size -ge 1024 ]]; then
                        log_success "VM $vmid ($net_name): Large RX queue size ($rx_queue_size) - good for high throughput"
                    fi
                fi
            fi
            
        done <<< "$net_config"
        
        if $is_pfsense; then
            if [[ $net_count -ge 2 ]]; then
                log_success "VM $vmid: Multiple network interfaces ($net_count) - good for pfSense routing"
            elif [[ $net_count -eq 1 ]]; then
                log_info "VM $vmid: Single network interface - consider adding WAN/LAN separation"
            fi
        fi
        
        # Add small delay to prevent overwhelming the system
        sleep 0.2
        
    done <<< "$vm_list"
    
    # Enhanced Summary
    echo "" >&3
    print_section "VM Configuration Summary"
    echo "Total VMs found: $total_vms" >&3
    echo "VMs successfully analyzed: $analyzed_vms" >&3
    echo "VMs failed/skipped: $failed_vms" >&3
    echo "pfSense/Router VMs detected: $pfsense_vms" >&3
    echo "" >&3
    
    if [[ $analyzed_vms -gt 0 ]]; then
        echo "Optimization opportunities found:" >&3
        echo "- CPU optimization needed: $cpu_issues VMs" >&3
        echo "- Memory optimization needed: $memory_issues VMs" >&3
        echo "- Storage optimization needed: $storage_issues VMs" >&3
        echo "- Network optimization needed: $network_issues VMs" >&3
        
        if [[ $((cpu_issues + memory_issues + storage_issues + network_issues)) -eq 0 ]]; then
            log_success "All analyzed VMs are well-optimized!"
        fi
        
        if [[ $pfsense_vms -gt 0 ]]; then
            echo "" >&3
            echo "pfSense-specific recommendations:" >&3
            echo "- Use 'host' CPU type for maximum performance" >&3
            echo "- Disable memory ballooning (balloon: 0)" >&3
            echo "- Use VirtIO storage with iothread and writeback cache" >&3
            echo "- Use VirtIO network with multiqueue (queues=cores)" >&3
            echo "- Allocate 2GB+ RAM for optimal performance" >&3
            echo "- Consider CPU pinning for high-throughput scenarios" >&3
        fi
    fi
}

# Enhanced Network Bridge Configuration for pfSense Performance
check_network_configuration() {
    print_section "Network Configuration Analysis (pfSense Optimized)"
    
    log_progress "Analyzing network bridges and performance settings..."
    
    local bridges
    bridges=$(ip link show type bridge | grep -o "vmbr[0-9]*" || echo "")
    
    if [[ -z "$bridges" ]]; then
        log_error "No VM bridges found"
        return
    fi
    
    local bridge_issues=0
    local total_bridges=0
    
    while read -r bridge; do
        [[ -z "$bridge" ]] && continue
        total_bridges=$((total_bridges + 1))
        
        log_info "Analyzing bridge $bridge..."
        
        # Check if bridge is up
        if ip link show "$bridge" | grep -q "state UP"; then
            log_success "Bridge $bridge: UP and active"
        else
            log_warning "Bridge $bridge: DOWN - may affect VM connectivity"
            bridge_issues=$((bridge_issues + 1))
        fi
        
        # Check for STP (should be disabled for performance)
        local stp_state
        stp_state=$(cat "/sys/class/net/$bridge/bridge/stp_state" 2>/dev/null || echo "unknown")
        
        if [[ "$stp_state" == "0" ]]; then
            log_success "Bridge $bridge: STP disabled (optimal for performance)"
        elif [[ "$stp_state" == "1" ]]; then
            log_warning "Bridge $bridge: STP enabled - disable for better performance: echo 0 > /sys/class/net/$bridge/bridge/stp_state"
            bridge_issues=$((bridge_issues + 1))
        fi
        
        # Check bridge forward delay
        local forward_delay
        forward_delay=$(cat "/sys/class/net/$bridge/bridge/forward_delay" 2>/dev/null || echo "unknown")
        
        if [[ "$forward_delay" == "0" ]]; then
            log_success "Bridge $bridge: Forward delay disabled (optimal)"
        elif [[ "$forward_delay" != "unknown" && $forward_delay -gt 0 ]]; then
            log_info "Bridge $bridge: Forward delay ${forward_delay} centiseconds - consider setting to 0 for performance"
        fi
        
        # Check for VLAN awareness
        local vlan_filtering
        vlan_filtering=$(cat "/sys/class/net/$bridge/bridge/vlan_filtering" 2>/dev/null || echo "0")
        
        if [[ "$vlan_filtering" == "1" ]]; then
            log_info "Bridge $bridge: VLAN-aware - good for complex network setups"
        fi
        
        # Check MTU settings
        local mtu
        mtu=$(ip link show "$bridge" | grep -o "mtu [0-9]*" | awk '{print $2}')
        
        case "$mtu" in
            "1500")
                log_info "Bridge $bridge: Standard MTU (1500)"
                ;;
            "9000")
                log_success "Bridge $bridge: Jumbo frames enabled (9000) - excellent for high-throughput"
                ;;
            *)
                log_info "Bridge $bridge: Custom MTU ($mtu)"
                ;;
        esac
        
        # Check bridge multicast settings
        local multicast_snooping
        multicast_snooping=$(cat "/sys/class/net/$bridge/bridge/multicast_snooping" 2>/dev/null || echo "unknown")
        
        if [[ "$multicast_snooping" == "1" ]]; then
            log_info "Bridge $bridge: Multicast snooping enabled"
        fi
        
        # Check for bridge netfilter (can impact performance)
        if [[ -f "/proc/sys/net/bridge/bridge-nf-call-iptables" ]]; then
            local bridge_netfilter
            bridge_netfilter=$(cat "/proc/sys/net/bridge/bridge-nf-call-iptables" 2>/dev/null)
            
            if [[ "$bridge_netfilter" == "0" ]]; then
                log_success "Bridge netfilter disabled - good for performance"
            else
                log_info "Bridge netfilter enabled - may impact performance for high-throughput scenarios"
            fi
        fi
        
        # Check bridge interfaces and their settings
        local bridge_ports
        bridge_ports=$(ls "/sys/class/net/$bridge/brif/" 2>/dev/null | tr '\n' ' ' || echo "")
        
        if [[ -n "$bridge_ports" ]]; then
            local port_count
            port_count=$(echo "$bridge_ports" | wc -w)
            log_info "Bridge $bridge: $port_count connected interfaces ($bridge_ports)"
            
            # Check individual port settings
            for port in $bridge_ports; do
                if [[ "$port" =~ ^tap[0-9]+i[0-9]+ ]]; then
                    # This is a VM interface
                    local vm_id
                    vm_id=$(echo "$port" | grep -o '[0-9]\+' | head -1)
                    
                    # Check if this port has optimal settings
                    local port_hairpin
                    port_hairpin=$(cat "/sys/class/net/$bridge/brif/$port/hairpin_mode" 2>/dev/null || echo "0")
                    
                    if [[ "$port_hairpin" == "1" ]]; then
                        log_info "Bridge $bridge port $port: Hairpin mode enabled"
                    fi
                fi
            done
        else
            log_warning "Bridge $bridge: No interfaces connected"
            bridge_issues=$((bridge_issues + 1))
        fi
        
        # Check bridge queue discipline
        local qdisc
        qdisc=$(tc qdisc show dev "$bridge" 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
        
        if [[ "$qdisc" != "unknown" ]]; then
            log_info "Bridge $bridge: Using $qdisc queue discipline"
        fi
        
    done <<< "$bridges"
    
    # Check overall network performance settings
    echo "" >&3
    log_info "Checking system-wide network performance settings..."
    
    # Check receive packet steering (RPS)
    local rps_enabled=0
    for netdev in /sys/class/net/*/queues/rx-*/rps_cpus; do
        if [[ -f "$netdev" ]]; then
            local rps_value
            rps_value=$(cat "$netdev" 2>/dev/null || echo "0")
            if [[ "$rps_value" != "0" && "$rps_value" != "00000000" ]]; then
                rps_enabled=$((rps_enabled + 1))
            fi
        fi
    done
    
    if [[ $rps_enabled -gt 0 ]]; then
        log_success "Receive Packet Steering (RPS) configured on $rps_enabled interfaces"
    else
        log_info "RPS not configured - consider enabling for multi-core network performance"
    fi
    
    # Check for network interrupt distribution
    log_info "Analyzing network interrupt distribution..."
    check_interrupt_distribution
    
    # Summary
    echo "" >&3
    echo "Network Bridge Summary:" >&3
    echo "- Total bridges: $total_bridges" >&3
    echo "- Bridge optimization needed: $bridge_issues" >&3
    
    if [[ $bridge_issues -eq 0 ]]; then
        log_success "All bridges are optimally configured"
    else
        echo "" >&3
        echo "Bridge optimization recommendations:" >&3
        echo "- Disable STP: echo 0 > /sys/class/net/vmbr0/bridge/stp_state" >&3
        echo "- Set forward delay: echo 0 > /sys/class/net/vmbr0/bridge/forward_delay" >&3
        echo "- Consider jumbo frames: ip link set vmbr0 mtu 9000" >&3
    fi
}

# New function: Check interrupt distribution across CPU cores
check_interrupt_distribution() {
    print_section "Interrupt Distribution Analysis"
    
    log_progress "Analyzing interrupt distribution across CPU cores..."
    
    local cpu_count
    cpu_count=$(nproc)
    
    # Check network interface interrupts
    if [[ -f /proc/interrupts ]]; then
        local network_interrupts
        network_interrupts=$(grep -E "(eth|en|virtio|vmbr)" /proc/interrupts 2>/dev/null || echo "")
        
        if [[ -n "$network_interrupts" ]]; then
            log_info "Network interface interrupts detected"
            
            # Count interrupts per CPU
            local total_interrupts=0
            local -a cpu_interrupt_counts
            
            for ((i=0; i<cpu_count; i++)); do
                cpu_interrupt_counts[$i]=0
            done
            
            while IFS= read -r line; do
                if [[ -z "$line" ]]; then
                    continue
                fi
                
                # Extract interrupt counts for each CPU
                local interrupt_line
                interrupt_line=$(echo "$line" | awk '{for(i=2; i<=NF && i<='$((cpu_count+1))'; i++) print $(i)}' | tr '\n' ' ')
                
                local cpu_index=0
                for count in $interrupt_line; do
                    if [[ "$count" =~ ^[0-9]+$ ]]; then
                        cpu_interrupt_counts[$cpu_index]=$((cpu_interrupt_counts[$cpu_index] + count))
                        total_interrupts=$((total_interrupts + count))
                        cpu_index=$((cpu_index + 1))
                    fi
                    if [[ $cpu_index -ge $cpu_count ]]; then
                        break
                    fi
                done
                
            done <<< "$network_interrupts"
            
            # Analyze distribution
            if [[ $total_interrupts -gt 0 ]]; then
                local max_interrupts=0
                local min_interrupts=${cpu_interrupt_counts[0]}
                
                for ((i=0; i<cpu_count; i++)); do
                    if [[ ${cpu_interrupt_counts[$i]} -gt $max_interrupts ]]; then
                        max_interrupts=${cpu_interrupt_counts[$i]}
                    fi
                    if [[ ${cpu_interrupt_counts[$i]} -lt $min_interrupts ]]; then
                        min_interrupts=${cpu_interrupt_counts[$i]}
                    fi
                done
                
                local distribution_ratio=0
                if [[ $min_interrupts -gt 0 ]]; then
                    distribution_ratio=$((max_interrupts / min_interrupts))
                fi
                
                if [[ $distribution_ratio -le 3 ]]; then
                    log_success "Good interrupt distribution across CPUs (ratio: ${distribution_ratio}:1)"
                else
                    log_warning "Uneven interrupt distribution (ratio: ${distribution_ratio}:1) - consider interrupt affinity tuning"
                fi
                
                # Show per-CPU distribution
                echo "Per-CPU interrupt distribution:" >&3
                for ((i=0; i<cpu_count; i++)); do
                    local percentage=0
                    if [[ $total_interrupts -gt 0 ]]; then
                        percentage=$((cpu_interrupt_counts[$i] * 100 / total_interrupts))
                    fi
                    echo "  CPU$i: ${cpu_interrupt_counts[$i]} interrupts (${percentage}%)" >&3
                done
            fi
        else
            log_info "No network interrupts detected in /proc/interrupts"
        fi
    fi
    
    # Check IRQ balance service
    if systemctl is-active irqbalance >/dev/null 2>&1; then
        log_success "irqbalance service is active - automatic interrupt balancing enabled"
    else
        log_info "irqbalance service not running - consider enabling for automatic interrupt distribution"
    fi
}

# New function: Check CPU governor and performance settings
check_cpu_governor_settings() {
    print_section "CPU Governor and Performance Settings"
    
    log_progress "Analyzing CPU governor settings..."
    
    local cpu_count
    cpu_count=$(nproc)
    
    # Check CPU scaling governor
    local governors_set=()
    local performance_cpus=0
    local powersave_cpus=0
    local ondemand_cpus=0
    
    for ((cpu=0; cpu<cpu_count; cpu++)); do
        local governor_file="/sys/devices/system/cpu/cpu${cpu}/cpufreq/scaling_governor"
        
        if [[ -f "$governor_file" ]]; then
            local governor
            governor=$(cat "$governor_file" 2>/dev/null || echo "unknown")
            
            case "$governor" in
                "performance")
                    performance_cpus=$((performance_cpus + 1))
                    ;;
                "powersave")
                    powersave_cpus=$((powersave_cpus + 1))
                    ;;
                "ondemand")
                    ondemand_cpus=$((ondemand_cpus + 1))
                    ;;
                *)
                    governors_set+=("$governor")
                    ;;
            esac
        fi
    done
    
    # Report governor distribution
    if [[ $performance_cpus -eq $cpu_count ]]; then
        log_success "All CPUs using 'performance' governor - optimal for pfSense/router workloads"
    elif [[ $performance_cpus -gt 0 ]]; then
        log_info "$performance_cpus/$cpu_count CPUs using 'performance' governor"
        if [[ $powersave_cpus -gt 0 ]]; then
            log_warning "$powersave_cpus CPUs using 'powersave' governor - consider 'performance' for consistent network performance"
        fi
    else
        log_warning "No CPUs using 'performance' governor - consider setting for optimal pfSense performance"
        echo "Set performance governor: echo performance > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor" >&3
    fi
    
    # Check CPU frequency scaling
    local base_freq=""
    local max_freq=""
    
    if [[ -f "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq" ]]; then
        max_freq=$(cat "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq" 2>/dev/null)
        max_freq=$((max_freq / 1000)) # Convert to MHz
        log_info "Maximum CPU frequency: ${max_freq} MHz"
    fi
    
    if [[ -f "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq" ]]; then
        local cur_freq
        cur_freq=$(cat "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq" 2>/dev/null)
        cur_freq=$((cur_freq / 1000)) # Convert to MHz
        log_info "Current CPU frequency: ${cur_freq} MHz"
        
        if [[ -n "$max_freq" ]] && [[ $cur_freq -lt $((max_freq - 100)) ]]; then
            log_warning "CPU not running at maximum frequency - may impact performance"
        fi
    fi
    
    # Check CPU idle states (C-states)
    if [[ -d "/sys/devices/system/cpu/cpu0/cpuidle" ]]; then
        local idle_states
        idle_states=$(find /sys/devices/system/cpu/cpu0/cpuidle -name "state*" -type d | wc -l)
        
        if [[ $idle_states -gt 0 ]]; then
            log_info "CPU idle states available: $idle_states"
            
            # Check if deep C-states are disabled (good for latency-sensitive workloads)
            local deep_states_disabled=0
            for state_dir in /sys/devices/system/cpu/cpu0/cpuidle/state*/; do
                if [[ -f "${state_dir}disable" ]]; then
                    local disabled
                    disabled=$(cat "${state_dir}disable" 2>/dev/null || echo "0")
                    if [[ "$disabled" == "1" ]]; then
                        deep_states_disabled=$((deep_states_disabled + 1))
                    fi
                fi
            done
            
            if [[ $deep_states_disabled -gt 0 ]]; then
                log_info "$deep_states_disabled deep C-states disabled - good for low-latency networking"
            else
                log_info "All C-states enabled - consider disabling deep states for pfSense: intel_idle.max_cstate=1"
            fi
        fi
    fi
    
    # Check for CPU pinning of VM processes
    log_info "Checking for CPU affinity settings..."
    
    local vm_processes
    vm_processes=$(ps aux | grep -E "qemu.*-id [0-9]+" | grep -v grep || echo "")
    
    if [[ -n "$vm_processes" ]]; then
        local pinned_vms=0
        
        while IFS= read -r process_line; do
            if [[ -z "$process_line" ]]; then
                continue
            fi
            
            local pid
            pid=$(echo "$process_line" | awk '{print $2}')
            
            if [[ -n "$pid" ]]; then
                local cpu_affinity
                cpu_affinity=$(taskset -cp "$pid" 2>/dev/null | grep -o '[0-9,-]*

# NUMA and CPU Pinning Analysis
check_numa_configuration() {
    print_section "NUMA and CPU Configuration Analysis"
    
    # Check NUMA topology
    if command -v numactl >/dev/null 2>&1; then
        local numa_nodes
        numa_nodes=$(numactl --hardware 2>/dev/null | grep "available:" | awk '{print $2}' || echo "1")
        
        log_info "NUMA nodes available: $numa_nodes"
        
        # Get VM list with timeout
        local vm_list
        if ! vm_list=$(timeout 30 qm list 2>/dev/null | awk 'NR>1 {print $1}'); then
            log_warning "Could not get VM list for NUMA analysis"
            return
        fi
        
        if [[ -z "$vm_list" ]]; then
            log_info "No VMs found for NUMA analysis"
            return
        fi
        
        local numa_recommendations=0
        local cpu_affinity_found=0
        
        while read -r vmid; do
            [[ -z "$vmid" ]] && continue
            
            # Skip if we can't get config (already handled in VM analysis)
            local vm_config
            if ! vm_config=$(timeout 10 qm config "$vmid" 2>/dev/null); then
                continue
            fi
            
            local cores
            cores=$(echo "$vm_config" | grep "^cores:" | awk '{print $2}' || echo "1")
            
            local numa_config
            numa_config=$(echo "$vm_config" | grep "^numa:" || echo "")
            
            if [[ $cores -gt 8 && -z "$numa_config" && $numa_nodes -gt 1 ]]; then
                log_warning "VM $vmid: Large VM ($cores cores) without NUMA configuration on multi-node system"
                numa_recommendations=$((numa_recommendations + 1))
            elif [[ -n "$numa_config" ]]; then
                log_success "VM $vmid: NUMA configuration present"
            fi
            
            # Check CPU affinity
            local affinity
            affinity=$(echo "$vm_config" | grep "^affinity:" || echo "")
            
            if [[ -n "$affinity" ]]; then
                log_success "VM $vmid: CPU affinity configured"
                cpu_affinity_found=$((cpu_affinity_found + 1))
            fi
            
        done <<< "$vm_list"
        
        # Summary
        echo "" >&3
        if [[ $numa_nodes -gt 1 ]]; then
            echo "NUMA recommendations: $numa_recommendations VMs could benefit from NUMA configuration" >&3
        else
            echo "Single NUMA node system - NUMA configuration not critical" >&3
        fi
        echo "VMs with CPU affinity: $cpu_affinity_found" >&3
        
    else
        log_warning "numactl not available - cannot check NUMA topology"
        echo "Install numactl package: apt install numactl" >&3
    fi
}

# Enhanced Storage I/O Performance Analysis
check_storage_configuration() {
    print_section "Storage Configuration Analysis (I/O Performance Focus)"
    
    log_progress "Analyzing storage configurations and I/O performance..."
    
    # Check storage definitions
    if [[ -f /etc/pve/storage.cfg ]]; then
        log_info "Analyzing Proxmox storage configurations..."
        
        local storage_types
        storage_types=$(grep "^[a-z]" /etc/pve/storage.cfg | grep -v "^$" | cut -d':' -f1 | sort | uniq)
        
        while read -r storage_type; do
            [[ -z "$storage_type" ]] && continue
            
            local storage_count
            storage_count=$(grep "^$storage_type:" /etc/pve/storage.cfg | wc -l)
            
            log_info "Storage type '$storage_type': $storage_count configured"
            
            # Check for performance-related settings
            case "$storage_type" in
                "zfs")
                    check_zfs_performance
                    ;;
                "lvm"|"lvm-thin")
                    check_lvm_performance
                    ;;
                "dir")
                    check_directory_storage_performance
                    ;;
                "ceph"|"rbd")
                    check_ceph_performance
                    ;;
            esac
            
        done <<< "$storage_types"
    fi
    
    # Enhanced I/O scheduler analysis
    log_info "Analyzing I/O schedulers and performance settings..."
    
    local disk_performance_issues=0
    
    for disk_path in /sys/block/*/queue/scheduler; do
        local device
        device=$(basename "$(dirname "$(dirname "$disk_path")")")
        
        # Skip virtual/loop devices
        [[ "$device" =~ ^(loop|ram|dm-) ]] && continue
        
        local scheduler
        scheduler=$(cat "$disk_path" | grep -o "\[.*\]" | tr -d '[]' || echo "unknown")
        
        local disk_type="unknown"
        local is_ssd=false
        local is_nvme=false
        
        # Detect disk type
        if [[ "$device" =~ ^nvme ]]; then
            is_nvme=true
            disk_type="NVMe"
        elif [[ -f "/sys/block/$device/queue/rotational" ]]; then
            local rotational
            rotational=$(cat "/sys/block/$device/queue/rotational" 2>/dev/null || echo "1")
            if [[ "$rotational" == "0" ]]; then
                is_ssd=true
                disk_type="SSD"
            else
                disk_type="HDD"
            fi
        fi
        
        log_info "Device $device ($disk_type): Using $scheduler scheduler"
        
        # Check scheduler optimality based on disk type
        case "$disk_type" in
            "NVMe")
                if [[ "$scheduler" == "none" ]]; then
                    log_success "Device $device: Optimal scheduler (none) for NVMe"
                else
                    log_warning "Device $device: Consider 'none' scheduler for NVMe performance"
                    disk_performance_issues=$((disk_performance_issues + 1))
                fi
                ;;
            "SSD")
                if [[ "$scheduler" == "mq-deadline" || "$scheduler" == "none" ]]; then
                    log_success "Device $device: Good scheduler ($scheduler) for SSD"
                else
                    log_warning "Device $device: Consider 'mq-deadline' or 'none' for SSD performance"
                    disk_performance_issues=$((disk_performance_issues + 1))
                fi
                ;;
            "HDD")
                if [[ "$scheduler" == "mq-deadline" || "$scheduler" == "bfq" ]]; then
                    log_success "Device $device: Good scheduler ($scheduler) for HDD"
                else
                    log_info "Device $device: Current scheduler acceptable for HDD"
                fi
                ;;
        esac
        
        # Check queue depth
        if [[ -f "/sys/block/$device/queue/nr_requests" ]]; then
            local queue_depth
            queue_depth=$(cat "/sys/block/$device/queue/nr_requests" 2>/dev/null || echo "0")
            
            if $is_nvme && [[ $queue_depth -lt 128 ]]; then
                log_warning "Device $device: Low queue depth ($queue_depth) for NVMe - consider increasing"
            elif $is_ssd && [[ $queue_depth -lt 32 ]]; then
                log_warning "Device $device: Low queue depth ($queue_depth) for SSD"
            else
                log_info "Device $device: Queue depth $queue_depth"
            fi
        fi
        
        # Check read-ahead settings
        if [[ -f "/sys/block/$device/queue/read_ahead_kb" ]]; then
            local read_ahead
            read_ahead=$(cat "/sys/block/$device/queue/read_ahead_kb" 2>/dev/null || echo "0")
            
            if $is_ssd || $is_nvme; then
                if [[ $read_ahead -gt 128 ]]; then
                    log_warning "Device $device: High read-ahead (${read_ahead}KB) for SSD/NVMe - consider reducing to 4-128KB"
                else
                    log_success "Device $device: Appropriate read-ahead (${read_ahead}KB) for SSD/NVMe"
                fi
            else
                log_info "Device $device: Read-ahead set to ${read_ahead}KB"
            fi
        fi
        
    done
    
    # Check for real-time I/O performance
    check_realtime_io_performance
    
    echo "" >&3
    echo "Storage Performance Summary:" >&3
    echo "- Disk optimization opportunities: $disk_performance_issues" >&3
    
    if [[ $disk_performance_issues -eq 0 ]]; then
        log_success "Storage I/O configuration appears optimal"
    fi
}

# New function: Check ZFS-specific performance
check_zfs_performance() {
    if command -v zpool >/dev/null 2>&1; then
        local zpools
        zpools=$(zpool list -H -o name 2>/dev/null || echo "")
        
        while read -r zpool_name; do
            [[ -z "$zpool_name" ]] && continue
            
            log_info "Analyzing ZFS pool: $zpool_name"
            
            # Check ashift value
            local ashift
            ashift=$(zpool list -o ashift "$zpool_name" -H 2>/dev/null | head -1 || echo "unknown")
            
            if [[ "$ashift" == "12" ]]; then
                log_success "ZFS pool '$zpool_name': Optimal ashift value (12) for 4K sectors"
            elif [[ "$ashift" == "9" ]]; then
                log_warning "ZFS pool '$zpool_name': ashift 9 - may not be optimal for modern disks"
            elif [[ "$ashift" != "unknown" ]]; then
                log_info "ZFS pool '$zpool_name': ashift value $ashift"
            fi
            
            # Check compression
            local compression
            compression=$(zfs get compression "$zpool_name" -H -o value 2>/dev/null || echo "unknown")
            
            if [[ "$compression" != "off" && "$compression" != "unknown" ]]; then
                log_success "ZFS pool '$zpool_name': Compression enabled ($compression)"
            fi
            
            # Check ARC usage
            if [[ -f /proc/spl/kstat/zfs/arcstats ]]; then
                local arc_size
                arc_size=$(awk '/^size/ {print int($3/1024/1024/1024)}' /proc/spl/kstat/zfs/arcstats 2>/dev/null || echo "0")
                
                if [[ $arc_size -gt 0 ]]; then
                    log_info "ZFS ARC size: ${arc_size}GB"
                fi
            fi
            
        done <<< "$zpools"
    fi
}

# New function: Check LVM performance
check_lvm_performance() {
    if command -v lvs >/dev/null 2>&1; then
        local lv_count
        lv_count=$(lvs --noheadings 2>/dev/null | wc -l || echo "0")
        
        if [[ $lv_count -gt 0 ]]; then
            log_info "LVM: $lv_count logical volumes found"
            
            # Check for thin provisioning
            local thin_pools
            thin_pools=$(lvs -o lv_layout --noheadings 2>/dev/null | grep -c "thin,pool" || echo "0")
            
            if [[ $thin_pools -gt 0 ]]; then
                log_info "LVM: $thin_pools thin pools configured"
            fi
        fi
    fi
}

# New function: Check directory storage performance
check_directory_storage_performance() {
    log_info "Directory storage: Check underlying filesystem for optimization"
    
    # Check mount options for common filesystems
    local mount_info
    mount_info=$(mount | grep -E "(ext4|xfs|btrfs)" || echo "")
    
    while IFS= read -r mount_line; do
        if [[ -z "$mount_line" ]]; then
            continue
        fi
        
        local filesystem
        filesystem=$(echo "$mount_line" | awk '{print $5}')
        local mount_point
        mount_point=$(echo "$mount_line" | awk '{print $3}')
        local options
        options=$(echo "$mount_line" | grep -o '([^)]*)' | tr -d '()')
        
        case "$filesystem" in
            "ext4")
                if echo "$options" | grep -q "noatime"; then
                    log_success "$mount_point (ext4): noatime option enabled - good for performance"
                else
                    log_info "$mount_point (ext4): Consider adding noatime mount option"
                fi
                ;;
            "xfs")
                if echo "$options" | grep -q "noatime"; then
                    log_success "$mount_point (xfs): noatime option enabled"
                fi
                ;;
        esac
        
    done <<< "$mount_info"
}

# New function: Check Ceph performance
check_ceph_performance() {
    if command -v ceph >/dev/null 2>&1; then
        local ceph_status
        if ceph_status=$(timeout 10 ceph status 2>/dev/null); then
            log_info "Ceph cluster detected and accessible"
            
            # Check cluster health
            if echo "$ceph_status" | grep -q "HEALTH_OK"; then
                log_success "Ceph cluster: HEALTH_OK"
            elif echo "$ceph_status" | grep -q "HEALTH_WARN"; then
                log_warning "Ceph cluster: HEALTH_WARN - check cluster status"
            fi
        else
            log_info "Ceph configured but cluster not accessible"
        fi
    fi
}

# New function: Real-time I/O performance monitoring
check_realtime_io_performance() {
    log_info "Sampling real-time I/O performance..."
    
    # Use iostat if available for quick I/O sampling
    if command -v iostat >/dev/null 2>&1; then
        local io_stats
        if io_stats=$(timeout 5 iostat -x 1 2 2>/dev/null | tail -n +4); then
            
            echo "Current I/O Statistics:" >&3
            echo "$io_stats" | head -20 >&3
            
            # Analyze I/O utilization
            local high_util_devices=0
            while IFS= read -r line; do
                if [[ -z "$line" || "$line" =~ ^Device: ]]; then
                    continue
                fi
                
                local device util
                device=$(echo "$line" | awk '{print $1}')
                util=$(echo "$line" | awk '{print $NF}' | tr -d '%')
                
                if [[ "$util" =~ ^[0-9]+\.?[0-9]*$ ]] && (( $(echo "$util > 80" | bc -l) 2>/dev/null )); then
                    log_warning "Device $device: High I/O utilization (${util}%)"
                    high_util_devices=$((high_util_devices + 1))
                fi
                
            done <<< "$io_stats"
            
            if [[ $high_util_devices -eq 0 ]]; then
                log_success "All storage devices have healthy I/O utilization"
            fi
        fi
    else
        log_info "iostat not available - install sysstat package for I/O monitoring"
    fi
}

# New function: Real-time performance bottleneck identification
check_performance_bottlenecks() {
    print_section "Performance Bottleneck Analysis"
    
    log_progress "Identifying potential performance bottlenecks..."
    
    local bottlenecks=0
    
    # CPU bottleneck analysis
    log_info "Analyzing CPU performance..."
    
    local load_1min load_5min load_15min
    read -r load_1min load_5min load_15min _ < /proc/loadavg
    
    local cpu_count
    cpu_count=$(nproc)
    
    local load_threshold=$((cpu_count * 80 / 100)) # 80% of CPU count
    
    if (( $(echo "$load_1min > $cpu_count" | bc -l) 2>/dev/null )); then
        log_warning "CPU bottleneck: 1-minute load ($load_1min) exceeds CPU count ($cpu_count)"
        bottlenecks=$((bottlenecks + 1))
    elif (( $(echo "$load_1min > $load_threshold" | bc -l) 2>/dev/null )); then
        log_info "CPU load elevated: 1-minute load ($load_1min) approaching capacity"
    else
        log_success "CPU load healthy: $load_1min (vs $cpu_count cores)"
    fi
    
    # Memory bottleneck analysis
    log_info "Analyzing memory performance..."
    
    local mem_total mem_available mem_used
    mem_total=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
    mem_available=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
    mem_used=$((mem_total - mem_available))
    
    local mem_usage_percent=$((mem_used * 100 / mem_total))
    
    if [[ $mem_usage_percent -gt 90 ]]; then
        log_warning "Memory bottleneck: ${mem_usage_percent}% memory utilization"
        bottlenecks=$((bottlenecks + 1))
    elif [[ $mem_usage_percent -gt 80 ]]; then
        log_info "Memory usage elevated: ${mem_usage_percent}%"
    else
        log_success "Memory usage healthy: ${mem_usage_percent}%"
    fi
    
    # Check for memory pressure
    if [[ -f /proc/pressure/memory ]]; then
        local mem_pressure
        mem_pressure=$(awk '/some avg10=/ {print $2}' /proc/pressure/memory 2>/dev/null | cut -d'=' -f2 || echo "0")
        
        if [[ -n "$mem_pressure" ]] && (( $(echo "$mem_pressure > 10" | bc -l) 2>/dev/null )); then
            log_warning "Memory pressure detected: ${mem_pressure}% (10min average)"
            bottlenecks=$((bottlenecks + 1))
        fi
    fi
    
    # Network bottleneck analysis
    log_info "Analyzing network performance..."
    
    local network_bottlenecks=0
    
    # Check network interface utilization
    for interface in /sys/class/net/*/statistics/rx_bytes; do
        local iface_name
        iface_name=$(basename "$(dirname "$(dirname "$interface")")")
        
        # Skip loopback and virtual interfaces for basic check
        [[ "$iface_name" =~ ^(lo|veth|docker) ]] && continue
        
        # Sample network statistics
        local rx_bytes_before rx_bytes_after tx_bytes_before tx_bytes_after
        rx_bytes_before=$(cat "/sys/class/net/$iface_name/statistics/rx_bytes" 2>/dev/null || echo "0")
        tx_bytes_before=$(cat "/sys/class/net/$iface_name/statistics/tx_bytes" 2>/dev/null || echo "0")
        
        sleep 2
        
        rx_bytes_after=$(cat "/sys/class/net/$iface_name/statistics/rx_bytes" 2>/dev/null || echo "0")
        tx_bytes_after=$(cat "/sys/class/net/$iface_name/statistics/tx_bytes" 2>/dev/null || echo "0")
        
        local rx_rate tx_rate
        rx_rate=$(( (rx_bytes_after - rx_bytes_before) / 2 )) # bytes per second
        tx_rate=$(( (tx_bytes_after - tx_bytes_before) / 2 )) # bytes per second
        
        # Convert to Mbps
        local rx_mbps tx_mbps
        rx_mbps=$((rx_rate * 8 / 1000000))
        tx_mbps=$((tx_rate * 8 / 1000000))
        
        if [[ $rx_mbps -gt 100 || $tx_mbps -gt 100 ]]; then
            log_info "Interface $iface_name: High throughput (RX: ${rx_mbps}Mbps, TX: ${tx_mbps}Mbps)"
        fi
        
        # Check for errors
        local rx_errors tx_errors
        rx_errors=$(cat "/sys/class/net/$iface_name/statistics/rx_errors" 2>/dev/null || echo "0")
        tx_errors=$(cat "/sys/class/net/$iface_name/statistics/tx_errors" 2>/dev/null || echo "0")
        
        if [[ $rx_errors -gt 0 || $tx_errors -gt 0 ]]; then
            log_warning "Interface $iface_name: Network errors detected (RX: $rx_errors, TX: $tx_errors)"
            network_bottlenecks=$((network_bottlenecks + 1))
        fi
        
    done
    
    # Storage I/O bottleneck analysis
    log_info "Analyzing storage I/O bottlenecks..."
    
    local io_bottlenecks=0
    
    # Check I/O wait time
    local io_wait
    io_wait=$(iostat -c 1 2 2>/dev/null | tail -1 | awk '{print $4}' || echo "0")
    
    if [[ -n "$io_wait" ]] && (( $(echo "$io_wait > 20" | bc -l) 2>/dev/null )); then
        log_warning "I/O bottleneck: High I/O wait time (${io_wait}%)"
        io_bottlenecks=$((io_bottlenecks + 1))
    elif [[ -n "$io_wait" ]] && (( $(echo "$io_wait > 10" | bc -l) 2>/dev/null )); then
        log_info "I/O wait time elevated: ${io_wait}%"
    else
        log_success "I/O wait time healthy: ${io_wait}%"
    fi
    
    # VM-specific bottleneck analysis
    log_info "Analyzing VM resource contention..."
    
    local vm_bottlenecks=0
    
    # Check for over-committed memory
    local total_vm_memory=0
    local vm_list
    if vm_list=$(timeout 10 qm list 2>/dev/null | awk 'NR>1 {print $1":"$4}'); then
        while IFS=: read -r vmid vm_memory; do
            [[ -z "$vmid" || -z "$vm_memory" ]] && continue
            total_vm_memory=$((total_vm_memory + vm_memory))
        done <<< "$vm_list"
        
        local host_memory_mb
        host_memory_mb=$((mem_total / 1024))
        
        if [[ $total_vm_memory -gt $host_memory_mb ]]; then
            local overcommit_ratio
            overcommit_ratio=$((total_vm_memory * 100 / host_memory_mb))
            log_warning "Memory overcommitment: ${overcommit_ratio}% (${total_vm_memory}MB allocated vs ${host_memory_mb}MB available)"
            vm_bottlenecks=$((vm_bottlenecks + 1))
        else
            log_success "Memory allocation healthy: ${total_vm_memory}MB allocated vs ${host_memory_mb}MB available"
        fi
    fi
    
    # Summary
    echo "" >&3
    echo "Performance Bottleneck Summary:" >&3
    echo "- CPU bottlenecks: $((bottlenecks > 0 ? 1 : 0))" >&3
    echo "- Memory bottlenecks: $((bottlenecks > 1 ? 1 : 0))" >&3
    echo "- Network bottlenecks: $network_bottlenecks" >&3
    echo "- I/O bottlenecks: $io_bottlenecks" >&3
    echo "- VM resource issues: $vm_bottlenecks" >&3
    
    local total_bottlenecks=$((bottlenecks + network_bottlenecks + io_bottlenecks + vm_bottlenecks))
    
    if [[ $total_bottlenecks -eq 0 ]]; then
        log_success "No significant performance bottlenecks detected"
    else
        log_warning "$total_bottlenecks performance issues detected - review recommendations"
    fi
}

# System Performance Tunables
check_system_tunables() {
    print_section "System Performance Tunables Analysis"
    
    # Check GRUB configuration
    if [[ -f /etc/default/grub ]]; then
        local grub_cmdline
        grub_cmdline=$(grep "GRUB_CMDLINE_LINUX_DEFAULT" /etc/default/grub | cut -d'"' -f2)
        
        log_info "GRUB command line: $grub_cmdline"
        
        # Check for important parameters
        if echo "$grub_cmdline" | grep -q "intel_iommu=on\|amd_iommu=on"; then
            log_success "IOMMU enabled in GRUB"
        else
            log_warning "IOMMU not explicitly enabled - required for GPU passthrough"
        fi
        
        if echo "$grub_cmdline" | grep -q "hugepages="; then
            local hugepages
            hugepages=$(echo "$grub_cmdline" | grep -o "hugepages=[0-9]*" | cut -d'=' -f2)
            log_success "Hugepages configured: $hugepages"
        else
            log_info "Hugepages not configured in GRUB"
        fi
    fi
    
    # Check current system parameters
    log_info "Checking system performance parameters..."
    
    # Check hugepages
    local hugepages_total
    hugepages_total=$(grep "HugePages_Total:" /proc/meminfo | awk '{print $2}' || echo "0")
    
    local hugepages_free  
    hugepages_free=$(grep "HugePages_Free:" /proc/meminfo | awk '{print $2}' || echo "0")
    
    if [[ $hugepages_total -gt 0 ]]; then
        local hugepages_used=$((hugepages_total - hugepages_free))
        log_success "Hugepages: $hugepages_used/$hugepages_total used"
    else
        log_info "Hugepages: Not configured"
    fi
    
    # Check swappiness
    local swappiness
    swappiness=$(cat /proc/sys/vm/swappiness)
    
    if [[ $swappiness -le 10 ]]; then
        log_success "vm.swappiness = $swappiness (optimal for virtualization)"
    else
        log_warning "vm.swappiness = $swappiness (consider lowering to 1-10 for virtualization)"
    fi
    
    # Check transparent hugepages
    local thp_status
    thp_status=$(cat /sys/kernel/mm/transparent_hugepage/enabled | grep -o "\[.*\]" | tr -d '[]')
    
    if [[ "$thp_status" == "never" ]]; then
        log_success "Transparent hugepages: Disabled (optimal for VMs)"
    else
        log_warning "Transparent hugepages: $thp_status (consider disabling for VMs)"
    fi
}

# Hardware Acceleration Check
check_hardware_acceleration() {
    print_section "Hardware Acceleration Analysis"
    
    # Check CPU features
    log_info "Checking CPU virtualization features..."
    
    if grep -q "vmx" /proc/cpuinfo; then
        log_success "Intel VT-x supported"
    elif grep -q "svm" /proc/cpuinfo; then
        log_success "AMD-V supported"
    else
        log_error "Hardware virtualization not supported"
    fi
    
    if grep -q "aes" /proc/cpuinfo; then
        log_success "AES-NI supported"
    else
        log_info "AES-NI not available"
    fi
    
    # Check IOMMU
    if dmesg | grep -q "DMAR\|IOMMU"; then
        log_success "IOMMU supported in hardware"
        
        if dmesg | grep -q "IOMMU enabled"; then
            log_success "IOMMU enabled"
        else
            log_warning "IOMMU supported but not enabled"
        fi
    else
        log_info "IOMMU not available or not enabled"
    fi
    
    # Check for GPU passthrough setup
    if lsmod | grep -q "vfio"; then
        log_success "VFIO modules loaded for GPU passthrough"
        
        local vfio_devices
        vfio_devices=$(find /sys/kernel/iommu_groups -name devices | xargs ls 2>/dev/null | wc -l)
        
        log_info "VFIO devices available: $vfio_devices"
    else
        log_info "VFIO not configured"
    fi
}

# Enhanced performance recommendations with pfSense focus
generate_recommendations() {
    print_section "Performance Recommendations (pfSense Optimized)"
    
    local recommendations=()
    local pfsense_recommendations=()
    
    # System resource analysis
    log_progress "Analyzing system resources for optimization opportunities..."
    
    # Analyze system load
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | xargs)
    
    local cpu_cores
    cpu_cores=$(nproc)
    
    if (( $(echo "$load_avg > $cpu_cores" | bc -l) 2>/dev/null )); then
        recommendations+=("High system load detected ($load_avg vs $cpu_cores cores) - consider balancing VM workloads")
    else
        log_success "System load is healthy ($load_avg vs $cpu_cores cores)"
    fi
    
    # Analyze memory usage
    local mem_usage
    mem_usage=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
    
    if [[ $mem_usage -gt 90 ]]; then
        recommendations+=("High memory usage (${mem_usage}%) - consider adding more RAM or reducing VM memory allocation")
    elif [[ $mem_usage -gt 70 ]]; then
        recommendations+=("Moderate memory usage (${mem_usage}%) - monitor for peak usage periods")
    else
        log_success "Memory usage is healthy (${mem_usage}%)"
    fi
    
    # Analyze storage usage
    local storage_issues=0
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            recommendations+=("High disk usage: $line - consider cleanup or expansion")
            storage_issues=$((storage_issues + 1))
        fi
    done < <(df -h | awk 'NR>1 {gsub(/%/,"",$5); if($5>85) print $6": "$5"%"}')
    
    if [[ $storage_issues -eq 0 ]]; then
        log_success "Storage usage is healthy"
    fi
    
    # Check CPU governor settings
    local performance_cpus=0
    local total_cpus=0
    
    for cpu_gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        if [[ -f "$cpu_gov" ]]; then
            total_cpus=$((total_cpus + 1))
            local governor
            governor=$(cat "$cpu_gov" 2>/dev/null || echo "unknown")
            if [[ "$governor" == "performance" ]]; then
                performance_cpus=$((performance_cpus + 1))
            fi
        fi
    done
    
    if [[ $total_cpus -gt 0 && $performance_cpus -lt $total_cpus ]]; then
        pfsense_recommendations+=("Set CPU governor to 'performance' for optimal pfSense performance: echo performance > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor")
    fi
    
    # Check for hugepages configuration
    local hugepages_total
    hugepages_total=$(grep "HugePages_Total:" /proc/meminfo | awk '{print $2}' || echo "0")
    
    if [[ $hugepages_total -eq 0 ]]; then
        local total_memory_gb
        total_memory_gb=$(free -g | awk 'NR==2{print $2}')
        
        if [[ $total_memory_gb -gt 8 ]]; then
            recommendations+=("Consider enabling hugepages for VMs with >4GB RAM: add hugepages=512 to GRUB_CMDLINE_LINUX_DEFAULT")
        fi
    fi
    
    # Check cluster health (if applicable)
    if command -v pvecm >/dev/null 2>&1; then
        if timeout 10 pvecm status >/dev/null 2>&1; then
            if pvecm status | grep -q "Quorate: Yes"; then
                log_success "Cluster is healthy and quorate"
            else
                recommendations+=("Cluster quorum issues detected - check node connectivity")
            fi
        fi
    fi
    
    # Check for pfSense-specific optimizations
    local vm_list
    if vm_list=$(timeout 10 qm list 2>/dev/null | awk 'NR>1 {print $1}'); then
        local has_pfsense=false
        
        while read -r vmid; do
            [[ -z "$vmid" ]] && continue
            
            local vm_config
            if vm_config=$(timeout 10 qm config "$vmid" 2>/dev/null); then
                local vm_name
                vm_name=$(echo "$vm_config" | grep "^name:" | cut -d' ' -f2 || echo "")
                
                if echo "$vm_name" | grep -qi "pfsense\|opnsense\|router\|firewall"; then
                    has_pfsense=true
                    
                    # Check CPU type
                    local cpu_type
                    cpu_type=$(echo "$vm_config" | grep "^cpu:" | cut -d' ' -f2 || echo "kvm64")
                    
                    if [[ "$cpu_type" != "host" ]]; then
                        pfsense_recommendations+=("VM $vmid ($vm_name): Change CPU type to 'host': qm set $vmid -cpu host")
                    fi
                    
                    # Check memory ballooning
                    local balloon
                    balloon=$(echo "$vm_config" | grep "^balloon:" | awk '{print $2}' || echo "")
                    
                    if [[ -n "$balloon" && "$balloon" != "0" ]]; then
                        pfsense_recommendations+=("VM $vmid ($vm_name): Disable memory ballooning: qm set $vmid -balloon 0")
                    fi
                    
                    # Check storage configuration
                    if ! echo "$vm_config" | grep -q "virtio.*iothread=1"; then
                        pfsense_recommendations+=("VM $vmid ($vm_name): Enable VirtIO with iothread for storage performance")
                    fi
                    
                    if ! echo "$vm_config" | grep -q "cache=writeback"; then
                        pfsense_recommendations+=("VM $vmid ($vm_name): Consider writeback caching for storage performance (ensure UPS protection)")
                    fi
                    
                    # Check network configuration
                    local cores
                    cores=$(echo "$vm_config" | grep "^cores:" | awk '{print $2}' || echo "1")
                    
                    if [[ $cores -gt 1 ]] && ! echo "$vm_config" | grep -q "queues=$cores"; then
                        pfsense_recommendations+=("VM $vmid ($vm_name): Configure network multiqueue: add queues=$cores to network interfaces")
                    fi
                fi
            fi
        done <<< "$vm_list"
        
        if $has_pfsense; then
            log_info "pfSense/router VMs detected - including specialized recommendations"
        fi
    fi
    
    # System-level pfSense optimizations
    if command -v qm >/dev/null 2>&1; then
        # Check for network bridge optimizations
        local bridges
        bridges=$(ip link show type bridge | grep -o "vmbr[0-9]*" || echo "")
        
        if [[ -n "$bridges" ]]; then
            while read -r bridge; do
                [[ -z "$bridge" ]] && continue
                
                local stp_state
                stp_state=$(cat "/sys/class/net/$bridge/bridge/stp_state" 2>/dev/null || echo "1")
                
                if [[ "$stp_state" == "1" ]]; then
                    pfsense_recommendations+=("Disable STP on bridge $bridge: echo 0 > /sys/class/net/$bridge/bridge/stp_state")
                fi
                
                local forward_delay
                forward_delay=$(cat "/sys/class/net/$bridge/bridge/forward_delay" 2>/dev/null || echo "15")
                
                if [[ $forward_delay -gt 0 ]]; then
                    pfsense_recommendations+=("Set bridge forward delay to 0 on $bridge: echo 0 > /sys/class/net/$bridge/bridge/forward_delay")
                fi
            done <<< "$bridges"
        fi
        
        # Check interrupt balance
        if ! systemctl is-active irqbalance >/dev/null 2>&1; then
            pfsense_recommendations+=("Enable IRQ balancing for network performance: systemctl enable --now irqbalance")
        fi
        
        # Check for network optimizations in sysctl
        if [[ -f /proc/sys/net/core/netdev_max_backlog ]]; then
            local backlog
            backlog=$(cat /proc/sys/net/core/netdev_max_backlog 2>/dev/null || echo "1000")
            
            if [[ $backlog -lt 5000 ]]; then
                pfsense_recommendations+=("Increase network backlog: echo 'net.core.netdev_max_backlog = 5000' >> /etc/sysctl.conf")
            fi
        fi
    fi
    
    # Print recommendations
    echo "" >&3
    if [[ ${#recommendations[@]} -gt 0 ]]; then
        echo "⚠️  General optimization recommendations:" >&3
        for rec in "${recommendations[@]}"; do
            echo "   • $rec" >&3
        done
        echo "" >&3
    fi
    
    if [[ ${#pfsense_recommendations[@]} -gt 0 ]]; then
        echo "🔥 pfSense-specific optimization recommendations:" >&3
        for rec in "${pfsense_recommendations[@]}"; do
            echo "   • $rec" >&3
        done
        echo "" >&3
    fi
    
    if [[ ${#recommendations[@]} -eq 0 && ${#pfsense_recommendations[@]} -eq 0 ]]; then
        echo "✅ System appears well-optimized for pfSense workloads!" >&3
        echo "" >&3
    fi
    
    # Additional pfSense-specific optimization tips
    echo "💡 pfSense Performance Optimization Checklist:" >&3
    echo "   • Use 'host' CPU type for maximum performance" >&3
    echo "   • Disable memory ballooning (balloon: 0)" >&3
    echo "   • Use VirtIO storage with iothread and writeback cache" >&3
    echo "   • Use VirtIO network with multiqueue (queues=cores)" >&3
    echo "   • Allocate 2GB+ RAM for optimal performance" >&3
    echo "   • Consider CPU pinning for high-throughput scenarios" >&3
    echo "   • Disable STP on bridges and set forward delay to 0" >&3
    echo "   • Set CPU governor to 'performance' mode" >&3
    echo "   • Enable hardware acceleration (AES-NI, IOMMU)" >&3
    echo "   • Monitor network interrupt distribution" >&3
}

# Enhanced main execution function
main() {
    print_header "Proxmox VE Performance Diagnostic Report - v2.0 (pfSense Optimized)"
    echo "Generated: $(date)" >&3
    echo "Hostname: $(hostname)" >&3
    
    local pve_version
    pve_version=$(pveversion | head -1 2>/dev/null || echo "Version unknown")
    echo "Proxmox Version: $pve_version" >&3
    echo "Focus: pfSense/Router VM Performance Optimization" >&3
    echo "" >&3
    
    # Pre-flight checks
    log_progress "Starting comprehensive diagnostic analysis..."
    verify_proxmox
    clear_vm_locks
    
    # System resource check before starting
    local mem_usage
    mem_usage=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | xargs)
    
    echo "System Status at Start:" >&3
    echo "- Memory Usage: ${mem_usage}%" >&3
    echo "- Load Average: $load_avg" >&3
    echo "- Available Disk: $(df -h / | awk 'NR==2 {print $4}')" >&3
    echo "- CPU Cores: $(nproc)" >&3
    echo "" >&3
    
    # Run diagnostic sections with enhanced analysis
    log_progress "Phase 1: Enhanced VM Configuration Analysis"
    check_vm_configurations
    
    log_progress "Phase 2: Advanced Network Configuration Analysis"
    check_network_configuration
    
    log_progress "Phase 3: NUMA and CPU Configuration Analysis"
    check_numa_configuration
    
    log_progress "Phase 4: CPU Governor and Performance Settings"
    check_cpu_governor_settings
    
    log_progress "Phase 5: Enhanced Storage and I/O Performance Analysis"
    check_storage_configuration
    
    log_progress "Phase 6: System Tunables Analysis"
    check_system_tunables
    
    log_progress "Phase 7: Hardware Acceleration Analysis"
    check_hardware_acceleration
    
    log_progress "Phase 8: Real-time Performance Bottleneck Analysis"
    check_performance_bottlenecks
    
    log_progress "Phase 9: Generating Comprehensive Recommendations"
    generate_recommendations
    
    echo "" >&3
    print_header "Diagnostic Complete - pfSense Performance Analysis"
    echo "Analysis completed successfully!" >&3
    echo "Full detailed log saved to: $LOG_FILE" >&3
    echo "" >&3
    echo "🎯 Next steps for pfSense optimization:" >&3
    echo "1. Review pfSense-specific recommendations above" >&3
    echo "2. Implement VM-level optimizations (CPU, memory, storage)" >&3
    echo "3. Apply network-level optimizations (bridges, interrupts)" >&3
    echo "4. Configure system-level performance settings" >&3
    echo "5. Test network throughput and latency after changes" >&3
    echo "6. Monitor performance metrics over time" >&3
    echo "" >&3
    echo "📋 For pfSense configuration within the VM:" >&3
    echo "   • Disable hardware checksum offload in pfSense" >&3
    echo "   • Configure appropriate MSS clamping" >&3
    echo "   • Optimize network buffer sizes" >&3
    echo "   • Consider traffic shaping for QoS" >&3
}

# Script initialization
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    setup_logging
    main
    log_success "Proxmox diagnostic completed successfully. Check $LOG_FILE for full details."
fi