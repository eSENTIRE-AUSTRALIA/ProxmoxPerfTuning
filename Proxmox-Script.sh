
#bash -c "$(curl -fsSL https://raw.githubusercontent.com/eSENTIRE-AUSTRALIA/ProxmoxPerfTuning/refs/heads/main/Proxmox-Script.sh)"
#curl -fsSL https://raw.githubusercontent.com/eSENTIRE-AUSTRALIA/ProxmoxPerfTuning/refs/heads/main/Proxmox-Script.sh -o Proxmox-Script.sh

#!/usr/bin/env bash
# Proxmox Performance Diagnostic Script - pfSense Optimized
# Version: 2.1 - Fixed bash compatibility issues
# Focus: pfSense VM performance optimization on Proxmox

set -eo pipefail

# Script directory detection
SCRIPT_DIR="${PWD}"
if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

readonly LOG_FILE="${SCRIPT_DIR}/proxmox_diagnostic_$(date +%Y%m%d_%H%M%S).log"
readonly VERBOSE="${VERBOSE:-false}"

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m' 
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Logging functions
setup_logging() {
    exec 3>&1 1>"$LOG_FILE" 2>&1
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
    echo -e "${YELLOW}WARNING: $1${NC}" >&3
    echo "WARNING: $1"
}

log_error() {
    echo -e "${RED}ERROR: $1${NC}" >&3
    echo "ERROR: $1"
}

log_success() {
    echo -e "${GREEN}SUCCESS: $1${NC}" >&3
    echo "SUCCESS: $1"
}

log_progress() {
    echo -e "${BLUE}PROGRESS: $1${NC}" >&3
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

# Check if running on Proxmox
verify_proxmox() {
    if [[ ! -f /etc/pve/storage.cfg ]]; then
        log_error "This script must be run on a Proxmox VE host"
        exit 1
    fi
    
    if ! command -v qm >/dev/null 2>&1; then
        log_error "Proxmox qm command not found"
        exit 1
    fi
    
    log_success "Proxmox VE environment detected"
}

# Clear VM locks
clear_vm_locks() {
    log_progress "Checking for stale VM locks..."
    
    local lock_files
    lock_files=$(find /var/lock/qemu-server/ -name "lock-*.conf" -type f 2>/dev/null || true)
    
    if [[ -n "$lock_files" ]]; then
        echo "$lock_files" | while read -r lock_file; do
            [[ -z "$lock_file" ]] && continue
            
            local vmid
            vmid=$(basename "$lock_file" | grep -o '[0-9]*')
            
            if [[ -n "$vmid" ]]; then
                log_info "Found stale lock for VM $vmid - clearing"
                qm unlock "$vmid" 2>/dev/null || true
                
                if [[ ! -s "$lock_file" ]]; then
                    rm -f "$lock_file" 2>/dev/null || true
                    log_success "Cleared lock for VM $vmid"
                fi
            fi
        done
    else
        log_success "No stale VM locks found"
    fi
}

# VM Configuration Analysis
check_vm_configurations() {
    print_section "VM Configuration Analysis (pfSense Focus)"
    
    local vm_list
    log_progress "Getting VM list..."
    
    if ! vm_list=$(timeout 30 qm list 2>/dev/null | awk 'NR>1 {print $1}'); then
        log_error "Failed to get VM list"
        return 1
    fi
    
    if [[ -z "$vm_list" ]]; then
        log_info "No VMs found on this host"
        return
    fi
    
    local total_vms=0
    local issues_found=0
    local pfsense_vms=0
    
    while read -r vmid; do
        [[ -z "$vmid" ]] && continue
        total_vms=$((total_vms + 1))
        
        log_progress "Analyzing VM $vmid..."
        
        # Check VM status first
        if ! timeout 10 qm status "$vmid" >/dev/null 2>&1; then
            log_warning "VM $vmid: Cannot get status - skipping"
            continue
        fi
        
        # Get VM configuration
        local vm_config
        if ! vm_config=$(timeout 15 qm config "$vmid" 2>/dev/null); then
            log_warning "VM $vmid: Cannot get configuration - skipping"
            continue
        fi
        
        # Detect pfSense/router VMs
        local vm_name
        vm_name=$(echo "$vm_config" | grep "^name:" | cut -d' ' -f2- || echo "VM$vmid")
        
        local is_pfsense=false
        if echo "$vm_name" | grep -qi "pfsense\|opnsense\|router\|firewall\|gateway"; then
            is_pfsense=true
            pfsense_vms=$((pfsense_vms + 1))
            log_success "VM $vmid ($vm_name): Detected pfSense/router VM"
        fi
        
        # Check CPU configuration
        local cpu_type
        cpu_type=$(echo "$vm_config" | grep "^cpu:" | cut -d' ' -f2 || echo "kvm64")
        
        if [[ "$cpu_type" == "host" ]]; then
            if $is_pfsense; then
                log_success "VM $vmid: Optimal CPU type (host) for pfSense"
            else
                log_success "VM $vmid: Using host CPU type"
            fi
        else
            if $is_pfsense; then
                log_error "VM $vmid: pfSense should use 'host' CPU type for optimal performance"
                echo "Fix: qm set $vmid -cpu host" >&3
            else
                log_warning "VM $vmid: Consider using 'host' CPU type"
            fi
            issues_found=$((issues_found + 1))
        fi
        
        # Check memory ballooning (critical for pfSense)
        local balloon
        balloon=$(echo "$vm_config" | grep "^balloon:" | awk '{print $2}' || echo "")
        
        if [[ -n "$balloon" && "$balloon" != "0" ]]; then
            if $is_pfsense; then
                log_error "VM $vmid: Memory ballooning MUST be disabled for pfSense stability"
                echo "Fix: qm set $vmid -balloon 0" >&3
            else
                log_info "VM $vmid: Memory ballooning enabled ($balloon MB)"
            fi
            issues_found=$((issues_found + 1))
        elif $is_pfsense; then
            log_success "VM $vmid: Memory ballooning properly disabled"
        fi
        
        # Check memory allocation
        local memory_mb
        memory_mb=$(echo "$vm_config" | grep "^memory:" | awk '{print $2}' || echo "0")
        
        if $is_pfsense; then
            if [[ $memory_mb -ge 2048 ]]; then
                log_success "VM $vmid: Good memory allocation (${memory_mb}MB) for pfSense"
            else
                log_warning "VM $vmid: Low memory for pfSense (${memory_mb}MB) - consider 2GB+"
            fi
        fi
        
        # Check storage configuration
        local storage_lines
        storage_lines=$(echo "$vm_config" | grep -E "^(virtio|scsi|ide|sata)[0-9]*:")
        
        if echo "$storage_lines" | grep -q "ide\|sata"; then
            if $is_pfsense; then
                log_error "VM $vmid: pfSense should use VirtIO storage for optimal performance"
            else
                log_warning "VM $vmid: IDE/SATA storage - consider VirtIO"
            fi
            issues_found=$((issues_found + 1))
        fi
        
        # Check VirtIO iothread
        if echo "$storage_lines" | grep -q "virtio"; then
            if echo "$storage_lines" | grep -q "iothread=1"; then
                log_success "VM $vmid: VirtIO with iothread enabled"
            else
                log_warning "VM $vmid: VirtIO without iothread - consider enabling"
                issues_found=$((issues_found + 1))
            fi
        fi
        
        # Check cache settings
        if echo "$storage_lines" | grep -q "cache=writeback"; then
            log_success "VM $vmid: Writeback caching enabled (optimal)"
        elif echo "$storage_lines" | grep -q "cache="; then
            local cache_mode
            cache_mode=$(echo "$storage_lines" | grep -o "cache=[a-z]*" | head -1 | cut -d'=' -f2)
            log_info "VM $vmid: Using $cache_mode caching"
        else
            log_warning "VM $vmid: No explicit cache setting - consider writeback"
            issues_found=$((issues_found + 1))
        fi
        
        # Check network configuration
        local net_lines
        net_lines=$(echo "$vm_config" | grep "^net[0-9]*:")
        
        if [[ -z "$net_lines" ]] && $is_pfsense; then
            log_error "VM $vmid: pfSense requires network interfaces!"
            issues_found=$((issues_found + 1))
        fi
        
        local net_count=0
        while read -r net_line; do
            [[ -z "$net_line" ]] && continue
            net_count=$((net_count + 1))
            
            if echo "$net_line" | grep -q "virtio"; then
                log_success "VM $vmid: Using VirtIO network"
            else
                if $is_pfsense; then
                    log_error "VM $vmid: pfSense should use VirtIO network"
                else
                    log_warning "VM $vmid: Not using VirtIO network"
                fi
                issues_found=$((issues_found + 1))
            fi
            
            # Check multiqueue
            local cores
            cores=$(echo "$vm_config" | grep "^cores:" | awk '{print $2}' || echo "1")
            
            if echo "$net_line" | grep -q "queues="; then
                local queues
                queues=$(echo "$net_line" | grep -o "queues=[0-9]*" | cut -d'=' -f2)
                
                if [[ "$queues" == "$cores" ]]; then
                    log_success "VM $vmid: Network multiqueue matches CPU cores"
                else
                    log_warning "VM $vmid: Network queues ($queues) don't match CPU cores ($cores)"
                fi
            elif [[ $cores -gt 1 ]] && echo "$net_line" | grep -q "virtio"; then
                log_warning "VM $vmid: Consider adding multiqueue (queues=$cores)"
                issues_found=$((issues_found + 1))
            fi
            
        done <<< "$net_lines"
        
        if $is_pfsense && [[ $net_count -ge 2 ]]; then
            log_success "VM $vmid: Multiple interfaces for WAN/LAN separation"
        fi
        
    done <<< "$vm_list"
    
    # Summary
    echo "" >&3
    print_section "VM Configuration Summary"
    echo "Total VMs analyzed: $total_vms" >&3
    echo "pfSense/Router VMs found: $pfsense_vms" >&3
    echo "Configuration issues found: $issues_found" >&3
    
    if [[ $issues_found -eq 0 ]]; then
        log_success "All VM configurations are optimal!"
    fi
}

# Network Configuration Analysis
check_network_configuration() {
    print_section "Network Configuration Analysis"
    
    log_progress "Analyzing network bridges..."
    
    local bridges
    bridges=$(ip link show type bridge | grep -o "vmbr[0-9]*" | sort || echo "")
    
    if [[ -z "$bridges" ]]; then
        log_error "No VM bridges found"
        return
    fi
    
    local bridge_issues=0
    
    while read -r bridge; do
        [[ -z "$bridge" ]] && continue
        
        log_info "Analyzing bridge $bridge..."
        
        # Check bridge status
        if ip link show "$bridge" | grep -q "state UP"; then
            log_success "Bridge $bridge: UP"
        else
            log_warning "Bridge $bridge: DOWN"
            bridge_issues=$((bridge_issues + 1))
        fi
        
        # Check STP (should be disabled for performance)
        local stp_state
        stp_state=$(cat "/sys/class/net/$bridge/bridge/stp_state" 2>/dev/null || echo "1")
        
        if [[ "$stp_state" == "0" ]]; then
            log_success "Bridge $bridge: STP disabled (optimal)"
        else
            log_warning "Bridge $bridge: STP enabled - disable for performance"
            echo "Fix: echo 0 > /sys/class/net/$bridge/bridge/stp_state" >&3
            bridge_issues=$((bridge_issues + 1))
        fi
        
        # Check forward delay
        local forward_delay
        forward_delay=$(cat "/sys/class/net/$bridge/bridge/forward_delay" 2>/dev/null || echo "15")
        
        if [[ "$forward_delay" == "0" ]]; then
            log_success "Bridge $bridge: Forward delay disabled"
        else
            log_info "Bridge $bridge: Forward delay ${forward_delay} centiseconds"
            echo "Optimize: echo 0 > /sys/class/net/$bridge/bridge/forward_delay" >&3
        fi
        
        # Check MTU
        local mtu
        mtu=$(ip link show "$bridge" | grep -o "mtu [0-9]*" | awk '{print $2}')
        
        case "$mtu" in
            "1500") log_info "Bridge $bridge: Standard MTU (1500)" ;;
            "9000") log_success "Bridge $bridge: Jumbo frames enabled" ;;
            *) log_info "Bridge $bridge: Custom MTU ($mtu)" ;;
        esac
        
    done <<< "$bridges"
    
    # Check IRQ balance
    if systemctl is-active irqbalance >/dev/null 2>&1; then
        log_success "IRQ balancing service is active"
    else
        log_warning "IRQ balancing not running - consider enabling"
        echo "Fix: systemctl enable --now irqbalance" >&3
    fi
    
    echo "" >&3
    echo "Network bridge issues found: $bridge_issues" >&3
}

# System Performance Analysis
check_system_performance() {
    print_section "System Performance Analysis"
    
    log_progress "Analyzing system performance..."
    
    # CPU analysis
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | xargs)
    local cpu_count
    cpu_count=$(nproc)
    
    # Simple load comparison
    local load_int
    load_int=${load_avg%.*}
    
    if [[ $load_int -gt $cpu_count ]]; then
        log_warning "High CPU load: $load_avg (vs $cpu_count cores)"
    else
        log_success "CPU load healthy: $load_avg"
    fi
    
    # Memory analysis
    local mem_total mem_available
    mem_total=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
    mem_available=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
    local mem_used
    mem_used=$((mem_total - mem_available))
    local mem_percent
    mem_percent=$((mem_used * 100 / mem_total))
    
    if [[ $mem_percent -gt 90 ]]; then
        log_warning "High memory usage: ${mem_percent}%"
    elif [[ $mem_percent -gt 80 ]]; then
        log_info "Elevated memory usage: ${mem_percent}%"
    else
        log_success "Memory usage healthy: ${mem_percent}%"
    fi
    
    # Check CPU governor
    local governor_file="/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
    if [[ -f "$governor_file" ]]; then
        local governor
        governor=$(cat "$governor_file" 2>/dev/null || echo "unknown")
        
        if [[ "$governor" == "performance" ]]; then
            log_success "CPU governor set to performance"
        else
            log_warning "CPU governor: $governor - consider 'performance' for pfSense"
            echo "Fix: echo performance > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor" >&3
        fi
    fi
    
    # Check hugepages
    local hugepages_total
    hugepages_total=$(grep "HugePages_Total:" /proc/meminfo | awk '{print $2}' || echo "0")
    
    if [[ $hugepages_total -gt 0 ]]; then
        local hugepages_free
        hugepages_free=$(grep "HugePages_Free:" /proc/meminfo | awk '{print $2}' || echo "0")
        local hugepages_used
        hugepages_used=$((hugepages_total - hugepages_free))
        log_success "Hugepages: $hugepages_used/$hugepages_total used"
    else
        log_info "Hugepages not configured"
    fi
    
    # Check swappiness
    local swappiness
    swappiness=$(cat /proc/sys/vm/swappiness 2>/dev/null || echo "60")
    
    if [[ $swappiness -le 10 ]]; then
        log_success "Swappiness optimal for virtualization: $swappiness"
    else
        log_warning "High swappiness ($swappiness) - consider lowering to 1-10"
        echo "Fix: echo 'vm.swappiness = 1' >> /etc/sysctl.conf" >&3
    fi
}

# Hardware Analysis
check_hardware_acceleration() {
    print_section "Hardware Acceleration Analysis"
    
    log_progress "Checking hardware acceleration capabilities..."
    
    # Check CPU virtualization features
    if grep -q "vmx\|svm" /proc/cpuinfo; then
        log_success "Hardware virtualization supported"
    else
        log_error "Hardware virtualization not available"
    fi
    
    # Check AES-NI
    if grep -q "aes" /proc/cpuinfo; then
        log_success "AES-NI supported"
    else
        log_warning "AES-NI not available - will impact crypto performance"
    fi
    
    # Check IOMMU
    if dmesg | grep -qi "iommu.*enabled\|dmar"; then
        log_success "IOMMU available and enabled"
    else
        log_info "IOMMU not detected - needed for GPU passthrough"
    fi
    
    # Check VFIO
    if lsmod | grep -q "vfio"; then
        log_success "VFIO modules loaded for device passthrough"
    else
        log_info "VFIO not configured"
    fi
}

# Storage Analysis
check_storage_configuration() {
    print_section "Storage Configuration Analysis"
    
    log_progress "Analyzing storage performance settings..."
    
    # Check I/O schedulers
    local scheduler_issues=0
    
    for scheduler_file in /sys/block/*/queue/scheduler; do
        local device
        device=$(basename "$(dirname "$(dirname "$scheduler_file")")")
        
        # Skip virtual devices
        [[ "$device" =~ ^(loop|ram|dm-) ]] && continue
        
        local current_scheduler
        current_scheduler=$(grep -o '\[.*\]' "$scheduler_file" | tr -d '[]' 2>/dev/null || echo "unknown")
        
        # Detect storage type
        local is_ssd=false
        local is_nvme=false
        
        if [[ "$device" =~ ^nvme ]]; then
            is_nvme=true
        elif [[ -f "/sys/block/$device/queue/rotational" ]]; then
            local rotational
            rotational=$(cat "/sys/block/$device/queue/rotational" 2>/dev/null || echo "1")
            [[ "$rotational" == "0" ]] && is_ssd=true
        fi
        
        # Check scheduler optimality
        if $is_nvme; then
            if [[ "$current_scheduler" == "none" ]]; then
                log_success "Device $device (NVMe): Optimal scheduler (none)"
            else
                log_warning "Device $device (NVMe): Consider 'none' scheduler"
                echo "Fix: echo none > /sys/block/$device/queue/scheduler" >&3
                scheduler_issues=$((scheduler_issues + 1))
            fi
        elif $is_ssd; then
            if [[ "$current_scheduler" == "mq-deadline" || "$current_scheduler" == "none" ]]; then
                log_success "Device $device (SSD): Good scheduler ($current_scheduler)"
            else
                log_info "Device $device (SSD): Using $current_scheduler scheduler"
            fi
        else
            log_info "Device $device (HDD): Using $current_scheduler scheduler"
        fi
        
    done
    
    echo "" >&3
    echo "Storage optimization opportunities: $scheduler_issues" >&3
}

# Generate comprehensive recommendations
generate_recommendations() {
    print_section "pfSense Optimization Recommendations"
    
    log_progress "Generating optimization recommendations..."
    
    echo "" >&3
    echo "🔥 Critical pfSense Optimizations:" >&3
    echo "" >&3
    
    echo "VM Configuration:" >&3
    echo "• CPU Type: qm set VMID -cpu host" >&3
    echo "• Disable Balloon: qm set VMID -balloon 0" >&3
    echo "• Memory: Allocate 2GB+ for pfSense VMs" >&3
    echo "• Storage: Use VirtIO with iothread and writeback cache" >&3
    echo "• Network: Use VirtIO with multiqueue (queues=cores)" >&3
    echo "" >&3
    
    echo "Host-Level Optimizations:" >&3
    echo "• CPU Governor: echo performance > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor" >&3
    echo "• Disable STP: echo 0 > /sys/class/net/vmbr*/bridge/stp_state" >&3
    echo "• Forward Delay: echo 0 > /sys/class/net/vmbr*/bridge/forward_delay" >&3
    echo "• IRQ Balance: systemctl enable --now irqbalance" >&3
    echo "• Swappiness: echo 'vm.swappiness = 1' >> /etc/sysctl.conf" >&3
    echo "" >&3
    
    echo "pfSense VM Settings (inside pfSense):" >&3
    echo "• Disable hardware checksum offload" >&3
    echo "• Configure MSS clamping for your connection" >&3
    echo "• Optimize network buffers (kern.ipc.nmbclusters)" >&3
    echo "• Enable hardware crypto acceleration (AES-NI)" >&3
    echo "" >&3
    
    echo "Performance Testing:" >&3
    echo "• Test throughput with iperf3" >&3
    echo "• Monitor CPU usage during high load" >&3
    echo "• Check network latency and packet loss" >&3
    echo "• Verify interrupt distribution across cores" >&3
    echo "" >&3
}

# Main execution
main() {
    print_header "Proxmox pfSense Performance Diagnostic v2.1"
    echo "Generated: $(date)" >&3
    echo "Hostname: $(hostname)" >&3
    echo "Proxmox Version: $(pveversion | head -1 2>/dev/null || echo "Unknown")" >&3
    echo "Focus: pfSense/Router VM Performance Optimization" >&3
    echo "" >&3
    
    # System info
    local mem_total_gb
    mem_total_gb=$(free -g | awk 'NR==2{print $2}')
    local cpu_count
    cpu_count=$(nproc)
    
    echo "System Overview:" >&3
    echo "- CPU Cores: $cpu_count" >&3
    echo "- Total Memory: ${mem_total_gb}GB" >&3
    echo "- Load Average: $(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | xargs)" >&3
    echo "" >&3
    
    # Run diagnostics
    verify_proxmox
    clear_vm_locks
    
    log_progress "Phase 1: VM Configuration Analysis"
    check_vm_configurations
    
    log_progress "Phase 2: Network Configuration Analysis" 
    check_network_configuration
    
    log_progress "Phase 3: System Performance Analysis"
    check_system_performance
    
    log_progress "Phase 4: Hardware Acceleration Analysis"
    check_hardware_acceleration
    
    log_progress "Phase 5: Storage Configuration Analysis"
    check_storage_configuration
    
    log_progress "Phase 6: Generating Recommendations"
    generate_recommendations
    
    print_header "Diagnostic Complete"
    echo "" >&3
    echo "✅ Analysis completed successfully!" >&3
    echo "📋 Full log saved to: $LOG_FILE" >&3
    echo "" >&3
    echo "🚀 Next Steps:" >&3
    echo "1. Review recommendations above" >&3
    echo "2. Apply VM-level optimizations" >&3
    echo "3. Configure host-level settings" >&3
    echo "4. Test performance improvements" >&3
}

# Script execution
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
    setup_logging
    main
    log_success "Diagnostic completed. Check $LOG_FILE for full details."
fi