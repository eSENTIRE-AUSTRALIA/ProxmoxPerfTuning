#!/usr/bin/env bash
# Proxmox Performance Diagnostic Script
# Validates VM configuration, network, storage, and system tunables
# Version: 1.0

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="${SCRIPT_DIR}/proxmox_diagnostic_$(date +%Y%m%d_%H%M%S).log"
readonly VERBOSE=${VERBOSE:-false}

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m' 
readonly YELLOW='\033[1;33m'
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

# VM Configuration Validation
check_vm_configurations() {
    print_section "VM Configuration Analysis"
    
    local vm_list
    vm_list=$(qm list | awk 'NR>1 {print $1}')
    
    if [[ -z "$vm_list" ]]; then
        log_info "No VMs found on this host"
        return
    fi
    
    local total_vms=0
    local cpu_issues=0
    local memory_issues=0
    local storage_issues=0
    
    while read -r vmid; do
        [[ -z "$vmid" ]] && continue
        total_vms=$((total_vms + 1))
        
        log_info "Analyzing VM $vmid..."
        
        # Check CPU configuration
        local cpu_config
        cpu_config=$(qm config "$vmid" | grep "^cpu:" | cut -d' ' -f2 || echo "kvm64")
        
        case "$cpu_config" in
            "host")
                log_success "VM $vmid: Optimal CPU type (host)"
                ;;
            "kvm64")
                log_warning "VM $vmid: Using default CPU type - consider 'host' for better performance"
                cpu_issues=$((cpu_issues + 1))
                ;;
            *)
                log_info "VM $vmid: Using CPU type $cpu_config"
                ;;
        esac
        
        # Check memory and hugepages
        local memory_mb
        memory_mb=$(qm config "$vmid" | grep "^memory:" | awk '{print $2}' || echo "0")
        
        if [[ $memory_mb -gt 0 ]]; then
            local hugepages
            hugepages=$(qm config "$vmid" | grep "hugepages" | cut -d'=' -f2 || echo "none")
            
            if [[ "$hugepages" == "none" && $memory_mb -ge 4096 ]]; then
                log_warning "VM $vmid: Large VM (${memory_mb}MB) without hugepages - consider enabling"
                memory_issues=$((memory_issues + 1))
            fi
        fi
        
        # Check storage configuration
        local storage_config
        storage_config=$(qm config "$vmid" | grep -E "^(virtio|scsi|ide|sata)" || echo "")
        
        if echo "$storage_config" | grep -q "ide\|sata"; then
            log_warning "VM $vmid: Using IDE/SATA storage - consider VirtIO for better performance"
            storage_issues=$((storage_issues + 1))
        fi
        
        if echo "$storage_config" | grep -q "virtio.*iothread=1"; then
            log_success "VM $vmid: Using VirtIO with iothread"
        elif echo "$storage_config" | grep -q "virtio"; then
            log_warning "VM $vmid: VirtIO without iothread - consider enabling for high-performance workloads"
            storage_issues=$((storage_issues + 1))
        fi
        
        # Check network configuration
        local net_config
        net_config=$(qm config "$vmid" | grep "^net" || echo "")
        
        if echo "$net_config" | grep -q "virtio.*queues="; then
            local queues
            queues=$(echo "$net_config" | grep -o "queues=[0-9]*" | cut -d'=' -f2)
            local cores
            cores=$(qm config "$vmid" | grep "^cores:" | awk '{print $2}' || echo "1")
            
            if [[ $queues -ne $cores ]]; then
                log_warning "VM $vmid: Network queues ($queues) don't match CPU cores ($cores)"
            else
                log_success "VM $vmid: Network multiqueue properly configured"
            fi
        fi
        
    done <<< "$vm_list"
    
    # Summary
    echo "" >&3
    print_section "VM Configuration Summary"
    echo "Total VMs analyzed: $total_vms" >&3
    echo "VMs with CPU optimization opportunities: $cpu_issues" >&3
    echo "VMs with memory optimization opportunities: $memory_issues" >&3
    echo "VMs with storage optimization opportunities: $storage_issues" >&3
}

# Network Bridge Configuration Assessment
check_network_configuration() {
    print_section "Network Configuration Analysis"
    
    # Check bridge configuration
    log_info "Checking network bridges..."
    
    local bridges
    bridges=$(ip link show type bridge | grep -o "vmbr[0-9]*" || echo "")
    
    if [[ -z "$bridges" ]]; then
        log_error "No VM bridges found"
        return
    fi
    
    while read -r bridge; do
        [[ -z "$bridge" ]] && continue
        
        log_info "Analyzing bridge $bridge..."
        
        # Check if bridge is up
        if ip link show "$bridge" | grep -q "state UP"; then
            log_success "Bridge $bridge: UP"
        else
            log_warning "Bridge $bridge: DOWN"
        fi
        
        # Check for STP (should be disabled for performance)
        local stp_state
        stp_state=$(cat "/sys/class/net/$bridge/bridge/stp_state" 2>/dev/null || echo "unknown")
        
        if [[ "$stp_state" == "0" ]]; then
            log_success "Bridge $bridge: STP disabled (optimal)"
        elif [[ "$stp_state" == "1" ]]; then
            log_warning "Bridge $bridge: STP enabled - consider disabling for performance"
        fi
        
        # Check for VLAN awareness
        local vlan_filtering
        vlan_filtering=$(cat "/sys/class/net/$bridge/bridge/vlan_filtering" 2>/dev/null || echo "0")
        
        if [[ "$vlan_filtering" == "1" ]]; then
            log_info "Bridge $bridge: VLAN-aware"
        fi
        
        # Check MTU settings
        local mtu
        mtu=$(ip link show "$bridge" | grep -o "mtu [0-9]*" | awk '{print $2}')
        
        if [[ $mtu -eq 1500 ]]; then
            log_info "Bridge $bridge: Standard MTU (1500)"
        elif [[ $mtu -eq 9000 ]]; then
            log_success "Bridge $bridge: Jumbo frames enabled (9000)"
        else
            log_info "Bridge $bridge: Custom MTU ($mtu)"
        fi
        
    done <<< "$bridges"
}

# NUMA and CPU Pinning Analysis
check_numa_configuration() {
    print_section "NUMA and CPU Configuration Analysis"
    
    # Check NUMA topology
    if command -v numactl >/dev/null 2>&1; then
        local numa_nodes
        numa_nodes=$(numactl --hardware | grep "available:" | awk '{print $2}')
        
        log_info "NUMA nodes available: $numa_nodes"
        
        # Check VMs with NUMA configuration
        local vm_list
        vm_list=$(qm list | awk 'NR>1 {print $1}')
        
        while read -r vmid; do
            [[ -z "$vmid" ]] && continue
            
            local cores
            cores=$(qm config "$vmid" | grep "^cores:" | awk '{print $2}' || echo "1")
            
            local numa_config
            numa_config=$(qm config "$vmid" | grep "^numa:" || echo "")
            
            if [[ $cores -gt 8 && -z "$numa_config" ]]; then
                log_warning "VM $vmid: Large VM ($cores cores) without NUMA configuration"
            fi
            
            # Check CPU affinity
            local affinity
            affinity=$(qm config "$vmid" | grep "^affinity:" || echo "")
            
            if [[ -n "$affinity" ]]; then
                log_success "VM $vmid: CPU affinity configured"
            fi
            
        done <<< "$vm_list"
    else
        log_warning "numactl not available - cannot check NUMA topology"
    fi
}

# Storage Performance Analysis
check_storage_configuration() {
    print_section "Storage Configuration Analysis"
    
    # Check storage definitions
    if [[ -f /etc/pve/storage.cfg ]]; then
        log_info "Analyzing storage configurations..."
        
        local storage_types
        storage_types=$(grep "^[a-z]" /etc/pve/storage.cfg | grep -v "^$" | cut -d':' -f1 | sort | uniq)
        
        while read -r storage_type; do
            [[ -z "$storage_type" ]] && continue
            
            local storage_count
            storage_count=$(grep "^$storage_type:" /etc/pve/storage.cfg | wc -l)
            
            log_info "Storage type '$storage_type': $storage_count configured"
            
            # Check for performance-related settings
            if [[ "$storage_type" == "zfs" ]]; then
                # Check ZFS configuration
                if command -v zpool >/dev/null 2>&1; then
                    local zpools
                    zpools=$(zpool list -H -o name 2>/dev/null || echo "")
                    
                    while read -r zpool_name; do
                        [[ -z "$zpool_name" ]] && continue
                        
                        local ashift
                        ashift=$(zpool list -v "$zpool_name" 2>/dev/null | grep "ashift" || echo "")
                        
                        if [[ -n "$ashift" ]]; then
                            log_info "ZFS pool '$zpool_name': $ashift"
                        fi
                    done <<< "$zpools"
                fi
            fi
            
        done <<< "$storage_types"
    fi
    
    # Check I/O scheduler
    log_info "Checking I/O schedulers..."
    
    for disk in /sys/block/*/queue/scheduler; do
        local device
        device=$(basename "$(dirname "$(dirname "$disk")")")
        
        [[ "$device" =~ ^(loop|ram) ]] && continue
        
        local scheduler
        scheduler=$(cat "$disk" | grep -o "\[.*\]" | tr -d '[]' || echo "unknown")
        
        case "$scheduler" in
            "mq-deadline")
                log_success "Device $device: Using mq-deadline scheduler (good for SSDs)"
                ;;
            "none")
                log_info "Device $device: No scheduler (optimal for NVMe)"
                ;;
            "bfq")
                log_info "Device $device: Using BFQ scheduler (good for interactive workloads)"
                ;;
            *)
                log_info "Device $device: Using $scheduler scheduler"
                ;;
        esac
    done
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

# Performance Monitoring and Recommendations
generate_recommendations() {
    print_section "Performance Recommendations"
    
    local recommendations=()
    
    # Analyze system load
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | xargs)
    
    local cpu_cores
    cpu_cores=$(nproc)
    
    if (( $(echo "$load_avg > $cpu_cores" | bc -l) 2>/dev/null )); then
        recommendations+=("High system load detected ($load_avg vs $cpu_cores cores) - consider balancing VM workloads")
    fi
    
    # Analyze memory usage
    local mem_usage
    mem_usage=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
    
    if [[ $mem_usage -gt 90 ]]; then
        recommendations+=("High memory usage (${mem_usage}%) - consider adding more RAM or reducing VM memory allocation")
    fi
    
    # Analyze storage
    df -h | awk 'NR>1 {gsub(/%/,"",$5); if($5>85) print $6": "$5"%"}' | while read disk_info; do
        recommendations+=("High disk usage: $disk_info - consider cleanup or expansion")
    done
    
    # Print recommendations
    if [[ ${#recommendations[@]} -gt 0 ]]; then
        for rec in "${recommendations[@]}"; do
            echo "- $rec" >&3
        done
    else
        echo "No critical issues detected." >&3
    fi
}

# Main execution function
main() {
    print_header "Proxmox VE Performance Diagnostic Report"
    echo "Generated: $(date)" >&3
    echo "Hostname: $(hostname)" >&3
    echo "Proxmox Version: $(pveversion | head -1)" >&3
    echo "" >&3
    
    verify_proxmox
    check_vm_configurations
    check_network_configuration
    check_numa_configuration
    check_storage_configuration
    check_system_tunables
    check_hardware_acceleration
    generate_recommendations
    
    echo "" >&3
    print_header "Diagnostic Complete"
    echo "Full log saved to: $LOG_FILE" >&3
}

# Script initialization
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    setup_logging
    main
    log_success "Proxmox diagnostic completed. Check $LOG_FILE for full details."
fi
