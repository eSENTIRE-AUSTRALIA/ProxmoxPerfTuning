#!/usr/bin/env bash
# Comprehensive Proxmox pfSense Performance Diagnostic Script
# Version: 3.0 - Complete rewrite for reliability and comprehensive analysis
# Focus: Maximum pfSense VM performance optimization

# Basic script setup - minimal error handling to avoid early exits
set -e

# Global variables
SCRIPT_NAME="Proxmox pfSense Performance Diagnostic v3.0"
LOG_FILE="proxmox_diagnostic_$(date +%Y%m%d_%H%M%S).log"
VERBOSE="${VERBOSE:-false}"
TOTAL_ISSUES=0
PFSENSE_VMS=0

# Colors for output
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
fi

# Logging functions
log_to_file() {
    echo "$1" >> "$LOG_FILE"
}

log_info() {
    local msg="INFO: $1"
    echo "$msg" >> "$LOG_FILE"
    [[ "$VERBOSE" == "true" ]] && echo -e "${BLUE}$msg${NC}"
}

log_success() {
    local msg="SUCCESS: $1"
    echo "$msg" >> "$LOG_FILE"
    echo -e "${GREEN}$msg${NC}"
}

log_warning() {
    local msg="WARNING: $1"
    echo "$msg" >> "$LOG_FILE"
    echo -e "${YELLOW}$msg${NC}"
    TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
}

log_error() {
    local msg="ERROR: $1"
    echo "$msg" >> "$LOG_FILE"
    echo -e "${RED}$msg${NC}"
    TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
}

log_progress() {
    local msg="$1"
    echo "$msg" >> "$LOG_FILE"
    echo -e "${BOLD}$msg${NC}"
}

print_header() {
    local header="$1"
    echo "" | tee -a "$LOG_FILE"
    echo "===============================================" | tee -a "$LOG_FILE"
    echo "$header" | tee -a "$LOG_FILE"
    echo "===============================================" | tee -a "$LOG_FILE"
}

print_section() {
    echo "" | tee -a "$LOG_FILE"
    echo "--- $1 ---" | tee -a "$LOG_FILE"
}

# Utility functions
is_integer() {
    [[ $1 =~ ^[0-9]+$ ]]
}

safe_read_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cat "$file" 2>/dev/null || echo ""
    else
        echo ""
    fi
}

# Check if running on Proxmox
verify_proxmox() {
    log_progress "Verifying Proxmox VE environment..."
    
    if [[ ! -f /etc/pve/storage.cfg ]]; then
        log_error "This script must be run on a Proxmox VE host"
        echo "Missing /etc/pve/storage.cfg - not a Proxmox system"
        exit 1
    fi
    
    if ! command -v qm >/dev/null 2>&1; then
        log_error "Proxmox qm command not found"
        echo "qm command not available - Proxmox tools not installed"
        exit 1
    fi
    
    local pve_version
    pve_version=$(pveversion 2>/dev/null | head -1 || echo "Unknown version")
    
    log_success "Proxmox VE environment verified: $pve_version"
    echo "Proxmox Version: $pve_version" >> "$LOG_FILE"
}

# Clear VM locks safely
clear_vm_locks() {
    log_progress "Checking and clearing stale VM locks..."
    
    local locks_found=0
    local locks_cleared=0
    
    # Simple approach - iterate through lock files directly
    if [[ -d /var/lock/qemu-server ]]; then
        for lock_file in /var/lock/qemu-server/lock-*.conf; do
            # Skip if no files match the pattern
            [[ ! -f "$lock_file" ]] && continue
            
            locks_found=$((locks_found + 1))
            local vmid
            vmid=$(basename "$lock_file" | sed 's/lock-//g' | sed 's/\.conf//g')
            
            if is_integer "$vmid"; then
                log_info "Found lock for VM $vmid - attempting to clear"
                
                # Try to unlock
                if qm unlock "$vmid" >/dev/null 2>&1; then
                    log_info "Successfully unlocked VM $vmid"
                fi
                
                # Remove empty lock file
                if [[ ! -s "$lock_file" ]]; then
                    rm -f "$lock_file" 2>/dev/null && locks_cleared=$((locks_cleared + 1))
                fi
            fi
        done
    fi
    
    if [[ $locks_found -eq 0 ]]; then
        log_success "No VM locks found"
    else
        log_success "Processed $locks_found locks, cleared $locks_cleared"
    fi
}

# Comprehensive VM analysis
analyze_vm_configurations() {
    print_section "VM Configuration Analysis (pfSense Optimized)"
    
    log_progress "Retrieving VM list..."
    
    # Get VM list with timeout
    local vm_list=""
    if ! vm_list=$(timeout 30 qm list 2>/dev/null); then
        log_error "Failed to retrieve VM list - qm command timed out"
        return 1
    fi
    
    if [[ -z "$vm_list" ]]; then
        log_info "No VMs found on this host"
        return 0
    fi
    
    # Parse VMs (skip header line)
    local vm_count=0
    local analyzed_count=0
    local skipped_count=0
    
    while IFS= read -r vm_line; do
        # Skip header and empty lines
        [[ "$vm_line" =~ ^[[:space:]]*$ ]] && continue
        [[ "$vm_line" =~ ^[[:space:]]*VMID ]] && continue
        
        vm_count=$((vm_count + 1))
        
        # Extract VM info
        local vmid name status memory
        vmid=$(echo "$vm_line" | awk '{print $1}')
        name=$(echo "$vm_line" | awk '{print $2}')
        status=$(echo "$vm_line" | awk '{print $3}')
        memory=$(echo "$vm_line" | awk '{print $4}')
        
        # Skip if we can't parse VMID
        if ! is_integer "$vmid"; then
            continue
        fi
        
        log_progress "Analyzing VM $vmid ($name)..."
        
        # Try to get VM status first
        local vm_status=""
        if ! vm_status=$(timeout 15 qm status "$vmid" 2>/dev/null); then
            log_warning "VM $vmid: Cannot retrieve status - skipping detailed analysis"
            skipped_count=$((skipped_count + 1))
            continue
        fi
        
        # Try to get VM configuration
        local vm_config=""
        if ! vm_config=$(timeout 15 qm config "$vmid" 2>/dev/null); then
            log_warning "VM $vmid: Cannot retrieve configuration - skipping detailed analysis"
            skipped_count=$((skipped_count + 1))
            continue
        fi
        
        analyzed_count=$((analyzed_count + 1))
        
        # Detect if this is a pfSense/router VM
        local is_pfsense=false
        if echo "$name" | grep -qi "pfsense\|opnsense\|router\|firewall\|gateway\|fw"; then
            is_pfsense=true
            PFSENSE_VMS=$((PFSENSE_VMS + 1))
            log_success "VM $vmid ($name): pfSense/Router VM detected"
        fi
        
        # Analyze CPU configuration
        analyze_vm_cpu "$vmid" "$name" "$vm_config" "$is_pfsense"
        
        # Analyze memory configuration
        analyze_vm_memory "$vmid" "$name" "$vm_config" "$is_pfsense"
        
        # Analyze storage configuration
        analyze_vm_storage "$vmid" "$name" "$vm_config" "$is_pfsense"
        
        # Analyze network configuration
        analyze_vm_network "$vmid" "$name" "$vm_config" "$is_pfsense"
        
    done <<< "$vm_list"
    
    # Summary
    echo "" >> "$LOG_FILE"
    echo "VM Analysis Summary:" >> "$LOG_FILE"
    echo "- Total VMs found: $vm_count" >> "$LOG_FILE"
    echo "- VMs analyzed: $analyzed_count" >> "$LOG_FILE"
    echo "- VMs skipped: $skipped_count" >> "$LOG_FILE"
    echo "- pfSense/Router VMs: $PFSENSE_VMS" >> "$LOG_FILE"
    
    if [[ $PFSENSE_VMS -gt 0 ]]; then
        log_success "Found $PFSENSE_VMS pfSense/router VMs - applied enhanced analysis"
    fi
}

# VM CPU analysis
analyze_vm_cpu() {
    local vmid="$1" name="$2" config="$3" is_pfsense="$4"
    
    # Extract CPU configuration
    local cpu_type cores sockets
    cpu_type=$(echo "$config" | grep "^cpu:" | cut -d' ' -f2 2>/dev/null || echo "kvm64")
    cores=$(echo "$config" | grep "^cores:" | awk '{print $2}' 2>/dev/null || echo "1")
    sockets=$(echo "$config" | grep "^sockets:" | awk '{print $2}' 2>/dev/null || echo "1")
    
    # Check CPU type
    case "$cpu_type" in
        "host")
            if [[ "$is_pfsense" == "true" ]]; then
                log_success "VM $vmid: Optimal CPU type (host) - excellent for pfSense performance"
            else
                log_success "VM $vmid: Using host CPU type"
            fi
            ;;
        "kvm64")
            if [[ "$is_pfsense" == "true" ]]; then
                log_error "VM $vmid: pfSense REQUIRES 'host' CPU type for optimal performance"
                echo "CRITICAL FIX: qm set $vmid -cpu host" >> "$LOG_FILE"
            else
                log_warning "VM $vmid: Using default CPU type - consider 'host' for better performance"
                echo "OPTIMIZE: qm set $vmid -cpu host" >> "$LOG_FILE"
            fi
            ;;
        *)
            log_info "VM $vmid: Using CPU type '$cpu_type'"
            if [[ "$is_pfsense" == "true" ]]; then
                log_warning "VM $vmid: pfSense performs best with 'host' CPU type"
                echo "OPTIMIZE: qm set $vmid -cpu host" >> "$LOG_FILE"
            fi
            ;;
    esac
    
    # Check core allocation for pfSense
    if [[ "$is_pfsense" == "true" ]]; then
        if is_integer "$cores"; then
            if [[ $cores -ge 4 ]]; then
                log_success "VM $vmid: Excellent CPU allocation ($cores cores) for pfSense"
            elif [[ $cores -eq 2 ]]; then
                log_info "VM $vmid: Good CPU allocation ($cores cores) for basic pfSense usage"
            else
                log_warning "VM $vmid: Low CPU allocation ($cores cores) - consider 2-4 cores for pfSense"
                echo "OPTIMIZE: qm set $vmid -cores 2" >> "$LOG_FILE"
            fi
        fi
    fi
    
    log_to_file "VM $vmid CPU: type=$cpu_type, cores=$cores, sockets=$sockets"
}

# VM memory analysis
analyze_vm_memory() {
    local vmid="$1" name="$2" config="$3" is_pfsense="$4"
    
    # Extract memory configuration
    local memory balloon hugepages shares
    memory=$(echo "$config" | grep "^memory:" | awk '{print $2}' 2>/dev/null || echo "0")
    balloon=$(echo "$config" | grep "^balloon:" | awk '{print $2}' 2>/dev/null || echo "")
    hugepages=$(echo "$config" | grep "^hugepages:" | awk '{print $2}' 2>/dev/null || echo "")
    shares=$(echo "$config" | grep "^shares:" | awk '{print $2}' 2>/dev/null || echo "")
    
    # Check memory balloon (critical for pfSense)
    if [[ -n "$balloon" && "$balloon" != "0" ]]; then
        if [[ "$is_pfsense" == "true" ]]; then
            log_error "VM $vmid: Memory ballooning ENABLED ($balloon MB) - CRITICAL: Must disable for pfSense!"
            echo "CRITICAL FIX: qm set $vmid -balloon 0" >> "$LOG_FILE"
        else
            log_info "VM $vmid: Memory ballooning enabled ($balloon MB)"
        fi
    else
        if [[ "$is_pfsense" == "true" ]]; then
            log_success "VM $vmid: Memory ballooning properly disabled"
        fi
    fi
    
    # Check memory allocation
    if is_integer "$memory" && [[ $memory -gt 0 ]]; then
        if [[ "$is_pfsense" == "true" ]]; then
            if [[ $memory -ge 4096 ]]; then
                log_success "VM $vmid: Excellent memory allocation (${memory}MB) for pfSense"
            elif [[ $memory -ge 2048 ]]; then
                log_success "VM $vmid: Good memory allocation (${memory}MB) for pfSense"
            elif [[ $memory -ge 1024 ]]; then
                log_warning "VM $vmid: Adequate memory (${memory}MB) - consider 2GB+ for optimal pfSense performance"
                echo "OPTIMIZE: qm set $vmid -memory 2048" >> "$LOG_FILE"
            else
                log_error "VM $vmid: Insufficient memory (${memory}MB) for pfSense - minimum 1GB recommended"
                echo "CRITICAL FIX: qm set $vmid -memory 2048" >> "$LOG_FILE"
            fi
        fi
        
        # Check hugepages for large VMs
        if [[ $memory -ge 4096 ]]; then
            if [[ -n "$hugepages" && "$hugepages" != "0" ]]; then
                log_success "VM $vmid: Hugepages enabled for large VM"
            else
                log_info "VM $vmid: Large VM (${memory}MB) - consider enabling hugepages"
                echo "OPTIMIZE: qm set $vmid -hugepages 1024" >> "$LOG_FILE"
            fi
        fi
    fi
    
    log_to_file "VM $vmid Memory: memory=${memory}MB, balloon=$balloon, hugepages=$hugepages"
}

# VM storage analysis
analyze_vm_storage() {
    local vmid="$1" name="$2" config="$3" is_pfsense="$4"
    
    # Find all storage devices
    local storage_lines
    storage_lines=$(echo "$config" | grep -E "^(virtio|scsi|ide|sata|efidisk)[0-9]*:" || echo "")
    
    if [[ -z "$storage_lines" ]]; then
        log_warning "VM $vmid: No storage devices found"
        return
    fi
    
    local has_virtio=false
    local has_iothread=false
    local has_writeback=false
    local has_io_uring=false
    local storage_count=0
    
    while IFS= read -r storage_line; do
        [[ -z "$storage_line" ]] && continue
        storage_count=$((storage_count + 1))
        
        local disk_name
        disk_name=$(echo "$storage_line" | cut -d':' -f1)
        
        # Check storage type
        if echo "$storage_line" | grep -q "^virtio"; then
            has_virtio=true
            log_success "VM $vmid ($disk_name): Using VirtIO storage"
            
            # Check for iothread
            if echo "$storage_line" | grep -q "iothread=1"; then
                has_iothread=true
                log_success "VM $vmid ($disk_name): iothread enabled - optimal for performance"
            else
                if [[ "$is_pfsense" == "true" ]]; then
                    log_warning "VM $vmid ($disk_name): iothread disabled - enable for pfSense performance"
                    echo "OPTIMIZE: Add iothread=1 to $disk_name configuration" >> "$LOG_FILE"
                else
                    log_info "VM $vmid ($disk_name): Consider enabling iothread"
                fi
            fi
            
            # Check cache mode
            if echo "$storage_line" | grep -q "cache=writeback"; then
                has_writeback=true
                log_success "VM $vmid ($disk_name): Writeback caching - optimal for performance"
            elif echo "$storage_line" | grep -q "cache=writethrough"; then
                log_info "VM $vmid ($disk_name): Writethrough caching - safe but slower"
                if [[ "$is_pfsense" == "true" ]]; then
                    log_info "VM $vmid ($disk_name): Consider writeback for pfSense (with UPS backup)"
                fi
            elif echo "$storage_line" | grep -q "cache=none"; then
                log_info "VM $vmid ($disk_name): No caching - direct I/O mode"
            else
                log_warning "VM $vmid ($disk_name): No cache setting specified"
                echo "OPTIMIZE: Add cache=writeback to $disk_name (ensure UPS protection)" >> "$LOG_FILE"
            fi
            
            # Check AIO mode
            if echo "$storage_line" | grep -q "aio=io_uring"; then
                has_io_uring=true
                log_success "VM $vmid ($disk_name): Using io_uring AIO - optimal for modern kernels"
            elif echo "$storage_line" | grep -q "aio=native"; then
                log_info "VM $vmid ($disk_name): Using native AIO"
            else
                log_info "VM $vmid ($disk_name): Default AIO - consider io_uring"
                echo "OPTIMIZE: Add aio=io_uring to $disk_name" >> "$LOG_FILE"
            fi
            
        elif echo "$storage_line" | grep -q -E "^(ide|sata)"; then
            if [[ "$is_pfsense" == "true" ]]; then
                log_error "VM $vmid ($disk_name): Using IDE/SATA - pfSense REQUIRES VirtIO for optimal performance"
                echo "CRITICAL FIX: Convert $disk_name to VirtIO storage" >> "$LOG_FILE"
            else
                log_warning "VM $vmid ($disk_name): Using IDE/SATA - consider VirtIO for better performance"
            fi
        elif echo "$storage_line" | grep -q "^scsi"; then
            log_info "VM $vmid ($disk_name): Using SCSI storage"
            if [[ "$is_pfsense" == "true" ]]; then
                log_info "VM $vmid ($disk_name): SCSI acceptable for pfSense, but VirtIO preferred"
            fi
        fi
        
    done <<< "$storage_lines"
    
    log_to_file "VM $vmid Storage: devices=$storage_count, virtio=$has_virtio, iothread=$has_iothread, writeback=$has_writeback, io_uring=$has_io_uring"
}

# VM network analysis
analyze_vm_network() {
    local vmid="$1" name="$2" config="$3" is_pfsense="$4"
    
    # Find all network devices
    local network_lines
    network_lines=$(echo "$config" | grep -E "^net[0-9]+:" || echo "")
    
    if [[ -z "$network_lines" ]]; then
        if [[ "$is_pfsense" == "true" ]]; then
            log_error "VM $vmid: No network interfaces - pfSense REQUIRES network interfaces!"
        else
            log_info "VM $vmid: No network interfaces configured"
        fi
        return
    fi
    
    local network_count=0
    local virtio_count=0
    local multiqueue_count=0
    local cores
    cores=$(echo "$config" | grep "^cores:" | awk '{print $2}' 2>/dev/null || echo "1")
    
    while IFS= read -r net_line; do
        [[ -z "$net_line" ]] && continue
        network_count=$((network_count + 1))
        
        local net_name
        net_name=$(echo "$net_line" | cut -d':' -f1)
        
        # Check network model
        if echo "$net_line" | grep -q "model=virtio\|virtio="; then
            virtio_count=$((virtio_count + 1))
            log_success "VM $vmid ($net_name): Using VirtIO network"
            
            # Check multiqueue
            if echo "$net_line" | grep -q "queues="; then
                local queues
                queues=$(echo "$net_line" | grep -o "queues=[0-9]*" | cut -d'=' -f2 | head -1)
                
                if [[ "$queues" == "$cores" ]]; then
                    multiqueue_count=$((multiqueue_count + 1))
                    log_success "VM $vmid ($net_name): Multiqueue matches CPU cores ($queues)"
                else
                    log_warning "VM $vmid ($net_name): Multiqueue ($queues) doesn't match CPU cores ($cores)"
                    echo "OPTIMIZE: Set queues=$cores for $net_name" >> "$LOG_FILE"
                fi
            else
                if is_integer "$cores" && [[ $cores -gt 1 ]]; then
                    if [[ "$is_pfsense" == "true" ]]; then
                        log_warning "VM $vmid ($net_name): Missing multiqueue - critical for pfSense performance"
                        echo "CRITICAL OPTIMIZE: Add queues=$cores to $net_name" >> "$LOG_FILE"
                    else
                        log_info "VM $vmid ($net_name): Consider adding multiqueue (queues=$cores)"
                    fi
                fi
            fi
            
            # Check advanced VirtIO settings
            if echo "$net_line" | grep -q "rx_queue_size="; then
                local rx_queue_size
                rx_queue_size=$(echo "$net_line" | grep -o "rx_queue_size=[0-9]*" | cut -d'=' -f2)
                if [[ $rx_queue_size -ge 1024 ]]; then
                    log_success "VM $vmid ($net_name): Large RX queue size ($rx_queue_size) - good for throughput"
                fi
            fi
            
        else
            if [[ "$is_pfsense" == "true" ]]; then
                log_error "VM $vmid ($net_name): Not using VirtIO - pfSense REQUIRES VirtIO for optimal performance"
                echo "CRITICAL FIX: Change $net_name to VirtIO model" >> "$LOG_FILE"
            else
                log_warning "VM $vmid ($net_name): Not using VirtIO network"
            fi
        fi
        
    done <<< "$network_lines"
    
    # pfSense specific network recommendations
    if [[ "$is_pfsense" == "true" ]]; then
        if [[ $network_count -ge 2 ]]; then
            log_success "VM $vmid: Multiple network interfaces ($network_count) - good for WAN/LAN separation"
        elif [[ $network_count -eq 1 ]]; then
            log_info "VM $vmid: Single network interface - consider separate WAN/LAN interfaces"
            echo "OPTIMIZE: Add second network interface for WAN/LAN separation" >> "$LOG_FILE"
        fi
    fi
    
    log_to_file "VM $vmid Network: interfaces=$network_count, virtio=$virtio_count, multiqueue=$multiqueue_count"
}

# System performance analysis
analyze_system_performance() {
    print_section "System Performance Analysis"
    
    log_progress "Analyzing system performance metrics..."
    
    # CPU Analysis
    local cpu_count load_1min load_5min load_15min
    cpu_count=$(nproc)
    read -r load_1min load_5min load_15min _ < /proc/loadavg
    
    echo "CPU Cores: $cpu_count" >> "$LOG_FILE"
    echo "Load Average: $load_1min (1min), $load_5min (5min), $load_15min (15min)" >> "$LOG_FILE"
    
    # Simple load analysis without bc
    local load_int=${load_1min%.*}
    if [[ $load_int -gt $cpu_count ]]; then
        log_warning "High CPU load: $load_1min (exceeds $cpu_count cores)"
        echo "INVESTIGATE: Check for CPU-intensive processes" >> "$LOG_FILE"
    else
        log_success "CPU load healthy: $load_1min"
    fi
    
    # Memory Analysis
    local mem_total mem_available mem_used mem_percent
    mem_total=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
    mem_available=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
    mem_used=$((mem_total - mem_available))
    mem_percent=$((mem_used * 100 / mem_total))
    
    echo "Memory Total: $((mem_total / 1024))MB" >> "$LOG_FILE"
    echo "Memory Used: $((mem_used / 1024))MB (${mem_percent}%)" >> "$LOG_FILE"
    
    if [[ $mem_percent -gt 90 ]]; then
        log_error "Critical memory usage: ${mem_percent}%"
        echo "CRITICAL: Consider adding more RAM or reducing VM allocation" >> "$LOG_FILE"
    elif [[ $mem_percent -gt 80 ]]; then
        log_warning "High memory usage: ${mem_percent}%"
        echo "MONITOR: Watch for memory pressure during peak usage" >> "$LOG_FILE"
    else
        log_success "Memory usage healthy: ${mem_percent}%"
    fi
    
    # Check for swap usage
    local swap_total swap_used
    swap_total=$(awk '/SwapTotal:/ {print $2}' /proc/meminfo)
    swap_used=$(awk '/SwapTotal:/ {print $2}' /proc/meminfo)
    swap_used=$((swap_used - $(awk '/SwapFree:/ {print $2}' /proc/meminfo)))
    
    if [[ $swap_used -gt 0 ]]; then
        log_warning "Swap usage detected: $((swap_used / 1024))MB used"
        echo "OPTIMIZE: Reduce memory pressure to avoid swap usage" >> "$LOG_FILE"
    fi
}

# CPU governor and performance settings analysis
analyze_cpu_performance() {
    print_section "CPU Performance Settings Analysis"
    
    log_progress "Checking CPU governor and performance settings..."
    
    local governor_file="/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
    if [[ -f "$governor_file" ]]; then
        local governor
        governor=$(safe_read_file "$governor_file")
        
        case "$governor" in
            "performance")
                log_success "CPU governor set to 'performance' - optimal for pfSense"
                ;;
            "powersave")
                log_warning "CPU governor set to 'powersave' - impacts performance"
                echo "OPTIMIZE: echo performance > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor" >> "$LOG_FILE"
                ;;
            "ondemand"|"conservative")
                log_info "CPU governor set to '$governor' - dynamic scaling enabled"
                if [[ $PFSENSE_VMS -gt 0 ]]; then
                    log_warning "Consider 'performance' governor for consistent pfSense performance"
                    echo "OPTIMIZE: echo performance > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor" >> "$LOG_FILE"
                fi
                ;;
            *)
                log_info "CPU governor: $governor"
                ;;
        esac
    else
        log_info "CPU frequency scaling not available"
    fi
    
    # Check current and max frequencies
    local cur_freq_file="/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"
    local max_freq_file="/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"
    
    if [[ -f "$cur_freq_file" && -f "$max_freq_file" ]]; then
        local cur_freq max_freq
        cur_freq=$(safe_read_file "$cur_freq_file")
        max_freq=$(safe_read_file "$max_freq_file")
        
        if [[ -n "$cur_freq" && -n "$max_freq" ]]; then
            cur_freq=$((cur_freq / 1000))  # Convert to MHz
            max_freq=$((max_freq / 1000))  # Convert to MHz
            
            echo "CPU Frequency: ${cur_freq}MHz (max: ${max_freq}MHz)" >> "$LOG_FILE"
            
            # Check if running near max frequency
            local freq_ratio=$((cur_freq * 100 / max_freq))
            if [[ $freq_ratio -lt 80 ]]; then
                log_info "CPU running at ${freq_ratio}% of max frequency"
                if [[ $PFSENSE_VMS -gt 0 ]]; then
                    log_warning "Low CPU frequency may impact pfSense performance"
                fi
            fi
        fi
    fi
    
    # Check CPU idle states
    if [[ -d "/sys/devices/system/cpu/cpu0/cpuidle" ]]; then
        local idle_states
        idle_states=$(find /sys/devices/system/cpu/cpu0/cpuidle -name "state*" -type d 2>/dev/null | wc -l)
        
        if [[ $idle_states -gt 0 ]]; then
            echo "CPU idle states available: $idle_states" >> "$LOG_FILE"
            
            # Check for disabled deep C-states (good for low latency)
            local disabled_states=0
            for state_dir in /sys/devices/system/cpu/cpu0/cpuidle/state*/; do
                [[ ! -d "$state_dir" ]] && continue
                local disable_file="${state_dir}disable"
                if [[ -f "$disable_file" ]]; then
                    local disabled
                    disabled=$(safe_read_file "$disable_file")
                    [[ "$disabled" == "1" ]] && disabled_states=$((disabled_states + 1))
                fi
            done
            
            if [[ $disabled_states -gt 0 ]]; then
                log_info "Deep C-states disabled: $disabled_states - good for low-latency networking"
            elif [[ $PFSENSE_VMS -gt 0 ]]; then
                log_info "Consider disabling deep C-states for pfSense: intel_idle.max_cstate=1"
                echo "OPTIMIZE: Add intel_idle.max_cstate=1 to kernel parameters" >> "$LOG_FILE"
            fi
        fi
    fi
}

# Network bridge and performance analysis
analyze_network_configuration() {
    print_section "Network Bridge and Performance Analysis"
    
    log_progress "Analyzing network bridges and performance settings..."
    
    # Find all bridges
    local bridges
    bridges=$(ip link show type bridge 2>/dev/null | grep -o "vmbr[0-9]*" | sort -u || echo "")
    
    if [[ -z "$bridges" ]]; then
        log_error "No VM bridges found"
        return 1
    fi
    
    local bridge_count=0
    local bridge_issues=0
    
    while IFS= read -r bridge; do
        [[ -z "$bridge" ]] && continue
        bridge_count=$((bridge_count + 1))
        
        log_info "Analyzing bridge: $bridge"
        
        # Check bridge status
        if ip link show "$bridge" 2>/dev/null | grep -q "state UP"; then
            log_success "Bridge $bridge: UP and active"
        else
            log_warning "Bridge $bridge: DOWN or inactive"
            bridge_issues=$((bridge_issues + 1))
        fi
        
        # Check STP (should be disabled for performance)
        local stp_file="/sys/class/net/$bridge/bridge/stp_state"
        if [[ -f "$stp_file" ]]; then
            local stp_state
            stp_state=$(safe_read_file "$stp_file")
            
            if [[ "$stp_state" == "0" ]]; then
                log_success "Bridge $bridge: STP disabled (optimal for performance)"
            else
                log_warning "Bridge $bridge: STP enabled - disable for better performance"
                echo "OPTIMIZE: echo 0 > /sys/class/net/$bridge/bridge/stp_state" >> "$LOG_FILE"
                bridge_issues=$((bridge_issues + 1))
            fi
        fi
        
        # Check forward delay (should be 0 for performance)
        local forward_delay_file="/sys/class/net/$bridge/bridge/forward_delay"
        if [[ -f "$forward_delay_file" ]]; then
            local forward_delay
            forward_delay=$(safe_read_file "$forward_delay_file")
            
            if [[ "$forward_delay" == "0" ]]; then
                log_success "Bridge $bridge: Forward delay disabled (optimal)"
            else
                log_info "Bridge $bridge: Forward delay ${forward_delay} centiseconds"
                echo "OPTIMIZE: echo 0 > /sys/class/net/$bridge/bridge/forward_delay" >> "$LOG_FILE"
            fi
        fi
        
        # Check MTU settings
        local mtu
        mtu=$(ip link show "$bridge" 2>/dev/null | grep -o "mtu [0-9]*" | awk '{print $2}' || echo "1500")
        
        case "$mtu" in
            "1500")
                log_info "Bridge $bridge: Standard MTU (1500)"
                ;;
            "9000")
                log_success "Bridge $bridge: Jumbo frames enabled (9000) - excellent for high throughput"
                ;;
            *)
                log_info "Bridge $bridge: Custom MTU ($mtu)"
                ;;
        esac
        
        # Check connected interfaces
        local brif_dir="/sys/class/net/$bridge/brif"
        if [[ -d "$brif_dir" ]]; then
            local connected_count
            connected_count=$(ls "$brif_dir" 2>/dev/null | wc -l)
            
            if [[ $connected_count -gt 0 ]]; then
                log_info "Bridge $bridge: $connected_count connected interfaces"
            else
                log_warning "Bridge $bridge: No connected interfaces"
                bridge_issues=$((bridge_issues + 1))
            fi
        fi
        
    done <<< "$bridges"
    
    # Check IRQ balancing
    if systemctl is-active irqbalance >/dev/null 2>&1; then
        log_success "IRQ balancing service active - good for network performance"
    else
        log_warning "IRQ balancing service not running"
        echo "OPTIMIZE: systemctl enable --now irqbalance" >> "$LOG_FILE"
        bridge_issues=$((bridge_issues + 1))
    fi
    
    echo "Network Bridge Summary: $bridge_count bridges found, $bridge_issues optimization opportunities" >> "$LOG_FILE"
}

# System tunables analysis
analyze_system_tunables() {
    print_section "System Tunables Analysis"
    
    log_progress "Checking system performance tunables..."
    
    # Check hugepages
    local hugepages_total hugepages_free hugepages_used
    hugepages_total=$(grep "HugePages_Total:" /proc/meminfo | awk '{print $2}' 2>/dev/null || echo "0")
    hugepages_free=$(grep "HugePages_Free:" /proc/meminfo | awk '{print $2}' 2>/dev/null || echo "0")
    hugepages_used=$((hugepages_total - hugepages_free))
    
    if [[ $hugepages_total -gt 0 ]]; then
        log_success "Hugepages configured: $hugepages_used/$hugepages_total used"
        echo "Hugepages: ${hugepages_used}/${hugepages_total} used" >> "$LOG_FILE"
    else
        log_info "Hugepages not configured"
        local total_memory_gb
        total_memory_gb=$(free -g | awk 'NR==2{print $2}')
        if [[ $total_memory_gb -gt 8 ]]; then
            log_info "System has ${total_memory_gb}GB RAM - consider enabling hugepages for large VMs"
            echo "OPTIMIZE: Add hugepages=1024 to GRUB_CMDLINE_LINUX_DEFAULT" >> "$LOG_FILE"
        fi
    fi
    
    # Check swappiness
    local swappiness
    swappiness=$(safe_read_file "/proc/sys/vm/swappiness")
    
    if is_integer "$swappiness"; then
        if [[ $swappiness -le 10 ]]; then
            log_success "Swappiness optimal for virtualization: $swappiness"
        elif [[ $swappiness -le 60 ]]; then
            log_info "Swappiness: $swappiness (default)"
            if [[ $PFSENSE_VMS -gt 0 ]]; then
                log_warning "Consider lowering swappiness for pfSense performance"
                echo "OPTIMIZE: echo 'vm.swappiness = 1' >> /etc/sysctl.conf" >> "$LOG_FILE"
            fi
        else
            log_warning "High swappiness: $swappiness - may impact VM performance"
            echo "OPTIMIZE: echo 'vm.swappiness = 10' >> /etc/sysctl.conf" >> "$LOG_FILE"
        fi
    fi
    
    # Check transparent hugepages
    local thp_file="/sys/kernel/mm/transparent_hugepage/enabled"
    if [[ -f "$thp_file" ]]; then
        local thp_status
        thp_status=$(grep -o '\[.*\]' "$thp_file" 2>/dev/null | tr -d '[]' || echo "unknown")
        
        case "$thp_status" in
            "never")
                log_success "Transparent hugepages disabled (optimal for VMs)"
                ;;
            "always")
                log_warning "Transparent hugepages always enabled - may impact VM performance"
                echo "OPTIMIZE: echo never > /sys/kernel/mm/transparent_hugepage/enabled" >> "$LOG_FILE"
                ;;
            "madvise")
                log_info "Transparent hugepages in madvise mode"
                ;;
            *)
                log_info "Transparent hugepages status: $thp_status"
                ;;
        esac
    fi
    
    # Check GRUB configuration
    if [[ -f /etc/default/grub ]]; then
        local grub_cmdline
        grub_cmdline=$(grep "GRUB_CMDLINE_LINUX_DEFAULT" /etc/default/grub 2>/dev/null | cut -d'"' -f2 || echo "")
        
        echo "GRUB cmdline: $grub_cmdline" >> "$LOG_FILE"
        
        # Check for important parameters
        if echo "$grub_cmdline" | grep -q "intel_iommu=on\|amd_iommu=on"; then
            log_success "IOMMU enabled in GRUB"
        else
            log_info "IOMMU not explicitly enabled in GRUB"
            if lscpu | grep -q "VT-d\|AMD-Vi"; then
                echo "OPTIMIZE: Add intel_iommu=on or amd_iommu=on to GRUB_CMDLINE_LINUX_DEFAULT" >> "$LOG_FILE"
            fi
        fi
        
        if echo "$grub_cmdline" | grep -q "hugepages="; then
            local grub_hugepages
            grub_hugepages=$(echo "$grub_cmdline" | grep -o "hugepages=[0-9]*" | cut -d'=' -f2)
            log_info "Hugepages configured in GRUB: $grub_hugepages"
        fi
    fi
}

# Hardware acceleration analysis
analyze_hardware_acceleration() {
    print_section "Hardware Acceleration Analysis"
    
    log_progress "Checking hardware acceleration capabilities..."
    
    # Check CPU virtualization features
    if grep -q "vmx" /proc/cpuinfo; then
        log_success "Intel VT-x virtualization supported"
    elif grep -q "svm" /proc/cpuinfo; then
        log_success "AMD-V virtualization supported"
    else
        log_error "Hardware virtualization not supported - critical for VM performance"
        return 1
    fi
    
    # Check AES-NI support
    if grep -q "aes" /proc/cpuinfo; then
        log_success "AES-NI supported - excellent for pfSense crypto performance"
    else
        log_warning "AES-NI not available - will significantly impact crypto performance"
        if [[ $PFSENSE_VMS -gt 0 ]]; then
            log_warning "pfSense VPN performance will be severely limited without AES-NI"
        fi
    fi
    
    # Check IOMMU support
    if dmesg | grep -qi "iommu.*enabled\|dmar.*enabled"; then
        log_success "IOMMU enabled - supports device passthrough"
    elif dmesg | grep -qi "iommu\|dmar"; then
        log_info "IOMMU hardware detected but not enabled"
        echo "OPTIMIZE: Enable IOMMU in BIOS and add intel_iommu=on to kernel parameters" >> "$LOG_FILE"
    else
        log_info "IOMMU not detected - limits device passthrough capabilities"
    fi
    
    # Check VFIO modules
    if lsmod | grep -q "vfio"; then
        local vfio_devices=0
        if [[ -d /sys/kernel/iommu_groups ]]; then
            vfio_devices=$(find /sys/kernel/iommu_groups -name devices 2>/dev/null | xargs ls 2>/dev/null | wc -l)
        fi
        log_success "VFIO modules loaded - device passthrough available ($vfio_devices devices)"
    else
        log_info "VFIO not configured - needed for GPU/device passthrough"
    fi
    
    # Check for additional CPU features relevant to pfSense
    local cpu_features=""
    for feature in "rdrand" "rdseed" "avx" "avx2"; do
        if grep -q "$feature" /proc/cpuinfo; then
            cpu_features="$cpu_features $feature"
        fi
    done
    
    if [[ -n "$cpu_features" ]]; then
        log_info "Additional CPU features available:$cpu_features"
    fi
}

# Storage I/O performance analysis
analyze_storage_performance() {
    print_section "Storage I/O Performance Analysis"
    
    log_progress "Analyzing storage I/O configuration and performance..."
    
    local scheduler_issues=0
    local total_devices=0
    
    # Check I/O schedulers for each block device
    for scheduler_file in /sys/block/*/queue/scheduler; do
        [[ ! -f "$scheduler_file" ]] && continue
        
        local device
        device=$(basename "$(dirname "$(dirname "$scheduler_file")")")
        
        # Skip virtual/loop devices
        [[ "$device" =~ ^(loop|ram|dm-) ]] && continue
        
        total_devices=$((total_devices + 1))
        
        local current_scheduler
        current_scheduler=$(grep -o '\[.*\]' "$scheduler_file" 2>/dev/null | tr -d '[]' || echo "unknown")
        
        # Detect device type
        local device_type="HDD"
        local is_nvme=false
        local is_ssd=false
        
        if [[ "$device" =~ ^nvme ]]; then
            device_type="NVMe"
            is_nvme=true
        elif [[ -f "/sys/block/$device/queue/rotational" ]]; then
            local rotational
            rotational=$(safe_read_file "/sys/block/$device/queue/rotational")
            if [[ "$rotational" == "0" ]]; then
                device_type="SSD"
                is_ssd=true
            fi
        fi
        
        log_info "Device $device ($device_type): $current_scheduler scheduler"
        
        # Check scheduler optimality
        case "$device_type" in
            "NVMe")
                if [[ "$current_scheduler" == "none" ]]; then
                    log_success "Device $device: Optimal scheduler for NVMe"
                else
                    log_warning "Device $device: Consider 'none' scheduler for NVMe"
                    echo "OPTIMIZE: echo none > /sys/block/$device/queue/scheduler" >> "$LOG_FILE"
                    scheduler_issues=$((scheduler_issues + 1))
                fi
                ;;
            "SSD")
                if [[ "$current_scheduler" == "mq-deadline" || "$current_scheduler" == "none" ]]; then
                    log_success "Device $device: Good scheduler for SSD"
                else
                    log_info "Device $device: Consider mq-deadline for SSD"
                    echo "OPTIMIZE: echo mq-deadline > /sys/block/$device/queue/scheduler" >> "$LOG_FILE"
                fi
                ;;
            "HDD")
                if [[ "$current_scheduler" == "mq-deadline" || "$current_scheduler" == "bfq" ]]; then
                    log_success "Device $device: Good scheduler for HDD"
                else
                    log_info "Device $device: Current scheduler acceptable for HDD"
                fi
                ;;
        esac
        
        # Check queue depth
        local nr_requests_file="/sys/block/$device/queue/nr_requests"
        if [[ -f "$nr_requests_file" ]]; then
            local queue_depth
            queue_depth=$(safe_read_file "$nr_requests_file")
            
            if is_integer "$queue_depth"; then
                if $is_nvme && [[ $queue_depth -lt 128 ]]; then
                    log_info "Device $device: Consider increasing queue depth for NVMe (current: $queue_depth)"
                    echo "OPTIMIZE: echo 256 > /sys/block/$device/queue/nr_requests" >> "$LOG_FILE"
                elif $is_ssd && [[ $queue_depth -lt 32 ]]; then
                    log_info "Device $device: Consider increasing queue depth for SSD (current: $queue_depth)"
                fi
            fi
        fi
        
        # Check read-ahead settings
        local read_ahead_file="/sys/block/$device/queue/read_ahead_kb"
        if [[ -f "$read_ahead_file" ]]; then
            local read_ahead
            read_ahead=$(safe_read_file "$read_ahead_file")
            
            if is_integer "$read_ahead"; then
                if ($is_ssd || $is_nvme) && [[ $read_ahead -gt 256 ]]; then
                    log_info "Device $device: High read-ahead for SSD/NVMe (${read_ahead}KB) - consider reducing"
                    echo "OPTIMIZE: echo 128 > /sys/block/$device/queue/read_ahead_kb" >> "$LOG_FILE"
                fi
            fi
        fi
        
    done
    
    echo "Storage Analysis: $total_devices devices checked, $scheduler_issues optimization opportunities" >> "$LOG_FILE"
    
    # Check for real-time I/O performance if iostat is available
    if command -v iostat >/dev/null 2>&1; then
        log_info "Sampling I/O performance..."
        
        local io_sample
        if io_sample=$(timeout 5 iostat -x 1 2 2>/dev/null | tail -n +4 | head -20); then
            echo "I/O Performance Sample:" >> "$LOG_FILE"
            echo "$io_sample" >> "$LOG_FILE"
            
            # Look for high utilization
            local high_util_count=0
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                [[ "$line" =~ ^Device: ]] && continue
                
                local device util
                device=$(echo "$line" | awk '{print $1}')
                util=$(echo "$line" | awk '{print $NF}' | tr -d '%')
                
                if [[ "$util" =~ ^[0-9]+\.?[0-9]*$ ]]; then
                    local util_int=${util%.*}
                    if [[ $util_int -gt 80 ]]; then
                        log_warning "Device $device: High I/O utilization (${util}%)"
                        high_util_count=$((high_util_count + 1))
                    fi
                fi
            done <<< "$io_sample"
            
            if [[ $high_util_count -eq 0 ]]; then
                log_success "All storage devices show healthy I/O utilization"
            fi
        fi
    else
        log_info "iostat not available - install sysstat package for I/O monitoring"
        echo "INSTALL: apt install sysstat" >> "$LOG_FILE"
    fi
}

# Generate comprehensive recommendations
generate_comprehensive_recommendations() {
    print_section "Comprehensive pfSense Optimization Recommendations"
    
    echo "" >> "$LOG_FILE"
    echo "=================================" >> "$LOG_FILE"
    echo "COMPREHENSIVE RECOMMENDATIONS" >> "$LOG_FILE"
    echo "=================================" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    
    if [[ $PFSENSE_VMS -gt 0 ]]; then
        echo "CRITICAL pfSense VM Optimizations:" >> "$LOG_FILE"
        echo "1. CPU Configuration:" >> "$LOG_FILE"
        echo "   qm set VMID -cpu host" >> "$LOG_FILE"
        echo "" >> "$LOG_FILE"
        echo "2. Memory Configuration:" >> "$LOG_FILE"
        echo "   qm set VMID -balloon 0" >> "$LOG_FILE"
        echo "   qm set VMID -memory 2048  # or higher" >> "$LOG_FILE"
        echo "" >> "$LOG_FILE"
        echo "3. Storage Configuration:" >> "$LOG_FILE"
        echo "   # Use VirtIO with iothread and writeback cache" >> "$LOG_FILE"
        echo "   qm set VMID -virtio0 local-lvm:vm-VMID-disk-0,cache=writeback,iothread=1" >> "$LOG_FILE"
        echo "" >> "$LOG_FILE"
        echo "4. Network Configuration:" >> "$LOG_FILE"
        echo "   # Use VirtIO with multiqueue" >> "$LOG_FILE"
        echo "   qm set VMID -net0 virtio,bridge=vmbr0,queues=4  # match CPU cores" >> "$LOG_FILE"
        echo "   qm set VMID -net1 virtio,bridge=vmbr1,queues=4  # for LAN interface" >> "$LOG_FILE"
        echo "" >> "$LOG_FILE"
    fi
    
    echo "Host-Level Performance Optimizations:" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    echo "1. CPU Performance:" >> "$LOG_FILE"
    echo "   echo performance > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    echo "2. Network Bridge Optimization:" >> "$LOG_FILE"
    echo "   echo 0 > /sys/class/net/vmbr*/bridge/stp_state" >> "$LOG_FILE"
    echo "   echo 0 > /sys/class/net/vmbr*/bridge/forward_delay" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    echo "3. System Tunables:" >> "$LOG_FILE"
    echo "   echo 1 > /proc/sys/vm/swappiness" >> "$LOG_FILE"
    echo "   echo never > /sys/kernel/mm/transparent_hugepage/enabled" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    echo "4. Network Performance:" >> "$LOG_FILE"
    echo "   systemctl enable --now irqbalance" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    echo "5. Storage Optimization:" >> "$LOG_FILE"
    echo "   # Set optimal I/O schedulers" >> "$LOG_FILE"
    echo "   echo none > /sys/block/nvme*/queue/scheduler      # for NVMe" >> "$LOG_FILE"
    echo "   echo mq-deadline > /sys/block/sd*/queue/scheduler # for SSDs" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    
    if [[ $PFSENSE_VMS -gt 0 ]]; then
        echo "pfSense VM Internal Configuration (within pfSense):" >> "$LOG_FILE"
        echo "1. Disable hardware checksum offload" >> "$LOG_FILE"
        echo "2. Configure MSS clamping based on your connection:" >> "$LOG_FILE"
        echo "   - Standard Ethernet: 1460 bytes" >> "$LOG_FILE"
        echo "   - PPPoE: 1452 bytes" >> "$LOG_FILE"
        echo "3. Optimize network buffers:" >> "$LOG_FILE"
        echo "   kern.ipc.nmbclusters=1000000" >> "$LOG_FILE"
        echo "4. Enable hardware crypto acceleration (AES-NI)" >> "$LOG_FILE"
        echo "" >> "$LOG_FILE"
    fi
    
    echo "Performance Monitoring Commands:" >> "$LOG_FILE"
    echo "1. VM Resource Usage: pvesh get /cluster/resources" >> "$LOG_FILE"
    echo "2. Network Throughput: iperf3 -s (on target), iperf3 -c TARGET (on source)" >> "$LOG_FILE"
    echo "3. I/O Performance: iostat -x 1" >> "$LOG_FILE"
    echo "4. Interrupt Distribution: cat /proc/interrupts" >> "$LOG_FILE"
    echo "5. pfSense Traffic: Monitor via pfSense GUI or pfTop" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    
    # Display summary on console
    echo ""
    echo -e "${BOLD}Critical Next Steps:${NC}"
    if [[ $PFSENSE_VMS -gt 0 ]]; then
        echo -e "${GREEN}pfSense VMs Found: $PFSENSE_VMS${NC}"
        echo "1. Apply VM-level optimizations (CPU, memory, storage, network)"
        echo "2. Configure host-level performance settings"
        echo "3. Optimize pfSense internal settings"
        echo "4. Test performance improvements"
    else
        echo "1. Apply host-level optimizations"
        echo "2. Configure VM settings for optimal performance"
        echo "3. Monitor system performance"
    fi
    
    echo ""
    if [[ $TOTAL_ISSUES -gt 0 ]]; then
        echo -e "${YELLOW}Total optimization opportunities found: $TOTAL_ISSUES${NC}"
    else
        echo -e "${GREEN}System appears well-optimized!${NC}"
    fi
}

# Main execution function
main() {
    # Initialize
    print_header "$SCRIPT_NAME"
    echo "Generated: $(date)" | tee -a "$LOG_FILE"
    echo "Hostname: $(hostname)" | tee -a "$LOG_FILE"
    
    local pve_version
    pve_version=$(pveversion 2>/dev/null | head -1 || echo "Unknown")
    echo "Proxmox Version: $pve_version" | tee -a "$LOG_FILE"
    echo "Focus: pfSense/Router VM Performance Optimization" | tee -a "$LOG_FILE"
    
    # System overview
    local cpu_count memory_gb load_avg
    cpu_count=$(nproc)
    memory_gb=$(free -g | awk 'NR==2{print $2}')
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | xargs)
    
    echo "" | tee -a "$LOG_FILE"
    echo "System Overview:" | tee -a "$LOG_FILE"
    echo "- CPU Cores: $cpu_count" | tee -a "$LOG_FILE"
    echo "- Total Memory: ${memory_gb}GB" | tee -a "$LOG_FILE"
    echo "- Current Load: $load_avg" | tee -a "$LOG_FILE"
    
    # Execute analysis phases
    log_progress "Phase 1: Verifying Proxmox environment..."
    verify_proxmox
    
    log_progress "Phase 2: Clearing stale VM locks..."
    clear_vm_locks
    
    log_progress "Phase 3: Analyzing VM configurations..."
    analyze_vm_configurations
    
    log_progress "Phase 4: Analyzing system performance..."
    analyze_system_performance
    
    log_progress "Phase 5: Analyzing CPU performance settings..."
    analyze_cpu_performance
    
    log_progress "Phase 6: Analyzing network configuration..."
    analyze_network_configuration
    
    log_progress "Phase 7: Analyzing system tunables..."
    analyze_system_tunables
    
    log_progress "Phase 8: Analyzing hardware acceleration..."
    analyze_hardware_acceleration
    
    log_progress "Phase 9: Analyzing storage performance..."
    analyze_storage_performance
    
    log_progress "Phase 10: Generating comprehensive recommendations..."
    generate_comprehensive_recommendations
    
    # Final summary
    print_header "Analysis Complete"
    echo "" | tee -a "$LOG_FILE"
    echo "Comprehensive analysis completed successfully!" | tee -a "$LOG_FILE"
    echo "Full detailed log: $LOG_FILE" | tee -a "$LOG_FILE"
    
    if [[ $PFSENSE_VMS -gt 0 ]]; then
        echo "" | tee -a "$LOG_FILE"
        echo -e "${GREEN}pfSense optimization recommendations generated!${NC}"
        echo "Review the detailed recommendations in the log file."
    fi
    
    echo ""
    echo -e "${BOLD}Log file location: $LOG_FILE${NC}"
}

# Script execution
main "$@"