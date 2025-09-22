#!/bin/bash
# VM 102 complete diagnosis

echo "=== VM 102 Complete Diagnosis ==="

echo "1. Checking VM 102 status..."
timeout 10 qm status 102 --verbose 2>/dev/null || echo "Status check failed/timeout"

echo -e "\n2. Checking for active tasks..."
echo "Active cluster tasks:"
pvesh get /cluster/tasks --active 1 2>/dev/null | grep -i "102\|backup\|migrate" || echo "No active tasks found"

echo -e "\n3. Checking for VM processes..."
ps aux | grep -E "(102|qemu.*102)" | grep -v grep || echo "No VM processes found"

echo -e "\n4. Checking for locks..."
echo "Lock files:"
ls -la /var/lock/qemu-server/ | grep 102 || echo "No lock files"
echo "Config lock status:"
grep -i lock /etc/pve/qemu-server/102.conf 2>/dev/null || echo "No locks in config"

echo -e "\n5. Checking configuration accessibility..."
if timeout 5 head -5 /etc/pve/qemu-server/102.conf >/dev/null 2>&1; then
    echo "✓ Config file accessible"
    echo "Config size: $(wc -l < /etc/pve/qemu-server/102.conf) lines"
else
    echo "✗ Config file not accessible"
fi

echo -e "\n6. Testing qm config command..."
if timeout 10 qm config 102 >/dev/null 2>&1; then
    echo "✓ qm config works"
else
    echo "✗ qm config hangs/fails"
fi

echo -e "\n7. System resource check..."
echo "Load: $(cat /proc/loadavg)"
echo "Memory: $(free | awk 'NR==2{printf "%.1f%% used\n", $3*100/$2}')"
echo "Storage: $(df -h /etc/pve | tail -1 | awk '{print $5" used"}')"

echo -e "\n8. Cluster/Storage status..."
if command -v pvecm >/dev/null 2>&1; then
    echo "Cluster status:"
    timeout 5 pvecm status 2>/dev/null || echo "Cluster check timeout/failed"
fi

echo "Storage status:"
timeout 10 pvesm status 2>/dev/null || echo "Storage check timeout/failed"

echo -e "\n=== Diagnosis complete ===="