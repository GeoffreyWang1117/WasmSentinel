#!/bin/bash

# CVE-2024-21626 (runc escape) Simulation
# ⚠️ FOR TESTING ONLY!

echo "🔴 Simulating CVE-2024-21626 (runc escape) syscall patterns"
echo "============================================================"

# This attack often involves opening /proc/self/exe and keeping it open
# while entering a new container, or using a leaked file descriptor.

echo "1. Attempting to open /proc/self/exe for reading..."
# This is a key step in runc escape where the file descriptor is leaked.
exec 3< /proc/self/exe

echo "2. Attempting to access sensitive host files via proc fd..."
# In a real escape, the attacker might try to use the fd to access host files.
ls -l /proc/self/fd/3 2>/dev/null

echo "3. Attempting suspicious directory access (fchdir escape)..."
# Another variant involves changing directory to a leaked file descriptor.
# cd /proc/self/fd/X/../../
# Since we are not in a real container, we just simulate the syscall sequence.
# We'll use python to trigger specific syscalls.
python3 -c "
import os
try:
    fd = os.open('/proc/self/exe', os.O_RDONLY)
    # Simulate the directory traversal attempt
    os.fchdir(fd)
    os.chdir('../../../../../../../')
    print('Simulated escape directory traversal')
    os.close(fd)
except Exception as e:
    print(f'Simulation failed: {e}')
"

echo "4. Attempting to execute a host binary via leaked fd..."
# execveat(3, '', ...)
# We simulate the intent by calling a binary through the fd.
/proc/self/fd/3 --version 2>/dev/null || echo "Execution via fd failed (expected)"

# Clean up
exec 3<&-

echo ""
echo "✅ CVE-2024-21626 simulation complete"
