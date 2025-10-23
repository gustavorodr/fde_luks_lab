#!/usr/bin/env python3
"""
LUKS Memory Forensics Suite
Advanced memory analysis for VMK extraction and LUKS key recovery
Author: Security Research Team
Date: October 2025
"""

import os
import sys
import json
import struct
import hashlib
import binascii
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any

class LUKSMemoryForensics:
    """Advanced memory forensics for LUKS key extraction"""
    
    def __init__(self):
        self.results = {}
        self.extracted_keys = []
        self.volatility_path = self._find_volatility()
        
        # LUKS key patterns and signatures
        self.key_patterns = {
            'aes_256': b'\x00\x10\x00\x00\x20\x00\x00\x00',  # AES-256 signature
            'aes_128': b'\x00\x10\x00\x00\x10\x00\x00\x00',  # AES-128 signature
            'luks_magic': b'LUKS\xba\xbe',  # LUKS header magic
            'pbkdf2_hmac': b'PBKDF2-HMAC-SHA',  # PBKDF2 KDF signature
            'argon2id': b'argon2id',  # Argon2id KDF signature
        }
        
        # Memory search patterns for VMKs
        self.vmk_patterns = [
            # AES key schedule patterns
            b'\x52\x09\x6a\xd5\x30\x36\xa5\x38',  # AES S-box pattern
            b'\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5',  # AES inverse S-box
            # PBKDF2 intermediate values
            b'\x01\x00\x00\x00' * 8,  # PBKDF2 counter pattern
            # Entropy indicators
            b'\xaa\x55\xaa\x55' * 8,  # High entropy pattern
        ]
        
    def _find_volatility(self) -> Optional[str]:
        """Find Volatility installation"""
        volatility_paths = [
            '/usr/bin/vol.py',
            '/usr/local/bin/vol.py',
            '/opt/volatility/vol.py',
            'volatility3',
            'vol.py'
        ]
        
        for path in volatility_paths:
            if os.path.exists(path) or subprocess.run(['which', path], capture_output=True).returncode == 0:
                return path
        return None
    
    def analyze_memory_dump(self, dump_path: str, profile: Optional[str] = None) -> Dict[str, Any]:
        """Comprehensive memory dump analysis for LUKS artifacts"""
        print(f"[*] Starting memory forensics analysis: {dump_path}")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'dump_path': dump_path,
            'dump_size': os.path.getsize(dump_path) if os.path.exists(dump_path) else 0,
            'analysis_methods': [],
            'extracted_keys': [],
            'luks_artifacts': [],
            'process_analysis': {},
            'volatility_results': {}
        }
        
        if not os.path.exists(dump_path):
            results['error'] = f"Memory dump not found: {dump_path}"
            return results
        
        # Method 1: Raw binary analysis
        print("[*] Performing raw binary analysis...")
        raw_results = self._analyze_raw_dump(dump_path)
        results['analysis_methods'].append('raw_binary')
        results.update(raw_results)
        
        # Method 2: Volatility analysis
        if self.volatility_path:
            print("[*] Running Volatility analysis...")
            vol_results = self._volatility_analysis(dump_path, profile)
            results['analysis_methods'].append('volatility')
            results['volatility_results'] = vol_results
        
        # Method 3: Entropy analysis
        print("[*] Performing entropy analysis...")
        entropy_results = self._entropy_analysis(dump_path)
        results['analysis_methods'].append('entropy_analysis')
        results['entropy_analysis'] = entropy_results
        
        # Method 4: Process memory analysis
        print("[*] Analyzing process memory regions...")
        process_results = self._process_memory_analysis(dump_path)
        results['analysis_methods'].append('process_memory')
        results['process_analysis'] = process_results
        
        # Method 5: Cryptographic artifact detection
        print("[*] Detecting cryptographic artifacts...")
        crypto_results = self._crypto_artifact_detection(dump_path)
        results['analysis_methods'].append('crypto_artifacts')
        results['crypto_artifacts'] = crypto_results
        
        return results
    
    def _analyze_raw_dump(self, dump_path: str) -> Dict[str, Any]:
        """Raw binary analysis of memory dump"""
        results = {
            'potential_keys': [],
            'luks_signatures': [],
            'key_schedules': []
        }
        
        chunk_size = 1024 * 1024  # 1MB chunks
        
        try:
            with open(dump_path, 'rb') as f:
                offset = 0
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    # Search for LUKS signatures
                    luks_matches = self._find_luks_signatures(chunk, offset)
                    results['luks_signatures'].extend(luks_matches)
                    
                    # Search for potential AES keys
                    key_matches = self._find_potential_keys(chunk, offset)
                    results['potential_keys'].extend(key_matches)
                    
                    # Search for AES key schedules
                    schedule_matches = self._find_key_schedules(chunk, offset)
                    results['key_schedules'].extend(schedule_matches)
                    
                    offset += chunk_size
                    
                    if offset % (chunk_size * 100) == 0:
                        print(f"    Analyzed {offset // (1024*1024)} MB...")
        
        except Exception as e:
            results['error'] = f"Raw analysis error: {str(e)}"
        
        return results
    
    def _find_luks_signatures(self, data: bytes, base_offset: int) -> List[Dict[str, Any]]:
        """Find LUKS header signatures in memory"""
        signatures = []
        
        for pattern_name, pattern in self.key_patterns.items():
            offset = 0
            while True:
                pos = data.find(pattern, offset)
                if pos == -1:
                    break
                
                signatures.append({
                    'pattern': pattern_name,
                    'offset': base_offset + pos,
                    'data': binascii.hexlify(data[pos:pos+32]).decode(),
                    'context': binascii.hexlify(data[max(0, pos-16):pos+48]).decode()
                })
                
                offset = pos + 1
        
        return signatures
    
    def _find_potential_keys(self, data: bytes, base_offset: int) -> List[Dict[str, Any]]:
        """Find potential cryptographic keys using entropy analysis"""
        keys = []
        
        # Look for 32-byte (256-bit) and 16-byte (128-bit) high-entropy regions
        for key_size in [32, 16]:
            for i in range(len(data) - key_size):
                key_candidate = data[i:i+key_size]
                
                # Check entropy
                entropy = self._calculate_entropy(key_candidate)
                if entropy > 7.5:  # High entropy threshold
                    # Additional validation
                    if self._validate_key_candidate(key_candidate):
                        keys.append({
                            'offset': base_offset + i,
                            'size': key_size,
                            'entropy': entropy,
                            'data': binascii.hexlify(key_candidate).decode(),
                            'validation_score': self._score_key_candidate(key_candidate)
                        })
        
        return keys
    
    def _find_key_schedules(self, data: bytes, base_offset: int) -> List[Dict[str, Any]]:
        """Find AES key schedule patterns"""
        schedules = []
        
        # AES-256 expanded key is 240 bytes (60 32-bit words)
        # AES-128 expanded key is 176 bytes (44 32-bit words)
        
        for schedule_size in [240, 176]:
            for i in range(len(data) - schedule_size):
                schedule_candidate = data[i:i+schedule_size]
                
                if self._validate_key_schedule(schedule_candidate):
                    key_size = 32 if schedule_size == 240 else 16
                    original_key = schedule_candidate[:key_size]
                    
                    schedules.append({
                        'offset': base_offset + i,
                        'schedule_size': schedule_size,
                        'key_size': key_size,
                        'original_key': binascii.hexlify(original_key).decode(),
                        'full_schedule': binascii.hexlify(schedule_candidate).decode(),
                        'confidence': self._calculate_schedule_confidence(schedule_candidate)
                    })
        
        return schedules
    
    def _volatility_analysis(self, dump_path: str, profile: Optional[str] = None) -> Dict[str, Any]:
        """Run Volatility analysis for process and kernel memory"""
        results = {
            'processes': [],
            'kernel_modules': [],
            'crypto_processes': []
        }
        
        if not self.volatility_path:
            results['error'] = "Volatility not found"
            return results
        
        try:
            # Auto-detect profile if not provided
            if not profile:
                profile = self._detect_volatility_profile(dump_path)
            
            if not profile:
                results['error'] = "Could not detect memory profile"
                return results
            
            # Process list
            processes = self._run_volatility_plugin(dump_path, profile, 'pslist')
            results['processes'] = processes
            
            # Look for cryptographic processes
            crypto_procs = self._identify_crypto_processes(processes)
            results['crypto_processes'] = crypto_procs
            
            # Kernel modules
            modules = self._run_volatility_plugin(dump_path, profile, 'lsmod')
            results['kernel_modules'] = modules
            
            # Process memory dumps for crypto processes
            for proc in crypto_procs:
                proc_dump = self._extract_process_memory(dump_path, profile, proc['pid'])
                if proc_dump:
                    proc['memory_analysis'] = self._analyze_process_memory(proc_dump)
        
        except Exception as e:
            results['error'] = f"Volatility analysis error: {str(e)}"
        
        return results
    
    def _entropy_analysis(self, dump_path: str) -> Dict[str, Any]:
        """Perform entropy analysis to identify encrypted/compressed regions"""
        results = {
            'high_entropy_regions': [],
            'entropy_distribution': {},
            'potential_encrypted_data': []
        }
        
        chunk_size = 4096  # 4KB chunks
        entropy_threshold = 7.8
        
        try:
            with open(dump_path, 'rb') as f:
                offset = 0
                entropy_values = []
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    entropy = self._calculate_entropy(chunk)
                    entropy_values.append(entropy)
                    
                    if entropy >= entropy_threshold:
                        results['high_entropy_regions'].append({
                            'offset': offset,
                            'size': len(chunk),
                            'entropy': entropy,
                            'data_preview': binascii.hexlify(chunk[:32]).decode()
                        })
                    
                    offset += chunk_size
                
                # Calculate entropy distribution
                results['entropy_distribution'] = self._calculate_entropy_distribution(entropy_values)
        
        except Exception as e:
            results['error'] = f"Entropy analysis error: {str(e)}"
        
        return results
    
    def _process_memory_analysis(self, dump_path: str) -> Dict[str, Any]:
        """Analyze process memory regions for LUKS-related artifacts"""
        results = {
            'target_processes': [],
            'memory_regions': [],
            'extracted_artifacts': []
        }
        
        # Target process names related to LUKS/encryption
        target_processes = [
            'cryptsetup', 'dmcrypt', 'luks', 'gpg', 'gnupg',
            'systemd-cryptsetup', 'plymouth', 'askpass'
        ]
        
        try:
            if self.volatility_path:
                # Use Volatility to identify target processes
                processes = self._run_volatility_plugin(dump_path, None, 'pslist')
                
                for proc in processes:
                    proc_name = proc.get('name', '').lower()
                    if any(target in proc_name for target in target_processes):
                        results['target_processes'].append(proc)
                        
                        # Extract and analyze process memory
                        proc_memory = self._extract_process_memory(dump_path, None, proc['pid'])
                        if proc_memory:
                            artifacts = self._analyze_process_memory(proc_memory)
                            results['extracted_artifacts'].extend(artifacts)
        
        except Exception as e:
            results['error'] = f"Process memory analysis error: {str(e)}"
        
        return results
    
    def _crypto_artifact_detection(self, dump_path: str) -> Dict[str, Any]:
        """Detect cryptographic artifacts and key material"""
        results = {
            'pbkdf2_artifacts': [],
            'argon2_artifacts': [],
            'aes_artifacts': [],
            'random_data_regions': []
        }
        
        chunk_size = 1024 * 1024
        
        try:
            with open(dump_path, 'rb') as f:
                offset = 0
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    # Search for PBKDF2 artifacts
                    pbkdf2_matches = self._find_pbkdf2_artifacts(chunk, offset)
                    results['pbkdf2_artifacts'].extend(pbkdf2_matches)
                    
                    # Search for Argon2 artifacts
                    argon2_matches = self._find_argon2_artifacts(chunk, offset)
                    results['argon2_artifacts'].extend(argon2_matches)
                    
                    # Search for AES artifacts
                    aes_matches = self._find_aes_artifacts(chunk, offset)
                    results['aes_artifacts'].extend(aes_matches)
                    
                    offset += chunk_size
        
        except Exception as e:
            results['error'] = f"Crypto artifact detection error: {str(e)}"
        
        return results
    
    def extract_keys_from_analysis(self, analysis_results: Dict[str, Any], output_dir: str) -> List[str]:
        """Extract potential keys from analysis results"""
        extracted_files = []
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Extract potential keys
        if 'potential_keys' in analysis_results:
            for i, key_info in enumerate(analysis_results['potential_keys']):
                if key_info.get('validation_score', 0) > 0.7:
                    key_file = os.path.join(output_dir, f"potential_key_{i}.bin")
                    key_data = binascii.unhexlify(key_info['data'])
                    
                    with open(key_file, 'wb') as f:
                        f.write(key_data)
                    
                    extracted_files.append(key_file)
        
        # Extract key schedules
        if 'key_schedules' in analysis_results:
            for i, schedule_info in enumerate(analysis_results['key_schedules']):
                if schedule_info.get('confidence', 0) > 0.8:
                    key_file = os.path.join(output_dir, f"extracted_key_from_schedule_{i}.bin")
                    key_data = binascii.unhexlify(schedule_info['original_key'])
                    
                    with open(key_file, 'wb') as f:
                        f.write(key_data)
                    
                    extracted_files.append(key_file)
        
        return extracted_files
    
    def test_extracted_keys(self, key_files: List[str], luks_device: str) -> Dict[str, Any]:
        """Test extracted keys against LUKS device"""
        results = {
            'tested_keys': len(key_files),
            'successful_keys': [],
            'failed_keys': []
        }
        
        for key_file in key_files:
            try:
                # Test key with cryptsetup
                cmd = [
                    'cryptsetup', 'luksOpen', '--test-passphrase',
                    '--key-file', key_file, luks_device
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    results['successful_keys'].append({
                        'key_file': key_file,
                        'status': 'SUCCESS'
                    })
                    print(f"[+] SUCCESS: Key {key_file} unlocks device!")
                else:
                    results['failed_keys'].append({
                        'key_file': key_file,
                        'error': result.stderr.strip()
                    })
            
            except Exception as e:
                results['failed_keys'].append({
                    'key_file': key_file,
                    'error': str(e)
                })
        
        return results
    
    # Helper methods
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        entropy = 0
        for i in range(256):
            count = data.count(i)
            if count > 0:
                p = count / len(data)
                entropy -= p * (p.bit_length() - 1)
        
        return entropy
    
    def _validate_key_candidate(self, key: bytes) -> bool:
        """Validate if bytes could be a cryptographic key"""
        # Check for obvious non-key patterns
        if len(set(key)) < 4:  # Too few unique bytes
            return False
        if key == b'\x00' * len(key):  # All zeros
            return False
        if key == b'\xff' * len(key):  # All ones
            return False
        
        return True
    
    def _score_key_candidate(self, key: bytes) -> float:
        """Score key candidate based on various criteria"""
        score = 0.0
        
        # Entropy score
        entropy = self._calculate_entropy(key)
        score += min(entropy / 8.0, 1.0) * 0.4
        
        # Byte distribution score
        unique_bytes = len(set(key))
        score += (unique_bytes / 256.0) * 0.3
        
        # Pattern analysis score
        if not self._has_obvious_patterns(key):
            score += 0.3
        
        return score
    
    def _has_obvious_patterns(self, data: bytes) -> bool:
        """Check for obvious patterns that indicate non-key data"""
        # Check for repeating patterns
        for pattern_len in [1, 2, 4, 8]:
            if len(data) >= pattern_len * 4:
                pattern = data[:pattern_len]
                if data.startswith(pattern * (len(data) // pattern_len)):
                    return True
        
        return False
    
    def _validate_key_schedule(self, schedule: bytes) -> bool:
        """Validate if data looks like an AES key schedule"""
        # Basic validation - proper size and some entropy
        if len(schedule) not in [176, 240]:
            return False
        
        # Check entropy of first round key
        first_key = schedule[:32] if len(schedule) == 240 else schedule[:16]
        return self._calculate_entropy(first_key) > 6.0
    
    def _calculate_schedule_confidence(self, schedule: bytes) -> float:
        """Calculate confidence that data is a real key schedule"""
        # Simplified validation - real implementation would check
        # AES key expansion properties
        entropy = self._calculate_entropy(schedule)
        return min(entropy / 8.0, 1.0)
    
    def _detect_volatility_profile(self, dump_path: str) -> Optional[str]:
        """Auto-detect Volatility profile for memory dump"""
        try:
            cmd = [self.volatility_path, '-f', dump_path, 'imageinfo']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # Parse profile from output
                for line in result.stdout.split('\n'):
                    if 'Suggested Profile(s)' in line:
                        profiles = line.split(':')[1].strip().split(',')
                        return profiles[0].strip()
        
        except Exception:
            pass
        
        return None
    
    def _run_volatility_plugin(self, dump_path: str, profile: Optional[str], plugin: str) -> List[Dict[str, Any]]:
        """Run Volatility plugin and parse results"""
        results = []
        
        try:
            cmd = [self.volatility_path, '-f', dump_path]
            if profile:
                cmd.extend(['--profile', profile])
            cmd.append(plugin)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                # Parse output (simplified)
                for line in result.stdout.split('\n')[2:]:  # Skip headers
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            results.append({
                                'name': parts[1] if len(parts) > 1 else '',
                                'pid': parts[0] if parts[0].isdigit() else '',
                                'raw_line': line
                            })
        
        except Exception:
            pass
        
        return results
    
    def _identify_crypto_processes(self, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify processes that might contain crypto material"""
        crypto_processes = []
        crypto_names = ['cryptsetup', 'dmcrypt', 'gpg', 'ssh', 'ssl', 'tls']
        
        for proc in processes:
            proc_name = proc.get('name', '').lower()
            if any(crypto_name in proc_name for crypto_name in crypto_names):
                crypto_processes.append(proc)
        
        return crypto_processes
    
    def _extract_process_memory(self, dump_path: str, profile: Optional[str], pid: str) -> Optional[bytes]:
        """Extract process memory using Volatility"""
        try:
            cmd = [self.volatility_path, '-f', dump_path]
            if profile:
                cmd.extend(['--profile', profile])
            cmd.extend(['memdump', '-p', pid, '--dump-dir', '/tmp'])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Find generated dump file
                dump_file = f"/tmp/{pid}.dmp"
                if os.path.exists(dump_file):
                    with open(dump_file, 'rb') as f:
                        return f.read()
        
        except Exception:
            pass
        
        return None
    
    def _analyze_process_memory(self, memory_data: bytes) -> List[Dict[str, Any]]:
        """Analyze extracted process memory for artifacts"""
        artifacts = []
        
        # Search for key patterns in process memory
        for pattern_name, pattern in self.key_patterns.items():
            offset = 0
            while True:
                pos = memory_data.find(pattern, offset)
                if pos == -1:
                    break
                
                artifacts.append({
                    'type': 'pattern_match',
                    'pattern': pattern_name,
                    'offset': pos,
                    'context': binascii.hexlify(memory_data[max(0, pos-16):pos+48]).decode()
                })
                
                offset = pos + 1
        
        return artifacts
    
    def _find_pbkdf2_artifacts(self, data: bytes, base_offset: int) -> List[Dict[str, Any]]:
        """Find PBKDF2-related artifacts"""
        artifacts = []
        pbkdf2_signatures = [b'PBKDF2', b'pbkdf2', b'HMAC-SHA', b'hmac-sha']
        
        for sig in pbkdf2_signatures:
            offset = 0
            while True:
                pos = data.find(sig, offset)
                if pos == -1:
                    break
                
                artifacts.append({
                    'type': 'pbkdf2_signature',
                    'offset': base_offset + pos,
                    'signature': sig.decode('utf-8', errors='ignore'),
                    'context': binascii.hexlify(data[max(0, pos-16):pos+48]).decode()
                })
                
                offset = pos + 1
        
        return artifacts
    
    def _find_argon2_artifacts(self, data: bytes, base_offset: int) -> List[Dict[str, Any]]:
        """Find Argon2-related artifacts"""
        artifacts = []
        argon2_signatures = [b'argon2', b'Argon2', b'ARGON2']
        
        for sig in argon2_signatures:
            offset = 0
            while True:
                pos = data.find(sig, offset)
                if pos == -1:
                    break
                
                artifacts.append({
                    'type': 'argon2_signature',
                    'offset': base_offset + pos,
                    'signature': sig.decode('utf-8', errors='ignore'),
                    'context': binascii.hexlify(data[max(0, pos-16):pos+48]).decode()
                })
                
                offset = pos + 1
        
        return artifacts
    
    def _find_aes_artifacts(self, data: bytes, base_offset: int) -> List[Dict[str, Any]]:
        """Find AES-related artifacts"""
        artifacts = []
        
        # AES S-box signature
        aes_sbox = bytes([
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
            0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76
        ])
        
        pos = data.find(aes_sbox[:8])
        if pos != -1:
            artifacts.append({
                'type': 'aes_sbox',
                'offset': base_offset + pos,
                'context': binascii.hexlify(data[max(0, pos-16):pos+48]).decode()
            })
        
        return artifacts
    
    def _calculate_entropy_distribution(self, entropy_values: List[float]) -> Dict[str, Any]:
        """Calculate entropy distribution statistics"""
        if not entropy_values:
            return {}
        
        return {
            'min': min(entropy_values),
            'max': max(entropy_values),
            'mean': sum(entropy_values) / len(entropy_values),
            'high_entropy_regions': sum(1 for e in entropy_values if e > 7.5),
            'total_regions': len(entropy_values)
        }

def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="LUKS Memory Forensics Suite")
    parser.add_argument('dump_file', help="Memory dump file to analyze")
    parser.add_argument('--profile', help="Volatility profile (auto-detect if not specified)")
    parser.add_argument('--output-dir', default='extracted_keys', help="Directory for extracted keys")
    parser.add_argument('--test-device', help="LUKS device to test extracted keys against")
    parser.add_argument('--output-json', help="JSON file to save results")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.dump_file):
        print(f"[!] Error: Memory dump file not found: {args.dump_file}")
        sys.exit(1)
    
    forensics = LUKSMemoryForensics()
    
    # Perform analysis
    print("[*] Starting LUKS memory forensics analysis...")
    results = forensics.analyze_memory_dump(args.dump_file, args.profile)
    
    # Extract potential keys
    print("[*] Extracting potential keys...")
    key_files = forensics.extract_keys_from_analysis(results, args.output_dir)
    print(f"[*] Extracted {len(key_files)} potential keys to {args.output_dir}")
    
    # Test keys if device provided
    if args.test_device and key_files:
        print(f"[*] Testing extracted keys against {args.test_device}...")
        test_results = forensics.test_extracted_keys(key_files, args.test_device)
        results['key_testing'] = test_results
        
        if test_results['successful_keys']:
            print(f"[+] SUCCESS: Found {len(test_results['successful_keys'])} working keys!")
        else:
            print("[-] No extracted keys successfully unlocked the device")
    
    # Save results
    if args.output_json:
        with open(args.output_json, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[*] Results saved to {args.output_json}")
    
    # Summary
    print(f"\n[*] Analysis Summary:")
    print(f"    - Dump size: {results.get('dump_size', 0) // (1024*1024)} MB")
    print(f"    - Analysis methods: {', '.join(results.get('analysis_methods', []))}")
    print(f"    - Potential keys found: {len(results.get('potential_keys', []))}")
    print(f"    - LUKS signatures: {len(results.get('luks_signatures', []))}")
    print(f"    - Key schedules: {len(results.get('key_schedules', []))}")
    
    if 'volatility_results' in results and results['volatility_results']:
        vol_results = results['volatility_results']
        print(f"    - Processes analyzed: {len(vol_results.get('processes', []))}")
        print(f"    - Crypto processes: {len(vol_results.get('crypto_processes', []))}")

if __name__ == '__main__':
    main()