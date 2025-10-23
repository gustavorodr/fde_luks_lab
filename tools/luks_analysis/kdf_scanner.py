#!/usr/bin/env python3
"""
KDF Vulnerability Scanner - Detects weak Key Derivation Functions in LUKS
Specifically targets PBKDF2 weakness vs Argon2id strength analysis

Author: Penetration Testing Lab
Target: LUKS KDF downgrade attacks
"""

import subprocess
import re
import sys
import argparse
import json
import time
from pathlib import Path
from typing import Dict, List, Tuple

class KDFVulnerabilityScanner:
    """Scanner for KDF-specific vulnerabilities in LUKS implementations"""
    
    def __init__(self):
        self.supported_kdfs = ['pbkdf2', 'argon2i', 'argon2id']
        self.benchmark_results = {}
        
    def scan_device(self, device_path: str) -> Dict:
        """Scan a LUKS device for KDF vulnerabilities"""
        results = {
            'device': device_path,
            'keyslots': {},
            'vulnerabilities': [],
            'attack_complexity': {},
            'recommendations': []
        }
        
        # Extract keyslot information
        keyslots = self._extract_keyslot_info(device_path)
        results['keyslots'] = keyslots
        
        # Analyze each keyslot
        for slot_id, slot_info in keyslots.items():
            if slot_info['enabled']:
                vuln = self._analyze_keyslot_kdf(slot_id, slot_info)
                if vuln:
                    results['vulnerabilities'].extend(vuln)
        
        # Calculate attack complexity
        results['attack_complexity'] = self._calculate_attack_complexity(keyslots)
        
        # Generate recommendations
        results['recommendations'] = self._generate_kdf_recommendations(keyslots)
        
        return results
    
    def _extract_keyslot_info(self, device_path: str) -> Dict:
        """Extract detailed keyslot information including KDF parameters"""
        keyslots = {}
        
        try:
            # Use cryptsetup luksDump to get detailed information
            result = subprocess.run([
                'cryptsetup', 'luksDump', device_path
            ], capture_output=True, text=True, check=True)
            
            lines = result.stdout.split('\n')
            current_slot = None
            
            for line in lines:
                line = line.strip()
                
                # Detect keyslot
                slot_match = re.search(r'Key Slot (\d+): (ENABLED|DISABLED)', line)
                if slot_match:
                    slot_id = slot_match.group(1)
                    enabled = slot_match.group(2) == 'ENABLED'
                    
                    keyslots[slot_id] = {
                        'enabled': enabled,
                        'pbkdf': None,
                        'iterations': 0,
                        'memory': 0,
                        'parallel': 0,
                        'salt': None,
                        'estimated_time': 0
                    }
                    current_slot = slot_id
                
                elif current_slot and ':' in line and keyslots[current_slot]['enabled']:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if 'pbkdf' in key:
                        keyslots[current_slot]['pbkdf'] = value.lower()
                    elif 'iterations' in key:
                        try:
                            keyslots[current_slot]['iterations'] = int(value.replace(',', ''))
                        except ValueError:
                            pass
                    elif 'memory' in key:
                        try:
                            # Parse memory requirement (e.g., "1048576 bytes")
                            memory_match = re.search(r'(\d+)', value)
                            if memory_match:
                                keyslots[current_slot]['memory'] = int(memory_match.group(1))
                        except ValueError:
                            pass
                    elif 'parallelism' in key or 'parallel' in key:
                        try:
                            keyslots[current_slot]['parallel'] = int(value)
                        except ValueError:
                            pass
                    elif 'salt' in key:
                        keyslots[current_slot]['salt'] = value
        
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to extract keyslot info: {e}")
        
        return keyslots
    
    def _analyze_keyslot_kdf(self, slot_id: str, slot_info: Dict) -> List[Dict]:
        """Analyze individual keyslot for KDF vulnerabilities"""
        vulnerabilities = []
        pbkdf = slot_info.get('pbkdf', '').lower()
        iterations = slot_info.get('iterations', 0)
        memory = slot_info.get('memory', 0)
        
        # PBKDF2 vulnerability analysis
        if 'pbkdf2' in pbkdf:
            severity = 'HIGH'
            gpu_acceleration = self._calculate_gpu_acceleration_factor(iterations)
            
            vulnerabilities.append({
                'type': 'WEAK_KDF_PBKDF2',
                'severity': severity,
                'slot': slot_id,
                'pbkdf': pbkdf,
                'iterations': iterations,
                'description': 'PBKDF2 is vulnerable to GPU acceleration attacks',
                'gpu_acceleration_factor': gpu_acceleration,
                'estimated_crack_time': self._estimate_crack_time('pbkdf2', iterations, 0),
                'recommendation': 'Convert to Argon2id using cryptsetup luksConvertKey'
            })
            
            # Check for extremely weak configurations
            if iterations < 10000:
                vulnerabilities.append({
                    'type': 'CRITICAL_WEAK_ITERATIONS',
                    'severity': 'CRITICAL',
                    'slot': slot_id,
                    'iterations': iterations,
                    'description': f'Extremely low iteration count: {iterations}',
                    'recommendation': 'Immediate remediation required - increase iterations or migrate to Argon2id'
                })
        
        # Argon2 configuration analysis
        elif 'argon2' in pbkdf:
            if 'argon2i' in pbkdf:
                vulnerabilities.append({
                    'type': 'SUBOPTIMAL_ARGON2',
                    'severity': 'MEDIUM',
                    'slot': slot_id,
                    'pbkdf': pbkdf,
                    'description': 'Argon2i is less secure than Argon2id against side-channel attacks',
                    'recommendation': 'Upgrade to Argon2id for optimal security'
                })
            
            # Check memory requirements
            if memory < 1048576:  # Less than 1MB
                vulnerabilities.append({
                    'type': 'LOW_ARGON2_MEMORY',
                    'severity': 'MEDIUM',
                    'slot': slot_id,
                    'memory_bytes': memory,
                    'description': f'Low Argon2 memory requirement: {memory} bytes',
                    'recommendation': 'Increase memory parameter for better GPU resistance'
                })
        
        return vulnerabilities
    
    def _calculate_gpu_acceleration_factor(self, iterations: int) -> float:
        """Calculate GPU acceleration factor for PBKDF2"""
        # Based on research: GPU can be 100-200x faster than CPU for PBKDF2
        base_acceleration = 150.0
        
        # Lower iterations make GPU attacks more viable
        if iterations < 50000:
            base_acceleration *= 1.5
        elif iterations < 100000:
            base_acceleration *= 1.2
        
        return base_acceleration
    
    def _calculate_attack_complexity(self, keyslots: Dict) -> Dict:
        """Calculate overall attack complexity considering all keyslots"""
        complexity = {
            'weakest_kdf': None,
            'strongest_kdf': None,
            'mixed_kdfs': False,
            'attack_vectors': [],
            'overall_security_level': 'UNKNOWN'
        }
        
        enabled_slots = {k: v for k, v in keyslots.items() if v['enabled']}
        
        if not enabled_slots:
            return complexity
        
        kdfs = [slot['pbkdf'] for slot in enabled_slots.values() if slot['pbkdf']]
        unique_kdfs = set(kdfs)
        
        # Check for mixed KDF configurations
        if len(unique_kdfs) > 1:
            complexity['mixed_kdfs'] = True
            complexity['attack_vectors'].append('WEAKEST_LINK_ATTACK')
        
        # Determine weakest and strongest KDFs
        kdf_strength = {'pbkdf2': 1, 'argon2i': 2, 'argon2id': 3}
        
        if kdfs:
            strengths = [kdf_strength.get(kdf, 0) for kdf in kdfs]
            weakest_strength = min(strengths)
            strongest_strength = max(strengths)
            
            strength_to_kdf = {v: k for k, v in kdf_strength.items()}
            complexity['weakest_kdf'] = strength_to_kdf.get(weakest_strength)
            complexity['strongest_kdf'] = strength_to_kdf.get(strongest_strength)
            
            # Determine overall security level
            if weakest_strength == 1:  # PBKDF2 present
                complexity['overall_security_level'] = 'WEAK'
                complexity['attack_vectors'].extend(['GPU_BRUTE_FORCE', 'DICTIONARY_ATTACK'])
            elif weakest_strength == 2:  # Argon2i
                complexity['overall_security_level'] = 'MODERATE'
            else:  # Argon2id
                complexity['overall_security_level'] = 'STRONG'
        
        return complexity
    
    def _estimate_crack_time(self, kdf_type: str, iterations: int, memory: int) -> Dict:
        """Estimate crack time for different attack scenarios"""
        estimates = {
            'cpu_single_core': 0,
            'cpu_multi_core': 0,
            'gpu_single': 0,
            'gpu_farm': 0,
            'assumptions': ''
        }
        
        if kdf_type == 'pbkdf2':
            # Base time for 100k iterations on single CPU core (seconds per attempt)
            base_time_cpu = (iterations / 100000) * 0.001
            
            estimates['cpu_single_core'] = base_time_cpu
            estimates['cpu_multi_core'] = base_time_cpu / 8  # 8-core CPU
            estimates['gpu_single'] = base_time_cpu / 150  # GPU acceleration
            estimates['gpu_farm'] = base_time_cpu / (150 * 8)  # 8-GPU farm
            estimates['assumptions'] = 'Password space: 10^8 (8-digit PIN), 50% success probability'
            
        elif 'argon2' in kdf_type:
            # Argon2 is memory-hard, GPU acceleration is limited
            memory_gb = memory / (1024**3) if memory > 0 else 1
            base_time_cpu = (iterations / 10) * memory_gb * 0.01
            
            estimates['cpu_single_core'] = base_time_cpu
            estimates['cpu_multi_core'] = base_time_cpu / 4  # Limited parallel benefit
            estimates['gpu_single'] = base_time_cpu / 2  # Minimal GPU advantage
            estimates['gpu_farm'] = base_time_cpu / 4  # Memory bottleneck
            estimates['assumptions'] = f'Memory requirement: {memory_gb:.1f}GB limits GPU efficiency'
        
        return estimates
    
    def _generate_kdf_recommendations(self, keyslots: Dict) -> List[Dict]:
        """Generate specific recommendations for KDF hardening"""
        recommendations = []
        
        enabled_slots = {k: v for k, v in keyslots.items() if v['enabled']}
        
        # Check for PBKDF2 slots
        pbkdf2_slots = [k for k, v in enabled_slots.items() if 'pbkdf2' in v.get('pbkdf', '')]
        
        if pbkdf2_slots:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'CONVERT_KDF',
                'description': 'Convert PBKDF2 slots to Argon2id',
                'affected_slots': pbkdf2_slots,
                'commands': [
                    f'cryptsetup luksConvertKey --pbkdf argon2id /dev/sdX {slot}'
                    for slot in pbkdf2_slots
                ]
            })
        
        # Check for Argon2i slots
        argon2i_slots = [k for k, v in enabled_slots.items() if 'argon2i' in v.get('pbkdf', '')]
        
        if argon2i_slots:
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'UPGRADE_ARGON2',
                'description': 'Upgrade Argon2i to Argon2id',
                'affected_slots': argon2i_slots,
                'commands': [
                    f'cryptsetup luksConvertKey --pbkdf argon2id /dev/sdX {slot}'
                    for slot in argon2i_slots
                ]
            })
        
        # Check for mixed configurations
        unique_kdfs = set(v.get('pbkdf', '') for v in enabled_slots.values())
        if len(unique_kdfs) > 1:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'STANDARDIZE_KDF',
                'description': 'Standardize all keyslots to use Argon2id',
                'commands': ['# Convert all slots to consistent KDF configuration']
            })
        
        return recommendations
    
    def benchmark_kdf_performance(self, device_path: str = None) -> Dict:
        """Benchmark KDF performance on current system"""
        benchmarks = {}
        
        print("[INFO] Running KDF performance benchmarks...")
        
        # Test PBKDF2 performance
        benchmarks['pbkdf2'] = self._benchmark_pbkdf2()
        
        # Test Argon2id performance (if available)
        benchmarks['argon2id'] = self._benchmark_argon2id()
        
        return benchmarks
    
    def _benchmark_pbkdf2(self) -> Dict:
        """Benchmark PBKDF2 performance"""
        try:
            start_time = time.time()
            
            # Use cryptsetup benchmark for PBKDF2
            result = subprocess.run([
                'cryptsetup', 'benchmark', '--pbkdf', 'pbkdf2'
            ], capture_output=True, text=True, timeout=30)
            
            end_time = time.time()
            
            return {
                'duration': end_time - start_time,
                'output': result.stdout,
                'available': result.returncode == 0
            }
            
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return {'available': False, 'error': 'Benchmark failed'}
    
    def _benchmark_argon2id(self) -> Dict:
        """Benchmark Argon2id performance"""
        try:
            start_time = time.time()
            
            # Use cryptsetup benchmark for Argon2id
            result = subprocess.run([
                'cryptsetup', 'benchmark', '--pbkdf', 'argon2id'
            ], capture_output=True, text=True, timeout=60)
            
            end_time = time.time()
            
            return {
                'duration': end_time - start_time,
                'output': result.stdout,
                'available': result.returncode == 0
            }
            
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return {'available': False, 'error': 'Benchmark failed'}


def main():
    parser = argparse.ArgumentParser(description='LUKS KDF Vulnerability Scanner')
    parser.add_argument('device', nargs='?', help='Path to LUKS device')
    parser.add_argument('-b', '--benchmark', action='store_true', 
                       help='Run KDF performance benchmarks')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    scanner = KDFVulnerabilityScanner()
    
    if args.benchmark:
        print("Running KDF benchmarks...")
        benchmarks = scanner.benchmark_kdf_performance()
        
        print("\n[BENCHMARK RESULTS]")
        for kdf, result in benchmarks.items():
            if result.get('available'):
                print(f"{kdf.upper()}: {result['duration']:.2f}s")
            else:
                print(f"{kdf.upper()}: Not available")
    
    if args.device:
        if not Path(args.device).exists():
            print(f"[ERROR] Device not found: {args.device}")
            sys.exit(1)
        
        print(f"[INFO] Scanning device: {args.device}")
        results = scanner.scan_device(args.device)
        
        # Print results
        print("\n" + "="*60)
        print("KDF VULNERABILITY ANALYSIS REPORT")
        print("="*60)
        
        print(f"\nDevice: {results['device']}")
        
        # Keyslot summary
        print(f"\n[KEYSLOT ANALYSIS]")
        for slot_id, slot_info in results['keyslots'].items():
            if slot_info['enabled']:
                kdf = slot_info.get('pbkdf', 'Unknown')
                iterations = slot_info.get('iterations', 0)
                memory = slot_info.get('memory', 0)
                
                print(f"Slot {slot_id}: {kdf.upper()} ({iterations:,} iterations")
                if memory > 0:
                    print(f"           Memory: {memory:,} bytes")
        
        # Vulnerability summary
        print(f"\n[VULNERABILITIES]")
        if not results['vulnerabilities']:
            print("No KDF vulnerabilities detected.")
        else:
            for i, vuln in enumerate(results['vulnerabilities'], 1):
                print(f"\n{i}. [{vuln['severity']}] {vuln['type']}")
                print(f"   Slot: {vuln.get('slot', 'N/A')}")
                print(f"   Description: {vuln['description']}")
                print(f"   Recommendation: {vuln['recommendation']}")
                
                if 'gpu_acceleration_factor' in vuln:
                    print(f"   GPU Acceleration: {vuln['gpu_acceleration_factor']:.1f}x")
        
        # Attack complexity
        complexity = results['attack_complexity']
        print(f"\n[ATTACK COMPLEXITY]")
        print(f"Overall Security Level: {complexity['overall_security_level']}")
        print(f"Weakest KDF: {complexity['weakest_kdf']}")
        
        if complexity['attack_vectors']:
            print(f"Viable Attack Vectors: {', '.join(complexity['attack_vectors'])}")
        
        # Recommendations
        print(f"\n[RECOMMENDATIONS]")
        for i, rec in enumerate(results['recommendations'], 1):
            print(f"\n{i}. [{rec['priority']}] {rec['action']}")
            print(f"   Description: {rec['description']}")
            if 'affected_slots' in rec:
                print(f"   Affected Slots: {', '.join(rec['affected_slots'])}")
            
            if args.verbose and 'commands' in rec:
                print("   Commands:")
                for cmd in rec['commands']:
                    print(f"     {cmd}")
        
        # Export JSON if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n[INFO] Results exported to: {args.output}")


if __name__ == "__main__":
    main()