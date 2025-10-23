#!/usr/bin/env python3
"""
LUKS Header Analyzer - Advanced LUKS vulnerability reconnaissance tool
Identifies weak KDFs, vulnerable key slots, and architectural weaknesses

Author: Penetration Testing Lab
Target: LUKS FDE vulnerability analysis
"""

import subprocess
import json
import re
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple

class LUKSHeaderAnalyzer:
    """Advanced LUKS header analysis for penetration testing"""
    
    def __init__(self, device_path: str):
        self.device_path = device_path
        self.header_data = {}
        self.vulnerabilities = []
        
    def extract_header_info(self) -> Dict:
        """Extract comprehensive LUKS header information"""
        try:
            # Run cryptsetup luksDump to get header information
            result = subprocess.run([
                'cryptsetup', 'luksDump', self.device_path
            ], capture_output=True, text=True, check=True)
            
            self.header_data = self._parse_luks_dump(result.stdout)
            return self.header_data
            
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to dump LUKS header: {e}")
            return {}
    
    def _parse_luks_dump(self, dump_output: str) -> Dict:
        """Parse cryptsetup luksDump output into structured data"""
        data = {
            'version': None,
            'cipher': None,
            'cipher_mode': None,
            'hash': None,
            'payload_offset': None,
            'mk_bits': None,
            'uuid': None,
            'keyslots': {}
        }
        
        lines = dump_output.split('\n')
        current_keyslot = None
        
        for line in lines:
            line = line.strip()
            
            # Extract main header information
            if line.startswith('Version:'):
                data['version'] = line.split(':', 1)[1].strip()
            elif line.startswith('Cipher name:'):
                data['cipher'] = line.split(':', 1)[1].strip()
            elif line.startswith('Cipher mode:'):
                data['cipher_mode'] = line.split(':', 1)[1].strip()
            elif line.startswith('Hash spec:'):
                data['hash'] = line.split(':', 1)[1].strip()
            elif line.startswith('Payload offset:'):
                data['payload_offset'] = line.split(':', 1)[1].strip()
            elif line.startswith('MK bits:'):
                data['mk_bits'] = line.split(':', 1)[1].strip()
            elif line.startswith('UUID:'):
                data['uuid'] = line.split(':', 1)[1].strip()
            
            # Extract keyslot information
            elif line.startswith('Key Slot'):
                match = re.search(r'Key Slot (\d+):', line)
                if match:
                    current_keyslot = match.group(1)
                    data['keyslots'][current_keyslot] = {
                        'enabled': 'ENABLED' in line,
                        'iterations': None,
                        'salt': None,
                        'key_material_offset': None,
                        'af_stripes': None,
                        'pbkdf': None
                    }
            
            elif current_keyslot and ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower().replace(' ', '_')
                value = value.strip()
                
                if key in ['iterations', 'salt', 'key_material_offset', 'af_stripes']:
                    data['keyslots'][current_keyslot][key] = value
                elif key == 'pbkdf':
                    data['keyslots'][current_keyslot]['pbkdf'] = value
        
        return data
    
    def analyze_vulnerabilities(self) -> List[Dict]:
        """Identify potential vulnerabilities in LUKS configuration"""
        self.vulnerabilities = []
        
        if not self.header_data:
            self.extract_header_info()
        
        # Check for LUKS version vulnerabilities
        self._check_version_vulnerabilities()
        
        # Check KDF vulnerabilities
        self._check_kdf_vulnerabilities()
        
        # Check cipher vulnerabilities
        self._check_cipher_vulnerabilities()
        
        # Check keyslot configuration
        self._check_keyslot_vulnerabilities()
        
        return self.vulnerabilities
    
    def _check_version_vulnerabilities(self):
        """Check for LUKS version-specific vulnerabilities"""
        version = self.header_data.get('version', '')
        
        if version == '1':
            self.vulnerabilities.append({
                'type': 'VERSION_VULNERABILITY',
                'severity': 'MEDIUM',
                'description': 'LUKS1 detected - limited to PBKDF2, vulnerable to GPU acceleration',
                'recommendation': 'Upgrade to LUKS2 with Argon2id KDF'
            })
        
        # Check for CVE-2021-4122 affected versions
        if 'luks2' in version.lower():
            self.vulnerabilities.append({
                'type': 'CVE_POTENTIAL',
                'severity': 'HIGH',
                'cve': 'CVE-2021-4122',
                'description': 'LUKS2 header manipulation vulnerability potential',
                'recommendation': 'Verify cryptsetup version and apply patches'
            })
    
    def _check_kdf_vulnerabilities(self):
        """Check for weak Key Derivation Functions"""
        weak_kdfs = []
        
        for slot_id, slot_data in self.header_data.get('keyslots', {}).items():
            if not slot_data.get('enabled'):
                continue
                
            pbkdf = slot_data.get('pbkdf', '').lower()
            iterations = slot_data.get('iterations', '0')
            
            if 'pbkdf2' in pbkdf:
                weak_kdfs.append({
                    'slot': slot_id,
                    'kdf': 'PBKDF2',
                    'iterations': iterations
                })
                
                # Check for low iteration counts
                try:
                    iter_count = int(iterations.replace(',', ''))
                    if iter_count < 100000:
                        self.vulnerabilities.append({
                            'type': 'WEAK_KDF_ITERATIONS',
                            'severity': 'CRITICAL',
                            'slot': slot_id,
                            'description': f'Slot {slot_id}: Extremely low PBKDF2 iterations ({iterations})',
                            'recommendation': 'Increase iterations or migrate to Argon2id'
                        })
                except ValueError:
                    pass
        
        if weak_kdfs:
            self.vulnerabilities.append({
                'type': 'WEAK_KDF',
                'severity': 'HIGH',
                'description': f'PBKDF2 detected in {len(weak_kdfs)} key slots - vulnerable to GPU acceleration',
                'affected_slots': weak_kdfs,
                'recommendation': 'Convert key slots to Argon2id using: cryptsetup luksConvertKey --pbkdf argon2id'
            })
    
    def _check_cipher_vulnerabilities(self):
        """Check for cipher configuration issues"""
        cipher = self.header_data.get('cipher', '').lower()
        mode = self.header_data.get('cipher_mode', '').lower()
        mk_bits = self.header_data.get('mk_bits', '')
        
        # Check for weak ciphers
        if 'aes' not in cipher:
            self.vulnerabilities.append({
                'type': 'WEAK_CIPHER',
                'severity': 'HIGH',
                'description': f'Non-AES cipher detected: {cipher}',
                'recommendation': 'Use AES-256 for maximum security'
            })
        
        # Check for weak modes
        if mode not in ['xts-plain64', 'gcm-random']:
            self.vulnerabilities.append({
                'type': 'WEAK_CIPHER_MODE',
                'severity': 'MEDIUM',
                'description': f'Potentially weak cipher mode: {mode}',
                'recommendation': 'Use XTS mode for disk encryption'
            })
        
        # Check key size
        try:
            key_bits = int(mk_bits)
            if key_bits < 256:
                self.vulnerabilities.append({
                    'type': 'WEAK_KEY_SIZE',
                    'severity': 'HIGH',
                    'description': f'Key size below 256 bits: {mk_bits}',
                    'recommendation': 'Use 256-bit or larger keys'
                })
        except (ValueError, TypeError):
            pass
    
    def _check_keyslot_vulnerabilities(self):
        """Check for keyslot configuration issues"""
        enabled_slots = [slot for slot, data in self.header_data.get('keyslots', {}).items() 
                        if data.get('enabled')]
        
        if len(enabled_slots) > 1:
            # Check for mixed KDF configurations
            kdfs = set()
            for slot_id in enabled_slots:
                slot_data = self.header_data['keyslots'][slot_id]
                pbkdf = slot_data.get('pbkdf', '').lower()
                kdfs.add(pbkdf)
            
            if len(kdfs) > 1:
                self.vulnerabilities.append({
                    'type': 'MIXED_KDF_CONFIG',
                    'severity': 'HIGH',
                    'description': 'Multiple KDFs detected - weakest KDF determines overall security',
                    'recommendation': 'Standardize all key slots to use Argon2id'
                })
        
        # Check for GRUB compatibility issues
        grub_slots = []
        for slot_id, slot_data in self.header_data.get('keyslots', {}).items():
            if slot_data.get('enabled') and 'pbkdf2' in slot_data.get('pbkdf', '').lower():
                grub_slots.append(slot_id)
        
        if grub_slots:
            self.vulnerabilities.append({
                'type': 'GRUB_COMPATIBILITY_WEAKNESS',
                'severity': 'HIGH',
                'description': f'PBKDF2 slots ({grub_slots}) likely for GRUB compatibility - attack vector',
                'recommendation': 'Use high-entropy passphrase for GRUB slots or external boot media'
            })
    
    def generate_attack_recommendations(self) -> List[Dict]:
        """Generate specific attack recommendations based on vulnerabilities"""
        attacks = []
        
        for vuln in self.vulnerabilities:
            if vuln['type'] == 'WEAK_KDF':
                attacks.append({
                    'attack_type': 'GPU_BRUTE_FORCE',
                    'tool': 'hashcat',
                    'command': f"hashcat -m 14600 -a 3 {self.device_path} ?d?d?d?d?d?d",
                    'description': 'GPU-accelerated PBKDF2 brute force attack',
                    'affected_slots': vuln.get('affected_slots', [])
                })
            
            elif vuln['type'] == 'GRUB_COMPATIBILITY_WEAKNESS':
                attacks.append({
                    'attack_type': 'DICTIONARY_ATTACK',
                    'tool': 'custom_script',
                    'description': 'Dictionary attack against GRUB-compatible PBKDF2 slots',
                    'command': f"./brute_force/luks_dictionary.py -d {self.device_path} -w wordlists/common.txt"
                })
        
        return attacks
    
    def export_header_backup(self, output_path: str) -> bool:
        """Create LUKS header backup for offline analysis"""
        try:
            # Create header backup
            subprocess.run([
                'cryptsetup', 'luksHeaderBackup', self.device_path, 
                '--header-backup-file', output_path
            ], check=True)
            
            print(f"[SUCCESS] Header backup created: {output_path}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to backup header: {e}")
            return False
    
    def print_analysis_report(self):
        """Print comprehensive analysis report"""
        print("=" * 80)
        print("LUKS FULL DISK ENCRYPTION VULNERABILITY ANALYSIS")
        print("=" * 80)
        
        if not self.header_data:
            print("[ERROR] No header data available")
            return
        
        # Basic information
        print(f"\n[BASIC INFO]")
        print(f"Device: {self.device_path}")
        print(f"LUKS Version: {self.header_data.get('version', 'Unknown')}")
        print(f"Cipher: {self.header_data.get('cipher', 'Unknown')} ({self.header_data.get('cipher_mode', 'Unknown')})")
        print(f"Key Size: {self.header_data.get('mk_bits', 'Unknown')} bits")
        print(f"Hash: {self.header_data.get('hash', 'Unknown')}")
        print(f"UUID: {self.header_data.get('uuid', 'Unknown')}")
        
        # Keyslot analysis
        print(f"\n[KEYSLOT ANALYSIS]")
        enabled_count = 0
        for slot_id, slot_data in self.header_data.get('keyslots', {}).items():
            if slot_data.get('enabled'):
                enabled_count += 1
                pbkdf = slot_data.get('pbkdf', 'Unknown')
                iterations = slot_data.get('iterations', 'Unknown')
                print(f"Slot {slot_id}: ENABLED - {pbkdf} ({iterations} iterations)")
            else:
                print(f"Slot {slot_id}: DISABLED")
        
        print(f"Total enabled slots: {enabled_count}")
        
        # Vulnerability summary
        print(f"\n[VULNERABILITY SUMMARY]")
        if not self.vulnerabilities:
            print("No major vulnerabilities detected.")
        else:
            critical = sum(1 for v in self.vulnerabilities if v['severity'] == 'CRITICAL')
            high = sum(1 for v in self.vulnerabilities if v['severity'] == 'HIGH')
            medium = sum(1 for v in self.vulnerabilities if v['severity'] == 'MEDIUM')
            
            print(f"CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium}")
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n{i}. [{vuln['severity']}] {vuln['type']}")
                print(f"   Description: {vuln['description']}")
                print(f"   Recommendation: {vuln['recommendation']}")
        
        # Attack recommendations
        attacks = self.generate_attack_recommendations()
        if attacks:
            print(f"\n[ATTACK VECTORS]")
            for i, attack in enumerate(attacks, 1):
                print(f"\n{i}. {attack['attack_type']}")
                print(f"   Tool: {attack['tool']}")
                print(f"   Description: {attack['description']}")
                if 'command' in attack:
                    print(f"   Command: {attack['command']}")


def main():
    parser = argparse.ArgumentParser(description='LUKS FDE Vulnerability Analysis Tool')
    parser.add_argument('device', help='Path to LUKS device (e.g., /dev/sdb1)')
    parser.add_argument('-o', '--output', help='Output directory for results')
    parser.add_argument('-b', '--backup', help='Create header backup file')
    parser.add_argument('-j', '--json', help='Export results as JSON')
    
    args = parser.parse_args()
    
    # Verify device exists
    if not Path(args.device).exists():
        print(f"[ERROR] Device not found: {args.device}")
        sys.exit(1)
    
    # Initialize analyzer
    analyzer = LUKSHeaderAnalyzer(args.device)
    
    # Extract header information
    print("[INFO] Extracting LUKS header information...")
    header_data = analyzer.extract_header_info()
    
    if not header_data:
        print("[ERROR] Failed to extract header data")
        sys.exit(1)
    
    # Analyze vulnerabilities
    print("[INFO] Analyzing vulnerabilities...")
    vulnerabilities = analyzer.analyze_vulnerabilities()
    
    # Create header backup if requested
    if args.backup:
        analyzer.export_header_backup(args.backup)
    
    # Print analysis report
    analyzer.print_analysis_report()
    
    # Export JSON if requested
    if args.json:
        report_data = {
            'device': args.device,
            'header_info': header_data,
            'vulnerabilities': vulnerabilities,
            'attack_recommendations': analyzer.generate_attack_recommendations()
        }
        
        with open(args.json, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n[INFO] Report exported to: {args.json}")


if __name__ == "__main__":
    main()