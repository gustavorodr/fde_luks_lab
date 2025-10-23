# LUKS Full Disk Encryption Penetration Testing Lab

## Overview

Authorized penetration test project for public audit of the 2025 ballot-box TPU system (TSE Brazil). This comprehensive toolkit focuses on full disk encryption (LUKS2 + keyfile + PIN/TPM) vulnerability analysis and exploitation in a controlled lab environment.

Based on the technical security report addressing architectural weaknesses in LUKS-based Full Disk Encryption systems, this lab implements practical attack vectors including:

- **KDF Downgrade Attacks**: Exploiting PBKDF2 vs Argon2id weaknesses
- **GPU-Accelerated Brute Force**: Hardware-accelerated attacks against weak key derivation
- **Memory Extraction**: Cold boot and DMA-based VMK recovery
- **Evil Maid Attacks**: Boot chain compromise and keylogging
- **Side-Channel Analysis**: Timing attacks and acoustic keystroke recovery
- **TPM Exploitation**: PCR bypass and sealed key extraction

## Project Structure

```
fde_luks_lab/
├── tools/
│   ├── luks_analysis/          # LUKS header analysis and reconnaissance
│   │   ├── luks_analyzer.py    # Comprehensive LUKS vulnerability scanner
│   │   └── kdf_scanner.py      # KDF weakness detection
│   ├── brute_force/            # GPU-accelerated PBKDF2 attacks
│   │   ├── luks_bruteforce.py  # Main brute force framework
│   │   └── hashcat_integration.py  # Advanced hashcat integration
│   ├── memory_attacks/         # Cold boot and DMA exploitation
│   │   ├── cold_boot_attack.py # Memory remanence exploitation
│   │   └── dma_attack.py       # Direct Memory Access attacks
│   ├── evil_maid/              # Boot-time injection attacks
│   │   └── evil_maid_framework.py  # Complete Evil Maid implementation
│   ├── side_channel/           # Timing and acoustic analysis (placeholder)
│   ├── tpm_exploitation/       # TPM bypass techniques (placeholder)
│   ├── forensics/              # Memory forensics tools (placeholder)
│   └── payloads/               # Malicious payloads and backdoors
├── wordlists/                  # Custom dictionaries for FDE attacks
│   └── generate_wordlists.py   # Specialized wordlist generator
├── results/                    # Attack outputs and forensic evidence
└── main.py      # Master orchestration script
```

## Installation and Setup

### Prerequisites (Kali Linux)

```bash
# Install required packages
sudo apt update
sudo apt install -y cryptsetup-bin hashcat lime-forensics-dkms volatility3
sudo apt install -y python3-pip build-essential linux-headers-$(uname -r)

# Install Python dependencies
pip3 install -r requirements.txt

# Install GPU drivers for hashcat (if applicable)
sudo apt install -y nvidia-driver nvidia-cuda-toolkit  # For NVIDIA
# OR
sudo apt install -y mesa-opencl-icd  # For AMD/Intel

# Set up LiME kernel module
sudo modprobe lime
```

### Initial Setup

```bash
# Clone or set up the project
cd /home/gustavo/Documents/fde_luks_lab

# Make all scripts executable
find tools/ -name "*.py" -exec chmod +x {} \;
chmod +x luks_pentest_master.py
chmod +x wordlists/generate_wordlists.py

# Generate attack wordlists
cd wordlists && python3 generate_wordlists.py all && cd ..
```

## Usage Examples

### 1. Comprehensive Penetration Test

Run complete LUKS FDE security assessment:

```bash
# Full penetration test (requires root for memory operations)
sudo python3 luks_pentest_master.py /dev/sdb1 --output results/full_test

# Quick assessment (skips memory attacks)
python3 luks_pentest_master.py /dev/sdb1 --quick --output results/quick_test

# Specific attack phases only
python3 luks_pentest_master.py /dev/sdb1 --phases reconnaissance vulnerability_analysis brute_force_attacks
```

### 2. LUKS Header Analysis

Analyze LUKS device for vulnerabilities:

```bash
# Basic LUKS analysis
python3 tools/luks_analysis/luks_analyzer.py /dev/sdb1

# KDF vulnerability scanning
python3 tools/luks_analysis/kdf_scanner.py /dev/sdb1 --output kdf_analysis.json

# Create header backup for offline analysis
python3 tools/luks_analysis/luks_analyzer.py /dev/sdb1 --backup luks_header.img
```

### 3. GPU-Accelerated Brute Force

Attack PBKDF2 key slots using GPU acceleration:

```bash
# GPU benchmark for LUKS attacks
python3 tools/brute_force/luks_bruteforce.py /dev/sdb1 --attack benchmark

# Dictionary attack
python3 tools/brute_force/luks_bruteforce.py /dev/sdb1 --attack dict --wordlist wordlists/common.txt

# Mask attack (6-digit PIN)
python3 tools/brute_force/luks_bruteforce.py /dev/sdb1 --attack mask --mask "?d?d?d?d?d?d"

# Show common attack patterns
python3 tools/brute_force/luks_bruteforce.py /dev/sdb1 --show-masks

# Estimate attack time
python3 tools/brute_force/luks_bruteforce.py --estimate "?d?d?d?d?d?d"
```

### 4. Memory Extraction Attacks

Cold boot and DMA attacks for VMK recovery:

```bash
# Check cold boot prerequisites
python3 tools/memory_attacks/cold_boot_attack.py check

# Create memory dump (requires root)
sudo python3 tools/memory_attacks/cold_boot_attack.py dump --output memory.raw --method lime

# Analyze memory dump for keys
python3 tools/memory_attacks/cold_boot_attack.py analyze --input memory.raw

# Extract potential VMKs
python3 tools/memory_attacks/cold_boot_attack.py extract --input memory.raw --output extracted_keys/

# Test extracted keys
python3 tools/memory_attacks/cold_boot_attack.py test --input extracted_keys/ --device /dev/sdb1

# DMA attack surface analysis
python3 tools/memory_attacks/dma_attack.py check
python3 tools/memory_attacks/dma_attack.py analyze
```

### 5. Evil Maid Attacks

Boot chain compromise and keylogging:

```bash
# Analyze boot chain vulnerabilities
python3 tools/evil_maid/evil_maid_framework.py analyze --device /dev/sdb1

# Create malicious initramfs (testing only - requires root)
sudo python3 tools/evil_maid/evil_maid_framework.py create-initramfs \
    --input /boot/initrd.img --output evil_initrd.img --type keylogger

# Create malicious GRUB config
python3 tools/evil_maid/evil_maid_framework.py create-grub \
    --input /boot/grub/grub.cfg --output evil_grub.cfg

# Deploy attack (DANGEROUS - only in controlled environment)
# sudo python3 tools/evil_maid/evil_maid_framework.py deploy \
#     --device /dev/sdb1 --attack-vector INITRAMFS_INJECTION
```

### 6. Wordlist Generation

Create specialized wordlists for LUKS attacks:

```bash
# Generate all wordlist types
python3 wordlists/generate_wordlists.py all

# Generate specific wordlist types
python3 wordlists/generate_wordlists.py pins --min-length 4 --max-length 8
python3 wordlists/generate_wordlists.py dates --start-year 1980 --end-year 2025
python3 wordlists/generate_wordlists.py keyboard
python3 wordlists/generate_wordlists.py luks
python3 wordlists/generate_wordlists.py common

# Create hybrid wordlist
python3 wordlists/generate_wordlists.py hybrid --base-wordlist common.txt --output hybrid.txt

# Merge multiple wordlists
python3 wordlists/generate_wordlists.py merge --merge-files *.txt --output merged.txt
```

## Attack Methodology

### Phase 1: Reconnaissance and Analysis
- LUKS header analysis and version detection
- KDF vulnerability identification (PBKDF2 vs Argon2id)
- Key slot configuration analysis
- System architecture assessment

### Phase 2: Vulnerability Analysis
- DMA attack surface analysis
- Boot chain vulnerability assessment
- Memory protection analysis
- TPM and Secure Boot status

### Phase 3: Brute Force Attacks
- Wordlist generation and optimization
- GPU capability assessment
- Dictionary attacks against weak key slots
- Mask-based brute force (PIN patterns)

### Phase 4: Memory Attacks
- Cold boot attack prerequisites
- Memory dump creation and analysis
- VMK extraction from volatile memory
- DMA-based memory access attacks

### Phase 5: Boot Chain Attacks
- Evil Maid attack vector identification
- Initramfs modification and payload injection
- GRUB configuration manipulation
- Boot partition replacement techniques

### Phase 6: Post-Exploitation
- Key extraction and validation
- Persistence mechanism deployment
- Data exfiltration techniques
- Forensic evidence collection

## Security Considerations

### Legal and Ethical Use

This toolkit is designed exclusively for:
- Authorized penetration testing of the 2025 ballot-box TPU system (TSE Brazil)
- Controlled lab environments with proper authorization
- Educational and research purposes
- Security auditing with explicit permission

### Usage Warnings

- **DESTRUCTIVE POTENTIAL**: Some tools can cause data loss if misused
- **ROOT REQUIRED**: Memory operations require administrative privileges
- **HARDWARE RISK**: GPU attacks can cause thermal stress
- **LEGAL COMPLIANCE**: Only use on systems you own or have explicit permission to test

### Data Protection

- All extracted keys and forensic data should be handled securely
- Results should be encrypted and stored in secure locations
- Sensitive output should be sanitized before sharing
- Follow responsible disclosure practices for findings

## CVE References and Technical Background

This toolkit addresses vulnerabilities and techniques documented in:

- **CVE-2021-4122**: LUKS header manipulation bypass
- **CVE-2025-4382**: GRUB rescue mode VMK exposure (hypothetical reference from technical report)
- Various TPM and side-channel vulnerabilities
- GPU acceleration vulnerabilities in PBKDF2 implementations

### Key Technical Concepts

- **KDF Downgrade**: Exploiting PBKDF2 weakness vs Argon2id strength
- **GRUB Compatibility Issue**: PBKDF2 requirement creates attack vector
- **Memory Remanence**: Cold boot attacks on DRAM data persistence
- **DMA Bypass**: Direct memory access circumventing IOMMU protections
- **Evil Maid**: Physical access boot chain compromise

## Results and Reporting

### Output Structure

```
results/
├── final_report.json           # Executive summary and findings
├── reconnaissance_results.json # Phase 1 outputs
├── vulnerability_analysis.json # Phase 2 outputs  
├── brute_force_attacks.json   # Phase 3 outputs
├── memory_attacks.json        # Phase 4 outputs
├── boot_attacks.json          # Phase 5 outputs
├── post_exploitation.json     # Phase 6 outputs
├── luks_analysis.json         # Detailed LUKS analysis
├── memory_dump.raw            # Memory extraction (if performed)
└── extracted_keys/            # Recovered cryptographic material
```

### Risk Assessment Levels

- **CRITICAL**: Multiple successful attacks, immediate remediation required
- **HIGH**: Significant vulnerabilities found, high priority fixes needed
- **MEDIUM**: Moderate risk, should be addressed in security roadmap
- **LOW**: Minor issues or hardened configuration detected

## Contributing and Development

### Adding New Attack Vectors

1. Create new tool in appropriate `tools/` subdirectory
2. Follow existing code structure and naming conventions
3. Add integration hooks to `luks_pentest_master.py`
4. Include comprehensive error handling and logging
5. Document attack methodology and prerequisites

### Testing and Validation

- Test all tools in isolated lab environment
- Validate against known LUKS configurations
- Ensure compatibility with different LUKS versions
- Performance test GPU acceleration components

## License and Disclaimer

This project is for authorized security research and penetration testing only. Users are responsible for ensuring compliance with applicable laws and obtaining proper authorization before using these tools. The authors assume no liability for misuse or damage caused by these tools.

**USE AT YOUR OWN RISK - FOR AUTHORIZED TESTING ONLY**
