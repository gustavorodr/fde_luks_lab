#!/usr/bin/env python3
"""
LUKS FDE Wordlist Generator
Creates specialized wordlists for Full Disk Encryption attacks

Author: Penetration Testing Lab
Target: Common patterns in LUKS passphrases and PINs
"""

import itertools
import string
import random
import argparse
from pathlib import Path
from typing import List, Iterator

class LUKSWordlistGenerator:
    """Generate wordlists optimized for LUKS FDE attacks"""
    
    def __init__(self):
        self.common_passwords = [
            "password", "123456", "qwerty", "abc123", "letmein",
            "welcome", "monkey", "1234567890", "admin", "root",
            "toor", "pass", "test", "guest", "user", "linux"
        ]
        
        self.date_patterns = [
            "%Y", "%y", "%m", "%d", "%Y%m%d", "%d%m%Y", "%m%d%Y"
        ]
        
        self.keyboard_patterns = [
            "qwerty", "asdf", "zxcv", "123456", "654321",
            "qwertyuiop", "asdfghjkl", "zxcvbnm"
        ]
    
    def generate_pin_wordlist(self, min_length: int = 4, max_length: int = 12,
                            output_file: str = "pins.txt") -> int:
        """Generate numeric PIN wordlist"""
        
        count = 0
        with open(output_file, 'w') as f:
            for length in range(min_length, max_length + 1):
                # Generate all numeric combinations
                for pin in itertools.product('0123456789', repeat=length):
                    pin_str = ''.join(pin)
                    
                    # Skip patterns like 0000, 1111, etc. (too obvious)
                    if len(set(pin_str)) == 1:
                        continue
                    
                    # Skip sequential patterns like 1234, 4321
                    if self._is_sequential(pin_str):
                        continue
                    
                    f.write(pin_str + '\n')
                    count += 1
        
        print(f"Generated {count} PINs in {output_file}")
        return count
    
    def generate_date_wordlist(self, start_year: int = 1950, end_year: int = 2030,
                              output_file: str = "dates.txt") -> int:
        """Generate date-based wordlist"""
        
        count = 0
        with open(output_file, 'w') as f:
            # Years
            for year in range(start_year, end_year + 1):
                f.write(f"{year}\n")
                f.write(f"{year % 100:02d}\n")  # Two-digit year
                count += 2
            
            # DDMMYYYY and variants
            for year in range(start_year, end_year + 1):
                for month in range(1, 13):
                    for day in range(1, 32):
                        if day > 28 and month == 2:  # Skip invalid February dates
                            continue
                        if day > 30 and month in [4, 6, 9, 11]:  # Skip invalid dates
                            continue
                        
                        # Various date formats
                        dates = [
                            f"{day:02d}{month:02d}{year}",      # DDMMYYYY
                            f"{day:02d}{month:02d}{year % 100:02d}",  # DDMMYY
                            f"{month:02d}{day:02d}{year}",      # MMDDYYYY
                            f"{month:02d}{day:02d}{year % 100:02d}",  # MMDDYY
                            f"{year}{month:02d}{day:02d}",      # YYYYMMDD
                            f"{year % 100:02d}{month:02d}{day:02d}",  # YYMMDD
                        ]
                        
                        for date_str in dates:
                            f.write(date_str + '\n')
                            count += 1
        
        print(f"Generated {count} date patterns in {output_file}")
        return count
    
    def generate_keyboard_patterns(self, output_file: str = "keyboard.txt") -> int:
        """Generate keyboard pattern wordlist"""
        
        count = 0
        patterns = []
        
        # QWERTY rows
        qwerty_rows = [
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm"
        ]
        
        # Generate patterns from keyboard rows
        for row in qwerty_rows:
            for length in range(3, len(row) + 1):
                for start in range(len(row) - length + 1):
                    pattern = row[start:start + length]
                    patterns.append(pattern)
                    patterns.append(pattern.upper())
                    patterns.append(pattern.capitalize())
                    
                    # Reverse patterns
                    patterns.append(pattern[::-1])
                    patterns.append(pattern[::-1].upper())
        
        # Number row patterns
        number_row = "1234567890"
        for length in range(3, len(number_row) + 1):
            for start in range(len(number_row) - length + 1):
                pattern = number_row[start:start + length]
                patterns.append(pattern)
                patterns.append(pattern[::-1])
        
        # Common shifts and walks
        shift_patterns = [
            "!@#$%^&*()",
            "QWERTYUIOP",
            "ASDFGHJKL",
            "ZXCVBNM"
        ]
        
        for pattern in shift_patterns:
            for length in range(3, len(pattern) + 1):
                for start in range(len(pattern) - length + 1):
                    subpattern = pattern[start:start + length]
                    patterns.append(subpattern)
        
        # Remove duplicates and write
        patterns = list(set(patterns))
        
        with open(output_file, 'w') as f:
            for pattern in sorted(patterns):
                f.write(pattern + '\n')
                count += 1
        
        print(f"Generated {count} keyboard patterns in {output_file}")
        return count
    
    def generate_common_passwords(self, output_file: str = "common.txt") -> int:
        """Generate common password variations"""
        
        count = 0
        passwords = set()
        
        # Base common passwords
        for password in self.common_passwords:
            passwords.add(password)
            passwords.add(password.upper())
            passwords.add(password.capitalize())
            
            # Add numbers
            for i in range(10):
                passwords.add(f"{password}{i}")
                passwords.add(f"{i}{password}")
                passwords.add(f"{password}{i}{i}")
            
            # Add years
            for year in [2020, 2021, 2022, 2023, 2024, 2025]:
                passwords.add(f"{password}{year}")
                passwords.add(f"{year}{password}")
            
            # Add common symbols
            for symbol in ['!', '@', '#', '$', '123']:
                passwords.add(f"{password}{symbol}")
                passwords.add(f"{symbol}{password}")
        
        # L33t speak variations
        leet_map = {
            'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'
        }
        
        for password in list(passwords):
            if len(password) < 20:  # Avoid overly long passwords
                leet_version = password.lower()
                for char, replacement in leet_map.items():
                    leet_version = leet_version.replace(char, replacement)
                if leet_version != password.lower():
                    passwords.add(leet_version)
        
        with open(output_file, 'w') as f:
            for password in sorted(passwords):
                f.write(password + '\n')
                count += 1
        
        print(f"Generated {count} common passwords in {output_file}")
        return count
    
    def generate_luks_specific_wordlist(self, output_file: str = "luks_specific.txt") -> int:
        """Generate LUKS and cryptography specific wordlist"""
        
        count = 0
        passwords = set()
        
        # Crypto-related terms
        crypto_terms = [
            "luks", "crypt", "encrypt", "decrypt", "secure", "cipher",
            "aes", "sha", "key", "crypto", "hash", "disk", "volume",
            "master", "secret", "hidden", "private", "protect", "lock",
            "unlock", "passphrase", "keyfile", "argon2", "pbkdf2"
        ]
        
        # Generate combinations
        for term in crypto_terms:
            passwords.add(term)
            passwords.add(term.upper())
            passwords.add(term.capitalize())
            
            # Add numbers
            for i in range(10):
                passwords.add(f"{term}{i}")
                passwords.add(f"{i}{term}")
            
            # Combine terms
            for other_term in crypto_terms[:5]:  # Limit combinations
                if term != other_term:
                    passwords.add(f"{term}{other_term}")
                    passwords.add(f"{term}_{other_term}")
                    passwords.add(f"{term}-{other_term}")
        
        # Add Brazilian/Portuguese terms (for TSE context)
        portuguese_terms = [
            "senha", "chave", "seguro", "privado", "proteger", "bloquear",
            "desbloquear", "criptografia", "cifra", "urna", "eletronica",
            "tse", "brasil", "eleicao", "voto", "seguranca", "sistema"
        ]
        
        for term in portuguese_terms:
            passwords.add(term)
            passwords.add(term.upper())
            passwords.add(term.capitalize())
            
            for i in range(10):
                passwords.add(f"{term}{i}")
                passwords.add(f"{i}{term}")
        
        with open(output_file, 'w') as f:
            for password in sorted(passwords):
                f.write(password + '\n')
                count += 1
        
        print(f"Generated {count} LUKS-specific passwords in {output_file}")
        return count
    
    def generate_hybrid_wordlist(self, base_wordlist: str, 
                                output_file: str = "hybrid.txt") -> int:
        """Generate hybrid wordlist by combining base words with patterns"""
        
        if not Path(base_wordlist).exists():
            print(f"Base wordlist not found: {base_wordlist}")
            return 0
        
        count = 0
        with open(base_wordlist, 'r') as infile, open(output_file, 'w') as outfile:
            base_words = [line.strip() for line in infile if line.strip()]
        
        patterns = []
        for word in base_words[:100]:  # Limit to first 100 to avoid explosion
            # Add numbers
            for i in range(100):
                patterns.append(f"{word}{i}")
                patterns.append(f"{i}{word}")
            
            # Add years
            for year in range(1980, 2030):
                patterns.append(f"{word}{year}")
                patterns.append(f"{year}{word}")
            
            # Add symbols
            for symbol in ['!', '@', '#', '$', '%', '^', '&', '*']:
                patterns.append(f"{word}{symbol}")
                patterns.append(f"{symbol}{word}")
            
            # Add common suffixes
            for suffix in ['123', '456', '789', 'abc', 'xyz']:
                patterns.append(f"{word}{suffix}")
        
        # Remove duplicates and write
        patterns = list(set(patterns))
        
        with open(output_file, 'w') as f:
            for pattern in sorted(patterns):
                f.write(pattern + '\n')
                count += 1
        
        print(f"Generated {count} hybrid passwords in {output_file}")
        return count
    
    def _is_sequential(self, pin: str) -> bool:
        """Check if PIN is sequential (ascending or descending)"""
        if len(pin) < 3:
            return False
        
        # Check ascending
        ascending = all(int(pin[i]) == int(pin[i-1]) + 1 for i in range(1, len(pin)))
        
        # Check descending
        descending = all(int(pin[i]) == int(pin[i-1]) - 1 for i in range(1, len(pin)))
        
        return ascending or descending
    
    def merge_wordlists(self, wordlist_files: List[str], 
                       output_file: str = "merged.txt") -> int:
        """Merge multiple wordlists and remove duplicates"""
        
        all_passwords = set()
        
        for wordlist_file in wordlist_files:
            if Path(wordlist_file).exists():
                with open(wordlist_file, 'r') as f:
                    for line in f:
                        password = line.strip()
                        if password:
                            all_passwords.add(password)
            else:
                print(f"Warning: {wordlist_file} not found")
        
        count = 0
        with open(output_file, 'w') as f:
            for password in sorted(all_passwords):
                f.write(password + '\n')
                count += 1
        
        print(f"Merged {len(wordlist_files)} wordlists into {output_file} ({count} unique passwords)")
        return count


def main():
    parser = argparse.ArgumentParser(description='LUKS FDE Wordlist Generator')
    parser.add_argument('action', choices=['pins', 'dates', 'keyboard', 'common', 
                       'luks', 'hybrid', 'merge', 'all'])
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('--min-length', type=int, default=4, help='Minimum PIN length')
    parser.add_argument('--max-length', type=int, default=12, help='Maximum PIN length')
    parser.add_argument('--start-year', type=int, default=1950, help='Start year for dates')
    parser.add_argument('--end-year', type=int, default=2030, help='End year for dates')
    parser.add_argument('--base-wordlist', help='Base wordlist for hybrid generation')
    parser.add_argument('--merge-files', nargs='+', help='Files to merge')
    
    args = parser.parse_args()
    
    generator = LUKSWordlistGenerator()
    
    if args.action == 'pins':
        output = args.output or 'pins.txt'
        generator.generate_pin_wordlist(args.min_length, args.max_length, output)
    
    elif args.action == 'dates':
        output = args.output or 'dates.txt'
        generator.generate_date_wordlist(args.start_year, args.end_year, output)
    
    elif args.action == 'keyboard':
        output = args.output or 'keyboard.txt'
        generator.generate_keyboard_patterns(output)
    
    elif args.action == 'common':
        output = args.output or 'common.txt'
        generator.generate_common_passwords(output)
    
    elif args.action == 'luks':
        output = args.output or 'luks_specific.txt'
        generator.generate_luks_specific_wordlist(output)
    
    elif args.action == 'hybrid':
        if not args.base_wordlist:
            print("Base wordlist required for hybrid generation")
            return
        output = args.output or 'hybrid.txt'
        generator.generate_hybrid_wordlist(args.base_wordlist, output)
    
    elif args.action == 'merge':
        if not args.merge_files:
            print("Files to merge required")
            return
        output = args.output or 'merged.txt'
        generator.merge_wordlists(args.merge_files, output)
    
    elif args.action == 'all':
        print("Generating all wordlist types...")
        
        generator.generate_pin_wordlist(4, 8, 'pins.txt')  # Smaller PIN range
        generator.generate_date_wordlist(1980, 2030, 'dates.txt')  # Focused date range
        generator.generate_keyboard_patterns('keyboard.txt')
        generator.generate_common_passwords('common.txt')
        generator.generate_luks_specific_wordlist('luks_specific.txt')
        
        # Merge all into master wordlist
        wordlists = ['pins.txt', 'dates.txt', 'keyboard.txt', 'common.txt', 'luks_specific.txt']
        generator.merge_wordlists(wordlists, 'master_wordlist.txt')
        
        print("All wordlists generated!")


if __name__ == "__main__":
    main()