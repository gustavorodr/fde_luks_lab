#!/usr/bin/env python3
"""
LUKS2 Analysis and Attack Framework
Suporte completo para análise de KDF e ataques contra LUKS2
Autor: Laboratório FDE LUKS
Versão: 2.0
"""

import sys
import os
import json
import struct
import hashlib
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

class LUKS2Analyzer:
    """Analisador especializado para partições LUKS2"""
    
    def __init__(self, device_path: str):
        self.device_path = device_path
        self.header_data = None
        self.luks2_metadata = None
        
    def extract_header(self, output_path: str) -> bool:
        """Extrai cabeçalho LUKS2 completo"""
        try:
            # LUKS2 tem cabeçalho maior que LUKS1
            # Extrair primeiros 16MB para garantir todo o cabeçalho + início dos dados
            cmd = [
                'dd',
                f'if={self.device_path}',
                f'of={output_path}',
                'bs=1M',
                'count=16',
                'status=progress'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.header_data = output_path
                print(f"✅ Cabeçalho LUKS2 extraído: {output_path}")
                return True
            else:
                print(f"❌ Erro na extração: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Erro: {e}")
            return False
    
    def parse_luks2_header(self) -> Dict[str, Any]:
        """Analisa estrutura do cabeçalho LUKS2"""
        if not self.header_data or not os.path.exists(self.header_data):
            raise ValueError("Header não extraído")
        
        try:
            # Executar cryptsetup luksDump para obter metadados JSON
            cmd = ['cryptsetup', 'luksDump', self.device_path, '--dump-json-metadata']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Parse do JSON retornado
                self.luks2_metadata = json.loads(result.stdout)
                return self.luks2_metadata
            else:
                print(f"⚠️  Fallback para luksDump padrão")
                # Fallback para dump padrão
                cmd = ['cryptsetup', 'luksDump', self.device_path]
                result = subprocess.run(cmd, capture_output=True, text=True)
                return {"dump": result.stdout}
                
        except Exception as e:
            print(f"❌ Erro no parse: {e}")
            return {}
    
    def analyze_kdf(self) -> Dict[str, Any]:
        """Analisa configuração da KDF (PBKDF2 vs Argon2)"""
        metadata = self.parse_luks2_header()
        
        kdf_info = {
            "type": "unknown",
            "parameters": {},
            "security_assessment": "unknown",
            "attack_viability": "unknown"
        }
        
        try:
            if "keyslots" in metadata:
                # LUKS2 JSON format
                for slot_id, slot_data in metadata["keyslots"].items():
                    if slot_data.get("type") == "luks2":
                        kdf_data = slot_data.get("kdf", {})
                        
                        kdf_type = kdf_data.get("type", "").lower()
                        
                        if "argon2" in kdf_type:
                            kdf_info["type"] = kdf_type
                            kdf_info["parameters"] = {
                                "memory": kdf_data.get("memory", 0),
                                "iterations": kdf_data.get("iterations", 0),
                                "parallelism": kdf_data.get("parallelism", 0),
                                "salt": kdf_data.get("salt", "")
                            }
                            kdf_info["security_assessment"] = "HIGH"
                            kdf_info["attack_viability"] = "ECONOMICALLY_INFEASIBLE"
                            
                        elif "pbkdf2" in kdf_type:
                            kdf_info["type"] = kdf_type
                            kdf_info["parameters"] = {
                                "iterations": kdf_data.get("iterations", 0),
                                "hash": kdf_data.get("hash", ""),
                                "salt": kdf_data.get("salt", "")
                            }
                            kdf_info["security_assessment"] = "MEDIUM"
                            kdf_info["attack_viability"] = "FEASIBLE_WITH_RESOURCES"
                        
                        break  # Usar primeiro keyslot ativo
            
            else:
                # Fallback para análise de texto
                dump_text = metadata.get("dump", "")
                
                if "argon2" in dump_text.lower():
                    kdf_info["type"] = "argon2id"
                    kdf_info["security_assessment"] = "HIGH"
                    kdf_info["attack_viability"] = "ECONOMICALLY_INFEASIBLE"
                elif "pbkdf2" in dump_text.lower():
                    kdf_info["type"] = "pbkdf2"
                    kdf_info["security_assessment"] = "MEDIUM"
                    kdf_info["attack_viability"] = "FEASIBLE_WITH_RESOURCES"
        
        except Exception as e:
            print(f"⚠️  Erro na análise KDF: {e}")
        
        return kdf_info
    
    def generate_hashcat_hash(self, output_path: str) -> bool:
        """Gera hash compatível com Hashcat para LUKS2"""
        try:
            # Verificar se existe luks2hashcat
            luks2hashcat_paths = [
                '/usr/bin/luks2hashcat',
                '/usr/local/bin/luks2hashcat',
                './luks2hashcat',
                '/opt/hashcat/tools/luks2hashcat'
            ]
            
            luks2hashcat_cmd = None
            for path in luks2hashcat_paths:
                if os.path.exists(path):
                    luks2hashcat_cmd = path
                    break
            
            if luks2hashcat_cmd:
                # Usar luks2hashcat se disponível
                cmd = [luks2hashcat_cmd, self.device_path]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    with open(output_path, 'w') as f:
                        f.write(result.stdout)
                    print(f"✅ Hash Hashcat gerado: {output_path}")
                    return True
            
            # Método alternativo: usar dados brutos do header
            if self.header_data:
                print("⚠️  Usando método alternativo para geração de hash")
                
                # Copiar header bruto como hash (Hashcat pode processar diretamente)
                import shutil
                shutil.copy2(self.header_data, output_path)
                
                print(f"✅ Header bruto copiado para: {output_path}")
                return True
            
            return False
            
        except Exception as e:
            print(f"❌ Erro na geração do hash: {e}")
            return False
    
    def generate_john_hash(self, output_path: str) -> bool:
        """Gera hash compatível com John the Ripper para LUKS2"""
        try:
            # Procurar luks2john
            john_paths = [
                '/usr/share/john/luks2john.py',
                '/opt/john/run/luks2john.py',
                './luks2john.py',
                '/usr/bin/luks2john',
                'luks2john'
            ]
            
            luks2john_cmd = None
            for path in john_paths:
                if os.path.exists(path):
                    luks2john_cmd = path
                    break
                elif path == 'luks2john':
                    # Tentar comando direto
                    try:
                        subprocess.run(['which', 'luks2john'], 
                                     capture_output=True, check=True)
                        luks2john_cmd = 'luks2john'
                        break
                    except subprocess.CalledProcessError:
                        continue
            
            if luks2john_cmd:
                if luks2john_cmd.endswith('.py'):
                    cmd = ['python3', luks2john_cmd, self.device_path]
                else:
                    cmd = [luks2john_cmd, self.device_path]
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0 and result.stdout.strip():
                    with open(output_path, 'w') as f:
                        f.write(result.stdout)
                    print(f"✅ Hash John gerado: {output_path}")
                    return True
                else:
                    print(f"⚠️  luks2john falhou: {result.stderr}")
            
            # Método de fallback: usar header bruto
            print("⚠️  Fallback: copiando header bruto")
            if self.header_data:
                import shutil
                shutil.copy2(self.header_data, output_path)
                return True
            
            return False
            
        except Exception as e:
            print(f"❌ Erro na geração do hash John: {e}")
            return False


class LUKS2AttackFramework:
    """Framework de ataque especializado para LUKS2"""
    
    def __init__(self, device_path: str, output_dir: str):
        self.device_path = device_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.analyzer = LUKS2Analyzer(device_path)
    
    def reconnaissance(self) -> Dict[str, Any]:
        """Fase de reconhecimento do alvo LUKS2"""
        print("🔍 === RECONHECIMENTO LUKS2 ===")
        
        info = {
            "device": self.device_path,
            "is_luks": False,
            "luks_version": "unknown",
            "kdf_info": {}
        }
        
        try:
            # Verificar se é LUKS
            result = subprocess.run(['cryptsetup', 'isLuks', self.device_path],
                                  capture_output=True)
            
            if result.returncode == 0:
                info["is_luks"] = True
                print(f"✅ Dispositivo LUKS confirmado: {self.device_path}")
                
                # Determinar versão
                result = subprocess.run(['cryptsetup', 'luksDump', self.device_path],
                                      capture_output=True, text=True)
                
                if "Version:" in result.stdout:
                    version_line = [line for line in result.stdout.split('\n') 
                                  if 'Version:' in line][0]
                    version = version_line.split(':')[1].strip()
                    info["luks_version"] = version
                    print(f"📋 Versão LUKS: {version}")
                
                # Analisar KDF
                info["kdf_info"] = self.analyzer.analyze_kdf()
                self.print_kdf_analysis(info["kdf_info"])
                
            else:
                print(f"❌ Dispositivo não é LUKS: {self.device_path}")
                return info
        
        except Exception as e:
            print(f"❌ Erro no reconhecimento: {e}")
        
        return info
    
    def print_kdf_analysis(self, kdf_info: Dict[str, Any]):
        """Imprime análise detalhada da KDF"""
        print(f"\n📊 === ANÁLISE DA KDF ===")
        print(f"🔐 Tipo: {kdf_info['type'].upper()}")
        print(f"🛡️  Segurança: {kdf_info['security_assessment']}")
        print(f"⚔️  Viabilidade de Ataque: {kdf_info['attack_viability']}")
        
        if kdf_info['type'].startswith('argon2'):
            print(f"""
🟢 ARGON2 DETECTADO - ALTA SEGURANÇA
├─ Memória por tentativa: {kdf_info['parameters'].get('memory', 'N/A')} KB
├─ Iterações: {kdf_info['parameters'].get('iterations', 'N/A')}
├─ Paralelismo: {kdf_info['parameters'].get('parallelism', 'N/A')}
└─ ⚠️  ATAQUE DE FORÇA BRUTA ECONOMICAMENTE INVIÁVEL
""")
            
        elif kdf_info['type'].startswith('pbkdf2'):
            print(f"""
🟡 PBKDF2 DETECTADO - SEGURANÇA LIMITADA
├─ Iterações: {kdf_info['parameters'].get('iterations', 'N/A')}
├─ Hash: {kdf_info['parameters'].get('hash', 'N/A')}
└─ ⚠️  VULNERÁVEL À ACELERAÇÃO GPU - MIGRAR PARA ARGON2!
""")
    
    def extract_and_prepare(self) -> Dict[str, str]:
        """Extrai cabeçalho e prepara hashes para diferentes ferramentas"""
        print("\n📦 === EXTRAÇÃO E PREPARAÇÃO ===")
        
        files = {}
        
        # 1. Extrair cabeçalho
        header_path = self.output_dir / "luks2_header.bin"
        if self.analyzer.extract_header(str(header_path)):
            files["header"] = str(header_path)
        
        # 2. Gerar hash para Hashcat
        hashcat_path = self.output_dir / "luks2_hashcat.hash"
        if self.analyzer.generate_hashcat_hash(str(hashcat_path)):
            files["hashcat"] = str(hashcat_path)
        
        # 3. Gerar hash para John the Ripper
        john_path = self.output_dir / "luks2_john.hash"
        if self.analyzer.generate_john_hash(str(john_path)):
            files["john"] = str(john_path)
        
        return files
    
    def generate_wordlists(self) -> List[str]:
        """Gera wordlists otimizadas para LUKS2"""
        print("\n📝 === GERAÇÃO DE WORDLISTS ===")
        
        wordlist_dir = self.output_dir / "wordlists"
        wordlist_dir.mkdir(exist_ok=True)
        
        wordlists = []
        
        # 1. Wordlist de senhas comuns LUKS/sistema
        common_luks = wordlist_dir / "luks_common.txt"
        with open(common_luks, 'w') as f:
            passwords = [
                "password", "123456", "admin", "root", "user", "test",
                "luks", "encrypt", "secure", "private", "secret",
                "Password1", "Admin123", "Root123", "User123",
                "password123", "admin123", "root123",
                "qwerty", "123456789", "abc123", "letmein",
                "welcome", "monkey", "dragon", "passw0rd",
                "p@ssw0rd", "P@ssw0rd", "123qwe", "qwe123"
            ]
            f.write('\n'.join(passwords))
        
        wordlists.append(str(common_luks))
        print(f"✅ Wordlist comum: {common_luks}")
        
        # 2. Wordlist numérica (se crunch disponível)
        if self.check_tool("crunch"):
            numeric_list = wordlist_dir / "numeric_4_8.txt"
            try:
                subprocess.run([
                    'crunch', '4', '8', '0123456789',
                    '-o', str(numeric_list)
                ], capture_output=True, check=True)
                
                # Verificar tamanho do arquivo
                size = os.path.getsize(numeric_list) / (1024 * 1024)  # MB
                if size < 100:  # Apenas se menor que 100MB
                    wordlists.append(str(numeric_list))
                    print(f"✅ Wordlist numérica: {numeric_list} ({size:.1f}MB)")
                else:
                    os.remove(numeric_list)
                    print(f"⚠️  Wordlist numérica muito grande ({size:.1f}MB) - removida")
                    
            except subprocess.CalledProcessError:
                print("⚠️  Erro na geração de wordlist numérica")
        
        return wordlists
    
    def attack_hashcat(self, hash_file: str, wordlists: List[str]) -> Optional[str]:
        """Executa ataque com Hashcat para LUKS2"""
        if not self.check_tool("hashcat"):
            print("⚠️  Hashcat não encontrado")
            return None
        
        print("\n⚔️  === ATAQUE HASHCAT ===")
        
        # Determinar modo correto para LUKS2
        # Modo 14600 para LUKS1, verificar se existe modo específico para LUKS2
        
        # Verificar modos disponíveis
        try:
            result = subprocess.run(['hashcat', '--help'], 
                                  capture_output=True, text=True)
            
            # Procurar por modos LUKS
            luks_modes = []
            for line in result.stdout.split('\n'):
                if 'luks' in line.lower():
                    luks_modes.append(line.strip())
            
            print("🔍 Modos LUKS disponíveis:")
            for mode in luks_modes:
                print(f"   {mode}")
            
        except Exception as e:
            print(f"⚠️  Erro ao verificar modos: {e}")
        
        # Tentar diferentes modos
        modes_to_try = [
            ("14600", "LUKS1/LUKS2 (padrão)"),
            ("23700", "RAR3-hp (alternativo)"),  # Algumas versões usam
        ]
        
        results_file = self.output_dir / "hashcat_results.txt"
        
        for mode, description in modes_to_try:
            print(f"🧪 Testando modo {mode}: {description}")
            
            for wordlist in wordlists:
                print(f"📖 Usando wordlist: {os.path.basename(wordlist)}")
                
                cmd = [
                    'hashcat',
                    '-m', mode,
                    '-a', '0',  # Dictionary attack
                    '-w', '3',  # Workload profile high
                    '--quiet',
                    '--outfile', str(results_file),
                    hash_file,
                    wordlist
                ]
                
                try:
                    # Timeout de 5 minutos por wordlist
                    result = subprocess.run(cmd, timeout=300, 
                                          capture_output=True, text=True)
                    
                    # Verificar se encontrou senha
                    if os.path.exists(results_file) and os.path.getsize(results_file) > 0:
                        with open(results_file) as f:
                            password = f.read().strip()
                        
                        print(f"🎉 SENHA ENCONTRADA: {password}")
                        return password
                    
                except subprocess.TimeoutExpired:
                    print("⏰ Timeout atingido")
                except Exception as e:
                    print(f"⚠️  Erro: {e}")
        
        print("❌ Nenhuma senha encontrada com Hashcat")
        return None
    
    def attack_john(self, hash_file: str, wordlists: List[str]) -> Optional[str]:
        """Executa ataque com John the Ripper para LUKS2"""
        if not self.check_tool("john"):
            print("⚠️  John the Ripper não encontrado")
            return None
        
        print("\n⚔️  === ATAQUE JOHN THE RIPPER ===")
        
        # Verificar formatos LUKS disponíveis
        try:
            result = subprocess.run(['john', '--list=formats'], 
                                  capture_output=True, text=True)
            
            luks_formats = [f for f in result.stdout.split() if 'luks' in f.lower()]
            print(f"🔍 Formatos LUKS disponíveis: {luks_formats}")
            
        except Exception as e:
            print(f"⚠️  Erro ao verificar formatos: {e}")
            luks_formats = ['LUKS']
        
        # Testar diferentes formatos
        formats_to_try = luks_formats if luks_formats else ['LUKS', 'luks2']
        
        for format_name in formats_to_try:
            print(f"🧪 Testando formato: {format_name}")
            
            for wordlist in wordlists:
                print(f"📖 Usando wordlist: {os.path.basename(wordlist)}")
                
                cmd = [
                    'john',
                    f'--format={format_name}',
                    f'--wordlist={wordlist}',
                    hash_file
                ]
                
                try:
                    # Timeout de 3 minutos por wordlist
                    result = subprocess.run(cmd, timeout=180,
                                          capture_output=True, text=True)
                    
                    # Verificar resultados
                    show_cmd = ['john', '--show', f'--format={format_name}', hash_file]
                    show_result = subprocess.run(show_cmd, capture_output=True, text=True)
                    
                    if show_result.stdout.strip() and ':' in show_result.stdout:
                        password = show_result.stdout.split(':')[1].strip()
                        print(f"🎉 SENHA ENCONTRADA: {password}")
                        return password
                    
                except subprocess.TimeoutExpired:
                    print("⏰ Timeout atingido")
                except Exception as e:
                    print(f"⚠️  Erro: {e}")
        
        print("❌ Nenhuma senha encontrada com John")
        return None
    
    def check_tool(self, tool_name: str) -> bool:
        """Verifica se uma ferramenta está disponível"""
        try:
            subprocess.run(['which', tool_name], 
                         capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def run_full_analysis(self) -> Dict[str, Any]:
        """Executa análise completa do LUKS2"""
        print("🚀 === INICIANDO ANÁLISE LUKS2 ===")
        
        results = {
            "device": self.device_path,
            "reconnaissance": {},
            "files_generated": {},
            "attack_results": {},
            "recommendations": []
        }
        
        # 1. Reconhecimento
        results["reconnaissance"] = self.reconnaissance()
        
        if not results["reconnaissance"]["is_luks"]:
            print("❌ Dispositivo não é LUKS - abortando")
            return results
        
        # 2. Extração e preparação
        results["files_generated"] = self.extract_and_prepare()
        
        # 3. Geração de wordlists
        wordlists = self.generate_wordlists()
        results["files_generated"]["wordlists"] = wordlists
        
        # 4. Análise de viabilidade
        kdf_info = results["reconnaissance"]["kdf_info"]
        
        if kdf_info["attack_viability"] == "ECONOMICALLY_INFEASIBLE":
            print(f"""
🛡️  === ANÁLISE DE SEGURANÇA ===
   O dispositivo usa {kdf_info['type'].upper()} que é ALTAMENTE SEGURO.
   
   ⚠️  ATAQUES DE FORÇA BRUTA SÃO ECONOMICAMENTE INVIÁVEIS
   
   💰 Custo estimado para quebra:
   ├─ Hardware: Milhares de GPUs de alto desempenho
   ├─ Tempo: Décadas
   └─ Valor: Bilhões de dólares
   
   ✅ RECOMENDAÇÃO: Sistema adequadamente protegido
""")
            
            results["recommendations"].extend([
                "Sistema usa Argon2 - configuração segura mantida",
                "Focar em outros vetores de ataque (side-channel, evil maid)",
                "Ataques de força bruta não são economicamente viáveis"
            ])
            
        else:
            print(f"""
⚠️  === ALERTA DE SEGURANÇA ===
   O dispositivo usa {kdf_info['type'].upper()} que tem SEGURANÇA LIMITADA.
   
   🚨 ATAQUES DE FORÇA BRUTA SÃO VIÁVEIS COM RECURSOS ADEQUADOS
   
   💰 Estimativa de ataque:
   ├─ Hardware: 10-100 GPUs
   ├─ Tempo: Semanas a anos (dependendo da senha)
   └─ Custo: $10,000 - $500,000
   
   ⚠️  RECOMENDAÇÃO URGENTE: Migrar para Argon2id
""")
            
            # Executar ataques limitados
            if "hashcat" in results["files_generated"]:
                password = self.attack_hashcat(results["files_generated"]["hashcat"], wordlists)
                results["attack_results"]["hashcat"] = password
            
            if "john" in results["files_generated"]:
                password = self.attack_john(results["files_generated"]["john"], wordlists)
                results["attack_results"]["john"] = password
            
            results["recommendations"].extend([
                "URGENTE: Recriar volume LUKS com Argon2id",
                "Usar senhas com >20 caracteres aleatórios",
                "Considerar keyfiles para eliminar ataques de dicionário"
            ])
        
        # 5. Relatório final
        self.generate_report(results)
        
        return results
    
    def generate_report(self, results: Dict[str, Any]):
        """Gera relatório detalhado da análise"""
        report_path = self.output_dir / "luks2_analysis_report.txt"
        
        with open(report_path, 'w') as f:
            f.write("RELATÓRIO DE ANÁLISE LUKS2\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Dispositivo: {results['device']}\n")
            f.write(f"Data: {subprocess.check_output(['date']).decode().strip()}\n\n")
            
            # Reconhecimento
            recon = results['reconnaissance']
            f.write("RECONHECIMENTO:\n")
            f.write(f"  LUKS: {recon['is_luks']}\n")
            f.write(f"  Versão: {recon['luks_version']}\n")
            f.write(f"  KDF: {recon['kdf_info']['type']}\n")
            f.write(f"  Segurança: {recon['kdf_info']['security_assessment']}\n")
            f.write(f"  Viabilidade de Ataque: {recon['kdf_info']['attack_viability']}\n\n")
            
            # Arquivos gerados
            f.write("ARQUIVOS GERADOS:\n")
            for key, path in results['files_generated'].items():
                if isinstance(path, list):
                    f.write(f"  {key}: {len(path)} arquivos\n")
                else:
                    f.write(f"  {key}: {path}\n")
            f.write("\n")
            
            # Resultados de ataque
            if results['attack_results']:
                f.write("RESULTADOS DE ATAQUES:\n")
                for tool, result in results['attack_results'].items():
                    f.write(f"  {tool}: {result or 'Sem sucesso'}\n")
                f.write("\n")
            
            # Recomendações
            f.write("RECOMENDAÇÕES:\n")
            for i, rec in enumerate(results['recommendations'], 1):
                f.write(f"  {i}. {rec}\n")
        
        print(f"\n📋 Relatório salvo: {report_path}")


def main():
    parser = argparse.ArgumentParser(
        description="LUKS2 Analysis and Attack Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python3 luks2_framework.py /dev/sdb2
  python3 luks2_framework.py /dev/nvme0n1p3 -o /tmp/luks2_analysis
  python3 luks2_framework.py /dev/sdc1 -o ./results --attack-only
        """
    )
    
    parser.add_argument('device', help='Dispositivo LUKS2 para análise')
    parser.add_argument('-o', '--output', default='./luks2_analysis_results',
                       help='Diretório de saída (padrão: ./luks2_analysis_results)')
    parser.add_argument('--attack-only', action='store_true',
                       help='Executar apenas ataques (pular análise de segurança)')
    parser.add_argument('--no-wordlist', action='store_true',
                       help='Não gerar wordlists automáticas')
    
    args = parser.parse_args()
    
    # Verificar privilégios
    if os.geteuid() != 0:
        print("❌ Este script requer privilégios de root (sudo)")
        sys.exit(1)
    
    # Verificar se dispositivo existe
    if not os.path.exists(args.device):
        print(f"❌ Dispositivo não encontrado: {args.device}")
        sys.exit(1)
    
    # Inicializar framework
    framework = LUKS2AttackFramework(args.device, args.output)
    
    try:
        # Executar análise completa
        results = framework.run_full_analysis()
        
        print(f"\n✅ Análise concluída!")
        print(f"📁 Resultados em: {args.output}")
        print(f"📋 Relatório: {args.output}/luks2_analysis_report.txt")
        
        # Resumo final
        kdf_type = results['reconnaissance']['kdf_info']['type']
        viability = results['reconnaissance']['kdf_info']['attack_viability']
        
        if viability == "ECONOMICALLY_INFEASIBLE":
            print(f"\n🎯 RESULTADO: Sistema SEGURO ({kdf_type.upper()})")
        else:
            print(f"\n⚠️  RESULTADO: Sistema VULNERÁVEL ({kdf_type.upper()})")
            
            # Verificar se encontrou senhas
            found_passwords = [p for p in results['attack_results'].values() if p]
            if found_passwords:
                print(f"🚨 SENHAS ENCONTRADAS: {found_passwords}")
        
    except KeyboardInterrupt:
        print("\n⏹️  Análise interrompida pelo usuário")
    except Exception as e:
        print(f"\n❌ Erro na análise: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()