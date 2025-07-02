#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ネットワーク偵察モジュール
ポートスキャン、サービス検出、OS検出機能
"""

import socket
import threading
import nmap
import time
import paramiko
import ftplib
from concurrent.futures import ThreadPoolExecutor, as_completed

class NetworkScanner:
    """ネットワーク偵察クラス"""
    
    def __init__(self, target, timeout=1):
        self.target = target
        self.timeout = timeout
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443, 9000, 9090, 10000
        ]
        self.results = {
            'target': target,
            'ip': None,
            'open_ports': [],
            'services': {},
            'os_info': {},
            'scan_time': None,
            'auth_tests': {}
        }
        
        # よくあるユーザー名とパスワード
        self.common_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('root', 'root'),
            ('root', 'password'),
            ('root', '123456'),
            ('user', 'user'),
            ('user', 'password'),
            ('guest', 'guest'),
            ('test', 'test'),
            ('anonymous', ''),
            ('ftp', 'ftp'),
            ('anonymous', 'anonymous@example.com'),
            ('admin', 'admin123'),
            ('administrator', 'password'),
            ('pi', 'raspberry'),
            ('ubuntu', 'ubuntu'),
            ('centos', 'centos'),
            ('debian', 'debian'),
            ('vagrant', 'vagrant')
        ]
    
    def resolve_ip(self):
        """IPアドレスを解決"""
        try:
            # まず、ターゲットがIPアドレスかどうかをチェック
            if self.is_valid_ip(self.target):
                self.results['ip'] = self.target
                return self.target
            
            # ドメイン名の場合、IPアドレスを解決
            ip = socket.gethostbyname(self.target)
            self.results['ip'] = ip
            return ip
        except socket.gaierror as e:
            error_msg = f"IPアドレスの解決に失敗: {self.target}"
            print(f"⚠️  {error_msg}")
            print(f"   詳細: {str(e)}")
            print("💡 解決方法:")
            print("   - インターネット接続を確認してください")
            print("   - ドメイン名が正しく入力されているか確認してください")
            print("   - DNSサーバーの設定を確認してください")
            raise Exception(error_msg)
        except Exception as e:
            error_msg = f"予期しないエラー: {str(e)}"
            print(f"⚠️  {error_msg}")
            raise Exception(error_msg)
    
    def is_valid_ip(self, ip):
        """IPアドレスが有効かどうかをチェック"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except:
            return False
    
    def test_ssh_auth(self, ip, port=22):
        """SSH認証テスト"""
        print(f"🔐 SSH認証テストを開始: {ip}:{port}")
        
        # paramikoのログレベルを設定（詳細ログを抑制）
        import logging
        logging.getLogger("paramiko").setLevel(logging.WARNING)
        
        ssh_results = {
            'anonymous_login': False,
            'successful_logins': [],
            'failed_attempts': 0,
            'connection_errors': 0
        }
        
        def try_ssh_connection(username, password, connection_type="normal"):
            """SSH接続を試行するヘルパー関数"""
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # 接続設定を調整
                ssh.connect(
                    ip, 
                    port=port, 
                    username=username, 
                    password=password, 
                    timeout=10,  # タイムアウトを延長
                    banner_timeout=60,  # バナータイムアウトを設定
                    auth_timeout=10,  # 認証タイムアウトを設定
                    look_for_keys=False,  # キーベース認証を無効化
                    allow_agent=False  # エージェント認証を無効化
                )
                ssh.close()
                return True
            except paramiko.ssh_exception.SSHException as e:
                if "Error reading SSH protocol banner" in str(e):
                    ssh_results['connection_errors'] += 1
                    print(f"⚠️  SSH接続エラー ({connection_type}): プロトコルバナーの読み取りに失敗")
                return False
            except paramiko.ssh_exception.AuthenticationException:
                # 認証失敗は正常な動作
                return False
            except Exception as e:
                ssh_results['connection_errors'] += 1
                print(f"⚠️  SSH接続エラー ({connection_type}): {str(e)}")
                return False
        
        # 匿名ログイン試行
        if try_ssh_connection('anonymous', '', "anonymous"):
            ssh_results['anonymous_login'] = True
            print(f"✅ SSH匿名ログイン成功: {ip}:{port}")
        
        # ワードリストログイン試行
        for username, password in self.common_credentials:
            if try_ssh_connection(username, password, f"{username}:{password}"):
                ssh_results['successful_logins'].append({
                    'username': username,
                    'password': password,
                    'type': 'SSH'
                })
                print(f"✅ SSHログイン成功: {username}:{password} @ {ip}:{port}")
            else:
                ssh_results['failed_attempts'] += 1
        
        return ssh_results
    
    def test_ftp_auth(self, ip, port=21):
        """FTP認証テスト"""
        print(f"📁 FTP認証テストを開始: {ip}:{port}")
        ftp_results = {
            'anonymous_login': False,
            'successful_logins': [],
            'failed_attempts': 0,
            'ftp_contents': {}
        }
        
        def explore_ftp_contents(ftp, login_type):
            """FTPサーバーの内容を探索"""
            try:
                # FTP接続のタイムアウト設定を調整
                ftp.sock.settimeout(30)  # 30秒に延長
                
                # 現在のディレクトリのファイル一覧を取得
                files = []
                directories = []
                
                print(f"   📋 ファイル一覧を取得中...")
                
                # タイムアウト付きでファイル一覧を取得
                try:
                    ftp.retrlines('LIST', lambda x: files.append(x), timeout=30)
                except Exception as list_error:
                    print(f"   ⚠️  ファイル一覧取得エラー: {str(list_error)}")
                    # 部分的な情報でも表示
                    return {
                        'files': [],
                        'directories': [],
                        'total_files': 0,
                        'total_directories': 0,
                        'error': f"ファイル一覧取得に失敗: {str(list_error)}"
                    }
                
                print(f"   ✅ {len(files)}個のエントリを取得")
                
                # ファイル情報を解析
                parsed_files = []
                parsed_directories = []
                
                for file_info in files:
                    try:
                        parts = file_info.split()
                        if len(parts) >= 9:
                            permissions = parts[0]
                            size = parts[4]
                            date = ' '.join(parts[5:8])
                            name = ' '.join(parts[8:])
                            
                            if permissions.startswith('d'):
                                parsed_directories.append({
                                    'name': name,
                                    'type': 'directory',
                                    'permissions': permissions,
                                    'size': size,
                                    'date': date
                                })
                            else:
                                parsed_files.append({
                                    'name': name,
                                    'type': 'file',
                                    'permissions': permissions,
                                    'size': size,
                                    'date': date
                                })
                    except Exception as parse_error:
                        print(f"   ⚠️  ファイル情報解析エラー: {str(parse_error)}")
                        continue
                
                return {
                    'files': parsed_files,
                    'directories': parsed_directories,
                    'total_files': len(parsed_files),
                    'total_directories': len(parsed_directories)
                }
                
            except Exception as e:
                print(f"⚠️  FTP内容探索エラー: {str(e)}")
                return {
                    'files': [],
                    'directories': [],
                    'total_files': 0,
                    'total_directories': 0,
                    'error': str(e)
                }
        
        # 匿名ログイン試行
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=5)
            ftp.login('anonymous', 'anonymous@example.com')
            ftp_results['anonymous_login'] = True
            print(f"✅ FTP匿名ログイン成功: {ip}:{port}")
            
            # FTP内容を探索
            print("🔍 FTPサーバーの内容を探索中...")
            contents = explore_ftp_contents(ftp, "anonymous")
            if contents:
                ftp_results['ftp_contents']['anonymous'] = contents
                self.display_ftp_contents(contents, "匿名ログイン")
            
            ftp.quit()
        except:
            pass
        
        # 空パスワードで匿名ログイン試行
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=5)
            ftp.login('anonymous', '')
            ftp_results['anonymous_login'] = True
            print(f"✅ FTP匿名ログイン成功（空パスワード）: {ip}:{port}")
            
            # FTP内容を探索
            print("🔍 FTPサーバーの内容を探索中...")
            contents = explore_ftp_contents(ftp, "anonymous_empty")
            if contents:
                ftp_results['ftp_contents']['anonymous_empty'] = contents
                self.display_ftp_contents(contents, "匿名ログイン（空パスワード）")
            
            ftp.quit()
        except:
            pass
        
        # ワードリストログイン試行
        for username, password in self.common_credentials:
            try:
                ftp = ftplib.FTP()
                ftp.connect(ip, port, timeout=5)
                ftp.login(username, password)
                ftp_results['successful_logins'].append({
                    'username': username,
                    'password': password,
                    'type': 'FTP'
                })
                print(f"✅ FTPログイン成功: {username}:{password} @ {ip}:{port}")
                
                # FTP内容を探索
                print(f"🔍 FTPサーバーの内容を探索中... ({username})")
                contents = explore_ftp_contents(ftp, f"{username}:{password}")
                if contents:
                    ftp_results['ftp_contents'][f"{username}:{password}"] = contents
                    self.display_ftp_contents(contents, f"{username}:{password}")
                
                ftp.quit()
            except:
                ftp_results['failed_attempts'] += 1
        
        return ftp_results
    
    def display_ftp_contents(self, contents, login_type):
        """FTP内容を表示"""
        print(f"\n📁 FTPサーバー内容 ({login_type}):")
        
        # エラーがある場合は表示
        if 'error' in contents:
            print(f"   ❌ エラー: {contents['error']}")
            print(f"   💡 対処法:")
            print(f"      - ネットワーク接続を確認してください")
            print(f"      - FTPサーバーの状態を確認してください")
            print(f"      - ファイアウォールの設定を確認してください")
            print("-" * 50)
            return
        
        print(f"   📊 総ファイル数: {contents['total_files']}")
        print(f"   📁 総ディレクトリ数: {contents['total_directories']}")
        
        if contents['total_files'] == 0 and contents['total_directories'] == 0:
            print(f"   ℹ️  ファイルやディレクトリが見つかりませんでした")
            print(f"   💡 可能性:")
            print(f"      - 空のディレクトリ")
            print(f"      - アクセス権限の制限")
            print(f"      - サーバーの設定")
        
        if contents['directories']:
            print(f"\n📁 ディレクトリ一覧:")
            for directory in contents['directories']:
                print(f"   📁 {directory['name']}")
                print(f"      🔐 権限: {directory['permissions']}")
                print(f"      📅 日付: {directory['date']}")
        
        if contents['files']:
            print(f"\n📄 ファイル一覧:")
            for file in contents['files']:
                # ファイルサイズを読みやすい形式に変換
                size = int(file['size']) if file['size'].isdigit() else 0
                if size < 1024:
                    size_str = f"{size} B"
                elif size < 1024 * 1024:
                    size_str = f"{size // 1024} KB"
                else:
                    size_str = f"{size // (1024 * 1024)} MB"
                
                print(f"   📄 {file['name']}")
                print(f"      📏 サイズ: {size_str}")
                print(f"      🔐 権限: {file['permissions']}")
                print(f"      📅 日付: {file['date']}")
                
                # 重要なファイルの検出
                important_files = [
                    'config', 'conf', 'ini', 'cfg', 'xml', 'json', 'yaml', 'yml',
                    'log', 'txt', 'md', 'readme', 'license', 'backup', 'bak',
                    'sql', 'db', 'database', 'password', 'passwd', 'shadow',
                    'ssh', 'key', 'cert', 'pem', 'crt', 'p12', 'pfx',
                    'env', 'environment', 'secret', 'private', 'admin'
                ]
                
                file_lower = file['name'].lower()
                if any(keyword in file_lower for keyword in important_files):
                    print(f"      ⚠️  重要ファイルの可能性")
        
        print("-" * 50)
    
    def run_ftp_auth_test(self, ip):
        """FTP認証テストのみ実行"""
        ftp_results = self.test_ftp_auth(ip, 21)
        self.results['auth_tests'] = {'ftp': ftp_results}
        return ftp_results
    
    def port_scan(self, ip=None, ports=None):
        """ポートスキャンを実行"""
        if ip is None:
            ip = self.resolve_ip()
        
        if ports is None:
            ports = self.common_ports
        
        open_ports = []
        start_time = time.time()
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        # マルチスレッドでポートスキャン
        with ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                port = future.result()
                if port:
                    open_ports.append(port)
        
        self.results['open_ports'] = open_ports
        self.results['scan_time'] = time.time() - start_time
        return open_ports
    
    def service_detection(self, ip=None, ports=None):
        """サービス検出"""
        if ip is None:
            ip = self.resolve_ip()
        
        if ports is None:
            ports = self.results['open_ports']
        
        services = {}
        
        for port in ports:
            try:
                service_name = socket.getservbyport(port)
                services[port] = service_name
            except:
                services[port] = "unknown"
        
        self.results['services'] = services
        return services
    
    def os_detection(self, ip=None):
        """OS検出"""
        if ip is None:
            ip = self.resolve_ip()
        
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, arguments='-O --osscan-guess')
            
            if ip in nm.all_hosts():
                os_info = nm[ip].get('osmatch', [])
                if os_info:
                    self.results['os_info'] = os_info[0]
                    return os_info[0]
            
            self.results['os_info'] = "Unknown"
            return "Unknown"
        except Exception as e:
            self.results['os_info'] = f"Error: {str(e)}"
            return "Unknown"
    
    def ping_sweep(self, network):
        """Pingスイープ（ネットワーク範囲スキャン）"""
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=network, arguments='-sn')
            
            live_hosts = []
            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    live_hosts.append(host)
            
            return live_hosts
        except Exception as e:
            print(f"Pingスイープエラー: {str(e)}")
            return []
    
    def get_scan_results(self):
        """スキャン結果を取得"""
        return self.results
    
    def run_full_network_scan(self):
        """完全なネットワークスキャンを実行"""
        print(f"🔍 ネットワークスキャンを開始しています...")
        
        # IP解決
        print("📍 IPアドレスを解決中...")
        ip = self.resolve_ip()
        print(f"✅ IPアドレス: {ip}")
        
        # ポートスキャン
        print("🚪 ポートスキャンを実行中...")
        open_ports = self.port_scan(ip)
        if open_ports:
            print(f"✅ 開いているポート: {len(open_ports)}個")
            for port in open_ports:
                print(f"   - ポート {port}")
        else:
            print("ℹ️  開いているポートは見つかりませんでした")
        
        # サービス検出
        if open_ports:
            print("🔧 サービス検出を実行中...")
            services = self.service_detection(ip, open_ports)
            print(f"✅ 検出されたサービス: {len(services)}個")
            for port, service in services.items():
                print(f"   - ポート {port}: {service}")
        
        # FTP認証テストのみ実行（SSH認証テストは除外）
        if open_ports and 21 in open_ports:
            print("📁 FTP認証テストを実行中...")
            auth_results = self.run_ftp_auth_test(ip)
            
            # FTP認証テスト結果の表示
            if auth_results['anonymous_login']:
                print(f"⚠️  FTP匿名ログインが可能です")
            if auth_results['successful_logins']:
                print(f"⚠️  FTPで{len(auth_results['successful_logins'])}個の認証情報が有効です")
                for login in auth_results['successful_logins']:
                    print(f"   - {login['username']}:{login['password']}")
        
        # OS検出
        print("💻 OS検出を実行中...")
        os_info = self.os_detection(ip)
        print(f"✅ OS情報: {os_info}")
        
        print("🎉 ネットワークスキャンが完了しました！")
        return self.results 