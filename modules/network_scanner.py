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
            'failed_attempts': 0
        }
        
        # 匿名ログイン試行
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=5)
            ftp.login('anonymous', 'anonymous@example.com')
            ftp_results['anonymous_login'] = True
            print(f"✅ FTP匿名ログイン成功: {ip}:{port}")
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
                ftp.quit()
            except:
                ftp_results['failed_attempts'] += 1
        
        return ftp_results
    
    def run_auth_tests(self, ip, open_ports):
        """認証テストを実行"""
        auth_results = {}
        
        # SSHポート（22）が開いている場合
        if 22 in open_ports:
            print("🔐 SSH認証テストを実行中...")
            auth_results['ssh'] = self.test_ssh_auth(ip, 22)
        
        # FTPポート（21）が開いている場合
        if 21 in open_ports:
            print("📁 FTP認証テストを実行中...")
            auth_results['ftp'] = self.test_ftp_auth(ip, 21)
        
        # SFTPポート（2222）が開いている場合
        if 2222 in open_ports:
            print("🔐 SFTP認証テストを実行中...")
            auth_results['sftp'] = self.test_ssh_auth(ip, 2222)
        
        self.results['auth_tests'] = auth_results
        return auth_results
    
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
        
        # 認証テスト（SSH/FTPポートが開いている場合）
        if open_ports and (21 in open_ports or 22 in open_ports or 2222 in open_ports):
            print("🔐 認証テストを実行中...")
            auth_results = self.run_auth_tests(ip, open_ports)
            
            # 認証テスト結果の表示
            for service, results in auth_results.items():
                if results['anonymous_login']:
                    print(f"⚠️  {service.upper()}匿名ログインが可能です")
                if results['successful_logins']:
                    print(f"⚠️  {service.upper()}で{len(results['successful_logins'])}個の認証情報が有効です")
                    for login in results['successful_logins']:
                        print(f"   - {login['username']}:{login['password']}")
        
        # OS検出
        print("💻 OS検出を実行中...")
        os_info = self.os_detection(ip)
        print(f"✅ OS情報: {os_info}")
        
        print("🎉 ネットワークスキャンが完了しました！")
        return self.results 