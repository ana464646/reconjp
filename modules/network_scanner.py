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
            'scan_time': None
        }
    
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
        
        # OS検出
        print("💻 OS検出を実行中...")
        os_info = self.os_detection(ip)
        print(f"✅ OS情報: {os_info}")
        
        print("🎉 ネットワークスキャンが完了しました！")
        return self.results 