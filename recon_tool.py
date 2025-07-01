#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ReconJP - ペネトレーションテスト用偵察ツール
Windows/Mac対応の包括的なネットワーク・Webアプリケーション偵察ツール
"""

import os
import sys
import time
import socket
import threading
import subprocess
import requests
import dns.resolver
import nmap
from datetime import datetime
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# カラー出力用
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORS_ENABLED = True
except ImportError:
    COLORS_ENABLED = False
    Fore = Back = Style = type('Colors', (), {'__getattr__': lambda x, y: ''})()

# Rich コンソール出力
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.text import Text
    console = Console()
    RICH_ENABLED = True
except ImportError:
    RICH_ENABLED = False

class ReconTool:
    """ペネトレーションテスト用偵察ツールのメインクラス"""
    
    def __init__(self, target, output_dir="recon_results"):
        self.target = target
        self.output_dir = output_dir
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'network_scan': {},
            'dns_info': {},
            'web_recon': {},
            'osint': {},
            'vulnerabilities': []
        }
        
        # 出力ディレクトリの作成
        os.makedirs(output_dir, exist_ok=True)
        
        # ユーザーエージェント
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # ポートスキャン設定
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        
        self.print_banner()
    
    def print_banner(self):
        """ツールのバナーを表示"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    ReconJP - 偵察ツール                      ║
║             ペネトレーションテスト用ネットワーク偵察          ║
║                    Windows/Mac対応                           ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(Fore.CYAN + banner)
        print(Fore.YELLOW + f"ターゲット: {self.target}")
        print(Fore.YELLOW + f"出力ディレクトリ: {self.output_dir}")
        print("-" * 60)
    
    def log(self, message, level="INFO"):
        """ログメッセージを出力"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        color_map = {
            "INFO": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "SUCCESS": Fore.CYAN
        }
        color = color_map.get(level, Fore.WHITE)
        print(f"{color}[{timestamp}] {level}: {message}")
    
    def network_scan(self):
        """ネットワーク偵察を実行"""
        self.log("ネットワーク偵察を開始...", "INFO")
        
        try:
            # IPアドレスの解決
            try:
                ip = socket.gethostbyname(self.target)
                self.results['network_scan']['ip'] = ip
                self.log(f"IPアドレス: {ip}", "SUCCESS")
            except socket.gaierror:
                self.log(f"IPアドレスの解決に失敗: {self.target}", "ERROR")
                return
            
            # ポートスキャン
            self.log("ポートスキャンを実行中...", "INFO")
            open_ports = self.port_scan(ip)
            self.results['network_scan']['open_ports'] = open_ports
            
            # サービス検出
            if open_ports:
                self.log("サービス検出を実行中...", "INFO")
                services = self.service_detection(ip, open_ports)
                self.results['network_scan']['services'] = services
            
            # OS検出
            self.log("OS検出を実行中...", "INFO")
            os_info = self.os_detection(ip)
            self.results['network_scan']['os_info'] = os_info
            
        except Exception as e:
            self.log(f"ネットワーク偵察でエラー: {str(e)}", "ERROR")
    
    def port_scan(self, ip, timeout=1):
        """ポートスキャンを実行"""
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        # マルチスレッドでポートスキャン
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in self.common_ports}
            
            for future in as_completed(future_to_port):
                port = future.result()
                if port:
                    open_ports.append(port)
                    self.log(f"ポート {port} が開いています", "SUCCESS")
        
        return open_ports
    
    def service_detection(self, ip, ports):
        """サービス検出"""
        services = {}
        
        for port in ports:
            try:
                service_name = socket.getservbyport(port)
                services[port] = service_name
                self.log(f"ポート {port}: {service_name}", "INFO")
            except:
                services[port] = "unknown"
        
        return services
    
    def os_detection(self, ip):
        """OS検出（簡易版）"""
        try:
            # TCP/IPスタックフィンガープリント
            nm = nmap.PortScanner()
            nm.scan(ip, arguments='-O --osscan-guess')
            
            if ip in nm.all_hosts():
                os_info = nm[ip].get('osmatch', [])
                if os_info:
                    return os_info[0]
            
            return "Unknown"
        except:
            return "Unknown"
    
    def dns_reconnaissance(self):
        """DNS偵察を実行"""
        self.log("DNS偵察を開始...", "INFO")
        
        try:
            dns_info = {}
            
            # Aレコード
            try:
                answers = dns.resolver.resolve(self.target, 'A')
                dns_info['a_records'] = [str(rdata) for rdata in answers]
                self.log(f"Aレコード: {dns_info['a_records']}", "SUCCESS")
            except:
                dns_info['a_records'] = []
            
            # MXレコード
            try:
                answers = dns.resolver.resolve(self.target, 'MX')
                dns_info['mx_records'] = [str(rdata.exchange) for rdata in answers]
                self.log(f"MXレコード: {dns_info['mx_records']}", "SUCCESS")
            except:
                dns_info['mx_records'] = []
            
            # NSレコード
            try:
                answers = dns.resolver.resolve(self.target, 'NS')
                dns_info['ns_records'] = [str(rdata) for rdata in answers]
                self.log(f"NSレコード: {dns_info['ns_records']}", "SUCCESS")
            except:
                dns_info['ns_records'] = []
            
            # TXTレコード
            try:
                answers = dns.resolver.resolve(self.target, 'TXT')
                dns_info['txt_records'] = [str(rdata) for rdata in answers]
                self.log(f"TXTレコード: {dns_info['txt_records']}", "SUCCESS")
            except:
                dns_info['txt_records'] = []
            
            # CNAMEレコード
            try:
                answers = dns.resolver.resolve(self.target, 'CNAME')
                dns_info['cname_records'] = [str(rdata) for rdata in answers]
                self.log(f"CNAMEレコード: {dns_info['cname_records']}", "SUCCESS")
            except:
                dns_info['cname_records'] = []
            
            self.results['dns_info'] = dns_info
            
        except Exception as e:
            self.log(f"DNS偵察でエラー: {str(e)}", "ERROR")
    
    def web_reconnaissance(self):
        """Webアプリケーション偵察を実行"""
        self.log("Webアプリケーション偵察を開始...", "INFO")
        
        try:
            web_info = {}
            
            # HTTP/HTTPS確認
            for protocol in ['http', 'https']:
                url = f"{protocol}://{self.target}"
                try:
                    response = requests.get(url, headers=self.headers, timeout=10, verify=False)
                    web_info[f'{protocol}_status'] = response.status_code
                    web_info[f'{protocol}_headers'] = dict(response.headers)
                    web_info[f'{protocol}_server'] = response.headers.get('Server', 'Unknown')
                    self.log(f"{protocol.upper()} ステータス: {response.status_code}", "SUCCESS")
                except:
                    web_info[f'{protocol}_status'] = None
            
            # ディレクトリ探索
            if web_info.get('http_status') == 200 or web_info.get('https_status') == 200:
                self.log("ディレクトリ探索を実行中...", "INFO")
                directories = self.directory_enumeration()
                web_info['directories'] = directories
            
            # 技術スタック検出
            if web_info.get('http_status') == 200 or web_info.get('https_status') == 200:
                self.log("技術スタック検出を実行中...", "INFO")
                tech_stack = self.technology_detection()
                web_info['technology_stack'] = tech_stack
            
            # 脆弱性スキャン
            if web_info.get('http_status') == 200 or web_info.get('https_status') == 200:
                self.log("脆弱性スキャンを実行中...", "INFO")
                from modules.web_scanner import WebScanner
                web_scanner = WebScanner(self.target)
                web_scanner.results = web_info  # 既存の結果を設定
                vulnerabilities = web_scanner.basic_vulnerability_scan()
                web_info['vulnerabilities'] = vulnerabilities
                self.results['vulnerabilities'] = vulnerabilities
            
            self.results['web_recon'] = web_info
            
        except Exception as e:
            self.log(f"Webアプリケーション偵察でエラー: {str(e)}", "ERROR")
    
    def directory_enumeration(self):
        """ディレクトリ列挙"""
        common_dirs = [
            'admin', 'login', 'wp-admin', 'phpmyadmin', 'config', 'backup',
            'api', 'docs', 'test', 'dev', 'stage', 'beta', 'old', 'archive'
        ]
        
        found_dirs = []
        base_url = f"http://{self.target}"
        
        def check_dir(dir_name):
            try:
                url = f"{base_url}/{dir_name}"
                response = requests.get(url, headers=self.headers, timeout=5, verify=False)
                if response.status_code in [200, 301, 302, 403]:
                    return dir_name
                return None
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_dir = {executor.submit(check_dir, dir_name): dir_name for dir_name in common_dirs}
            
            for future in as_completed(future_to_dir):
                result = future.result()
                if result:
                    found_dirs.append(result)
                    self.log(f"ディレクトリ発見: /{result}", "SUCCESS")
        
        return found_dirs
    
    def technology_detection(self):
        """技術スタック検出"""
        tech_stack = {}
        
        try:
            # HTTPヘッダーから技術を検出
            for protocol in ['http', 'https']:
                url = f"{protocol}://{self.target}"
                try:
                    response = requests.get(url, headers=self.headers, timeout=10, verify=False)
                    
                    # Server ヘッダー
                    server = response.headers.get('Server', '')
                    if server:
                        tech_stack['server'] = server
                    
                    # X-Powered-By ヘッダー
                    powered_by = response.headers.get('X-Powered-By', '')
                    if powered_by:
                        tech_stack['framework'] = powered_by
                    
                    # レスポンスボディから技術を検出
                    content = response.text.lower()
                    
                    if 'wordpress' in content:
                        tech_stack['cms'] = 'WordPress'
                    elif 'drupal' in content:
                        tech_stack['cms'] = 'Drupal'
                    elif 'joomla' in content:
                        tech_stack['cms'] = 'Joomla'
                    
                    if 'jquery' in content:
                        tech_stack['javascript'] = 'jQuery'
                    if 'bootstrap' in content:
                        tech_stack['css_framework'] = 'Bootstrap'
                    
                    break
                    
                except:
                    continue
            
        except Exception as e:
            self.log(f"技術スタック検出でエラー: {str(e)}", "ERROR")
        
        return tech_stack
    
    def osint_gathering(self):
        """OSINT情報収集"""
        self.log("OSINT情報収集を開始...", "INFO")
        
        try:
            osint_info = {}
            
            # WHOIS情報
            try:
                import whois
                w = whois.whois(self.target)
                osint_info['whois'] = {
                    'registrar': w.registrar,
                    'creation_date': str(w.creation_date),
                    'expiration_date': str(w.expiration_date),
                    'name_servers': w.name_servers
                }
                self.log("WHOIS情報を取得しました", "SUCCESS")
            except:
                osint_info['whois'] = {}
            
            # サブドメイン列挙
            self.log("サブドメイン列挙を実行中...", "INFO")
            subdomains = self.subdomain_enumeration()
            osint_info['subdomains'] = subdomains
            
            self.results['osint'] = osint_info
            
        except Exception as e:
            self.log(f"OSINT情報収集でエラー: {str(e)}", "ERROR")
    
    def subdomain_enumeration(self):
        """サブドメイン列挙"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'stage',
            'api', 'cdn', 'static', 'img', 'images', 'media', 'support',
            'help', 'docs', 'forum', 'shop', 'store', 'app', 'mobile'
        ]
        
        found_subdomains = []
        domain = self.target
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{domain}"
                ip = socket.gethostbyname(full_domain)
                return full_domain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_subdomain = {executor.submit(check_subdomain, subdomain): subdomain for subdomain in common_subdomains}
            
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    found_subdomains.append(result)
                    self.log(f"サブドメイン発見: {result}", "SUCCESS")
        
        return found_subdomains
    
    def generate_report(self):
        """レポート生成"""
        self.log("レポートを生成中...", "INFO")
        
        # テキストレポート（1つのレポートのみ）
        report_file = os.path.join(self.output_dir, f"recon_report_{self.target}.txt")
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("🔍 ReconJP - ペネトレーションテスト偵察レポート 🔍\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"🎯 ターゲット: {self.target}\n")
            f.write(f"📅 実行日時: {self.results['timestamp']}\n")
            f.write(f"📁 レポートファイル: {report_file}\n\n")
            
            # ネットワーク情報
            f.write("🌐 【ネットワーク情報】\n")
            f.write("=" * 50 + "\n")
            if self.results['network_scan']:
                for key, value in self.results['network_scan'].items():
                    if isinstance(value, dict):
                        f.write(f"  📋 {key}:\n")
                        for k, v in value.items():
                            f.write(f"    • {k}: {v}\n")
                    elif isinstance(value, list):
                        f.write(f"  📋 {key}: {', '.join(map(str, value))}\n")
                    else:
                        f.write(f"  📋 {key}: {value}\n")
            else:
                f.write("  ⚠️  ネットワーク情報が取得できませんでした\n")
            f.write("\n")
            
            # DNS情報
            f.write("🔗 【DNS情報】\n")
            f.write("=" * 50 + "\n")
            if self.results['dns_info']:
                for key, value in self.results['dns_info'].items():
                    if isinstance(value, list):
                        f.write(f"  📋 {key}: {', '.join(value)}\n")
                    else:
                        f.write(f"  📋 {key}: {value}\n")
            else:
                f.write("  ⚠️  DNS情報が取得できませんでした\n")
            f.write("\n")
            
            # Web情報
            f.write("🌍 【Webアプリケーション情報】\n")
            f.write("=" * 50 + "\n")
            if self.results['web_recon']:
                for key, value in self.results['web_recon'].items():
                    if isinstance(value, dict):
                        f.write(f"  📋 {key}:\n")
                        for k, v in value.items():
                            f.write(f"    • {k}: {v}\n")
                    elif isinstance(value, list):
                        f.write(f"  📋 {key}: {', '.join(map(str, value))}\n")
                    else:
                        f.write(f"  📋 {key}: {value}\n")
            else:
                f.write("  ⚠️  Web情報が取得できませんでした\n")
            f.write("\n")
            
            # OSINT情報
            f.write("🔎 【OSINT情報】\n")
            f.write("=" * 50 + "\n")
            if self.results['osint']:
                for key, value in self.results['osint'].items():
                    if isinstance(value, dict):
                        f.write(f"  📋 {key}:\n")
                        for k, v in value.items():
                            f.write(f"    • {k}: {v}\n")
                    elif isinstance(value, list):
                        f.write(f"  📋 {key}: {', '.join(map(str, value))}\n")
                    else:
                        f.write(f"  📋 {key}: {value}\n")
            else:
                f.write("  ⚠️  OSINT情報が取得できませんでした\n")
            f.write("\n")
            
            # 脆弱性情報
            if self.results.get('vulnerabilities'):
                f.write("🔍 【脆弱性情報】\n")
                f.write("=" * 50 + "\n")
                for vuln in self.results['vulnerabilities']:
                    severity_emoji = {
                        'High': '🔴',
                        'Medium': '🟡',
                        'Low': '🟢'
                    }.get(vuln.get('severity', 'Low'), '⚪')
                    
                    cve_info = f" (CVE: {vuln.get('cve', 'N/A')})" if vuln.get('cve') else ""
                    cms_info = f" [CMS: {vuln.get('cms', 'N/A')}]" if vuln.get('cms') else ""
                    server_info = f" [Server: {vuln.get('server', 'N/A')}]" if vuln.get('server') else ""
                    
                    f.write(f"  {severity_emoji} {vuln.get('type', 'Unknown')}{cve_info}{cms_info}{server_info}\n")
                    f.write(f"    URL: {vuln.get('url', 'N/A')}\n")
                    if vuln.get('description'):
                        f.write(f"    説明: {vuln['description']}\n")
                    f.write(f"    重要度: {vuln.get('severity', 'Unknown')}\n\n")
            else:
                f.write("✅ 【脆弱性情報】\n")
                f.write("=" * 50 + "\n")
                f.write("  脆弱性は検出されませんでした\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("✅ レポート生成完了\n")
            f.write("=" * 80 + "\n")
        
        self.log(f"📄 レポートが生成されました: {report_file}", "SUCCESS")
        return report_file
    
    def run_full_reconnaissance(self):
        """完全な偵察を実行"""
        self.log("完全な偵察を開始します...", "INFO")
        
        # 各偵察モジュールを実行
        self.network_scan()
        self.dns_reconnaissance()
        self.web_reconnaissance()
        self.osint_gathering()
        
        # レポート生成
        self.generate_report()
        
        self.log("偵察が完了しました！", "SUCCESS")
        return self.results

def main():
    """メイン関数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ReconJP - ペネトレーションテスト用偵察ツール')
    parser.add_argument('target', help='ターゲットドメインまたはIPアドレス')
    parser.add_argument('-o', '--output', default='recon_results', help='出力ディレクトリ')
    parser.add_argument('--network-only', action='store_true', help='ネットワーク偵察のみ実行')
    parser.add_argument('--dns-only', action='store_true', help='DNS偵察のみ実行')
    parser.add_argument('--web-only', action='store_true', help='Web偵察のみ実行')
    parser.add_argument('--osint-only', action='store_true', help='OSINTのみ実行')
    
    args = parser.parse_args()
    
    # ツールの初期化
    recon = ReconTool(args.target, args.output)
    
    # 指定されたモジュールのみ実行
    if args.network_only:
        recon.network_scan()
    elif args.dns_only:
        recon.dns_reconnaissance()
    elif args.web_only:
        recon.web_reconnaissance()
    elif args.osint_only:
        recon.osint_gathering()
    else:
        # 完全な偵察を実行
        recon.run_full_reconnaissance()
    
    # 結果を表示
    if RICH_ENABLED:
        table = Table(title="偵察結果サマリー")
        table.add_column("カテゴリ", style="cyan")
        table.add_column("項目", style="magenta")
        table.add_column("値", style="green")
        
        for category, data in recon.results.items():
            if isinstance(data, dict):
                for key, value in data.items():
                    table.add_row(category, key, str(value))
        
        console.print(table)
    else:
        print("\n" + "=" * 60)
        print("偵察結果サマリー")
        print("=" * 60)
        for category, data in recon.results.items():
            if isinstance(data, dict):
                print(f"\n【{category}】")
                for key, value in data.items():
                    print(f"  {key}: {value}")

if __name__ == "__main__":
    main() 