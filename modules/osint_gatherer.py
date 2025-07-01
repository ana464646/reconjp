#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSINT情報収集モジュール
WHOIS情報、サブドメイン列挙、公開情報収集機能
"""

import socket
import requests
import dns.resolver
import whois
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

class OSINTGatherer:
    """OSINT情報収集クラス"""
    
    def __init__(self, target):
        self.target = target
        self.results = {
            'target': target,
            'whois_info': {},
            'dns_records': {},
            'subdomains': [],
            'reverse_dns': [],
            'public_info': {},
            'email_addresses': [],
            'social_media': []
        }
        
        # よくあるサブドメイン
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'stage',
            'api', 'cdn', 'static', 'img', 'images', 'media', 'support',
            'help', 'docs', 'forum', 'shop', 'store', 'app', 'mobile',
            'webmail', 'remote', 'vpn', 'ns1', 'ns2', 'mx1', 'mx2',
            'smtp', 'pop', 'imap', 'calendar', 'drive', 'cloud',
            'git', 'svn', 'jenkins', 'jira', 'confluence', 'wiki'
        ]
        
        # 検索エンジン
        self.search_engines = [
            'https://www.google.com/search?q=site:',
            'https://www.bing.com/search?q=site:',
            'https://search.yahoo.com/search?p=site:'
        ]
    
    def get_whois_info(self):
        """WHOIS情報を取得"""
        try:
            w = whois.whois(self.target)
            
            whois_info = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'updated_date': str(w.updated_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'org': w.org,
                'country': w.country
            }
            
            self.results['whois_info'] = whois_info
            return whois_info
            
        except Exception as e:
            print(f"WHOIS情報取得エラー: {str(e)}")
            return {}
    
    def get_dns_records(self):
        """DNSレコードを取得"""
        dns_records = {}
        
        # Aレコード
        try:
            answers = dns.resolver.resolve(self.target, 'A')
            dns_records['a_records'] = [str(rdata) for rdata in answers]
        except:
            dns_records['a_records'] = []
        
        # AAAAレコード（IPv6）
        try:
            answers = dns.resolver.resolve(self.target, 'AAAA')
            dns_records['aaaa_records'] = [str(rdata) for rdata in answers]
        except:
            dns_records['aaaa_records'] = []
        
        # MXレコード
        try:
            answers = dns.resolver.resolve(self.target, 'MX')
            dns_records['mx_records'] = [str(rdata.exchange) for rdata in answers]
        except:
            dns_records['mx_records'] = []
        
        # NSレコード
        try:
            answers = dns.resolver.resolve(self.target, 'NS')
            dns_records['ns_records'] = [str(rdata) for rdata in answers]
        except:
            dns_records['ns_records'] = []
        
        # TXTレコード
        try:
            answers = dns.resolver.resolve(self.target, 'TXT')
            dns_records['txt_records'] = [str(rdata) for rdata in answers]
        except:
            dns_records['txt_records'] = []
        
        # CNAMEレコード
        try:
            answers = dns.resolver.resolve(self.target, 'CNAME')
            dns_records['cname_records'] = [str(rdata) for rdata in answers]
        except:
            dns_records['cname_records'] = []
        
        # SOAレコード
        try:
            answers = dns.resolver.resolve(self.target, 'SOA')
            dns_records['soa_records'] = [str(rdata) for rdata in answers]
        except:
            dns_records['soa_records'] = []
        
        self.results['dns_records'] = dns_records
        return dns_records
    
    def enumerate_subdomains(self):
        """サブドメイン列挙"""
        found_subdomains = []
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{self.target}"
                ip = socket.gethostbyname(full_domain)
                return {
                    'subdomain': full_domain,
                    'ip': ip
                }
            except:
                return None
        
        print(f"サブドメイン列挙を開始: {self.target}")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_subdomain = {executor.submit(check_subdomain, subdomain): subdomain for subdomain in self.common_subdomains}
            
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    found_subdomains.append(result)
                    print(f"サブドメイン発見: {result['subdomain']} -> {result['ip']}")
        
        self.results['subdomains'] = found_subdomains
        return found_subdomains
    
    def reverse_dns_lookup(self, ip_range=None):
        """逆引きDNS検索"""
        if ip_range is None:
            # デフォルトでAレコードのIPを使用
            ips = self.results.get('dns_records', {}).get('a_records', [])
        else:
            ips = ip_range
        
        reverse_dns_results = []
        
        for ip in ips:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                reverse_dns_results.append({
                    'ip': ip,
                    'hostname': hostname
                })
            except:
                pass
        
        self.results['reverse_dns'] = reverse_dns_results
        return reverse_dns_results
    
    def search_public_info(self):
        """公開情報を検索"""
        public_info = {}
        
        # 検索クエリ
        search_queries = [
            f'site:{self.target}',
            f'"{self.target}"',
            f'email @{self.target}',
            f'contact {self.target}'
        ]
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        for query in search_queries:
            try:
                # Google検索（簡易版）
                url = f"https://www.google.com/search?q={query}"
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    # 簡単な結果解析（実際の実装ではより詳細な解析が必要）
                    public_info[query] = {
                        'status': 'success',
                        'content_length': len(response.content)
                    }
                else:
                    public_info[query] = {
                        'status': 'failed',
                        'status_code': response.status_code
                    }
                    
            except Exception as e:
                public_info[query] = {
                    'status': 'error',
                    'error': str(e)
                }
        
        self.results['public_info'] = public_info
        return public_info
    
    def extract_email_addresses(self):
        """メールアドレスを抽出"""
        emails = []
        
        # WHOIS情報からメールアドレスを抽出
        whois_emails = self.results.get('whois_info', {}).get('emails', [])
        if whois_emails:
            if isinstance(whois_emails, list):
                emails.extend(whois_emails)
            else:
                emails.append(whois_emails)
        
        # TXTレコードからメールアドレスを抽出
        txt_records = self.results.get('dns_records', {}).get('txt_records', [])
        for txt in txt_records:
            # 簡単なメールアドレス正規表現
            import re
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            found_emails = re.findall(email_pattern, txt)
            emails.extend(found_emails)
        
        # 重複を除去
        emails = list(set(emails))
        
        self.results['email_addresses'] = emails
        return emails
    
    def find_social_media(self):
        """ソーシャルメディアアカウントを検索"""
        social_media = []
        
        # よくあるソーシャルメディアプラットフォーム
        platforms = [
            'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
            'youtube.com', 'github.com', 'reddit.com', 'pinterest.com'
        ]
        
        for platform in platforms:
            try:
                # サブドメインとしてチェック
                test_domain = f"{platform}.{self.target}"
                ip = socket.gethostbyname(test_domain)
                social_media.append({
                    'platform': platform,
                    'domain': test_domain,
                    'ip': ip
                })
            except:
                pass
        
        self.results['social_media'] = social_media
        return social_media
    
    def check_ssl_certificate(self):
        """SSL証明書情報を取得"""
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }
                    
                    return ssl_info
        except Exception as e:
            return {'error': str(e)}
    
    def run_full_osint_gathering(self):
        """完全なOSINT情報収集を実行"""
        print(f"OSINT情報収集を開始: {self.target}")
        
        # WHOIS情報
        print("WHOIS情報を取得中...")
        self.get_whois_info()
        
        # DNSレコード
        print("DNSレコードを取得中...")
        self.get_dns_records()
        
        # サブドメイン列挙
        print("サブドメイン列挙中...")
        self.enumerate_subdomains()
        
        # 逆引きDNS
        print("逆引きDNS検索中...")
        self.reverse_dns_lookup()
        
        # 公開情報検索
        print("公開情報を検索中...")
        self.search_public_info()
        
        # メールアドレス抽出
        print("メールアドレスを抽出中...")
        self.extract_email_addresses()
        
        # ソーシャルメディア検索
        print("ソーシャルメディアアカウントを検索中...")
        self.find_social_media()
        
        # SSL証明書情報
        print("SSL証明書情報を取得中...")
        ssl_info = self.check_ssl_certificate()
        self.results['ssl_certificate'] = ssl_info
        
        return self.results 