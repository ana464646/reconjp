#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Webアプリケーション偵察モジュール
ディレクトリ探索、技術スタック検出、脆弱性スキャン機能
"""

import requests
import urllib.parse
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

class WebScanner:
    """Webアプリケーション偵察クラス"""
    
    def __init__(self, target, timeout=10):
        self.target = target
        self.timeout = timeout
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.results = {
            'target': target,
            'http_status': None,
            'https_status': None,
            'headers': {},
            'technology_stack': {},
            'directories': [],
            'files': [],
            'forms': [],
            'vulnerabilities': [],
            'subdomains': [],
            'virtual_hosts': []
        }
        
        # よくあるディレクトリ
        self.common_directories = [
            'admin', 'login', 'wp-admin', 'phpmyadmin', 'config', 'backup',
            'api', 'docs', 'test', 'dev', 'stage', 'beta', 'old', 'archive',
            'cgi-bin', 'images', 'css', 'js', 'uploads', 'downloads',
            'includes', 'lib', 'src', 'bin', 'tmp', 'temp', 'cache',
            'logs', 'error', 'debug', 'status', 'health', 'monitor',
            # 隠しディレクトリ
            'simple', 'hidden', 'secret', 'private', 'internal', 'secure',
            'admin-panel', 'administrator', 'manage', 'management', 'control',
            'dashboard', 'panel', 'portal', 'console', 'webadmin', 'webmaster',
            'siteadmin', 'site-admin', 'cpanel', 'whm', 'plesk', 'directadmin',
            'webmin', 'phpmyadmin', 'mysql', 'database', 'db', 'sql',
            'backup', 'backups', 'bak', 'old', 'archive', 'archives',
            'temp', 'tmp', 'cache', 'cached', 'session', 'sessions',
            'upload', 'uploads', 'files', 'file', 'media', 'assets',
            'static', 'public', 'private', 'internal', 'external',
            'api', 'apis', 'rest', 'soap', 'xmlrpc', 'json',
            'test', 'testing', 'dev', 'development', 'staging', 'beta',
            'alpha', 'demo', 'sandbox', 'playground', 'lab', 'labs',
            'tools', 'utilities', 'scripts', 'cgi', 'cgi-bin',
            'bin', 'sbin', 'usr', 'etc', 'var', 'home', 'root',
            'windows', 'win', 'system', 'system32', 'sys', 'sys32',
            'program', 'programs', 'app', 'apps', 'application', 'applications',
            'web', 'www', 'wwwroot', 'htdocs', 'public_html', 'html',
            'css', 'js', 'javascript', 'images', 'img', 'pics', 'photos',
            'doc', 'docs', 'documentation', 'help', 'support', 'faq',
            'about', 'contact', 'info', 'information', 'news', 'blog',
            'forum', 'forums', 'board', 'boards', 'chat', 'irc',
            'mail', 'email', 'webmail', 'smtp', 'pop', 'imap',
            'ftp', 'ssh', 'telnet', 'remote', 'vpn', 'ssl',
            'cert', 'certs', 'certificate', 'certificates', 'ca',
            'auth', 'authentication', 'login', 'logout', 'signin', 'signout',
            'register', 'registration', 'signup', 'account', 'accounts',
            'user', 'users', 'member', 'members', 'profile', 'profiles',
            'settings', 'config', 'configuration', 'setup', 'install',
            'installer', 'installation', 'upgrade', 'update', 'patch',
            'maintenance', 'maintain', 'repair', 'fix', 'debug',
            'error', 'errors', '404', '403', '500', '502', '503',
            'status', 'health', 'monitor', 'monitoring', 'stats', 'statistics',
            'analytics', 'tracking', 'track', 'log', 'logs', 'logging',
            'audit', 'auditing', 'security', 'secure', 'protect', 'protection',
            'firewall', 'waf', 'ids', 'ips', 'honeypot', 'trap',
            'admin1', 'admin2', 'admin3', 'administrator1', 'administrator2',
            'manager', 'management', 'supervisor', 'super', 'master',
            'root1', 'root2', 'system1', 'system2', 'webmaster1', 'webmaster2',
            'test1', 'test2', 'test3', 'dev1', 'dev2', 'dev3',
            'staging1', 'staging2', 'beta1', 'beta2', 'alpha1', 'alpha2',
            'demo1', 'demo2', 'sandbox1', 'sandbox2', 'lab1', 'lab2',
            'hidden1', 'hidden2', 'secret1', 'secret2', 'private1', 'private2',
            'internal1', 'internal2', 'secure1', 'secure2', 'protected1', 'protected2',
            'admin-panel1', 'admin-panel2', 'dashboard1', 'dashboard2', 'panel1', 'panel2',
            'portal1', 'portal2', 'console1', 'console2', 'webadmin1', 'webadmin2',
            'siteadmin1', 'siteadmin2', 'cpanel1', 'cpanel2', 'whm1', 'whm2',
            'plesk1', 'plesk2', 'directadmin1', 'directadmin2', 'webmin1', 'webmin2',
            'phpmyadmin1', 'phpmyadmin2', 'mysql1', 'mysql2', 'database1', 'database2',
            'backup1', 'backup2', 'backup3', 'bak1', 'bak2', 'bak3',
            'old1', 'old2', 'old3', 'archive1', 'archive2', 'archive3',
            'temp1', 'temp2', 'tmp1', 'tmp2', 'cache1', 'cache2',
            'upload1', 'upload2', 'files1', 'files2', 'media1', 'media2',
            'api1', 'api2', 'api3', 'rest1', 'rest2', 'soap1', 'soap2',
            'test1', 'test2', 'test3', 'dev1', 'dev2', 'dev3',
            'tools1', 'tools2', 'utilities1', 'utilities2', 'scripts1', 'scripts2',
            'web1', 'web2', 'www1', 'www2', 'html1', 'html2',
            'css1', 'css2', 'js1', 'js2', 'images1', 'images2',
            'docs1', 'docs2', 'help1', 'help2', 'support1', 'support2',
            'about1', 'about2', 'contact1', 'contact2', 'info1', 'info2',
            'news1', 'news2', 'blog1', 'blog2', 'forum1', 'forum2',
            'mail1', 'mail2', 'email1', 'email2', 'webmail1', 'webmail2',
            'auth1', 'auth2', 'login1', 'login2', 'signin1', 'signin2',
            'register1', 'register2', 'signup1', 'signup2', 'account1', 'account2',
            'user1', 'user2', 'member1', 'member2', 'profile1', 'profile2',
            'settings1', 'settings2', 'config1', 'config2', 'setup1', 'setup2',
            'install1', 'install2', 'installer1', 'installer2', 'upgrade1', 'upgrade2',
            'maintenance1', 'maintenance2', 'repair1', 'repair2', 'fix1', 'fix2',
            'error1', 'error2', 'status1', 'status2', 'health1', 'health2',
            'monitor1', 'monitor2', 'stats1', 'stats2', 'analytics1', 'analytics2',
            'log1', 'log2', 'audit1', 'audit2', 'security1', 'security2',
            'firewall1', 'firewall2', 'waf1', 'waf2', 'ids1', 'ids2',
            'honeypot1', 'honeypot2', 'trap1', 'trap2'
        ]
        
        # よくあるファイル
        self.common_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
            'phpinfo.php', 'info.php', 'test.php', 'admin.php',
            'config.php', 'wp-config.php', 'config.ini', '.env',
            'README.md', 'CHANGELOG.txt', 'LICENSE.txt'
        ]
        
        # よくあるサブドメイン（Webサイト用）
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'stage',
            'api', 'cdn', 'static', 'img', 'images', 'media', 'support',
            'help', 'docs', 'forum', 'shop', 'store', 'app', 'mobile',
            'webmail', 'remote', 'vpn', 'ns1', 'ns2', 'mx1', 'mx2',
            'smtp', 'pop', 'imap', 'calendar', 'drive', 'cloud',
            'git', 'svn', 'jenkins', 'jira', 'confluence', 'wiki',
            'dashboard', 'panel', 'control', 'manage', 'portal',
            'secure', 'ssl', 'login', 'auth', 'account', 'user',
            'billing', 'payment', 'order', 'cart', 'checkout',
            'news', 'press', 'about', 'contact', 'careers', 'jobs'
        ]
    
    def check_http_https(self):
        """HTTP/HTTPSの状態を確認"""
        protocols = {}
        
        for protocol in ['http', 'https']:
            url = f"{protocol}://{self.target}"
            try:
                response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
                protocols[f'{protocol}_status'] = response.status_code
                protocols[f'{protocol}_headers'] = dict(response.headers)
                protocols[f'{protocol}_server'] = response.headers.get('Server', 'Unknown')
                protocols[f'{protocol}_url'] = url
            except requests.exceptions.RequestException as e:
                protocols[f'{protocol}_status'] = None
                # エラーメッセージは記録するが、技術スタックには含めない
                protocols[f'{protocol}_error'] = str(e)
                print(f"⚠️  {protocol.upper()}接続エラー: {str(e)}")
        
        self.results.update(protocols)
        return protocols
    
    def directory_enumeration(self, base_url=None):
        """ディレクトリ列挙（隠しディレクトリ検出含む）"""
        if base_url is None:
            # HTTP/HTTPSの状態に基づいてベースURLを決定
            if self.results.get('https_status') == 200:
                base_url = f"https://{self.target}"
            elif self.results.get('http_status') == 200:
                base_url = f"http://{self.target}"
            else:
                base_url = f"http://{self.target}"
        
        found_directories = []
        hidden_directories = []
        
        def check_directory(dir_name):
            try:
                url = f"{base_url}/{dir_name}"
                response = requests.get(url, headers=self.headers, timeout=5, verify=False)
                if response.status_code in [200, 301, 302, 403]:
                    result = {
                        'name': dir_name,
                        'url': url,
                        'status': response.status_code,
                        'size': len(response.content),
                        'title': self.extract_title(response.text),
                        'server': response.headers.get('Server', 'Unknown'),
                        'content_type': response.headers.get('Content-Type', 'Unknown')
                    }
                    
                    # 隠しディレクトリかどうかを判定
                    hidden_keywords = ['hidden', 'secret', 'private', 'internal', 'secure', 'admin', 'simple']
                    if any(keyword in dir_name.lower() for keyword in hidden_keywords):
                        result['hidden'] = True
                        hidden_directories.append(result)
                        print(f"🔍 隠しディレクトリ発見: {dir_name} (ステータス: {response.status_code}) - {result['title']}")
                    else:
                        result['hidden'] = False
                        print(f"📁 ディレクトリ発見: {dir_name} (ステータス: {response.status_code})")
                    
                    return result
                return None
            except Exception as e:
                print(f"⚠️  ディレクトリチェックエラー ({dir_name}): {str(e)}")
                return None
        
        print(f"🔍 ディレクトリ列挙を開始: {base_url}")
        print(f"📋 検索対象: {len(self.common_directories)}個のディレクトリ")
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_dir = {executor.submit(check_directory, dir_name): dir_name for dir_name in self.common_directories}
            
            for future in as_completed(future_to_dir):
                result = future.result()
                if result:
                    found_directories.append(result)
        
        # 結果の整理
        self.results['directories'] = found_directories
        self.results['hidden_directories'] = hidden_directories
        
        # 結果サマリー
        print(f"\n📊 ディレクトリ列挙結果:")
        print(f"   📁 総ディレクトリ数: {len(found_directories)}個")
        print(f"   🔍 隠しディレクトリ数: {len(hidden_directories)}個")
        
        if hidden_directories:
            print(f"\n⚠️  発見された隠しディレクトリ:")
            for hidden_dir in hidden_directories:
                status_emoji = {"200": "✅", "301": "🔄", "302": "🔄", "403": "🚫"}.get(str(hidden_dir['status']), "❓")
                print(f"   {status_emoji} /{hidden_dir['name']} - {hidden_dir['title']}")
                print(f"     📄 サイズ: {hidden_dir['size']} bytes")
                print(f"     🖥️  サーバー: {hidden_dir['server']}")
                print(f"     📋 タイプ: {hidden_dir['content_type']}")
        
        return found_directories
    
    def file_enumeration(self, base_url=None):
        """ファイル列挙"""
        if base_url is None:
            if self.results.get('https_status') == 200:
                base_url = f"https://{self.target}"
            elif self.results.get('http_status') == 200:
                base_url = f"http://{self.target}"
            else:
                base_url = f"http://{self.target}"
        
        found_files = []
        
        def check_file(file_name):
            try:
                url = f"{base_url}/{file_name}"
                response = requests.get(url, headers=self.headers, timeout=5, verify=False)
                if response.status_code in [200, 301, 302]:
                    return {
                        'name': file_name,
                        'url': url,
                        'status': response.status_code,
                        'size': len(response.content)
                    }
                return None
            except:
                return None
        
        print(f"ファイル列挙を開始: {base_url}")
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_file = {executor.submit(check_file, file_name): file_name for file_name in self.common_files}
            
            for future in as_completed(future_to_file):
                result = future.result()
                if result:
                    found_files.append(result)
                    print(f"ファイル発見: {result['name']} (ステータス: {result['status']})")
        
        self.results['files'] = found_files
        return found_files
    
    def technology_detection(self, url=None):
        """技術スタック検出"""
        if url is None:
            if self.results.get('https_status') == 200:
                url = f"https://{self.target}"
            elif self.results.get('http_status') == 200:
                url = f"http://{self.target}"
            else:
                url = f"http://{self.target}"
        
        tech_stack = {}
        
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            content = response.text.lower()
            headers = response.headers
            
            # Server ヘッダー
            server = headers.get('Server', '')
            if server:
                tech_stack['server'] = server
            
            # X-Powered-By ヘッダー
            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                tech_stack['framework'] = powered_by
            
            # レスポンスボディから技術を検出
            if 'wordpress' in content:
                tech_stack['cms'] = 'WordPress'
            elif 'drupal' in content:
                tech_stack['cms'] = 'Drupal'
            elif 'joomla' in content:
                tech_stack['cms'] = 'Joomla'
            elif 'magento' in content:
                tech_stack['cms'] = 'Magento'
            
            # JavaScript フレームワーク
            if 'jquery' in content:
                tech_stack['javascript'] = 'jQuery'
            if 'react' in content:
                tech_stack['javascript'] = 'React'
            if 'vue' in content:
                tech_stack['javascript'] = 'Vue.js'
            if 'angular' in content:
                tech_stack['javascript'] = 'Angular'
            
            # CSS フレームワーク
            if 'bootstrap' in content:
                tech_stack['css_framework'] = 'Bootstrap'
            if 'foundation' in content:
                tech_stack['css_framework'] = 'Foundation'
            
            # Webサーバー
            if 'apache' in server.lower():
                tech_stack['web_server'] = 'Apache'
            elif 'nginx' in server.lower():
                tech_stack['web_server'] = 'Nginx'
            elif 'iis' in server.lower():
                tech_stack['web_server'] = 'IIS'
            
            # プログラミング言語
            if '.php' in content or 'php' in server.lower():
                tech_stack['language'] = 'PHP'
            elif '.asp' in content or 'asp' in server.lower():
                tech_stack['language'] = 'ASP'
            elif '.jsp' in content:
                tech_stack['language'] = 'Java'
            elif '.py' in content or 'python' in server.lower():
                tech_stack['language'] = 'Python'
            
        except Exception as e:
            print(f"⚠️  技術スタック検出エラー: {str(e)}")
            # エラーが発生した場合は空の辞書を返す
            tech_stack = {}
        
        self.results['technology_stack'] = tech_stack
        return tech_stack
    
    def form_analysis(self, url=None):
        """フォーム分析"""
        if url is None:
            if self.results.get('https_status') == 200:
                url = f"https://{self.target}"
            elif self.results.get('http_status') == 200:
                url = f"http://{self.target}"
            else:
                url = f"http://{self.target}"
        
        forms = []
        
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.content, 'html5lib')
            
            for form in soup.find_all('form'):
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET'),
                    'inputs': []
                }
                
                for input_tag in form.find_all('input'):
                    input_info = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'id': input_tag.get('id', ''),
                        'placeholder': input_tag.get('placeholder', '')
                    }
                    form_info['inputs'].append(input_info)
                
                forms.append(form_info)
        
        except Exception as e:
            print(f"⚠️  フォーム分析エラー: {str(e)}")
        
        self.results['forms'] = forms
        return forms
    
    def basic_vulnerability_scan(self, url=None):
        """基本的な脆弱性スキャン"""
        if url is None:
            if self.results.get('https_status') == 200:
                url = f"https://{self.target}"
            elif self.results.get('http_status') == 200:
                url = f"http://{self.target}"
            else:
                url = f"http://{self.target}"
        
        vulnerabilities = []
        
        # ディレクトリトラバーサル
        traversal_paths = ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts']
        for path in traversal_paths:
            try:
                test_url = f"{url}/{path}"
                response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                if response.status_code == 200 and ('root:' in response.text or 'localhost' in response.text):
                    vulnerabilities.append({
                        'type': 'Directory Traversal',
                        'url': test_url,
                        'severity': 'High'
                    })
            except:
                pass
        
        # 情報漏洩
        info_files = ['robots.txt', '.htaccess', 'web.config', 'phpinfo.php']
        for file in info_files:
            try:
                test_url = f"{url}/{file}"
                response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'file': file,
                        'url': test_url,
                        'severity': 'Medium'
                    })
            except:
                pass
        
        # デフォルトページ
        default_pages = ['admin', 'login', 'administrator', 'admin.php']
        for page in default_pages:
            try:
                test_url = f"{url}/{page}"
                response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                if response.status_code in [200, 301, 302]:
                    vulnerabilities.append({
                        'type': 'Default Page',
                        'page': page,
                        'url': test_url,
                        'severity': 'Low'
                    })
            except:
                pass
        
        self.results['vulnerabilities'] = vulnerabilities
        return vulnerabilities
    
    def enumerate_subdomains(self):
        """サブドメイン列挙（Webサイト用）"""
        found_subdomains = []
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{self.target}"
                
                # HTTPでチェック
                http_url = f"http://{full_domain}"
                try:
                    response = requests.get(http_url, headers=self.headers, timeout=5, verify=False)
                    if response.status_code in [200, 301, 302, 403]:
                        return {
                            'subdomain': full_domain,
                            'protocol': 'http',
                            'status': response.status_code,
                            'title': self.extract_title(response.text),
                            'server': response.headers.get('Server', 'Unknown'),
                            'url': http_url
                        }
                except:
                    pass
                
                # HTTPSでチェック
                https_url = f"https://{full_domain}"
                try:
                    response = requests.get(https_url, headers=self.headers, timeout=5, verify=False)
                    if response.status_code in [200, 301, 302, 403]:
                        return {
                            'subdomain': full_domain,
                            'protocol': 'https',
                            'status': response.status_code,
                            'title': self.extract_title(response.text),
                            'server': response.headers.get('Server', 'Unknown'),
                            'url': https_url
                        }
                except:
                    pass
                
                return None
            except:
                return None
        
        print(f"🔗 サブドメイン列挙を開始: {self.target}")
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_subdomain = {executor.submit(check_subdomain, subdomain): subdomain for subdomain in self.common_subdomains}
            
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    found_subdomains.append(result)
                    print(f"✅ サブドメイン発見: {result['subdomain']} ({result['protocol']}) - {result['title']}")
        
        self.results['subdomains'] = found_subdomains
        return found_subdomains
    
    def detect_virtual_hosts(self, ip):
        """隠しドメイン（Virtual Host）検出"""
        print(f"🔍 隠しドメイン検出を開始: {ip}")
        
        virtual_hosts = []
        
        # よくあるドメイン名のリスト
        common_domains = [
            'example.com', 'test.com', 'dev.com', 'staging.com', 'admin.com',
            'internal.com', 'local.com', 'corp.com', 'company.com', 'business.com',
            'web.com', 'site.com', 'app.com', 'api.com', 'service.com',
            'mail.com', 'smtp.com', 'pop.com', 'imap.com', 'ftp.com',
            'vpn.com', 'remote.com', 'secure.com', 'ssl.com', 'portal.com',
            'dashboard.com', 'panel.com', 'control.com', 'manage.com', 'admin.local',
            'internal.local', 'corp.local', 'company.local', 'test.local', 'dev.local',
            'staging.local', 'web.local', 'app.local', 'api.local', 'service.local'
        ]
        
        def check_virtual_host(domain):
            try:
                # HTTPでチェック
                http_url = f"http://{ip}"
                headers = self.headers.copy()
                headers['Host'] = domain
                
                response = requests.get(http_url, headers=headers, timeout=5, verify=False)
                if response.status_code in [200, 301, 302, 403]:
                    title = self.extract_title(response.text)
                    if title and title != "タイトルなし" and "default" not in title.lower():
                        return {
                            'domain': domain,
                            'protocol': 'http',
                            'status': response.status_code,
                            'title': title,
                            'server': response.headers.get('Server', 'Unknown'),
                            'url': http_url,
                            'host_header': domain
                        }
                
                # HTTPSでチェック
                https_url = f"https://{ip}"
                response = requests.get(https_url, headers=headers, timeout=5, verify=False)
                if response.status_code in [200, 301, 302, 403]:
                    title = self.extract_title(response.text)
                    if title and title != "タイトルなし" and "default" not in title.lower():
                        return {
                            'domain': domain,
                            'protocol': 'https',
                            'status': response.status_code,
                            'title': title,
                            'server': response.headers.get('Server', 'Unknown'),
                            'url': https_url,
                            'host_header': domain
                        }
                
                return None
            except:
                return None
        
        # マルチスレッドでVirtual Host検出
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_domain = {executor.submit(check_virtual_host, domain): domain for domain in common_domains}
            
            for future in as_completed(future_to_domain):
                result = future.result()
                if result:
                    virtual_hosts.append(result)
                    print(f"✅ 隠しドメイン発見: {result['domain']} ({result['protocol']}) - {result['title']}")
        
        # カスタムドメインのテスト（IPアドレスの場合）
        if self.is_valid_ip(self.target):
            custom_domains = [
                f"{self.target}.local",
                f"www.{self.target}.local",
                f"admin.{self.target}.local",
                f"internal.{self.target}.local",
                f"corp.{self.target}.local",
                f"test.{self.target}.local",
                f"dev.{self.target}.local",
                f"staging.{self.target}.local"
            ]
            
            for domain in custom_domains:
                result = check_virtual_host(domain)
                if result:
                    virtual_hosts.append(result)
                    print(f"✅ カスタム隠しドメイン発見: {result['domain']} ({result['protocol']}) - {result['title']}")
        
        self.results['virtual_hosts'] = virtual_hosts
        return virtual_hosts
    
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
    
    def extract_title(self, html_content):
        """HTMLからタイトルを抽出"""
        try:
            soup = BeautifulSoup(html_content, 'html5lib')
            title_tag = soup.find('title')
            if title_tag:
                title = title_tag.get_text().strip()
                return title[:50] + "..." if len(title) > 50 else title
            return "タイトルなし"
        except:
            return "タイトルなし"
    
    def scan_subdomain_vulnerabilities(self, subdomain_info):
        """サブドメインの脆弱性スキャン"""
        vulnerabilities = []
        url = subdomain_info['url']
        
        # 基本的な脆弱性チェック
        test_paths = [
            '/admin', '/login', '/wp-admin', '/phpmyadmin',
            '/config', '/backup', '/test', '/debug',
            '/robots.txt', '/.htaccess', '/web.config'
        ]
        
        for path in test_paths:
            try:
                test_url = f"{url.rstrip('/')}{path}"
                response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                if response.status_code in [200, 301, 302]:
                    vulnerabilities.append({
                        'type': 'Subdomain Path Discovery',
                        'url': test_url,
                        'subdomain': subdomain_info['subdomain'],
                        'severity': 'Medium'
                    })
            except:
                pass
        
        return vulnerabilities
    
    def run_full_web_scan(self):
        """完全なWebスキャンを実行"""
        print(f"🌐 Webアプリケーションスキャンを開始しています...")
        
        # 脆弱性リストを初期化
        all_vulnerabilities = []
        
        # HTTP/HTTPS確認
        print("🌐 HTTP/HTTPS状態を確認中...")
        self.check_http_https()
        if self.results.get('http_status') == 200:
            print("✅ HTTP接続: 成功")
        if self.results.get('https_status') == 200:
            print("✅ HTTPS接続: 成功")
        
        # 技術スタック検出
        print("🛠️  技術スタック検出中...")
        tech_stack = self.technology_detection()
        if tech_stack and len(tech_stack) > 0:
            print(f"✅ 検出された技術: {len(tech_stack)}種類")
            for tech, value in tech_stack.items():
                print(f"   - {tech}: {value}")
        else:
            print("ℹ️  検出された技術スタックはありません")
        
        # ディレクトリ列挙
        print("📁 ディレクトリ列挙中...")
        directories = self.directory_enumeration()
        if directories:
            print(f"✅ 検出されたディレクトリ: {len(directories)}個")
            
            # 隠しディレクトリの詳細表示
            hidden_dirs = [d for d in directories if d.get('hidden', False)]
            if hidden_dirs:
                print(f"🔍 隠しディレクトリの詳細:")
                for hidden_dir in hidden_dirs:
                    status_emoji = {"200": "✅", "301": "🔄", "302": "🔄", "403": "🚫"}.get(str(hidden_dir['status']), "❓")
                    print(f"   {status_emoji} /{hidden_dir['name']} - {hidden_dir['title']}")
                    print(f"     📄 サイズ: {hidden_dir['size']} bytes")
                    print(f"     🖥️  サーバー: {hidden_dir['server']}")
                    print(f"     📋 タイプ: {hidden_dir['content_type']}")
        else:
            print("ℹ️  検出されたディレクトリはありません")
        
        # ファイル列挙
        print("📄 ファイル列挙中...")
        files = self.file_enumeration()
        if files:
            print(f"✅ 検出されたファイル: {len(files)}個")
        else:
            print("ℹ️  検出されたファイルはありません")
        
        # フォーム分析
        print("📝 フォーム分析中...")
        forms = self.form_analysis()
        if forms:
            print(f"✅ 検出されたフォーム: {len(forms)}個")
        else:
            print("ℹ️  検出されたフォームはありません")
        
        # サブドメイン列挙
        print("🔗 サブドメイン列挙中...")
        subdomains = self.enumerate_subdomains()
        if subdomains:
            print(f"✅ 検出されたサブドメイン: {len(subdomains)}個")
            for subdomain in subdomains:
                print(f"   - {subdomain['subdomain']} ({subdomain['protocol']}) - {subdomain['title']}")
        else:
            print("ℹ️  検出されたサブドメインはありません")
        
        # サブドメインの脆弱性スキャン
        if subdomains:
            print("🔍 サブドメインの脆弱性スキャン中...")
            subdomain_vulns = []
            for subdomain in subdomains:
                vulns = self.scan_subdomain_vulnerabilities(subdomain)
                subdomain_vulns.extend(vulns)
            
            if subdomain_vulns:
                print(f"⚠️  サブドメインで検出された脆弱性: {len(subdomain_vulns)}個")
                for vuln in subdomain_vulns:
                    print(f"   🟡 {vuln['type']}: {vuln['subdomain']}")
                all_vulnerabilities.extend(subdomain_vulns)
        
        # 脆弱性スキャン
        print("⚠️  脆弱性スキャン中...")
        main_vulnerabilities = self.basic_vulnerability_scan()
        if main_vulnerabilities:
            print(f"⚠️  メインドメインで検出された脆弱性: {len(main_vulnerabilities)}個")
            for vuln in main_vulnerabilities:
                severity_emoji = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(vuln.get('severity', 'Low'), "⚪")
                print(f"   {severity_emoji} {vuln.get('type', 'Unknown')}")
            all_vulnerabilities.extend(main_vulnerabilities)
        
        if not all_vulnerabilities:
            print("✅ 検出された脆弱性はありません")
        
        self.results['vulnerabilities'] = all_vulnerabilities
        
        print("🎉 Webアプリケーションスキャンが完了しました！")
        return self.results 