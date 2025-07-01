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
            'vulnerabilities': []
        }
        
        # よくあるディレクトリ
        self.common_directories = [
            'admin', 'login', 'wp-admin', 'phpmyadmin', 'config', 'backup',
            'api', 'docs', 'test', 'dev', 'stage', 'beta', 'old', 'archive',
            'cgi-bin', 'images', 'css', 'js', 'uploads', 'downloads',
            'includes', 'lib', 'src', 'bin', 'tmp', 'temp', 'cache',
            'logs', 'error', 'debug', 'status', 'health', 'monitor'
        ]
        
        # よくあるファイル
        self.common_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
            'phpinfo.php', 'info.php', 'test.php', 'admin.php',
            'config.php', 'wp-config.php', 'config.ini', '.env',
            'README.md', 'CHANGELOG.txt', 'LICENSE.txt'
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
                protocols[f'{protocol}_error'] = str(e)
        
        self.results.update(protocols)
        return protocols
    
    def directory_enumeration(self, base_url=None):
        """ディレクトリ列挙"""
        if base_url is None:
            # HTTP/HTTPSの状態に基づいてベースURLを決定
            if self.results.get('https_status') == 200:
                base_url = f"https://{self.target}"
            elif self.results.get('http_status') == 200:
                base_url = f"http://{self.target}"
            else:
                base_url = f"http://{self.target}"
        
        found_directories = []
        
        def check_directory(dir_name):
            try:
                url = f"{base_url}/{dir_name}"
                response = requests.get(url, headers=self.headers, timeout=5, verify=False)
                if response.status_code in [200, 301, 302, 403]:
                    return {
                        'name': dir_name,
                        'url': url,
                        'status': response.status_code,
                        'size': len(response.content)
                    }
                return None
            except:
                return None
        
        print(f"ディレクトリ列挙を開始: {base_url}")
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_dir = {executor.submit(check_directory, dir_name): dir_name for dir_name in self.common_directories}
            
            for future in as_completed(future_to_dir):
                result = future.result()
                if result:
                    found_directories.append(result)
                    print(f"ディレクトリ発見: {result['name']} (ステータス: {result['status']})")
        
        self.results['directories'] = found_directories
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
            tech_stack['error'] = str(e)
        
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
            print(f"フォーム分析エラー: {str(e)}")
        
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
    
    def run_full_web_scan(self):
        """完全なWebスキャンを実行"""
        print(f"🌐 Webアプリケーションスキャンを開始しています...")
        
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
        if tech_stack:
            print(f"✅ 検出された技術: {len(tech_stack)}種類")
            for tech, value in tech_stack.items():
                print(f"   - {tech}: {value}")
        
        # ディレクトリ列挙
        print("📁 ディレクトリ列挙中...")
        directories = self.directory_enumeration()
        if directories:
            print(f"✅ 検出されたディレクトリ: {len(directories)}個")
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
        
        # 脆弱性スキャン
        print("⚠️  脆弱性スキャン中...")
        vulnerabilities = self.basic_vulnerability_scan()
        if vulnerabilities:
            print(f"⚠️  検出された脆弱性: {len(vulnerabilities)}個")
            for vuln in vulnerabilities:
                severity_emoji = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(vuln.get('severity', 'Low'), "⚪")
                print(f"   {severity_emoji} {vuln.get('type', 'Unknown')}")
        else:
            print("✅ 検出された脆弱性はありません")
        
        print("🎉 Webアプリケーションスキャンが完了しました！")
        return self.results 