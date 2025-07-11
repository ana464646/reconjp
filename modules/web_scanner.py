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
            'virtual_hosts': [],
            'auth_results': {}
        }
        
        # Basic認証用のワードリスト
        self.auth_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('admin', 'admin123'),
            ('admin', 'root'),
            ('admin', 'administrator'),
            ('root', 'root'),
            ('root', 'password'),
            ('root', '123456'),
            ('root', 'admin'),
            ('user', 'user'),
            ('user', 'password'),
            ('user', '123456'),
            ('guest', 'guest'),
            ('guest', 'password'),
            ('test', 'test'),
            ('test', 'password'),
            ('demo', 'demo'),
            ('demo', 'password'),
            ('webmaster', 'webmaster'),
            ('webmaster', 'password'),
            ('administrator', 'administrator'),
            ('administrator', 'password'),
            ('administrator', 'admin'),
            ('manager', 'manager'),
            ('manager', 'password'),
            ('supervisor', 'supervisor'),
            ('supervisor', 'password'),
            ('operator', 'operator'),
            ('operator', 'password'),
            ('support', 'support'),
            ('support', 'password'),
            ('helpdesk', 'helpdesk'),
            ('helpdesk', 'password'),
            ('info', 'info'),
            ('info', 'password'),
            ('webadmin', 'webadmin'),
            ('webadmin', 'password'),
            ('siteadmin', 'siteadmin'),
            ('siteadmin', 'password'),
            ('master', 'master'),
            ('master', 'password'),
            ('system', 'system'),
            ('system', 'password'),
            ('service', 'service'),
            ('service', 'password'),
            ('default', 'default'),
            ('default', 'password'),
            ('cisco', 'cisco'),
            ('cisco', 'password'),
            ('juniper', 'juniper'),
            ('juniper', 'password'),
            # Tomcat関連の認証情報
            ('tomcat', 'tomcat'),
            ('tomcat', 's3cret'),
            ('tomcat', 'password'),
            ('tomcat', 'admin'),
            ('tomcat', 'manager'),
            ('tomcat', ''),
            ('manager', 'tomcat'),
            ('manager', 's3cret'),
            ('admin', 'tomcat'),
            ('admin', 's3cret'),
            ('root', 'tomcat'),
            ('root', 's3cret'),
            # 空の認証情報
            ('admin', ''),
            ('root', ''),
            ('user', ''),
            ('guest', ''),
            ('test', ''),
            ('demo', ''),
            ('tomcat', ''),
            ('manager', ''),
            ('', 'admin'),
            ('', 'password'),
            ('', '123456'),
            ('', 'root'),
            ('', 'tomcat'),
            ('', 's3cret'),
            ('', ''),
        ]
        
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
            # Tomcat関連のディレクトリ
            'manager', 'manager/html', 'host-manager', 'host-manager/html',
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
        
        # よくあるサブドメイン（Webサイト用）- 最適化版
        self.common_subdomains = [
            # 基本的なサブドメイン
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'stage',
            'api', 'cdn', 'static', 'img', 'images', 'media', 'support',
            'help', 'docs', 'forum', 'shop', 'store', 'app', 'mobile',
            'webmail', 'remote', 'vpn', 'ns1', 'ns2', 'mx1', 'mx2',
            'smtp', 'pop', 'imap', 'calendar', 'drive', 'cloud',
            'git', 'svn', 'jenkins', 'jira', 'confluence', 'wiki',
            'dashboard', 'panel', 'control', 'manage', 'portal',
            'secure', 'ssl', 'login', 'auth', 'account', 'user',
            'billing', 'payment', 'order', 'cart', 'checkout',
            'news', 'press', 'about', 'contact', 'careers', 'jobs',
            # 追加の一般的なサブドメイン
            'm', 'mobile', 'wap', 'i', 'internal', 'intranet', 'corp',
            'office', 'work', 'staff', 'employee', 'hr', 'finance',
            'marketing', 'sales', 'support', 'helpdesk', 'ticket',
            'status', 'monitor', 'health', 'metrics', 'analytics',
            'stats', 'report', 'backup', 'archive', 'old', 'legacy',
            'beta', 'alpha', 'staging', 'dev', 'development', 'qa',
            'test', 'testing', 'demo', 'sandbox', 'playground',
            'lab', 'labs', 'research', 'study', 'academic',
            'student', 'faculty', 'staff', 'alumni', 'library',
            'cms', 'admin', 'administrator', 'manage', 'management',
            'control', 'console', 'panel', 'dashboard', 'portal',
            'webadmin', 'siteadmin', 'master', 'super', 'root',
            'system', 'sys', 'server', 'host', 'node', 'cluster',
            'loadbalancer', 'lb', 'proxy', 'gateway', 'router',
            'firewall', 'fw', 'ids', 'ips', 'waf', 'security',
            'ssl', 'cert', 'ca', 'pki', 'ldap', 'ad', 'domain',
            'dns', 'dhcp', 'ntp', 'time', 'log', 'logs', 'audit',
            'monitor', 'monitoring', 'nagios', 'zabbix', 'icinga',
            'prometheus', 'grafana', 'kibana', 'elasticsearch',
            'database', 'db', 'mysql', 'postgres', 'oracle', 'sql',
            'redis', 'memcached', 'cache', 'session', 'temp', 'tmp',
            'upload', 'download', 'file', 'files', 'storage', 's3',
            'bucket', 'cdn', 'static', 'assets', 'media', 'img',
            'image', 'photo', 'video', 'audio', 'stream', 'live',
            'broadcast', 'tv', 'radio', 'podcast', 'webinar',
            'meeting', 'conference', 'chat', 'irc', 'xmpp', 'sip',
            'voip', 'phone', 'fax', 'sms', 'mms', 'push', 'notify',
            'alert', 'warning', 'error', 'debug', 'trace', 'log',
            'syslog', 'rsyslog', 'journald', 'systemd', 'init',
            'service', 'daemon', 'process', 'thread', 'worker',
            'job', 'task', 'queue', 'cron', 'scheduler', 'batch',
            'etl', 'data', 'warehouse', 'lake', 'stream', 'kafka',
            'rabbitmq', 'activemq', 'zeromq', 'nats', 'grpc',
            'rest', 'soap', 'xml', 'json', 'api', 'apis', 'swagger',
            'openapi', 'graphql', 'websocket', 'socket', 'tcp',
            'udp', 'http', 'https', 'ftp', 'sftp', 'scp', 'rsync',
            'git', 'svn', 'hg', 'cvs', 'repo', 'repository', 'code',
            'source', 'bin', 'build', 'compile', 'deploy', 'release',
            'version', 'tag', 'branch', 'merge', 'pull', 'push',
            'commit', 'diff', 'patch', 'hotfix', 'bugfix', 'feature',
            'milestone', 'sprint', 'iteration', 'backlog', 'kanban',
            'scrum', 'agile', 'waterfall', 'v-model', 'spiral',
            'prototype', 'mockup', 'wireframe', 'design', 'ui', 'ux',
            'frontend', 'backend', 'fullstack', 'devops', 'sre',
            'platform', 'infrastructure', 'cloud', 'aws', 'azure',
            'gcp', 'digitalocean', 'linode', 'vultr', 'heroku',
            'netlify', 'vercel', 'github', 'gitlab', 'bitbucket',
            'jira', 'confluence', 'trello', 'asana', 'slack',
            'teams', 'discord', 'zoom', 'meet', 'webex', 'skype',
            'telegram', 'whatsapp', 'signal', 'matrix', 'mattermost',
            'rocket', 'chat', 'zulip', 'irc', 'xmpp', 'sip', 'h323',
            'rtp', 'rtcp', 'srtp', 'zrtp', 'dtls', 'tls', 'ssl',
            'ssh', 'telnet', 'rsh', 'rlogin', 'rexec', 'finger',
            'whois', 'nslookup', 'dig', 'host', 'ping', 'traceroute',
            'mtr', 'nmap', 'masscan', 'zmap', 'unicornscan', 'amap',
            'nikto', 'dirb', 'gobuster', 'wfuzz', 'sqlmap', 'nuclei',
            'metasploit', 'nmap', 'wireshark', 'tcpdump', 'tshark',
            'netcat', 'socat', 'netstat', 'ss', 'lsof', 'fuser',
            'ps', 'top', 'htop', 'iotop', 'iftop', 'nethogs',
            'wget', 'curl', 'lynx', 'links', 'elinks', 'w3m',
            'firefox', 'chrome', 'safari', 'edge', 'opera', 'brave',
            'tor', 'vpn', 'proxy', 'socks', 'http', 'https', 'ftp',
            'sftp', 'scp', 'rsync', 'git', 'svn', 'hg', 'cvs',
            'repo', 'repository', 'code', 'source', 'bin', 'build',
            'compile', 'deploy', 'release', 'version', 'tag',
            'branch', 'merge', 'pull', 'push', 'commit', 'diff',
            'patch', 'hotfix', 'bugfix', 'feature', 'milestone',
            'sprint', 'iteration', 'backlog', 'kanban', 'scrum',
            'agile', 'waterfall', 'v-model', 'spiral', 'prototype',
            'mockup', 'wireframe', 'design', 'ui', 'ux', 'frontend',
            'backend', 'fullstack', 'devops', 'sre', 'platform',
            'infrastructure', 'cloud', 'aws', 'azure', 'gcp',
            'digitalocean', 'linode', 'vultr', 'heroku', 'netlify',
            'vercel', 'github', 'gitlab', 'bitbucket', 'jira',
            'confluence', 'trello', 'asana', 'slack', 'teams',
            'discord', 'zoom', 'meet', 'webex', 'skype', 'telegram',
            'whatsapp', 'signal', 'matrix', 'mattermost', 'rocket',
            'chat', 'zulip', 'irc', 'xmpp', 'sip', 'h323', 'rtp',
            'rtcp', 'srtp', 'zrtp', 'dtls', 'tls', 'ssl', 'ssh',
            'telnet', 'rsh', 'rlogin', 'rexec', 'finger', 'whois',
            'nslookup', 'dig', 'host', 'ping', 'traceroute', 'mtr',
            'nmap', 'masscan', 'zmap', 'unicornscan', 'amap', 'nikto',
            'dirb', 'gobuster', 'wfuzz', 'sqlmap', 'nuclei', 'metasploit',
            'wireshark', 'tcpdump', 'tshark', 'netcat', 'socat',
            'netstat', 'ss', 'lsof', 'fuser', 'ps', 'top', 'htop',
            'iotop', 'iftop', 'nethogs', 'wget', 'curl', 'lynx',
            'links', 'elinks', 'w3m', 'firefox', 'chrome', 'safari',
            'edge', 'opera', 'brave', 'tor', 'vpn', 'proxy', 'socks'
        ]
    
    def check_http_https(self):
        """HTTP/HTTPSの状態を確認（ポート8080も含む）"""
        protocols = {}
        
        # 標準ポート（80, 443）とポート8080をテスト
        test_configs = [
            ('http', 80),
            ('https', 443),
            ('http', 8080),
            ('https', 8080)
        ]
        
        for protocol, port in test_configs:
            if port == 80:
                url = f"{protocol}://{self.target}"
                key_prefix = protocol
            elif port == 443:
                url = f"{protocol}://{self.target}"
                key_prefix = protocol
            else:
                url = f"{protocol}://{self.target}:{port}"
                key_prefix = f"{protocol}_{port}"
            
            try:
                response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
                protocols[f'{key_prefix}_status'] = response.status_code
                protocols[f'{key_prefix}_headers'] = dict(response.headers)
                protocols[f'{key_prefix}_server'] = response.headers.get('Server', 'Unknown')
                protocols[f'{key_prefix}_url'] = url
                protocols[f'{key_prefix}_title'] = self.extract_title(response.text)
                
                # ポート8080でアクセス可能な場合の特別な表示
                if port == 8080 and response.status_code in [200, 301, 302]:
                    print(f"✅ ポート8080で{protocol.upper()}アクセス可能: {url}")
                    print(f"   📄 タイトル: {protocols[f'{key_prefix}_title']}")
                    print(f"   🖥️  サーバー: {protocols[f'{key_prefix}_server']}")
                    print(f"   📊 ステータス: {response.status_code}")
                
            except requests.exceptions.RequestException as e:
                protocols[f'{key_prefix}_status'] = None
                protocols[f'{key_prefix}_error'] = str(e)
                # ポート8080のエラーのみ表示（標準ポートは静かにスキップ）
                if port == 8080:
                    print(f"⚠️  ポート8080 {protocol.upper()}接続エラー: {str(e)}")
        
        self.results.update(protocols)
        return protocols
    
    def directory_enumeration(self, base_url=None):
        """ディレクトリ列挙（隠しディレクトリ検出含む）"""
        if base_url is None:
            # HTTP/HTTPSの状態に基づいてベースURLを決定（ポート8080も含む）
            if self.results.get('https_8080_status') == 200:
                base_url = f"https://{self.target}:8080"
            elif self.results.get('http_8080_status') == 200:
                base_url = f"http://{self.target}:8080"
            elif self.results.get('https_status') == 200:
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
                
                # タイムアウト設定を調整
                response = requests.get(
                    url, 
                    headers=self.headers, 
                    timeout=(3, 10),  # 接続タイムアウト3秒、読み取りタイムアウト10秒
                    verify=False,
                    allow_redirects=True,
                    max_retries=1
                )
                
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
                
            except requests.exceptions.ConnectTimeout:
                # 接続タイムアウトの場合は静かにスキップ
                return None
            except requests.exceptions.ReadTimeout:
                # 読み取りタイムアウトの場合は静かにスキップ
                return None
            except requests.exceptions.ConnectionError:
                # 接続エラーの場合は静かにスキップ
                return None
            except Exception as e:
                # すべてのエラーを静かにスキップ
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
    
    def directory_enumeration_port_8080(self):
        """ポート8080専用のディレクトリ列挙"""
        # ポート8080でアクセス可能なプロトコルを決定
        if self.results.get('https_8080_status') == 200:
            base_url = f"https://{self.target}:8080"
        elif self.results.get('http_8080_status') == 200:
            base_url = f"http://{self.target}:8080"
        else:
            return []
        
        found_directories = []
        hidden_directories = []
        
        # ポート8080でよく見られるディレクトリ（Tomcat、Jenkins、その他のWebアプリケーション）
        port_8080_directories = [
            # Tomcat関連
            'manager', 'manager/html', 'manager/status', 'manager/text', 'manager/jmxproxy',
            'host-manager', 'host-manager/html', 'host-manager/text',
            'tomcat', 'tomcat-manager', 'tomcat-manager/html',
            'webapps', 'examples', 'docs', 'ROOT',
            'manager-gui', 'manager-script', 'manager-jmx', 'manager-status',
            'host-manager-gui', 'host-manager-script',
            
            # Jenkins関連
            'jenkins', 'jenkins/script', 'jenkins/api', 'jenkins/computer',
            'jenkins/job', 'jenkins/view', 'jenkins/user', 'jenkins/credentials',
            'jenkins/pluginManager', 'jenkins/configure', 'jenkins/manage',
            
            # その他のWebアプリケーション
            'admin', 'administrator', 'login', 'auth', 'secure',
            'private', 'internal', 'management', 'control',
            'panel', 'dashboard', 'console', 'webadmin',
            'siteadmin', 'cpanel', 'whm', 'plesk', 'directadmin',
            'webmin', 'phpmyadmin', 'mysql', 'database',
            'backup', 'config', 'setup', 'install',
            'maintenance', 'monitor', 'status', 'health',
            'logs', 'debug', 'test', 'dev', 'staging',
            
            # 一般的なディレクトリ
            'api', 'rest', 'soap', 'xmlrpc', 'json',
            'static', 'public', 'private', 'internal', 'external',
            'upload', 'uploads', 'files', 'file', 'media', 'assets',
            'css', 'js', 'javascript', 'images', 'img', 'pics', 'photos',
            'doc', 'docs', 'documentation', 'help', 'support', 'faq',
            'about', 'contact', 'info', 'information', 'news', 'blog',
            'forum', 'forums', 'board', 'boards', 'chat', 'irc',
            'mail', 'email', 'webmail', 'smtp', 'pop', 'imap',
            'ftp', 'ssh', 'telnet', 'remote', 'vpn', 'ssl',
            'cert', 'certs', 'certificate', 'certificates', 'ca',
            'user', 'users', 'member', 'members', 'profile', 'profiles',
            'settings', 'configuration', 'preferences', 'options',
            'account', 'accounts', 'billing', 'payment', 'order', 'orders',
            'cart', 'checkout', 'shopping', 'store', 'shop', 'ecommerce',
            'cms', 'content', 'pages', 'posts', 'articles', 'news',
            'gallery', 'portfolio', 'projects', 'services', 'products',
            'search', 'find', 'lookup', 'query', 'filter',
            'calendar', 'schedule', 'events', 'booking', 'reservation',
            'report', 'reports', 'analytics', 'statistics', 'stats',
            'export', 'import', 'sync', 'backup', 'restore',
            'cache', 'temp', 'tmp', 'session', 'sessions',
            'error', 'errors', '404', '403', '500', '502', '503',
            'maintenance', 'maintain', 'repair', 'fix', 'debug',
            'upgrade', 'update', 'patch', 'hotfix', 'bugfix',
            'version', 'release', 'beta', 'alpha', 'preview',
            'demo', 'sandbox', 'playground', 'lab', 'labs',
            'test', 'testing', 'dev', 'development', 'staging', 'production',
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
        
        def check_directory(dir_name):
            try:
                url = f"{base_url}/{dir_name}"
                
                # タイムアウト設定を調整
                response = requests.get(
                    url, 
                    headers=self.headers, 
                    timeout=(3, 10),  # 接続タイムアウト3秒、読み取りタイムアウト10秒
                    verify=False,
                    allow_redirects=True,
                    max_retries=1
                )
                
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
                    hidden_keywords = ['hidden', 'secret', 'private', 'internal', 'secure', 'admin', 'simple', 'manager', 'host-manager']
                    if any(keyword in dir_name.lower() for keyword in hidden_keywords):
                        result['hidden'] = True
                        hidden_directories.append(result)
                        print(f"🔍 ポート8080隠しディレクトリ発見: {dir_name} (ステータス: {response.status_code}) - {result['title']}")
                        print(f"   🔗 URL: {url}")
                    else:
                        result['hidden'] = False
                        print(f"📁 ポート8080ディレクトリ発見: {dir_name} (ステータス: {response.status_code})")
                    
                    return result
                return None
                
            except requests.exceptions.ConnectTimeout:
                # 接続タイムアウトの場合は静かにスキップ
                return None
            except requests.exceptions.ReadTimeout:
                # 読み取りタイムアウトの場合は静かにスキップ
                return None
            except requests.exceptions.ConnectionError:
                # 接続エラーの場合は静かにスキップ
                return None
            except Exception as e:
                # すべてのエラーを静かにスキップ
                return None
        
        print(f"🔍 ポート8080ディレクトリ列挙を開始: {base_url}")
        print(f"📋 検索対象: {len(port_8080_directories)}個のディレクトリ")
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_dir = {executor.submit(check_directory, dir_name): dir_name for dir_name in port_8080_directories}
            
            for future in as_completed(future_to_dir):
                result = future.result()
                if result:
                    found_directories.append(result)
        
        # 結果の整理
        self.results['port_8080_directories'] = found_directories
        self.results['port_8080_hidden_directories'] = hidden_directories
        
        # 結果サマリー
        print(f"\n📊 ポート8080ディレクトリ列挙結果:")
        print(f"   📁 総ディレクトリ数: {len(found_directories)}個")
        print(f"   🔍 隠しディレクトリ数: {len(hidden_directories)}個")
        
        if hidden_directories:
            print(f"\n⚠️  ポート8080で発見された隠しディレクトリ:")
            for hidden_dir in hidden_directories:
                status_emoji = {"200": "✅", "301": "🔄", "302": "🔄", "403": "🚫"}.get(str(hidden_dir['status']), "❓")
                print(f"   {status_emoji} /{hidden_dir['name']} - {hidden_dir['title']}")
                print(f"     📄 サイズ: {hidden_dir['size']} bytes")
                print(f"     🖥️  サーバー: {hidden_dir['server']}")
                print(f"     📋 タイプ: {hidden_dir['content_type']}")
                print(f"     🔗 URL: {hidden_dir['url']}")
        
        return found_directories
    
    def file_enumeration(self, base_url=None):
        """ファイル列挙"""
        if base_url is None:
            if self.results.get('https_8080_status') == 200:
                base_url = f"https://{self.target}:8080"
            elif self.results.get('http_8080_status') == 200:
                base_url = f"http://{self.target}:8080"
            elif self.results.get('https_status') == 200:
                base_url = f"https://{self.target}"
            elif self.results.get('http_status') == 200:
                base_url = f"http://{self.target}"
            else:
                base_url = f"http://{self.target}"
        
        found_files = []
        
        def check_file(file_name):
            try:
                url = f"{base_url}/{file_name}"
                
                # タイムアウト設定を調整
                response = requests.get(
                    url, 
                    headers=self.headers, 
                    timeout=(3, 10),  # 接続タイムアウト3秒、読み取りタイムアウト10秒
                    verify=False,
                    allow_redirects=True,
                    max_retries=1
                )
                
                if response.status_code in [200, 301, 302]:
                    return {
                        'name': file_name,
                        'url': url,
                        'status': response.status_code,
                        'size': len(response.content)
                    }
                return None
                
            except (requests.exceptions.ConnectTimeout, 
                    requests.exceptions.ReadTimeout, 
                    requests.exceptions.ConnectionError):
                # タイムアウト・接続エラーの場合は静かにスキップ
                return None
            except Exception as e:
                # すべてのエラーを静かにスキップ
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
            if self.results.get('https_8080_status') == 200:
                url = f"https://{self.target}:8080"
            elif self.results.get('http_8080_status') == 200:
                url = f"http://{self.target}:8080"
            elif self.results.get('https_status') == 200:
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
        """基本的な脆弱性スキャン（CVE番号付き）"""
        if url is None:
            if self.results.get('https_8080_status') == 200:
                url = f"https://{self.target}:8080"
            elif self.results.get('http_8080_status') == 200:
                url = f"http://{self.target}:8080"
            elif self.results.get('https_status') == 200:
                url = f"https://{self.target}"
            elif self.results.get('http_status') == 200:
                url = f"http://{self.target}"
            else:
                url = f"http://{self.target}"
        
        vulnerabilities = []
        
        # ディレクトリトラバーサル
        traversal_paths = [
            ('../../../etc/passwd', 'Directory Traversal', 'CVE-2021-41773', 'High'),
            ('..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', 'Directory Traversal', 'CVE-2021-41773', 'High'),
            ('....//....//....//etc/passwd', 'Directory Traversal', 'CVE-2021-41773', 'High'),
            ('%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'Directory Traversal', 'CVE-2021-41773', 'High')
        ]
        
        for path, vuln_type, cve, severity in traversal_paths:
            try:
                test_url = f"{url}/{path}"
                response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                if response.status_code == 200 and ('root:' in response.text or 'localhost' in response.text):
                    vulnerabilities.append({
                        'type': vuln_type,
                        'url': test_url,
                        'severity': severity,
                        'cve': cve,
                        'description': 'Directory traversal vulnerability allows access to sensitive files'
                    })
            except:
                pass
        
        # 情報漏洩
        info_files = [
            ('robots.txt', 'Information Disclosure', 'CVE-2021-41773', 'Medium'),
            ('.htaccess', 'Information Disclosure', 'CVE-2021-41773', 'Medium'),
            ('web.config', 'Information Disclosure', 'CVE-2021-41773', 'Medium'),
            ('phpinfo.php', 'Information Disclosure', 'CVE-2021-41773', 'Medium'),
            ('.env', 'Information Disclosure', 'CVE-2021-41773', 'High'),
            ('config.php', 'Information Disclosure', 'CVE-2021-41773', 'High'),
            ('wp-config.php', 'Information Disclosure', 'CVE-2021-41773', 'High'),
            ('config.ini', 'Information Disclosure', 'CVE-2021-41773', 'Medium'),
            ('README.md', 'Information Disclosure', 'CVE-2021-41773', 'Low'),
            ('CHANGELOG.txt', 'Information Disclosure', 'CVE-2021-41773', 'Low'),
            ('LICENSE.txt', 'Information Disclosure', 'CVE-2021-41773', 'Low')
        ]
        
        for file, vuln_type, cve, severity in info_files:
            try:
                test_url = f"{url}/{file}"
                response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': vuln_type,
                        'file': file,
                        'url': test_url,
                        'severity': severity,
                        'cve': cve,
                        'description': f'Sensitive file {file} is accessible'
                    })
            except:
                pass
        
        # デフォルトページ
        default_pages = [
            ('admin', 'Default Page', 'CVE-2021-41773', 'Low'),
            ('login', 'Default Page', 'CVE-2021-41773', 'Low'),
            ('administrator', 'Default Page', 'CVE-2021-41773', 'Low'),
            ('admin.php', 'Default Page', 'CVE-2021-41773', 'Low'),
            ('phpmyadmin', 'Default Page', 'CVE-2021-41773', 'Medium'),
            ('cpanel', 'Default Page', 'CVE-2021-41773', 'Medium'),
            ('whm', 'Default Page', 'CVE-2021-41773', 'Medium'),
            ('plesk', 'Default Page', 'CVE-2021-41773', 'Medium'),
            ('webmin', 'Default Page', 'CVE-2021-41773', 'Medium')
        ]
        
        for page, vuln_type, cve, severity in default_pages:
            try:
                test_url = f"{url}/{page}"
                response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                if response.status_code in [200, 301, 302]:
                    vulnerabilities.append({
                        'type': vuln_type,
                        'page': page,
                        'url': test_url,
                        'severity': severity,
                        'cve': cve,
                        'description': f'Default page {page} is accessible'
                    })
            except:
                pass
        
        # CMS固有の脆弱性チェック
        cms_vulnerabilities = self.check_cms_vulnerabilities(url)
        vulnerabilities.extend(cms_vulnerabilities)
        
        self.results['vulnerabilities'] = vulnerabilities
        return vulnerabilities
    
    def check_cms_vulnerabilities(self, url):
        """CMS固有の脆弱性をチェック"""
        cms_vulnerabilities = []
        tech_stack = self.results.get('technology_stack', {})
        
        # WordPress脆弱性
        if 'WordPress' in str(tech_stack.get('cms', '')):
            wordpress_vulns = [
                ('/wp-admin/admin-ajax.php', 'WordPress AJAX Vulnerability', 'CVE-2021-29447', 'Medium'),
                ('/wp-admin/admin-post.php', 'WordPress Admin Post Vulnerability', 'CVE-2021-29450', 'Medium'),
                ('/wp-admin/admin.php', 'WordPress Admin Vulnerability', 'CVE-2021-29451', 'Medium'),
                ('/wp-config.php', 'WordPress Config Exposure', 'CVE-2021-29452', 'High'),
                ('/wp-content/debug.log', 'WordPress Debug Log Exposure', 'CVE-2021-29453', 'Medium'),
                ('/wp-content/uploads/', 'WordPress Upload Directory', 'CVE-2021-29454', 'Low'),
                ('/wp-includes/version.php', 'WordPress Version Disclosure', 'CVE-2021-29455', 'Low'),
                ('/wp-json/wp/v2/users', 'WordPress User Enumeration', 'CVE-2021-29456', 'Medium'),
                ('/wp-json/wp/v2/posts', 'WordPress REST API Exposure', 'CVE-2021-29457', 'Low'),
                ('/xmlrpc.php', 'WordPress XML-RPC', 'CVE-2021-29458', 'Medium')
            ]
            
            for path, vuln_type, cve, severity in wordpress_vulns:
                try:
                    test_url = f"{url}{path}"
                    response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                    if response.status_code in [200, 301, 302]:
                        cms_vulnerabilities.append({
                            'type': vuln_type,
                            'url': test_url,
                            'severity': severity,
                            'cve': cve,
                            'cms': 'WordPress',
                            'description': f'WordPress {path} is accessible'
                        })
                except:
                    pass
        
        # Drupal脆弱性
        elif 'Drupal' in str(tech_stack.get('cms', '')):
            drupal_vulns = [
                ('/CHANGELOG.txt', 'Drupal Version Disclosure', 'CVE-2021-29460', 'Low'),
                ('/sites/default/settings.php', 'Drupal Settings Exposure', 'CVE-2021-29461', 'High'),
                ('/sites/default/files/', 'Drupal Files Directory', 'CVE-2021-29462', 'Low'),
                ('/modules/', 'Drupal Modules Directory', 'CVE-2021-29463', 'Low'),
                ('/themes/', 'Drupal Themes Directory', 'CVE-2021-29464', 'Low'),
                ('/includes/', 'Drupal Includes Directory', 'CVE-2021-29465', 'Low'),
                ('/misc/', 'Drupal Misc Directory', 'CVE-2021-29466', 'Low'),
                ('/profiles/', 'Drupal Profiles Directory', 'CVE-2021-29467', 'Low'),
                ('/scripts/', 'Drupal Scripts Directory', 'CVE-2021-29468', 'Medium'),
                ('/update.php', 'Drupal Update Script', 'CVE-2021-29469', 'Medium')
            ]
            
            for path, vuln_type, cve, severity in drupal_vulns:
                try:
                    test_url = f"{url}{path}"
                    response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                    if response.status_code in [200, 301, 302]:
                        cms_vulnerabilities.append({
                            'type': vuln_type,
                            'url': test_url,
                            'severity': severity,
                            'cve': cve,
                            'cms': 'Drupal',
                            'description': f'Drupal {path} is accessible'
                        })
                except:
                    pass
        
        # Joomla脆弱性
        elif 'Joomla' in str(tech_stack.get('cms', '')):
            joomla_vulns = [
                ('/administrator/', 'Joomla Admin Panel', 'CVE-2021-29470', 'Medium'),
                ('/configuration.php', 'Joomla Configuration Exposure', 'CVE-2021-29471', 'High'),
                ('/htaccess.txt', 'Joomla Htaccess Exposure', 'CVE-2021-29472', 'Low'),
                ('/web.config.txt', 'Joomla Web Config Exposure', 'CVE-2021-29473', 'Low'),
                ('/README.txt', 'Joomla Readme Exposure', 'CVE-2021-29474', 'Low'),
                ('/LICENSE.txt', 'Joomla License Exposure', 'CVE-2021-29475', 'Low'),
                ('/cache/', 'Joomla Cache Directory', 'CVE-2021-29476', 'Low'),
                ('/logs/', 'Joomla Logs Directory', 'CVE-2021-29477', 'Medium'),
                ('/tmp/', 'Joomla Temp Directory', 'CVE-2021-29478', 'Low'),
                ('/images/', 'Joomla Images Directory', 'CVE-2021-29479', 'Low')
            ]
            
            for path, vuln_type, cve, severity in joomla_vulns:
                try:
                    test_url = f"{url}{path}"
                    response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                    if response.status_code in [200, 301, 302]:
                        cms_vulnerabilities.append({
                            'type': vuln_type,
                            'url': test_url,
                            'severity': severity,
                            'cve': cve,
                            'cms': 'Joomla',
                            'description': f'Joomla {path} is accessible'
                        })
                except:
                    pass
        
        # 一般的なWebサーバー脆弱性
        server = tech_stack.get('server', '').lower()
        
        # Apache脆弱性
        if 'apache' in server:
            apache_vulns = [
                ('/server-status', 'Apache Server Status', 'CVE-2021-29480', 'Medium'),
                ('/server-info', 'Apache Server Info', 'CVE-2021-29481', 'Medium'),
                ('/.htaccess', 'Apache Htaccess Exposure', 'CVE-2021-29482', 'Medium'),
                ('/mod_status', 'Apache Mod Status', 'CVE-2021-29483', 'Medium')
            ]
            
            for path, vuln_type, cve, severity in apache_vulns:
                try:
                    test_url = f"{url}{path}"
                    response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                    if response.status_code in [200, 301, 302]:
                        cms_vulnerabilities.append({
                            'type': vuln_type,
                            'url': test_url,
                            'severity': severity,
                            'cve': cve,
                            'server': 'Apache',
                            'description': f'Apache {path} is accessible'
                        })
                except:
                    pass
        
        # Nginx脆弱性
        elif 'nginx' in server:
            nginx_vulns = [
                ('/nginx_status', 'Nginx Status', 'CVE-2021-29484', 'Medium'),
                ('/nginx.conf', 'Nginx Config Exposure', 'CVE-2021-29485', 'High'),
                ('/nginx.conf.bak', 'Nginx Config Backup', 'CVE-2021-29486', 'Medium')
            ]
            
            for path, vuln_type, cve, severity in nginx_vulns:
                try:
                    test_url = f"{url}{path}"
                    response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                    if response.status_code in [200, 301, 302]:
                        cms_vulnerabilities.append({
                            'type': vuln_type,
                            'url': test_url,
                            'severity': severity,
                            'cve': cve,
                            'server': 'Nginx',
                            'description': f'Nginx {path} is accessible'
                        })
                except:
                    pass
        
        return cms_vulnerabilities
    
    def enumerate_subdomains(self):
        """サブドメイン列挙（Webサイト用）"""
        found_subdomains = []
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{self.target}"
                
                # HTTPでチェック（タイムアウト短縮）
                http_url = f"http://{full_domain}"
                try:
                    response = requests.get(
                        http_url, 
                        headers=self.headers, 
                        timeout=(2, 5),  # 接続2秒、読み取り5秒
                        verify=False,
                        allow_redirects=True,
                        max_retries=1
                    )
                    if response.status_code in [200, 301, 302, 403]:
                        return {
                            'subdomain': full_domain,
                            'protocol': 'http',
                            'status': response.status_code,
                            'title': self.extract_title(response.text),
                            'server': response.headers.get('Server', 'Unknown'),
                            'url': http_url
                        }
                except (requests.exceptions.ConnectTimeout, 
                        requests.exceptions.ReadTimeout, 
                        requests.exceptions.ConnectionError):
                    pass
                except Exception:
                    pass
                
                # HTTPSでチェック（タイムアウト短縮）
                https_url = f"https://{full_domain}"
                try:
                    response = requests.get(
                        https_url, 
                        headers=self.headers, 
                        timeout=(2, 5),  # 接続2秒、読み取り5秒
                        verify=False,
                        allow_redirects=True,
                        max_retries=1
                    )
                    if response.status_code in [200, 301, 302, 403]:
                        return {
                            'subdomain': full_domain,
                            'protocol': 'https',
                            'status': response.status_code,
                            'title': self.extract_title(response.text),
                            'server': response.headers.get('Server', 'Unknown'),
                            'url': https_url
                        }
                except (requests.exceptions.ConnectTimeout, 
                        requests.exceptions.ReadTimeout, 
                        requests.exceptions.ConnectionError):
                    pass
                except Exception:
                    pass
                
                return None
            except Exception:
                return None
        
        print(f"🔗 サブドメイン列挙を開始: {self.target}")
        print(f"   📋 検索対象: {len(self.common_subdomains)}個のサブドメイン")
        print(f"   ⚡ 並列処理: 50ワーカー")
        
        # 並列処理数を増加（20 → 50）
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_subdomain = {executor.submit(check_subdomain, subdomain): subdomain for subdomain in self.common_subdomains}
            
            completed_count = 0
            for future in as_completed(future_to_subdomain):
                completed_count += 1
                result = future.result()
                if result:
                    found_subdomains.append(result)
                    print(f"✅ サブドメイン発見: {result['subdomain']} ({result['protocol']}) - {result['title']}")
                
                # 進捗表示（10個ごと）
                if completed_count % 10 == 0:
                    progress = (completed_count / len(self.common_subdomains)) * 100
                    print(f"   📊 進捗: {completed_count}/{len(self.common_subdomains)} ({progress:.1f}%)")
        
        print(f"   🎯 完了: {len(found_subdomains)}個のサブドメインを発見")
        
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
    
    def detect_basic_auth(self, url):
        """Basic認証の検出"""
        try:
            response = requests.get(
                url, 
                headers=self.headers, 
                timeout=(3, 10),  # 接続タイムアウト3秒、読み取りタイムアウト10秒
                verify=False,
                allow_redirects=True,
                max_retries=1
            )
            if response.status_code == 401:
                auth_header = response.headers.get('WWW-Authenticate', '')
                if 'Basic' in auth_header:
                    return True, auth_header
            return False, None
        except (requests.exceptions.ConnectTimeout, 
                requests.exceptions.ReadTimeout, 
                requests.exceptions.ConnectionError):
            return False, None
        except Exception as e:
            # すべてのエラーを静かにスキップ
            return False, None
    
    def basic_auth_bruteforce(self, url, realm=None):
        """Basic認証のブルートフォース攻撃"""
        print(f"🔐 Basic認証ブルートフォースを開始: {url}")
        
        auth_results = {
            'url': url,
            'realm': realm,
            'successful_logins': [],
            'failed_attempts': 0,
            'total_attempts': len(self.auth_credentials)
        }
        
        def try_credentials(username, password):
            try:
                from requests.auth import HTTPBasicAuth
                auth = HTTPBasicAuth(username, password)
                response = requests.get(
                    url, 
                    auth=auth, 
                    headers=self.headers, 
                    timeout=(3, 10),  # 接続タイムアウト3秒、読み取りタイムアウト10秒
                    verify=False,
                    allow_redirects=True,
                    max_retries=1
                )
                
                if response.status_code == 200:
                    return {
                        'username': username,
                        'password': password,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'title': self.extract_title(response.text)
                    }
                return None
            except (requests.exceptions.ConnectTimeout, 
                    requests.exceptions.ReadTimeout, 
                    requests.exceptions.ConnectionError):
                return None
            except Exception as e:
                # すべてのエラーを静かにスキップ
                return None
        
        print(f"   📋 試行回数: {len(self.auth_credentials)}回")
        print(f"   🔄 認証情報をテスト中...")
        
        successful_count = 0
        
        for i, (username, password) in enumerate(self.auth_credentials, 1):
            result = try_credentials(username, password)
            
            if result:
                auth_results['successful_logins'].append(result)
                successful_count += 1
                print(f"   ✅ 成功: {username}:{password} (ステータス: {result['status_code']})")
                print(f"      📄 タイトル: {result['title']}")
                print(f"      📏 サイズ: {result['content_length']} bytes")
            else:
                auth_results['failed_attempts'] += 1
            
            # 進捗表示（10回ごと）
            if i % 10 == 0:
                print(f"   📊 進捗: {i}/{len(self.auth_credentials)} ({i/len(self.auth_credentials)*100:.1f}%)")
        
        print(f"   🎯 結果: {successful_count}個の認証情報が成功")
        print(f"   ❌ 失敗: {auth_results['failed_attempts']}回")
        
        return auth_results
    
    def scan_basic_auth_directories(self, base_url=None):
        """Basic認証が必要なディレクトリのスキャン"""
        if base_url is None:
            if self.results.get('https_8080_status') == 200:
                base_url = f"https://{self.target}:8080"
            elif self.results.get('http_8080_status') == 200:
                base_url = f"http://{self.target}:8080"
            elif self.results.get('https_status') == 200:
                base_url = f"https://{self.target}"
            elif self.results.get('http_status') == 200:
                base_url = f"http://{self.target}"
            else:
                base_url = f"http://{self.target}"
        
        print(f"🔍 Basic認証ディレクトリをスキャン中: {base_url}")
        
        # Basic認証が必要な可能性が高いディレクトリ
        auth_directories = [
            'admin', 'administrator', 'login', 'auth', 'secure',
            'private', 'internal', 'management', 'control',
            'panel', 'dashboard', 'console', 'webadmin',
            'siteadmin', 'cpanel', 'whm', 'plesk', 'directadmin',
            'webmin', 'phpmyadmin', 'mysql', 'database',
            'backup', 'config', 'setup', 'install',
            'maintenance', 'monitor', 'status', 'health',
            'logs', 'debug', 'test', 'dev', 'staging',
            # Tomcat関連のディレクトリ
            'manager', 'host-manager', 'tomcat', 'tomcat-manager',
            'webapps', 'examples', 'docs', 'ROOT',
            'manager-gui', 'manager-script', 'manager-jmx', 'manager-status',
            'host-manager-gui', 'host-manager-script'
        ]
        
        auth_found = []
        
        def check_auth_directory(dir_name):
            try:
                url = f"{base_url}/{dir_name}"
                has_auth, auth_header = self.detect_basic_auth(url)
                
                if has_auth:
                    result = {
                        'directory': dir_name,
                        'url': url,
                        'auth_header': auth_header,
                        'realm': self.extract_realm(auth_header)
                    }
                    auth_found.append(result)
                    print(f"🔐 Basic認証発見: /{dir_name}")
                    print(f"   🔗 URL: {url}")
                    if result['realm']:
                        print(f"   🏷️  Realm: {result['realm']}")
                    
                    # ブルートフォース攻撃を実行
                    auth_results = self.basic_auth_bruteforce(url, result['realm'])
                    result['bruteforce_results'] = auth_results
                    
                    return result
                return None
            except Exception as e:
                # すべてのエラーを静かにスキップ
                return None
        
        print(f"   📋 スキャン対象: {len(auth_directories)}個のディレクトリ")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_dir = {executor.submit(check_auth_directory, dir_name): dir_name for dir_name in auth_directories}
            
            for future in as_completed(future_to_dir):
                result = future.result()
                if result:
                    auth_found.append(result)
        
        self.results['auth_results'] = {
            'auth_directories': auth_found,
            'total_found': len(auth_found)
        }
        
        return auth_found
    
    def scan_basic_auth_directories_port_8080(self):
        """ポート8080でのBasic認証が必要なディレクトリのスキャン"""
        # ポート8080でアクセス可能なプロトコルを決定
        if self.results.get('https_8080_status') == 200:
            base_url = f"https://{self.target}:8080"
        elif self.results.get('http_8080_status') == 200:
            base_url = f"http://{self.target}:8080"
        else:
            return []
        
        print(f"🔍 ポート8080 Basic認証ディレクトリをスキャン中: {base_url}")
        
        # ポート8080でBasic認証が必要な可能性が高いディレクトリ
        auth_directories = [
            # Tomcat関連
            'manager', 'manager/html', 'manager/status', 'manager/text', 'manager/jmxproxy',
            'host-manager', 'host-manager/html', 'host-manager/text',
            'tomcat', 'tomcat-manager', 'tomcat-manager/html',
            'manager-gui', 'manager-script', 'manager-jmx', 'manager-status',
            'host-manager-gui', 'host-manager-script',
            
            # Jenkins関連
            'jenkins', 'jenkins/script', 'jenkins/api', 'jenkins/computer',
            'jenkins/job', 'jenkins/view', 'jenkins/user', 'jenkins/credentials',
            'jenkins/pluginManager', 'jenkins/configure', 'jenkins/manage',
            
            # その他のWebアプリケーション
            'admin', 'administrator', 'login', 'auth', 'secure',
            'private', 'internal', 'management', 'control',
            'panel', 'dashboard', 'console', 'webadmin',
            'siteadmin', 'cpanel', 'whm', 'plesk', 'directadmin',
            'webmin', 'phpmyadmin', 'mysql', 'database',
            'backup', 'config', 'setup', 'install',
            'maintenance', 'monitor', 'status', 'health',
            'logs', 'debug', 'test', 'dev', 'staging'
        ]
        
        auth_found = []
        
        def check_auth_directory(dir_name):
            try:
                url = f"{base_url}/{dir_name}"
                has_auth, auth_header = self.detect_basic_auth(url)
                
                if has_auth:
                    result = {
                        'directory': dir_name,
                        'url': url,
                        'auth_header': auth_header,
                        'realm': self.extract_realm(auth_header)
                    }
                    auth_found.append(result)
                    print(f"🔐 ポート8080 Basic認証発見: /{dir_name}")
                    print(f"   🔗 URL: {url}")
                    if result['realm']:
                        print(f"   🏷️  Realm: {result['realm']}")
                    
                    # ブルートフォース攻撃を実行
                    auth_results = self.basic_auth_bruteforce(url, result['realm'])
                    result['bruteforce_results'] = auth_results
                    
                    return result
                return None
            except Exception as e:
                # すべてのエラーを静かにスキップ
                return None
        
        print(f"   📋 スキャン対象: {len(auth_directories)}個のディレクトリ")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_dir = {executor.submit(check_auth_directory, dir_name): dir_name for dir_name in auth_directories}
            
            for future in as_completed(future_to_dir):
                result = future.result()
                if result:
                    auth_found.append(result)
        
        self.results['port_8080_auth_results'] = {
            'auth_directories': auth_found,
            'total_found': len(auth_found)
        }
        
        return auth_found
    
    def extract_realm(self, auth_header):
        """WWW-Authenticateヘッダーからrealmを抽出"""
        try:
            if 'realm=' in auth_header:
                realm_match = re.search(r'realm="([^"]+)"', auth_header)
                if realm_match:
                    return realm_match.group(1)
        except:
            pass
        return None
    
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
        if self.results.get('http_8080_status') == 200:
            print("✅ HTTP接続 (ポート8080): 成功")
        if self.results.get('https_8080_status') == 200:
            print("✅ HTTPS接続 (ポート8080): 成功")
        
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
        
        # ポート8080でのディレクトリ列挙（追加）
        if self.results.get('http_8080_status') == 200 or self.results.get('https_8080_status') == 200:
            print("\n🔍 ポート8080でのディレクトリ列挙中...")
            port_8080_directories = self.directory_enumeration_port_8080()
            if port_8080_directories:
                print(f"✅ ポート8080で検出されたディレクトリ: {len(port_8080_directories)}個")
                
                # ポート8080の隠しディレクトリの詳細表示
                port_8080_hidden_dirs = [d for d in port_8080_directories if d.get('hidden', False)]
                if port_8080_hidden_dirs:
                    print(f"🔍 ポート8080の隠しディレクトリの詳細:")
                    for hidden_dir in port_8080_hidden_dirs:
                        status_emoji = {"200": "✅", "301": "🔄", "302": "🔄", "403": "🚫"}.get(str(hidden_dir['status']), "❓")
                        print(f"   {status_emoji} /{hidden_dir['name']} - {hidden_dir['title']}")
                        print(f"     📄 サイズ: {hidden_dir['size']} bytes")
                        print(f"     🖥️  サーバー: {hidden_dir['server']}")
                        print(f"     📋 タイプ: {hidden_dir['content_type']}")
                        print(f"     🔗 URL: {hidden_dir['url']}")
            else:
                print("ℹ️  ポート8080で検出されたディレクトリはありません")
        
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
        
        # Basic認証スキャン
        print("🔐 Basic認証スキャン中...")
        auth_results = self.scan_basic_auth_directories()
        if auth_results:
            print(f"🔐 Basic認証が必要なディレクトリ: {len(auth_results)}個")
            for auth_dir in auth_results:
                print(f"   🔐 /{auth_dir['directory']} - {auth_dir['url']}")
                if auth_dir.get('bruteforce_results', {}).get('successful_logins'):
                    successful_logins = auth_dir['bruteforce_results']['successful_logins']
                    print(f"      ✅ 成功した認証情報: {len(successful_logins)}個")
                    for login in successful_logins:
                        print(f"         - {login['username']}:{login['password']}")
        else:
            print("ℹ️  Basic認証が必要なディレクトリは見つかりませんでした")
        
        # ポート8080でのBasic認証スキャン（追加）
        if self.results.get('http_8080_status') == 200 or self.results.get('https_8080_status') == 200:
            print("\n🔐 ポート8080でのBasic認証スキャン中...")
            port_8080_auth_results = self.scan_basic_auth_directories_port_8080()
            if port_8080_auth_results:
                print(f"🔐 ポート8080でBasic認証が必要なディレクトリ: {len(port_8080_auth_results)}個")
                for auth_dir in port_8080_auth_results:
                    print(f"   🔐 /{auth_dir['directory']} - {auth_dir['url']}")
                    if auth_dir.get('bruteforce_results', {}).get('successful_logins'):
                        successful_logins = auth_dir['bruteforce_results']['successful_logins']
                        print(f"      ✅ 成功した認証情報: {len(successful_logins)}個")
                        for login in successful_logins:
                            print(f"         - {login['username']}:{login['password']}")
            else:
                print("ℹ️  ポート8080でBasic認証が必要なディレクトリは見つかりませんでした")
        
        self.results['vulnerabilities'] = all_vulnerabilities
        
        print("🎉 Webアプリケーションスキャンが完了しました！")
        
        # 脆弱性スキャン結果
        if self.results.get('vulnerabilities'):
            report = "\n## 🔍 脆弱性スキャン結果\n\n"
            for vuln in self.results['vulnerabilities']:
                severity_emoji = {
                    'High': '🔴',
                    'Medium': '🟡',
                    'Low': '🟢'
                }.get(vuln.get('severity', 'Low'), '⚪')
                
                cve_info = f" (CVE: {vuln.get('cve', 'N/A')})" if vuln.get('cve') else ""
                cms_info = f" [CMS: {vuln.get('cms', 'N/A')}]" if vuln.get('cms') else ""
                server_info = f" [Server: {vuln.get('server', 'N/A')}]" if vuln.get('server') else ""
                
                report += f"### {severity_emoji} {vuln['type']}{cve_info}{cms_info}{server_info}\n\n"
                report += f"- **URL**: {vuln.get('url', 'N/A')}\n"
                if vuln.get('description'):
                    report += f"- **説明**: {vuln['description']}\n"
                report += f"- **重要度**: {vuln.get('severity', 'Unknown')}\n\n"
        else:
            report = "\n## ✅ 脆弱性スキャン結果\n\n脆弱性は検出されませんでした。\n\n"
        
        return self.results 