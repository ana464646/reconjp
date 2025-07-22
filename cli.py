#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ReconJP - コマンドラインインターフェース
ペネトレーションテスト用偵察ツールのCLI
"""

import os
import sys
import argparse
from datetime import datetime

# モジュールのインポート
from modules.network_scanner import NetworkScanner
from modules.web_scanner import WebScanner
from modules.osint_gatherer import OSINTGatherer
from modules.payload_generator import PayloadGenerator

def print_banner():
    """ツールのバナーを表示"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                    ReconJP - 偵察ツール                      ║
║             ペネトレーションテスト用ネットワーク偵察          ║
║                    Windows/Mac対応                           ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_help():
    """詳細なヘルプ画面を表示"""
    help_text = """
╔══════════════════════════════════════════════════════════════╗
║                    ReconJP - ヘルプ画面                      ║
╚══════════════════════════════════════════════════════════════╝

🎯 【基本使用方法】
  python cli.py <ターゲット> [オプション]

📋 【主要コマンド】
  1. 完全な偵察:
     python cli.py example.com

  2. 特定の偵察のみ:
     python cli.py example.com --network-only    # ネットワーク偵察
     python cli.py example.com --web-only        # Webアプリケーション偵察
     python cli.py example.com --osint-only      # OSINT情報収集

  3. ペイロード生成:
     python cli.py example.com --payload --lhost 192.168.1.100

🔧 【ネットワーク偵察機能】
  • ポートスキャン (TCP/UDP)
  • サービス検出 (FTP, SSH, Telnet, HTTP, HTTPS等)
  • OS検出
  • 認証テスト (匿名ログイン、デフォルト認証情報)

🌐 【Webアプリケーション偵察機能】
  • ディレクトリ探索 (隠しディレクトリ含む)
  • 技術スタック検出 (CMS, フレームワーク, サーバー)
  • サブドメイン列挙
  • 脆弱性スキャン (XSS, SQLインジェクション, ディレクトリトラバーサル等)
  • ファイル検出

📊 【OSINT情報収集機能】
  • WHOIS情報取得
  • DNSレコード取得 (A, AAAA, MX, TXT, NS等)
  • サブドメイン列挙
  • メールアドレス収集
  • SSL証明書情報

🔧 【ペイロード生成機能】
  • よくあるペイロードの一括生成
  • カスタムペイロード生成
  • 複数プラットフォーム対応 (Windows, Linux, Web)
  • エンコーダー対応
  • リスナーコマンド自動生成

📁 【出力ファイル】
  • 日本語レポート (recon_<target>_<timestamp>.txt)
  • ペイロードファイル (payloads/ディレクトリ)
  • 詳細なセキュリティ評価と推奨事項

⚙️ 【主要オプション】
  -o, --output DIR        出力ディレクトリを指定 (デフォルト: recon_results)
  --verbose, -v           詳細な出力を有効にする
  --quiet, -q             出力を最小限にする
  --help, -h              このヘルプ画面を表示

📚 【詳細ヘルプ】
  --help-network          ネットワーク偵察の詳細ヘルプを表示
  --help-web              Webアプリケーション偵察の詳細ヘルプを表示
  --help-osint            OSINT情報収集の詳細ヘルプを表示
  --help-payload          ペイロード生成の詳細ヘルプを表示

🔧 【ペイロード生成オプション】
  --lhost IP              リスナーのIPアドレス (必須)
  --lport PORT            リスナーのポート (デフォルト: 4444)
  --platform PLATFORM     プラットフォーム (windows/linux/web)
  --payload-type TYPE     ペイロードタイプ (reverse_shell/meterpreter/bind_shell)
  --custom-payload NAME   カスタムペイロード名
  --output-format FORMAT  出力形式 (raw/exe/elf/php/jsp/asp)
  --encoder ENCODER       エンコーダー名
  --iterations NUM        エンコーダーの繰り返し回数
  --list-payloads         利用可能なペイロードを一覧表示

📝 【使用例】
  1. 基本的な偵察:
     python cli.py example.com

  2. ネットワーク偵察のみ:
     python cli.py example.com --network-only

  3. カスタム出力ディレクトリ:
     python cli.py example.com -o ./my_results

  4. ペイロード一括生成:
     python cli.py example.com --payload --lhost 192.168.1.100

  5. 特定のペイロード生成:
     python cli.py example.com --payload --platform windows --payload-type meterpreter --lhost 192.168.1.100

  6. カスタムペイロード生成:
     python cli.py example.com --payload --custom-payload windows/meterpreter/reverse_tcp --lhost 192.168.1.100

⚠️ 【注意事項】
  • このツールは教育目的で作成されています
  • 実際のセキュリティ評価には専門家の判断が必要です
  • ターゲットの許可を得てから使用してください
  • 法律に従って適切に使用してください

📞 【サポート】
  • GitHub: https://github.com/yourusername/reconjp
  • ドキュメント: README.md

╔══════════════════════════════════════════════════════════════╗
║                    ヘルプ画面終了                            ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(help_text)

def print_network_help():
    """ネットワーク偵察の詳細ヘルプを表示"""
    help_text = """
╔══════════════════════════════════════════════════════════════╗
║                ネットワーク偵察 - 詳細ヘルプ                  ║
╚══════════════════════════════════════════════════════════════╝

🔧 【ネットワーク偵察機能の詳細】

📡 【ポートスキャン】
  • TCP SYN スキャン (高速)
  • TCP Connect スキャン (確実)
  • UDP スキャン (時間がかかる)
  • よく使われるポート (21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080等)

🔍 【サービス検出】
  • FTP (21) - ファイル転送プロトコル
  • SSH (22) - セキュアシェル
  • Telnet (23) - リモートログイン
  • SMTP (25) - メール送信
  • DNS (53) - ドメインネームシステム
  • HTTP (80) - Webサーバー
  • HTTPS (443) - セキュアWebサーバー
  • MySQL (3306) - データベース
  • RDP (3389) - リモートデスクトップ
  • PostgreSQL (5432) - データベース

💻 【OS検出】
  • TCP/IPスタックフィンガープリンティング
  • 応答時間とTTL値の分析
  • サポートされているオプションの検出

🔐 【認証テスト】
  • 匿名ログインのテスト
  • デフォルト認証情報のテスト
  • よく使われるユーザー名/パスワードの組み合わせ

📊 【出力情報】
  • 開いているポートの一覧
  • 各ポートで動作しているサービス
  • サービスのバージョン情報
  • OS情報
  • 認証テスト結果

⚠️ 【注意事項】
  • ポートスキャンは時間がかかる場合があります
  • ファイアウォールによってブロックされる可能性があります
  • 管理者権限が必要な場合があります

📝 【使用例】
  python cli.py example.com --network-only
  python cli.py 192.168.1.1 --network-only --verbose
    """
    print(help_text)

def print_web_help():
    """Webアプリケーション偵察の詳細ヘルプを表示"""
    help_text = """
╔══════════════════════════════════════════════════════════════╗
║              Webアプリケーション偵察 - 詳細ヘルプ             ║
╚══════════════════════════════════════════════════════════════╝

🌐 【Webアプリケーション偵察機能の詳細】

📁 【ディレクトリ探索】
  • 一般的なディレクトリの探索
  • 隠しディレクトリの探索 (.htaccess, .git, .env等)
  • 管理画面の探索 (admin, wp-admin, phpmyadmin等)
  • バックアップファイルの探索 (.bak, .old, .backup等)

🛠️ 【技術スタック検出】
  • Webサーバー (Apache, Nginx, IIS等)
  • プログラミング言語 (PHP, Python, Node.js等)
  • フレームワーク (WordPress, Drupal, Laravel等)
  • データベース (MySQL, PostgreSQL, MongoDB等)
  • フロントエンド (jQuery, Bootstrap, React等)

🔗 【サブドメイン列挙】
  • DNSレコードからの検出
  • 一般的なサブドメイン名の試行
  • ワイルドカードDNSの検出
  • サブドメインの有効性確認

⚠️ 【脆弱性スキャン】
  • XSS (クロスサイトスクリプティング)
  • SQLインジェクション
  • ディレクトリトラバーサル
  • ファイルインクルージョン
  • コマンドインジェクション
  • 情報漏洩 (エラーメッセージ、デバッグ情報)

📄 【ファイル検出】
  • ロボットファイル (robots.txt)
  • サイトマップ (sitemap.xml)
  • 設定ファイル (.env, config.php等)
  • ログファイル (access.log, error.log等)

📊 【出力情報】
  • HTTP/HTTPSステータス
  • 検出されたディレクトリとファイル
  • 技術スタック情報
  • サブドメイン一覧
  • 脆弱性レポート
  • セキュリティヘッダー情報

⚠️ 【注意事項】
  • 大量のリクエストを送信するため、サーバーに負荷がかかる可能性があります
  • レート制限に引っかかる可能性があります
  • 一部の機能は時間がかかる場合があります

📝 【使用例】
  python cli.py example.com --web-only
  python cli.py example.com --web-only --verbose
    """
    print(help_text)

def print_osint_help():
    """OSINT情報収集の詳細ヘルプを表示"""
    help_text = """
╔══════════════════════════════════════════════════════════════╗
║                 OSINT情報収集 - 詳細ヘルプ                   ║
╚══════════════════════════════════════════════════════════════╝

📊 【OSINT情報収集機能の詳細】

🏢 【WHOIS情報】
  • ドメイン登録者情報
  • レジストラ情報
  • 作成日・更新日・有効期限
  • ネームサーバー情報
  • 管理者連絡先情報

🌐 【DNSレコード】
  • A レコード (IPv4アドレス)
  • AAAA レコード (IPv6アドレス)
  • MX レコード (メールサーバー)
  • TXT レコード (SPF, DKIM等)
  • NS レコード (ネームサーバー)
  • CNAME レコード (エイリアス)
  • PTR レコード (逆引き)

🔗 【サブドメイン列挙】
  • 一般的なサブドメイン名の試行
  • DNSレコードからの検出
  • ワイルドカードDNSの検出
  • サブドメインの有効性確認
  • 逆引きDNS検索

📧 【メールアドレス収集】
  • WHOIS情報からの抽出
  • Webサイトからの抽出
  • ソーシャルメディアからの抽出
  • 公開データベースからの検索

🔒 【SSL証明書情報】
  • 証明書の有効期限
  • 発行者情報
  • サブジェクト代替名 (SAN)
  • 暗号化アルゴリズム
  • 証明書チェーン

📊 【出力情報】
  • WHOIS詳細情報
  • DNSレコード一覧
  • サブドメイン一覧
  • メールアドレス一覧
  • SSL証明書情報
  • セキュリティ評価

⚠️ 【注意事項】
  • 一部の情報は公開されていない場合があります
  • レート制限に引っかかる可能性があります
  • プライバシー保護のため一部情報が隠されている場合があります

📝 【使用例】
  python cli.py example.com --osint-only
  python cli.py example.com --osint-only --verbose
    """
    print(help_text)

def print_payload_help():
    """ペイロード生成の詳細ヘルプを表示"""
    help_text = """
╔══════════════════════════════════════════════════════════════╗
║                 ペイロード生成 - 詳細ヘルプ                  ║
╚══════════════════════════════════════════════════════════════╝

🔧 【ペイロード生成機能の詳細】

💻 【対応プラットフォーム】
  • Windows (exe, dll, ps1)
  • Linux (elf, sh)
  • Web (php, jsp, asp, aspx)

🎯 【ペイロードタイプ】
  • reverse_shell - リバースシェル
  • meterpreter - Metasploit Meterpreter
  • bind_shell - バインドシェル
  • custom - カスタムペイロード

🔧 【出力形式】
  • raw - 生のペイロード
  • exe - Windows実行ファイル
  • elf - Linux実行ファイル
  • php - PHPスクリプト
  • jsp - JSPスクリプト
  • asp - ASPスクリプト

🔐 【エンコーダー】
  • x86/shikata_ga_nai - 多段階エンコーダー
  • x86/xor - XORエンコーダー
  • x86/alpha_mixed - アルファベットエンコーダー
  • x86/countdown - カウントダウンエンコーダー

📋 【よくあるペイロード】
  • Windows Reverse TCP Shell
  • Windows Meterpreter Reverse TCP
  • Linux Reverse TCP Shell
  • Web Shell (PHP, JSP, ASP)
  • PowerShell Reverse Shell

🎧 【リスナーコマンド】
  • Netcat リスナー
  • Metasploit リスナー
  • PowerShell リスナー
  • Python リスナー

📊 【出力情報】
  • 生成されたペイロードファイル
  • ペイロードの詳細情報
  • リスナーコマンド
  • 使用方法の説明

⚠️ 【注意事項】
  • msfvenomが必要です (Metasploit Framework)
  • ペイロードは教育目的でのみ使用してください
  • 実際の攻撃には使用しないでください
  • 法律に従って適切に使用してください

📝 【使用例】
  # よくあるペイロードの一括生成
  python cli.py example.com --payload --lhost 192.168.1.100

  # 特定のペイロード生成
  python cli.py example.com --payload --platform windows --payload-type meterpreter --lhost 192.168.1.100

  # カスタムペイロード生成
  python cli.py example.com --payload --custom-payload windows/meterpreter/reverse_tcp --lhost 192.168.1.100

  # ペイロード一覧表示
  python cli.py example.com --payload --list-payloads
    """
    print(help_text)

def save_results(results, target, output_dir):
    """結果をファイルに保存"""
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 日本語レポートファイル（1つのレポートのみ）
    report_file = os.path.join(output_dir, f"recon_{target}_{timestamp}.txt")
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("🔍 ReconJP - ペネトレーションテスト偵察レポート 📊\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"🎯 ターゲット: {target}\n")
        f.write(f"📅 実行日時: {datetime.now().strftime('%Y年%m月%d日 %H時%M分%S秒')}\n")
        f.write(f"⏱️  実行時間: 約{results.get('scan_time', 'N/A')}秒\n\n")
        
        # ネットワーク情報
        if 'network' in results and results['network']:
            network_data = results['network']
            f.write("🌐 【ネットワーク情報】\n")
            f.write("=" * 50 + "\n")
            
            # エラー情報の表示
            if 'error' in network_data:
                f.write(f"❌ エラー: {network_data['error']}\n\n")
            
            if 'ip' in network_data and network_data['ip']:
                f.write(f"📍 IPアドレス: {network_data['ip']}\n")
            
            if 'open_ports' in network_data and network_data['open_ports']:
                f.write(f"🚪 開いているポート: {len(network_data['open_ports'])}個\n")
                for port in network_data['open_ports']:
                    service = network_data.get('services', {}).get(port, '不明')
                    f.write(f"   - ポート {port}: {service}\n")
            else:
                f.write("🚪 開いているポート: 見つかりませんでした\n")
            
            if 'os_info' in network_data:
                f.write(f"💻 OS情報: {network_data['os_info']}\n")
            
            # 認証テスト結果の表示
            if 'auth_tests' in network_data and network_data['auth_tests']:
                f.write("\n🔐 【認証テスト結果】\n")
                f.write("-" * 30 + "\n")
                for service, auth_result in network_data['auth_tests'].items():
                    f.write(f"📋 {service.upper()}:\n")
                    if auth_result.get('anonymous_login'):
                        f.write(f"   ⚠️  匿名ログイン: 可能\n")
                    if auth_result.get('successful_logins'):
                        f.write(f"   ⚠️  有効な認証情報: {len(auth_result['successful_logins'])}個\n")
                        for login in auth_result['successful_logins']:
                            f.write(f"     - {login['username']}:{login['password']}\n")
                    f.write(f"   📊 失敗回数: {auth_result.get('failed_attempts', 0)}回\n")
            
            f.write("\n")
        
        # Webアプリケーション情報
        if 'web' in results and results['web']:
            web_data = results['web']
            f.write("🌐 【Webアプリケーション情報】\n")
            f.write("=" * 50 + "\n")
            
            if 'http_status' in web_data:
                f.write(f"🌐 HTTPステータス: {web_data['http_status']}\n")
            if 'https_status' in web_data:
                f.write(f"🔒 HTTPSステータス: {web_data['https_status']}\n")
            
            if 'technology_stack' in web_data and web_data['technology_stack']:
                f.write("🛠️  技術スタック:\n")
                for tech, value in web_data['technology_stack'].items():
                    f.write(f"   - {tech}: {value}\n")
            
            if 'directories' in web_data and web_data['directories']:
                f.write(f"📁 検出されたディレクトリ: {len(web_data['directories'])}個\n")
                
                # 隠しディレクトリの表示
                hidden_dirs = [d for d in web_data['directories'] if d.get('hidden', False)]
                if hidden_dirs:
                    f.write(f"🔍 隠しディレクトリ: {len(hidden_dirs)}個\n")
                    for dir_info in hidden_dirs[:10]:  # 最初の10個のみ表示
                        status_emoji = {"200": "✅", "301": "🔄", "302": "🔄", "403": "🚫"}.get(str(dir_info['status']), "❓")
                        f.write(f"   {status_emoji} /{dir_info['name']} - {dir_info.get('title', 'N/A')}\n")
                    if len(hidden_dirs) > 10:
                        f.write(f"   ... 他 {len(hidden_dirs) - 10}個\n")
                
                # 通常のディレクトリの表示
                normal_dirs = [d for d in web_data['directories'] if not d.get('hidden', False)]
                if normal_dirs:
                    f.write(f"📁 通常ディレクトリ: {len(normal_dirs)}個\n")
                    for dir_info in normal_dirs[:5]:  # 最初の5個のみ表示
                        f.write(f"   - /{dir_info['name']} (ステータス: {dir_info['status']})\n")
                    if len(normal_dirs) > 5:
                        f.write(f"   ... 他 {len(normal_dirs) - 5}個\n")
            
            if 'files' in web_data and web_data['files']:
                f.write(f"📄 検出されたファイル: {len(web_data['files'])}個\n")
                for file_info in web_data['files'][:5]:  # 最初の5個のみ表示
                    f.write(f"   - {file_info['name']} (ステータス: {file_info['status']})\n")
                if len(web_data['files']) > 5:
                    f.write(f"   ... 他 {len(web_data['files']) - 5}個\n")
            
            if 'subdomains' in web_data and web_data['subdomains']:
                f.write(f"🔗 検出されたサブドメイン: {len(web_data['subdomains'])}個\n")
                for subdomain in web_data['subdomains'][:5]:  # 最初の5個のみ表示
                    f.write(f"   - {subdomain['subdomain']} ({subdomain['protocol']}) - {subdomain['title']}\n")
                if len(web_data['subdomains']) > 5:
                    f.write(f"   ... 他 {len(web_data['subdomains']) - 5}個\n")
            
            if 'vulnerabilities' in web_data and web_data['vulnerabilities']:
                f.write(f"⚠️  検出された脆弱性: {len(web_data['vulnerabilities'])}個\n")
                for vuln in web_data['vulnerabilities']:
                    severity_emoji = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(vuln.get('severity', 'Low'), "⚪")
                    vuln_url = vuln.get('url', vuln.get('file', vuln.get('page', 'N/A')))
                    if 'subdomain' in vuln:
                        f.write(f"   {severity_emoji} {vuln.get('type', 'Unknown')} ({vuln['subdomain']}): {vuln_url}\n")
                    else:
                        f.write(f"   {severity_emoji} {vuln.get('type', 'Unknown')}: {vuln_url}\n")
            
            f.write("\n")
        
        # OSINT情報
        if 'osint' in results and results['osint']:
            osint_data = results['osint']
            f.write("📊 【OSINT情報】\n")
            f.write("=" * 50 + "\n")
            
            if 'whois_info' in osint_data and osint_data['whois_info']:
                whois = osint_data['whois_info']
                f.write("🏢 WHOIS情報:\n")
                if 'registrar' in whois:
                    f.write(f"   - レジストラ: {whois['registrar']}\n")
                if 'creation_date' in whois:
                    f.write(f"   - 作成日: {whois['creation_date']}\n")
                if 'expiration_date' in whois:
                    f.write(f"   - 有効期限: {whois['expiration_date']}\n")
            
            if 'dns_records' in osint_data and osint_data['dns_records']:
                dns = osint_data['dns_records']
                f.write("🌐 DNSレコード:\n")
                for record_type, records in dns.items():
                    if records:
                        f.write(f"   - {record_type}: {', '.join(records[:3])}")
                        if len(records) > 3:
                            f.write(f" (他 {len(records) - 3}個)")
                        f.write("\n")
            
            if 'subdomains' in osint_data and osint_data['subdomains']:
                f.write(f"🔗 サブドメイン: {len(osint_data['subdomains'])}個\n")
                for subdomain in osint_data['subdomains'][:5]:  # 最初の5個のみ表示
                    f.write(f"   - {subdomain['subdomain']} → {subdomain['ip']}\n")
                if len(osint_data['subdomains']) > 5:
                    f.write(f"   ... 他 {len(osint_data['subdomains']) - 5}個\n")
            
            if 'email_addresses' in osint_data and osint_data['email_addresses']:
                f.write(f"📧 メールアドレス: {len(osint_data['email_addresses'])}個\n")
                for email in osint_data['email_addresses'][:3]:  # 最初の3個のみ表示
                    f.write(f"   - {email}\n")
                if len(osint_data['email_addresses']) > 3:
                    f.write(f"   ... 他 {len(osint_data['email_addresses']) - 3}個\n")
            
            f.write("\n")
        
        # セキュリティ評価
        f.write("🔒 【セキュリティ評価】\n")
        f.write("=" * 50 + "\n")
        
        total_vulns = 0
        high_vulns = 0
        medium_vulns = 0
        low_vulns = 0
        
        if 'web' in results and 'vulnerabilities' in results['web']:
            for vuln in results['web']['vulnerabilities']:
                total_vulns += 1
                severity = vuln.get('severity', 'Low')
                if severity == 'High':
                    high_vulns += 1
                elif severity == 'Medium':
                    medium_vulns += 1
                else:
                    low_vulns += 1
        
        f.write(f"🔴 高リスク脆弱性: {high_vulns}個\n")
        f.write(f"🟡 中リスク脆弱性: {medium_vulns}個\n")
        f.write(f"🟢 低リスク脆弱性: {low_vulns}個\n")
        f.write(f"📊 総脆弱性数: {total_vulns}個\n\n")
        
        # 推奨事項
        f.write("💡 【推奨事項】\n")
        f.write("=" * 50 + "\n")
        
        if high_vulns > 0:
            f.write("🔴 緊急対応が必要:\n")
            f.write("   - 高リスク脆弱性の即座の修正\n")
            f.write("   - セキュリティチームへの報告\n")
            f.write("   - 一時的なアクセス制限の検討\n\n")
        
        if medium_vulns > 0:
            f.write("🟡 計画的な対応が必要:\n")
            f.write("   - 中リスク脆弱性の優先度を付けた修正\n")
            f.write("   - セキュリティポリシーの見直し\n\n")
        
        if total_vulns == 0:
            f.write("✅ 良好な状態:\n")
            f.write("   - 検出された脆弱性はありません\n")
            f.write("   - 定期的なセキュリティ監査を継続\n\n")
        
        f.write("📝 注意事項:\n")
        f.write("   - このレポートは教育目的で作成されています\n")
        f.write("   - 実際のセキュリティ評価には専門家の判断が必要です\n")
        f.write("   - 定期的なセキュリティ監査の実施を推奨します\n\n")
        
        f.write("=" * 80 + "\n")
        f.write("🌐 公式サイト: https://github.com/yourusername/reconjp\n")
        f.write("=" * 80 + "\n")
    
    print(f"📄 レポートが保存されました: {report_file}")
    
    return report_file

def network_reconnaissance(target, output_dir):
    """ネットワーク偵察を実行"""
    print(f"\n🔍 ネットワーク偵察を開始しています...")
    print(f"🎯 ターゲット: {target}")
    
    try:
        scanner = NetworkScanner(target)
        results = scanner.run_full_network_scan()
        
        report_file = save_results(results, target, output_dir)
        print(f"📄 レポートファイル: {report_file}")
        return results
    except Exception as e:
        print(f"❌ ネットワーク偵察でエラーが発生しました: {str(e)}")
        # エラーが発生しても空の結果を返す
        error_results = {
            'target': target,
            'ip': None,
            'open_ports': [],
            'services': {},
            'os_info': {},
            'error': str(e)
        }
        report_file = save_results(error_results, target, output_dir)
        print(f"📄 エラーレポートファイル: {report_file}")
        return error_results

def web_reconnaissance(target, output_dir):
    """Webアプリケーション偵察を実行"""
    print(f"\n🌐 Webアプリケーション偵察を開始しています...")
    print(f"🎯 ターゲット: {target}")
    
    try:
        scanner = WebScanner(target)
        results = scanner.run_full_web_scan()
        
        report_file = save_results(results, target, output_dir)
        print(f"📄 レポートファイル: {report_file}")
        return results
    except Exception as e:
        print(f"❌ Webアプリケーション偵察でエラーが発生しました: {str(e)}")
        # エラーが発生しても空の結果を返す
        error_results = {
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
            'error': str(e)
        }
        report_file = save_results(error_results, target, output_dir)
        print(f"📄 エラーレポートファイル: {report_file}")
        return error_results

def osint_reconnaissance(target, output_dir):
    """OSINT情報収集を実行"""
    print(f"\n📊 OSINT情報収集を開始しています...")
    print(f"🎯 ターゲット: {target}")
    
    try:
        gatherer = OSINTGatherer(target)
        results = gatherer.run_full_osint_gathering()
        
        report_file = save_results(results, target, output_dir)
        print(f"📄 レポートファイル: {report_file}")
        return results
    except Exception as e:
        print(f"❌ OSINT情報収集でエラーが発生しました: {str(e)}")
        # エラーが発生しても空の結果を返す
        error_results = {
            'target': target,
            'whois_info': {},
            'dns_records': {},
            'subdomains': [],
            'email_addresses': [],
            'social_media': [],
            'ssl_info': {},
            'error': str(e)
        }
        report_file = save_results(error_results, target, output_dir)
        print(f"📄 エラーレポートファイル: {report_file}")
        return error_results

def full_reconnaissance(target, output_dir):
    """完全な偵察を実行"""
    print(f"\n🚀 完全な偵察を開始しています...")
    print(f"🎯 ターゲット: {target}")
    print(f"📁 出力先: {output_dir}")
    
    all_results = {
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'network': {},
        'web': {},
        'osint': {}
    }
    
    # ネットワーク偵察
    print("\n1️⃣ ネットワーク偵察を実行中...")
    print("   📡 ポートスキャン、サービス検出、OS検出を行います")
    network_results = network_reconnaissance(target, output_dir)
    all_results['network'] = network_results
    
    # Webアプリケーション偵察
    print("\n2️⃣ Webアプリケーション偵察を実行中...")
    print("   🌐 ディレクトリ探索、技術スタック検出、脆弱性スキャンを行います")
    web_results = web_reconnaissance(target, output_dir)
    all_results['web'] = web_results
    
    # OSINT情報収集
    print("\n3️⃣ OSINT情報収集を実行中...")
    print("   📊 WHOIS情報、DNSレコード、サブドメイン列挙を行います")
    osint_results = osint_reconnaissance(target, output_dir)
    all_results['osint'] = osint_results
    
    # 統合結果を保存
    print("\n📝 統合レポートを作成中...")
    report_file = save_results(all_results, target, output_dir)
    
    print(f"\n✅ 完全な偵察が完了しました！")
    print(f"🎯 ターゲット: {target}")
    print(f"📄 レポートファイル: {report_file}")
    return all_results

def payload_generation(target, output_dir, args):
    """ペイロード生成機能"""
    print("\n🔧 ペイロード生成を開始します...")
    
    # ペイロード生成器の初期化
    payload_dir = os.path.join(output_dir, "payloads")
    generator = PayloadGenerator(payload_dir)
    
    # 利用可能なペイロード一覧表示
    if args.list_payloads:
        generator.list_available_payloads()
        return {'payloads': [], 'message': 'ペイロード一覧を表示しました'}
    
    # msfvenomの存在確認
    if not generator.check_msfvenom():
        print("❌ msfvenomが見つかりません。")
        print("💡 Metasploit Frameworkをインストールしてください:")
        print("   - Kali Linux: sudo apt install metasploit-framework")
        print("   - Windows: https://www.metasploit.com/download")
        print("   - macOS: brew install metasploit")
        return {'payloads': [], 'error': 'msfvenom not found'}
    
    results = {'payloads': [], 'errors': []}
    
    # カスタムペイロードの生成
    if args.custom_payload:
        if not args.lhost:
            print("❌ カスタムペイロード生成には --lhost パラメータが必要です")
            return {'payloads': [], 'error': 'LHOST required for custom payload'}
        
        print(f"🔧 カスタムペイロードを生成中: {args.custom_payload}")
        payload_info = generator.generate_custom_payload(
            payload_name=args.custom_payload,
            lhost=args.lhost,
            lport=args.lport,
            output_format=args.output_format,
            encoder=args.encoder,
            iterations=args.iterations
        )
        
        if payload_info:
            results['payloads'].append(payload_info)
            
            # リスナーコマンドの表示
            listener_commands = generator.get_listener_commands(payload_info)
            if listener_commands:
                print("\n🎧 リスナーコマンド:")
                for cmd_info in listener_commands:
                    print(f"  {cmd_info['tool']}: {cmd_info['command']}")
                    print(f"    # {cmd_info['description']}")
    
    # 特定のペイロードタイプの生成
    elif args.payload_type and args.platform:
        if not args.lhost:
            print("❌ ペイロード生成には --lhost パラメータが必要です")
            return {'payloads': [], 'error': 'LHOST required for payload generation'}
        
        print(f"🔧 {args.platform} {args.payload_type}ペイロードを生成中...")
        payload_info = generator.generate_payload(
            payload_type=args.payload_type,
            platform=args.platform,
            lhost=args.lhost,
            lport=args.lport,
            output_format=args.output_format,
            encoder=args.encoder,
            iterations=args.iterations
        )
        
        if payload_info:
            results['payloads'].append(payload_info)
            
            # リスナーコマンドの表示
            listener_commands = generator.get_listener_commands(payload_info)
            if listener_commands:
                print("\n🎧 リスナーコマンド:")
                for cmd_info in listener_commands:
                    print(f"  {cmd_info['tool']}: {cmd_info['command']}")
                    print(f"    # {cmd_info['description']}")
    
    # よくあるペイロードの一括生成
    else:
        if not args.lhost:
            print("❌ ペイロード生成には --lhost パラメータが必要です")
            return {'payloads': [], 'error': 'LHOST required for payload generation'}
        
        print("🚀 よくあるペイロードを一括生成中...")
        generated_payloads = generator.generate_common_payloads(args.lhost, args.lport)
        results['payloads'].extend(generated_payloads)
        
        # リスナーコマンドの表示
        if generated_payloads:
            print("\n🎧 リスナーコマンド例:")
            for payload_info in generated_payloads[:2]:  # 最初の2個のみ表示
                listener_commands = generator.get_listener_commands(payload_info)
                if listener_commands:
                    print(f"\n📋 {payload_info['description']}:")
                    for cmd_info in listener_commands[:2]:  # 最初の2個のみ表示
                        print(f"  {cmd_info['tool']}: {cmd_info['command']}")
                        print(f"    # {cmd_info['description']}")
    
    # エラーの表示
    if generator.results['errors']:
        print("\n❌ エラー:")
        for error in generator.results['errors']:
            print(f"  - {error}")
        results['errors'].extend(generator.results['errors'])
    
    # 結果の保存
    if results['payloads']:
        generator.save_results()
        print(f"\n✅ {len(results['payloads'])}個のペイロードを生成しました")
        print(f"📁 保存先: {payload_dir}")
        
        # 生成されたペイロードの一覧表示
        print("\n📋 生成されたペイロード:")
        for payload_info in results['payloads']:
            print(f"  📄 {os.path.basename(payload_info['output_file'])}")
            print(f"     - タイプ: {payload_info.get('type', 'custom')}")
            print(f"     - プラットフォーム: {payload_info.get('platform', 'N/A')}")
            print(f"     - サイズ: {payload_info['file_size']} bytes")
            print(f"     - LHOST: {payload_info['lhost']}")
            print(f"     - LPORT: {payload_info['lport']}")
            if payload_info.get('encoder'):
                print(f"     - エンコーダー: {payload_info['encoder']} (x{payload_info['iterations']})")
            print()
    
    return results

def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(
        description='ReconJP - ペネトレーションテスト用偵察ツール',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,  # カスタムヘルプを使用するため無効化
        epilog="""
使用例:
  python cli.py example.com                    # 完全な偵察
  python cli.py example.com --network-only     # ネットワーク偵察のみ
  python cli.py example.com --web-only         # Web偵察のみ
  python cli.py example.com --osint-only       # OSINTのみ
  python cli.py example.com --payload --lhost 192.168.1.100  # ペイロード一括生成
  python cli.py example.com --payload --list-payloads        # ペイロード一覧表示
  python cli.py example.com --payload --platform windows --payload-type meterpreter --lhost 192.168.1.100
  python cli.py example.com --payload --custom-payload windows/meterpreter/reverse_tcp --lhost 192.168.1.100
  python cli.py example.com -o ./results       # 出力ディレクトリ指定
        """
    )
    
    # カスタムヘルプオプションを追加
    parser.add_argument('--help', '-h', action='store_true', help='詳細なヘルプ画面を表示')
    
    # 各機能の詳細ヘルプオプション
    parser.add_argument('--help-network', action='store_true', help='ネットワーク偵察の詳細ヘルプを表示')
    parser.add_argument('--help-web', action='store_true', help='Webアプリケーション偵察の詳細ヘルプを表示')
    parser.add_argument('--help-osint', action='store_true', help='OSINT情報収集の詳細ヘルプを表示')
    parser.add_argument('--help-payload', action='store_true', help='ペイロード生成の詳細ヘルプを表示')
    
    parser.add_argument('target', nargs='?', help='ターゲットドメインまたはIPアドレス')
    parser.add_argument('-o', '--output', default='recon_results', 
                       help='出力ディレクトリ (デフォルト: recon_results)')
    
    # 偵察タイプの選択
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--network-only', action='store_true', 
                      help='ネットワーク偵察のみ実行')
    group.add_argument('--web-only', action='store_true', 
                      help='Webアプリケーション偵察のみ実行')
    group.add_argument('--osint-only', action='store_true', 
                      help='OSINT情報収集のみ実行')
    group.add_argument('--payload', action='store_true',
                      help='ペイロード生成のみ実行')
    
    # 追加オプション
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='詳細な出力を有効にする')
    parser.add_argument('--quiet', '-q', action='store_true', 
                       help='出力を最小限にする')
    
    # ペイロード生成オプション
    parser.add_argument('--lhost', help='リスナーのIPアドレス (ペイロード生成時)')
    parser.add_argument('--lport', type=int, default=4444, help='リスナーのポート (デフォルト: 4444)')
    parser.add_argument('--platform', choices=['windows', 'linux', 'web'], 
                       help='ペイロードのプラットフォーム')
    parser.add_argument('--payload-type', choices=['reverse_shell', 'meterpreter', 'bind_shell', 'custom'],
                       help='ペイロードタイプ')
    parser.add_argument('--custom-payload', help='カスタムペイロード名 (例: windows/meterpreter/reverse_tcp)')
    parser.add_argument('--output-format', choices=['raw', 'exe', 'elf', 'php', 'jsp', 'asp'],
                       default='raw', help='出力形式 (デフォルト: raw)')
    parser.add_argument('--encoder', help='エンコーダー (例: x86/shikata_ga_nai)')
    parser.add_argument('--iterations', type=int, default=1, help='エンコーダーの繰り返し回数 (デフォルト: 1)')
    parser.add_argument('--list-payloads', action='store_true', help='利用可能なペイロードを一覧表示')
    
    args = parser.parse_args()
    
    # ヘルプ画面の表示
    if args.help:
        print_banner()
        print_help()
        sys.exit(0)
    
    # 各機能の詳細ヘルプ表示
    if args.help_network:
        print_banner()
        print_network_help()
        sys.exit(0)
    
    if args.help_web:
        print_banner()
        print_web_help()
        sys.exit(0)
    
    if args.help_osint:
        print_banner()
        print_osint_help()
        sys.exit(0)
    
    if args.help_payload:
        print_banner()
        print_payload_help()
        sys.exit(0)
    
    # ターゲットが指定されていない場合はヘルプを表示
    if not args.target:
        print_banner()
        print_help()
        sys.exit(0)
    
    # バナー表示
    if not args.quiet:
        print_banner()
    
    # 出力ディレクトリの作成
    os.makedirs(args.output, exist_ok=True)
    
    try:
        # 偵察タイプに基づいて実行
        if args.network_only:
            results = network_reconnaissance(args.target, args.output)
        elif args.web_only:
            results = web_reconnaissance(args.target, args.output)
        elif args.osint_only:
            results = osint_reconnaissance(args.target, args.output)
        elif args.payload:
            results = payload_generation(args.target, args.output, args)
        else:
            results = full_reconnaissance(args.target, args.output)
        
        # 結果サマリーの表示
        if not args.quiet:
            print("\n" + "=" * 80)
            print("📋 偵察結果サマリー")
            print("=" * 80)
            
            if 'network' in results:
                network_data = results['network']
                print(f"\n🌐 【ネットワーク情報】")
                print(f"  📍 IPアドレス: {network_data.get('ip', 'N/A')}")
                print(f"  🚪 開いているポート: {len(network_data.get('open_ports', []))}個")
                print(f"  🔧 検出されたサービス: {len(network_data.get('services', {}))}個")
                if network_data.get('os_info'):
                    print(f"  💻 OS情報: {network_data.get('os_info')}")
                
                # 認証テスト結果の表示
                if 'auth_tests' in network_data and network_data['auth_tests']:
                    print(f"  🔐 認証テスト結果:")
                    for service, auth_result in network_data['auth_tests'].items():
                        if auth_result.get('anonymous_login'):
                            print(f"    ⚠️  {service.upper()}匿名ログイン: 可能")
                        if auth_result.get('successful_logins'):
                            print(f"    ⚠️  {service.upper()}有効認証: {len(auth_result['successful_logins'])}個")
                            for login in auth_result['successful_logins'][:3]:  # 最初の3個のみ表示
                                print(f"      - {login['username']}:{login['password']}")
                            if len(auth_result['successful_logins']) > 3:
                                print(f"      ... 他 {len(auth_result['successful_logins']) - 3}個")
            
            if 'web' in results:
                web_data = results['web']
                print(f"\n🌐 【Webアプリケーション情報】")
                print(f"  🌐 HTTPステータス: {web_data.get('http_status', 'N/A')}")
                print(f"  🔒 HTTPSステータス: {web_data.get('https_status', 'N/A')}")
                print(f"  📁 検出されたディレクトリ: {len(web_data.get('directories', []))}個")
                
                # 隠しディレクトリの表示
                hidden_dirs = [d for d in web_data.get('directories', []) if d.get('hidden', False)]
                if hidden_dirs:
                    print(f"  🔍 隠しディレクトリ: {len(hidden_dirs)}個")
                    for hidden_dir in hidden_dirs[:3]:  # 最初の3個のみ表示
                        status_emoji = {"200": "✅", "301": "🔄", "302": "🔄", "403": "🚫"}.get(str(hidden_dir['status']), "❓")
                        print(f"    {status_emoji} /{hidden_dir['name']} - {hidden_dir.get('title', 'N/A')}")
                    if len(hidden_dirs) > 3:
                        print(f"    ... 他 {len(hidden_dirs) - 3}個")
                
                print(f"  📄 検出されたファイル: {len(web_data.get('files', []))}個")
                print(f"  🔗 検出されたサブドメイン: {len(web_data.get('subdomains', []))}個")
                print(f"  ⚠️  検出された脆弱性: {len(web_data.get('vulnerabilities', []))}個")
                
                # サブドメインの詳細表示
                subdomains = web_data.get('subdomains', [])
                if subdomains:
                    print(f"  🔍 サブドメインの詳細:")
                    for subdomain in subdomains[:3]:  # 最初の3個のみ表示
                        print(f"    🔗 {subdomain['subdomain']} ({subdomain['protocol']}) - {subdomain['title']}")
                    if len(subdomains) > 3:
                        print(f"    ... 他 {len(subdomains) - 3}個")
                
                # 脆弱性の詳細表示
                vulnerabilities = web_data.get('vulnerabilities', [])
                if vulnerabilities:
                    print(f"  🔍 脆弱性の詳細:")
                    for vuln in vulnerabilities[:3]:  # 最初の3個のみ表示
                        severity_emoji = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(vuln.get('severity', 'Low'), "⚪")
                        vuln_info = vuln.get('type', 'Unknown')
                        if 'subdomain' in vuln:
                            vuln_info += f" ({vuln['subdomain']})"
                        print(f"    {severity_emoji} {vuln_info}")
                    if len(vulnerabilities) > 3:
                        print(f"    ... 他 {len(vulnerabilities) - 3}個")
                
                # 脆弱性スキャン結果の表示
                if web_data.get('vulnerabilities'):
                    print(f"\n🔍 脆弱性スキャン結果:")
                    for vuln in web_data['vulnerabilities']:
                        severity_emoji = {
                            'High': '🔴',
                            'Medium': '🟡', 
                            'Low': '🟢'
                        }.get(vuln.get('severity', 'Low'), '⚪')
                        
                        cve_info = f" (CVE: {vuln.get('cve', 'N/A')})" if vuln.get('cve') else ""
                        cms_info = f" [CMS: {vuln.get('cms', 'N/A')}]" if vuln.get('cms') else ""
                        server_info = f" [Server: {vuln.get('server', 'N/A')}]" if vuln.get('server') else ""
                        
                        print(f"  {severity_emoji} {vuln['type']}{cve_info}{cms_info}{server_info}")
                        print(f"     URL: {vuln.get('url', 'N/A')}")
                        if vuln.get('description'):
                            print(f"     説明: {vuln['description']}")
                        print()
                else:
                    print(f"\n✅ 脆弱性は検出されませんでした")
            
            if 'osint' in results:
                osint_data = results['osint']
                print(f"\n📊 【OSINT情報】")
                print(f"  🔗 サブドメイン: {len(osint_data.get('subdomains', []))}個")
                print(f"  📧 メールアドレス: {len(osint_data.get('email_addresses', []))}個")
                print(f"  🌐 DNSレコード: {len(osint_data.get('dns_records', {}))}種類")
                if osint_data.get('whois_info', {}).get('registrar'):
                    print(f"  🏢 レジストラ: {osint_data['whois_info']['registrar']}")
        
        print(f"\n✅ 偵察が正常に完了しました！")
        print(f"📁 結果は {args.output} ディレクトリに保存されました。")
        print(f"📝 詳細なレポートは日本語で生成されています。")
        
    except KeyboardInterrupt:
        print("\n\n⚠️ ユーザーによって偵察が中断されました。")
        print("🔄 再度実行する場合は同じコマンドを使用してください。")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ エラーが発生しました: {str(e)}")
        print("🔧 トラブルシューティング:")
        print("   - インターネット接続を確認してください")
        print("   - ターゲットが正しく指定されているか確認してください")
        print("   - 管理者権限が必要な場合があります")
        if args.verbose:
            print("\n📋 詳細なエラー情報:")
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 