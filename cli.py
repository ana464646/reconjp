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
                for dir_info in web_data['directories'][:10]:  # 最初の10個のみ表示
                    f.write(f"   - /{dir_info['name']} (ステータス: {dir_info['status']})\n")
                if len(web_data['directories']) > 10:
                    f.write(f"   ... 他 {len(web_data['directories']) - 10}個\n")
            
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
        f.write("📧 お問い合わせ: info@reconjp.com\n")
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

def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(
        description='ReconJP - ペネトレーションテスト用偵察ツール',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用例:
  python cli.py example.com                    # 完全な偵察
  python cli.py example.com --network-only     # ネットワーク偵察のみ
  python cli.py example.com --web-only         # Web偵察のみ
  python cli.py example.com --osint-only       # OSINTのみ
  python cli.py example.com -o ./results       # 出力ディレクトリ指定
        """
    )
    
    parser.add_argument('target', help='ターゲットドメインまたはIPアドレス')
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
    
    # 追加オプション
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='詳細な出力を有効にする')
    parser.add_argument('--quiet', '-q', action='store_true', 
                       help='出力を最小限にする')
    
    args = parser.parse_args()
    
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
            
            if 'web' in results:
                web_data = results['web']
                print(f"\n🌐 【Webアプリケーション情報】")
                print(f"  🌐 HTTPステータス: {web_data.get('http_status', 'N/A')}")
                print(f"  🔒 HTTPSステータス: {web_data.get('https_status', 'N/A')}")
                print(f"  📁 検出されたディレクトリ: {len(web_data.get('directories', []))}個")
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