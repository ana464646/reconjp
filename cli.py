#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ReconJP - コマンドラインインターフェース
ペネトレーションテスト用偵察ツールのCLI
"""

import os
import sys
import json
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
    
    # JSONファイル
    json_file = os.path.join(output_dir, f"recon_{target}_{timestamp}.json")
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    # テキストファイル
    txt_file = os.path.join(output_dir, f"recon_{target}_{timestamp}.txt")
    with open(txt_file, 'w', encoding='utf-8') as f:
        f.write("=" * 60 + "\n")
        f.write("ReconJP - ペネトレーションテスト偵察レポート\n")
        f.write("=" * 60 + "\n\n")
        
        f.write(f"ターゲット: {target}\n")
        f.write(f"実行日時: {datetime.now().isoformat()}\n\n")
        
        for category, data in results.items():
            f.write(f"【{category.upper()}】\n")
            f.write("-" * 30 + "\n")
            
            if isinstance(data, dict):
                for key, value in data.items():
                    f.write(f"{key}: {value}\n")
            elif isinstance(data, list):
                for item in data:
                    f.write(f"- {item}\n")
            else:
                f.write(f"{data}\n")
            f.write("\n")
    
    print(f"結果が保存されました:")
    print(f"  JSON: {json_file}")
    print(f"  テキスト: {txt_file}")
    
    return json_file, txt_file

def network_reconnaissance(target, output_dir):
    """ネットワーク偵察を実行"""
    print(f"\n🔍 ネットワーク偵察を開始: {target}")
    
    scanner = NetworkScanner(target)
    results = scanner.run_full_network_scan()
    
    save_results(results, target, output_dir)
    return results

def web_reconnaissance(target, output_dir):
    """Webアプリケーション偵察を実行"""
    print(f"\n🌐 Webアプリケーション偵察を開始: {target}")
    
    scanner = WebScanner(target)
    results = scanner.run_full_web_scan()
    
    save_results(results, target, output_dir)
    return results

def osint_reconnaissance(target, output_dir):
    """OSINT情報収集を実行"""
    print(f"\n📊 OSINT情報収集を開始: {target}")
    
    gatherer = OSINTGatherer(target)
    results = gatherer.run_full_osint_gathering()
    
    save_results(results, target, output_dir)
    return results

def full_reconnaissance(target, output_dir):
    """完全な偵察を実行"""
    print(f"\n🚀 完全な偵察を開始: {target}")
    
    all_results = {
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'network': {},
        'web': {},
        'osint': {}
    }
    
    # ネットワーク偵察
    print("\n1️⃣ ネットワーク偵察を実行中...")
    network_results = network_reconnaissance(target, output_dir)
    all_results['network'] = network_results
    
    # Webアプリケーション偵察
    print("\n2️⃣ Webアプリケーション偵察を実行中...")
    web_results = web_reconnaissance(target, output_dir)
    all_results['web'] = web_results
    
    # OSINT情報収集
    print("\n3️⃣ OSINT情報収集を実行中...")
    osint_results = osint_reconnaissance(target, output_dir)
    all_results['osint'] = osint_results
    
    # 統合結果を保存
    save_results(all_results, target, output_dir)
    
    print(f"\n✅ 完全な偵察が完了しました: {target}")
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
            print("\n" + "=" * 60)
            print("📋 偵察結果サマリー")
            print("=" * 60)
            
            if 'network' in results:
                network_data = results['network']
                print(f"\n🌐 ネットワーク情報:")
                print(f"  IPアドレス: {network_data.get('ip', 'N/A')}")
                print(f"  開いているポート: {len(network_data.get('open_ports', []))}")
                print(f"  検出されたサービス: {len(network_data.get('services', {}))}")
            
            if 'web' in results:
                web_data = results['web']
                print(f"\n🌐 Webアプリケーション情報:")
                print(f"  HTTPステータス: {web_data.get('http_status', 'N/A')}")
                print(f"  HTTPSステータス: {web_data.get('https_status', 'N/A')}")
                print(f"  検出されたディレクトリ: {len(web_data.get('directories', []))}")
                print(f"  検出されたファイル: {len(web_data.get('files', []))}")
                print(f"  脆弱性: {len(web_data.get('vulnerabilities', []))}")
            
            if 'osint' in results:
                osint_data = results['osint']
                print(f"\n📊 OSINT情報:")
                print(f"  サブドメイン: {len(osint_data.get('subdomains', []))}")
                print(f"  メールアドレス: {len(osint_data.get('email_addresses', []))}")
                print(f"  DNSレコード: {len(osint_data.get('dns_records', {}))}")
        
        print(f"\n✅ 偵察が正常に完了しました！")
        print(f"📁 結果は {args.output} ディレクトリに保存されました。")
        
    except KeyboardInterrupt:
        print("\n\n⚠️ ユーザーによって中断されました。")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ エラーが発生しました: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 