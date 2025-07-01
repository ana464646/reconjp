#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ReconJP - 使用例スクリプト
各モジュールの基本的な使用方法を示します
"""

import sys
import os

# プロジェクトルートをパスに追加
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.network_scanner import NetworkScanner
from modules.web_scanner import WebScanner
from modules.osint_gatherer import OSINTGatherer

def example_network_scan():
    """ネットワーク偵察の使用例"""
    print("=== ネットワーク偵察の使用例 ===")
    
    # ターゲットを設定（実際のテストでは許可されたターゲットを使用してください）
    target = "example.com"
    
    # ネットワークスキャナーの初期化
    scanner = NetworkScanner(target)
    
    # 完全なネットワークスキャンを実行
    results = scanner.run_full_network_scan()
    
    # 結果の表示
    print(f"\n結果:")
    print(f"IPアドレス: {results.get('ip')}")
    print(f"開いているポート: {results.get('open_ports')}")
    print(f"サービス: {results.get('services')}")
    print(f"OS情報: {results.get('os_info')}")
    
    return results

def example_web_scan():
    """Webアプリケーション偵察の使用例"""
    print("\n=== Webアプリケーション偵察の使用例 ===")
    
    # ターゲットを設定
    target = "example.com"
    
    # Webスキャナーの初期化
    scanner = WebScanner(target)
    
    # 完全なWebスキャンを実行
    results = scanner.run_full_web_scan()
    
    # 結果の表示
    print(f"\n結果:")
    print(f"HTTPステータス: {results.get('http_status')}")
    print(f"HTTPSステータス: {results.get('https_status')}")
    print(f"技術スタック: {results.get('technology_stack')}")
    print(f"検出されたディレクトリ数: {len(results.get('directories', []))}")
    print(f"検出されたファイル数: {len(results.get('files', []))}")
    print(f"脆弱性数: {len(results.get('vulnerabilities', []))}")
    
    return results

def example_osint_gathering():
    """OSINT情報収集の使用例"""
    print("\n=== OSINT情報収集の使用例 ===")
    
    # ターゲットを設定
    target = "example.com"
    
    # OSINT収集器の初期化
    gatherer = OSINTGatherer(target)
    
    # 完全なOSINT情報収集を実行
    results = gatherer.run_full_osint_gathering()
    
    # 結果の表示
    print(f"\n結果:")
    print(f"WHOIS情報: {results.get('whois_info', {}).get('registrar', 'N/A')}")
    print(f"DNSレコード数: {len(results.get('dns_records', {}))}")
    print(f"サブドメイン数: {len(results.get('subdomains', []))}")
    print(f"メールアドレス数: {len(results.get('email_addresses', []))}")
    print(f"ソーシャルメディア数: {len(results.get('social_media', []))}")
    
    return results

def example_custom_scan():
    """カスタムスキャンの使用例"""
    print("\n=== カスタムスキャンの使用例 ===")
    
    target = "example.com"
    
    # ネットワークスキャナー
    network_scanner = NetworkScanner(target)
    
    # 特定のポートのみスキャン
    custom_ports = [80, 443, 22, 21, 25]
    print(f"カスタムポートスキャン: {custom_ports}")
    open_ports = network_scanner.port_scan(ports=custom_ports)
    print(f"開いているポート: {open_ports}")
    
    # Webスキャナー
    web_scanner = WebScanner(target)
    
    # 技術スタックのみ検出
    print("技術スタック検出中...")
    tech_stack = web_scanner.technology_detection()
    print(f"技術スタック: {tech_stack}")
    
    # OSINT収集器
    osint_gatherer = OSINTGatherer(target)
    
    # DNSレコードのみ取得
    print("DNSレコード取得中...")
    dns_records = osint_gatherer.get_dns_records()
    print(f"DNSレコード: {dns_records}")

def example_error_handling():
    """エラーハンドリングの使用例"""
    print("\n=== エラーハンドリングの使用例 ===")
    
    # 無効なターゲットでテスト
    invalid_target = "invalid-domain-that-does-not-exist.com"
    
    try:
        scanner = NetworkScanner(invalid_target)
        results = scanner.run_full_network_scan()
    except Exception as e:
        print(f"エラーが発生しました: {e}")
        print("適切なエラーハンドリングが重要です")

def main():
    """メイン関数"""
    print("ReconJP - 使用例スクリプト")
    print("=" * 50)
    
    # 注意事項
    print("⚠️  注意: このスクリプトは教育目的です。")
    print("実際の使用では、必ず許可されたターゲットでのみ実行してください。")
    print("📄 レポートは1つのターゲットに対して1つのテキストファイルで生成されます。")
    print()
    
    try:
        # 各使用例を実行
        example_network_scan()
        example_web_scan()
        example_osint_gathering()
        example_custom_scan()
        example_error_handling()
        
        print("\n✅ 全ての使用例が完了しました！")
        
    except KeyboardInterrupt:
        print("\n\n⚠️ ユーザーによって中断されました。")
    except Exception as e:
        print(f"\n❌ エラーが発生しました: {e}")

if __name__ == "__main__":
    main() 