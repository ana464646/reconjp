# ReconJP - ペネトレーションテスト用偵察ツール

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Mac-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

ReconJPは、WindowsとMac環境で動作する包括的なペネトレーションテスト用偵察ツールです。ネットワーク偵察、Webアプリケーション偵察、OSINT情報収集を統合し、効率的な情報収集を支援します。
日本語で親しみのあるプログラムを目指しました。

## 🚀 主な機能

### 🌐 ネットワーク偵察
- **ポートスキャン**: 一般的なポートの開閉状態を高速スキャン
- **サービス検出**: 開いているポートで動作しているサービスの特定
- **OS検出**: ターゲットシステムのOS情報の取得
- **Pingスイープ**: ネットワーク範囲での生存ホスト検出
- **認証テスト**: SSH/FTPポートでの匿名ログインとワードリストログイン試行

### 🌐 Webアプリケーション偵察
- **HTTP/HTTPS確認**: プロトコル対応状況の確認
- **ディレクトリ列挙**: 一般的なディレクトリの存在確認
- **隠しディレクトリ検出**: `/simple`、`/admin`、`/secret`などの隠しディレクトリの検出
- **ファイル列挙**: 設定ファイルや情報ファイルの検出
- **技術スタック検出**: CMS、フレームワーク、サーバー技術の特定
- **フォーム分析**: Webフォームの構造と入力フィールドの解析
- **サブドメイン列挙**: Webサイトのサブドメイン検出とタイトル取得
- **サブドメイン脆弱性スキャン**: 検出されたサブドメインの脆弱性チェック
- **基本的な脆弱性スキャン**: 情報漏洩やディレクトリトラバーサルの検出（CVE番号付き）
- **CMS固有脆弱性検出**: WordPress、Drupal、Joomlaの脆弱性検出
- **Webサーバー脆弱性検出**: Apache、Nginxの設定ファイル漏洩検出

### 📊 OSINT情報収集
- **WHOIS情報**: ドメイン登録情報の取得
- **DNSレコード**: A、AAAA、MX、NS、TXT、CNAME、SOAレコードの取得
- **サブドメイン列挙**: 一般的なサブドメインの存在確認
- **逆引きDNS**: IPアドレスからホスト名の取得
- **メールアドレス抽出**: WHOIS情報やDNSレコードからのメールアドレス抽出
- **ソーシャルメディア検索**: 関連するソーシャルメディアアカウントの検索
- **SSL証明書情報**: SSL/TLS証明書の詳細情報取得

## 📋 必要条件

- Python 3.7以上
- Windows 10/11 または macOS 10.14以上
- インターネット接続

## 🛠️ インストール

### Windows環境
```bash
# 自動インストールスクリプトを使用
install.bat

# または手動でインストール
pip install requests dnspython beautifulsoup4 html5lib colorama rich click pyfiglet whois urllib3
pip install python-nmap cryptography shodan censys virustotal-api
```

### Mac/Linux環境
```bash
# 自動インストールスクリプトを使用
./install.sh

# または手動でインストール
pip install -r requirements.txt
```

### 1. リポジトリのクローン
```bash
git clone https://github.com/yourusername/reconjp.git
cd reconjp
```

### 2. 依存関係のインストール
```bash
# Windows環境では上記のコマンドを使用
# Mac/Linux環境では以下を使用
pip install -r requirements.txt
```

### 3. オプション: パッケージとしてインストール
```bash
pip install -e .
```

## 🚀 使用方法

### 基本的な使用方法

#### 完全な偵察を実行
```bash
python cli.py example.com
```

#### 特定の偵察のみ実行
```bash
# ネットワーク偵察のみ
python cli.py example.com --network-only

# Webアプリケーション偵察のみ
python cli.py example.com --web-only

# OSINT情報収集のみ
python cli.py example.com --osint-only
```

#### 出力ディレクトリを指定
```bash
python cli.py example.com -o ./my_results
```

### コマンドラインオプション

```bash
python cli.py --help
```

**オプション:**
- `target`: ターゲットドメインまたはIPアドレス（必須）
- `-o, --output`: 出力ディレクトリ（デフォルト: recon_results）
- `--network-only`: ネットワーク偵察のみ実行
- `--web-only`: Webアプリケーション偵察のみ実行
- `--osint-only`: OSINT情報収集のみ実行
- `--verbose, -v`: 詳細な出力を有効にする
- `--quiet, -q`: 出力を最小限にする

## 📁 出力ファイル

ツールは1つのターゲットに対して1つのレポートファイルを生成します：

### テキストレポート
読みやすい日本語形式でレポートを生成（絵文字付き）

### 出力例
```
recon_results/
├── recon_example.com_20231201_143022.txt
└── ...
```

## 🔧 設定

### カスタムポートリスト
`modules/network_scanner.py`の`common_ports`リストを編集して、スキャンするポートをカスタマイズできます。

### カスタムディレクトリリスト
`modules/web_scanner.py`の`common_directories`リストを編集して、列挙するディレクトリをカスタマイズできます。

## 📊 使用例

### 例1: 基本的なネットワーク偵察
```bash
python cli.py 192.168.1.1 --network-only
```

**出力例:**
```
🔍 ネットワーク偵察を開始: 192.168.1.1
IPアドレス: 192.168.1.1
ポートスキャンを実行中...
開いているポート: [22, 21, 80, 443, 8080]
サービス検出を実行中...
検出されたサービス: {22: 'ssh', 21: 'ftp', 80: 'http', 443: 'https', 8080: 'http-proxy'}
🔐 認証テストを実行中...
✅ SSH匿名ログイン成功: 192.168.1.1:22
✅ FTP匿名ログイン成功: 192.168.1.1:21
⚠️  SSH匿名ログインが可能です
⚠️  FTP匿名ログインが可能です
OS検出を実行中...
OS情報: Linux 3.x
```

### 例2: Webアプリケーションの完全偵察
```bash
python cli.py example.com --web-only
```

**出力例:**
```
🌐 Webアプリケーションスキャンを開始しています...
🌐 HTTP/HTTPS状態を確認中...
✅ HTTP接続: 成功
✅ HTTPS接続: 成功
🛠️  技術スタック検出中...
✅ 検出された技術: 3種類
   - server: nginx
   - language: PHP
   - cms: WordPress
📁 ディレクトリ列挙中...
🔍 ディレクトリ列挙を開始: http://example.com
📋 検索対象: 200個のディレクトリ
🔍 隠しディレクトリ発見: simple (ステータス: 200) - Simple Admin Panel
🔍 隠しディレクトリ発見: admin (ステータス: 403) - Access Denied
📁 ディレクトリ発見: images (ステータス: 200)
📁 ディレクトリ発見: css (ステータス: 200)

📊 ディレクトリ列挙結果:
   📁 総ディレクトリ数: 15個
   🔍 隠しディレクトリ数: 2個

⚠️  発見された隠しディレクトリ:
   ✅ /simple - Simple Admin Panel
   🚫 /admin - Access Denied

🔍 隠しディレクトリの詳細:
   ✅ /simple - Simple Admin Panel
     📄 サイズ: 2048 bytes
     🖥️  サーバー: nginx/1.18.0
     📋 タイプ: text/html
   🚫 /admin - Access Denied
     📄 サイズ: 512 bytes
     🖥️  サーバー: nginx/1.18.0
     📋 タイプ: text/html
✅ 検出されたディレクトリ: 15個
📄 ファイル列挙中...
✅ 検出されたファイル: 3個
   - robots.txt (ステータス: 200)
🔗 サブドメイン列挙中...
✅ サブドメイン発見: www.example.com (https) - Example Domain
✅ サブドメイン発見: admin.example.com (https) - Admin Panel
🔍 脆弱性スキャン中...
🔍 検出された脆弱性: 3個
   🟡 Information Disclosure (CVE-2021-41773): robots.txt
   🟢 Default Page (CVE-2021-41773): admin
   🔴 WordPress Config Exposure (CVE-2021-29452) [CMS: WordPress]: wp-config.php
```

### 例3: OSINT情報収集
```bash
python cli.py example.com --osint-only
```

**出力例:**
```
📊 OSINT情報収集を開始: example.com
WHOIS情報を取得中...
DNSレコードを取得中...
サブドメイン列挙中...
サブドメイン発見: www.example.com -> 93.184.216.34
サブドメイン発見: mail.example.com -> 93.184.216.35
メールアドレスを抽出中...
```

## ⚠️ 注意事項

### 法的責任
- このツールは**教育目的**および**許可されたペネトレーションテスト**でのみ使用してください
- 無許可での使用は違法となる可能性があります
- 使用前に必ず適切な許可を取得してください

### 技術的制限
- 一部の機能は外部APIに依存する場合があります
- ファイアウォールやIDS/IPSによって検出される可能性があります
- 大量のリクエストはターゲットシステムに負荷をかける可能性があります

## 📝 ライセンス

このプロジェクトはMITライセンスの下で公開されています。詳細は[LICENSE](LICENSE)ファイルを参照してください。

## 🆘 サポート

問題や質問がある場合は、以下の方法でサポートを受けることができます：

- [Issues](https://github.com/yourusername/reconjp/issues)でバグレポートや機能リクエストを作成
- [Wiki](https://github.com/yourusername/reconjp/wiki)でドキュメントを確認
- [Discussions](https://github.com/yourusername/reconjp/discussions)でコミュニティと交流

## 🙏 謝辞

このツールは以下のオープンソースプロジェクトに依存しています：

- [python-nmap](https://github.com/nmap/nmap-python)
- [dnspython](https://github.com/rthalley/dnspython)
- [requests](https://github.com/psf/requests)
- [beautifulsoup4](https://www.crummy.com/software/BeautifulSoup/)
- [rich](https://github.com/Textualize/rich)

---

**⚠️ 免責事項**: このツールは教育目的で提供されています。無許可での使用は違法となる可能性があります。使用前に必ず適切な許可を取得してください。