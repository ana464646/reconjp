#!/bin/bash

echo "========================================"
echo "ReconJP - インストールスクリプト (Mac/Linux)"
echo "========================================"
echo

# Pythonのバージョンを確認
if ! command -v python3 &> /dev/null; then
    echo "エラー: Python3がインストールされていません。"
    echo "Python 3.7以上をインストールしてください。"
    echo "https://www.python.org/downloads/"
    exit 1
fi

echo "Pythonのバージョンを確認中..."
python3 --version
echo

# pipの確認
if ! command -v pip3 &> /dev/null; then
    echo "エラー: pip3が利用できません。"
    echo "Pythonの再インストールを試してください。"
    exit 1
fi

echo "pipのバージョンを確認中..."
pip3 --version
echo

# 仮想環境の作成（オプション）
read -p "仮想環境を作成しますか？ (y/n): " create_venv
if [[ $create_venv == "y" || $create_venv == "Y" ]]; then
    echo "仮想環境を作成中..."
    python3 -m venv venv
    echo "仮想環境をアクティベート中..."
    source venv/bin/activate
    echo "仮想環境がアクティベートされました。"
    echo
fi

# 依存関係のインストール
echo "依存関係をインストール中..."
pip3 install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "エラー: 依存関係のインストールに失敗しました。"
    exit 1
fi

echo
echo "依存関係のインストールが完了しました。"
echo

# パッケージのインストール（オプション）
read -p "パッケージとしてインストールしますか？ (y/n): " install_package
if [[ $install_package == "y" || $install_package == "Y" ]]; then
    echo "パッケージをインストール中..."
    pip3 install -e .
    echo "パッケージのインストールが完了しました。"
    echo
fi

# 実行権限を付与
chmod +x cli.py
chmod +x examples/example_usage.py

echo "========================================"
echo "インストールが完了しました！"
echo "========================================"
echo
echo "使用方法:"
echo "  python3 cli.py example.com"
echo "  python3 cli.py example.com --network-only"
echo "  python3 cli.py example.com --web-only"
echo "  python3 cli.py example.com --osint-only"
echo
echo "ヘルプを表示:"
echo "  python3 cli.py --help"
echo
echo "使用例スクリプトを実行:"
echo "  python3 examples/example_usage.py"
echo
echo "注意: このツールは教育目的および許可されたペネトレーションテストでのみ使用してください。"
echo 