@echo off
echo ========================================
echo ReconJP - インストールスクリプト (Windows)
echo ========================================
echo.

REM Pythonのバージョンを確認
python --version >nul 2>&1
if errorlevel 1 (
    echo エラー: Pythonがインストールされていません。
    echo Python 3.7以上をインストールしてください。
    echo https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Pythonのバージョンを確認中...
python --version
echo.

REM pipの確認
pip --version >nul 2>&1
if errorlevel 1 (
    echo エラー: pipが利用できません。
    echo Pythonの再インストールを試してください。
    pause
    exit /b 1
)

echo pipのバージョンを確認中...
pip --version
echo.

REM 仮想環境の作成（オプション）
set /p create_venv="仮想環境を作成しますか？ (y/n): "
if /i "%create_venv%"=="y" (
    echo 仮想環境を作成中...
    python -m venv venv
    echo 仮想環境をアクティベート中...
    call venv\Scripts\activate.bat
    echo 仮想環境がアクティベートされました。
    echo.
)

REM 依存関係のインストール
echo 依存関係をインストール中...
echo 基本的な依存関係をインストール中...
pip install requests dnspython beautifulsoup4 html5lib colorama rich click pyfiglet whois urllib3

echo 追加の依存関係をインストール中...
pip install python-nmap cryptography shodan censys virustotal-api

if errorlevel 1 (
    echo 警告: 一部の依存関係のインストールに失敗しました。
    echo 基本的な機能は動作する可能性があります。
    echo 続行しますか？ (y/n)
    set /p continue_anyway=
    if /i not "%continue_anyway%"=="y" (
        pause
        exit /b 1
    )
)

echo.
echo 依存関係のインストールが完了しました。
echo.

REM パッケージのインストール（オプション）
set /p install_package="パッケージとしてインストールしますか？ (y/n): "
if /i "%install_package%"=="y" (
    echo パッケージをインストール中...
    pip install -e .
    echo パッケージのインストールが完了しました。
    echo.
)

echo ========================================
echo インストールが完了しました！
echo ========================================
echo.
echo 使用方法:
echo   python cli.py example.com
echo   python cli.py example.com --network-only
echo   python cli.py example.com --web-only
echo   python cli.py example.com --osint-only
echo.
echo ヘルプを表示:
echo   python cli.py --help
echo.
echo 注意: このツールは教育目的および許可されたペネトレーションテストでのみ使用してください。
echo.
pause 