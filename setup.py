#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ReconJP Setup Script
ペネトレーションテスト用偵察ツールのセットアップ
"""

from setuptools import setup, find_packages
import os

# READMEファイルを読み込み
def read_readme():
    try:
        with open("README.md", "r", encoding="utf-8") as fh:
            return fh.read()
    except UnicodeDecodeError:
        # フォールバック: エンコーディングエラーの場合は空文字を返す
        return "ReconJP - ペネトレーションテスト用偵察ツール"

# requirements.txtを読み込み
def read_requirements():
    try:
        with open("requirements.txt", "r", encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    except UnicodeDecodeError:
        # フォールバック: 基本的な依存関係を返す
        return [
            "requests>=2.31.0",
            "dnspython>=2.4.2", 
            "python-nmap>=0.7.1",
            "beautifulsoup4>=4.12.2",
            "colorama>=0.4.6",
            "whois>=0.9.27"
        ]

setup(
    name="reconjp",
    version="1.0.0",
    author="ReconJP Team",
    author_email="info@reconjp.com",
    description="ペネトレーションテスト用包括的偵察ツール - Windows/Mac対応",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/reconjp",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Internet :: WWW/HTTP :: Site Management",
    ],
    python_requires=">=3.7",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "reconjp=cli:main",
        ],
    },
    keywords="penetration testing, reconnaissance, network security, osint, web security",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/reconjp/issues",
        "Source": "https://github.com/yourusername/reconjp",
        "Documentation": "https://github.com/yourusername/reconjp/wiki",
    },
) 