# mail-analyzer

ルールベースインジケーターとGemini LLMを組み合わせた不審メール分析ツール。
`.eml`/`.msg`ファイルを解析し、SHA-256ハッシュ、認証結果、送信者整合性チェック、
URL/添付ファイルリスク評価、LLMによるコンテンツ分析を含む構造化JSONを出力。

## 機能

- **デュアル分析エンジン**: 確定的ルールベース + Gemini LLMコンテンツ分析
- **EML/MSG両対応**: 全charset対応（ISO-2022-JP, Shift_JIS, EUC-JP等）
- **SHA-256ハッシュ**: ファイル・添付ファイル個別のハッシュ（IoC突合用）
- **認証分析**: SPF, DKIM, DMARC結果のパース
- **送信者整合性**: From/Return-Path不一致、Display Name偽装、Reply-To乖離
- **URL分析**: 抽出、デファング、フリーホスティング/短縮URL/不審TLD検出
- **添付ファイル分析**: 危険拡張子、マクロ付きOffice、二重拡張子
- **ルーティング分析**: X-Mailer分類、不審なReceivedヘッダー検出
- **オフラインモード**: LLMなしのルールベース分析（API呼び出しなし）
- **プロンプトインジェクション防御**: ノンスタグXMLラッピング（防御指示をプロンプト冒頭に配置）

## インストール

```bash
git clone https://github.com/nlink-jp/mail-analyzer.git
cd mail-analyzer
make build    # → dist/mail-analyzer
```

## 使い方

```bash
# Gemini LLM付き分析（GCPプロジェクトとVertex AI必要）
export MAIL_ANALYZER_PROJECT=your-project-id
mail-analyzer email.eml

# オフラインモード（ルールベースのみ、API呼び出しなし）
mail-analyzer --offline email.eml

# MSG形式
mail-analyzer message.msg

# パイプフレンドリー
mail-analyzer email.eml | jq '.judgment'
mail-analyzer email.eml | jq '.indicators.urls[] | select(.suspicious)'
```

## 設定

以下の優先順位で設定を読み込みます:

1. **環境変数** (`MAIL_ANALYZER_*` または `GOOGLE_CLOUD_*`)
2. **TOML設定ファイル** (`~/.config/mail-analyzer/config.toml`)
3. **デフォルト値**

```bash
# 設定ファイルのセットアップ（任意）
mkdir -p ~/.config/mail-analyzer
cp config.example.toml ~/.config/mail-analyzer/config.toml
# プロジェクトIDを編集
```

| 環境変数 | デフォルト | 説明 |
|----------|-----------|------|
| `MAIL_ANALYZER_PROJECT` | (必須) | GCPプロジェクトID |
| `MAIL_ANALYZER_LOCATION` | `us-central1` | Vertex AIリージョン |
| `MAIL_ANALYZER_MODEL` | `gemini-2.5-flash` | Geminiモデル名 |
| `MAIL_ANALYZER_LANG` | (自動) | 出力言語の強制指定 |
| `--config <path>` | | 設定ファイルパスの上書き |

## ビルド

```bash
make build      # ビルド → dist/
make build-all  # クロスコンパイル
make test       # テスト実行
make clean      # dist/ 削除
```

## ドキュメント

- [Architecture](docs/architecture.md)（設計判断、分析手法、根拠）
- [README.md](README.md)（English）
- [README.ja.md](README.ja.md)（日本語）
- [CHANGELOG.md](CHANGELOG.md)
