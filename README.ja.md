# mail-analyzer

ルールベースインジケーターとGemini LLMを組み合わせた不審メール分析ツール。
`.eml`/`.msg`ファイルを解析し、SHA-256ハッシュ、認証結果、送信者整合性チェック、
URL/添付ファイルリスク評価、LLMによるコンテンツ分析を含む構造化JSONを出力。

## 機能

- **デュアル分析エンジン**: 確定的ルールベース + Gemini LLMコンテンツ分析
- **EML・MSG・winmail.dat**: 組織のメールパーサー [mailparse](https://github.com/nlink-jp/mailparse)（攻撃者が
  作ったメールを前提に書かれている）で読む。形式は中身で判別。全charset対応（ISO-2022-JP, Shift_JIS, EUC-JP等）
- **SHA-256ハッシュ**: ファイル・添付ファイル個別のハッシュ（IoC突合用）
- **認証分析**: SPF, DKIM, DMARC はいちばん上の Authentication-Results（受信者のサーバーのもの）から。
  すべての欄を生のまま残し、下の欄が食い違えば `conflicting` で知らせる
- **送信者整合性**: From/Return-Path不一致、Display Name偽装、Reply-To乖離。すべての mailbox で判定するので、
  2 つ目の From で 1 つ目を隠せない
- **URL分析**: 抽出、デファング、フリーホスティング/短縮URL/不審TLD検出。本文、添付された（転送された）メール、
  カレンダーの招待などの text の添付から
- **添付ファイル分析**: 危険拡張子、マクロ付きOffice、二重拡張子。添付されたメールの中も
- **パーサーの警告**: 解析が処理したこと（重複したヘッダー、壊れたアドレス、壊れた符号化）を `warnings` に。
  LLM には警告のコードを渡す

出力（JSON）について:

- `from` はすべての From の mailbox を `, ` で連ねる。atom だけでない表示名は引用符で囲むので、復号するとアドレスに
  なる表示名も表示名のまま
- URL と添付の `layer` は、それが見つかった添付されたメールを mailparse の `Message.Walk` の path（`2`、`2>1`）で示す。
  外側のメールなら無い。URL の `attachment` は、それが見つかった text の添付の名前
- `authentication.raw` にすべての Authentication-Results、`authentication.conflicting` は知らせるだけ（正当な転送でも立つ）
- `warnings` はメールと添付されたすべてのメールの mailparse の警告（安定したコード、mailparse の README を見よ）。常に配列
- 64 MiB を超えるファイルは断る
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

設定ファイルにある知らないキー（打ち間違いなど）は黙って無視せず、そのキー名を示してエラーにします。

```bash
# 設定ファイルのセットアップ（任意）
mkdir -p ~/.config/mail-analyzer
cp config.example.toml ~/.config/mail-analyzer/config.toml
# プロジェクトIDを編集
```

| 環境変数 | デフォルト | 説明 |
|----------|-----------|------|
| `MAIL_ANALYZER_PROJECT` | (必須) | GCPプロジェクトID |
| `MAIL_ANALYZER_LOCATION` | `global` | Vertex AIロケーション（Gemini 3系は`global`必須） |
| `MAIL_ANALYZER_MODEL` | `gemini-3.7-flash` | Geminiモデル名 |
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

- [Architecture](docs/ja/architecture.ja.md)（設計判断、分析手法、根拠）
- [README.md](README.md)（English）
- [README.ja.md](README.ja.md)（日本語）
- [CHANGELOG.md](CHANGELOG.md)
