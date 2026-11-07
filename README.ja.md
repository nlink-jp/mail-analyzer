# mail-analyzer

ルールベースインジケーターとGemini LLMを組み合わせた不審メール分析ツール。
`.eml`/`.msg`ファイルを解析し、SHA-256ハッシュ、認証結果、送信者整合性チェック、
URL/添付ファイルリスク評価、LLMによるコンテンツ分析を含む構造化JSONを出力。

## 機能

- **デュアル分析エンジン**: 確定的ルールベース + Gemini LLMコンテンツ分析
- **EML/MSG両対応**: 攻撃者が作ったメールを前提にした [mailparse](https://github.com/nlink-jp/mailparse) で読む —
  ヘッダは出てきた順・重複込み、アドレスを解析してから表示名を復号、全charset対応（ISO-2022-JP, Shift_JIS,
  EUC-JP, HTMLの`<meta charset>`）、Outlookの圧縮RTFの本文とwinmail.dat（TNEF）
- **添付されたメールも開く**: 転送された`.eml`/`.msg`（message/rfc822、または中身で判別）、埋め込みの`.msg`、
  winmail.dat — その中のURLと添付も調べる（`in_message`）
- **解析の警告**: コロンの無いヘッダ行、重複したFrom、壊れたBase64、閉じない境界などを黙って捨てず
  `parse_warnings` に出す
- **SHA-256ハッシュ**: ファイル・添付ファイル個別のハッシュ（IoC突合用）
- **認証分析**: すべての`Authentication-Results`からSPF, DKIM, DMARCを読み、最も重い判定を採る（先頭に
  置かれた偽の`pass`で後ろの`fail`を隠せない）
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

## 出力

```json
{
  "source_file": "alert.eml",
  "hash": "sha256...",
  "message_id": "<...>",
  "subject": "...",
  "from": "...",
  "to": ["..."],
  "date": "...",
  "indicators": {
    "authentication": {
      "spf": "fail", "dkim": "pass", "dmarc": "fail",
      "per_header": [{ "spf": "pass", "dkim": "pass", "dmarc": "pass" }, { "spf": "fail", "dkim": "pass", "dmarc": "fail" }],
      "conflicting": true
    },
    "sender": { "from_return_path_mismatch": true, ... },
    "urls": [{ "url": "hxxps://evil[.]com/path", "suspicious": true, "reason": "...", "in_message": "2" }],
    "attachments": [{ "filename": "...", "hash": "sha256...", "suspicious": false }],
    "routing": { "hop_count": 7, "x_mailer": "...", "x_mailer_suspicious": false }
  },
  "judgment": {
    "is_suspicious": true,
    "category": "phishing",
    "confidence": 0.95,
    "summary": "...",
    "reasons": ["...", "..."],
    "tags": ["...", "..."]
  },
  "parse_warnings": [{ "code": "duplicate_field", "detail": "...", "part": "" }]
}
```

項目について:

- `from` は最初のFromフィールド。Fromが複数あればすべてをルールが読み、LLMにも見せる（重複は警告になる）。
  メールボックスはRFC 5322の形で`表示名 <アドレス>`、表示名の無いものは括弧なしのアドレスで書く。表示名が
  ただの語でなければ（`<`・`@`・`,`・`.`・`(`・引用符などを含めば）引用符で囲み、アドレスに見える表示名も
  表示名のままにする。Exchangeの`/O=...`の差出人は書かれたまま出す
- `authentication` はすべての`Authentication-Results`のうち、方式ごとに最も重い判定。複数あるときは
  `per_header`（上から順）と`conflicting`も出す。転送されたメールには受け取った段ごとに1つずつあり、食い違う
  ことが多い
- `in_message` は添付されたメールの中で見つけたURL・添付の印で、そのメールを持っていた添付のパートの位置
  （`2`、`msg/attach/1`。メールの中のメールは`2>1`）
- バイト列を取り出せなかった添付（埋め込みの`.msg`、OLEオブジェクト）には`hash`が無い
- `parse_warnings` はmailparseの警告コード。`part`はメールの中の位置（添付されたメールの中は`2>1`）。
  64 MiBを超える入力は受け付けない

## ビルド

```bash
make build      # ビルド → dist/
make build-all  # クロスコンパイル
make test       # テスト実行
make lint       # gofmt + golangci-lint
make clean      # dist/ 削除
```

## ドキュメント

- [Architecture](docs/ja/architecture.ja.md)（設計判断、分析手法、根拠）
- [README.md](README.md)（English）
- [README.ja.md](README.ja.md)（日本語）
- [CHANGELOG.md](CHANGELOG.md)
