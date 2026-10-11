<div align="center">

# ysign

**純 Go 製のクロスプラットフォーム iOS コード署名 / 再署名ツール — zsign 互換の機能代替**

Xcode も macOS も不要。単一バイナリで `.ipa` / `.app` を再署名できます。

**Language / 语言 / 言語 / 언어**：
[简体中文](README.md) · [English](README_EN.md) · [日本語](README_JA.md) · [한국어](README_KO.md)

</div>

---

## はじめに

`ysign` は **純 Go** で書かれたクロスプラットフォームな iOS コード署名 / 再署名ツールで、[zsign](https://github.com/zhlynn/zsign) の機能互換代替として実装されています。Xcode にも macOS にも依存せず、あなたの証明書（`.p12` / PEM）とプロビジョニングプロファイル（`.mobileprovision`）を使うだけで、1 コマンドで `.ipa` や `.app` を再署名できます。

コード署名スタックは **すべて自作** です。Mach-O（fat / thin）の解析、SHA-256 CodeDirectory の再構築、そしてサードパーティライブラリに依存しない CMS / PKCS#7 署名の生成（RSA / ECDSA 対応）を備えています。「署名を速く」という要望に応え、コンテンツアドレス方式のディスクキャッシュを実装。23MB・38 バイナリのアプリをコールドで **約 2.4 秒**、キャッシュが効けばさらに高速です。

---

## 特徴

**Bundle 編集**
- `-b` バンドル ID、`-n` 名前、`-r` バージョン、`-M` 最低 OS バージョンの変更
- `-e` 新しい entitlements、`-I` アプリアイコンの差し替え、`-S` ファイル App 連携（`UISupportsDocumentBrowser` / `UIFileSharingEnabled`）の有効化

**dylib**
- `-l` dylib 注入、`-w` weak 注入、`-D` dylib 削除、`-P` 拡張への同時注入

**証明書とプロファイル**
- `-k` 秘密鍵 / `.p12`、`-c` 証明書、`-p` パスワード
- `-m` は複数プロファイルに対応。先頭は `embedded.mobileprovision` として埋め込み、以降は `application-identifier` で `PlugIns/*.appex` 拡張に自動マッチ
- `-a` ad-hoc 署名（証明書不要）

**検査とメタデータ**
- `-C` 証明書 / プロファイル / コード署名の検査（ベストエフォートの OCSP 付き）
- `-x` `metadata.json` とアプリアイコンの書き出し

**クリーンアップとパッケージング**
- `-E` 拡張削除、`-W` Watch 削除、`-U` `UISupportedDevices` のクリア、`-R` プロファイル削除
- `-z 0-9` 圧縮レベル、`-o` 出力先、`-t` 一時 / キャッシュディレクトリ

**パフォーマンス**
- コンテンツアドレス方式のディスクキャッシュ（ページハッシュ、CMS 署名）。`-f` でバイパス、`-t` でディレクトリ指定

---

## 技術的な特長

- **純 Go 標準ライブラリ + わずかな依存**、単一バイナリのクロスコンパイル、Windows / macOS / Linux 対応
- **自作 CMS / PKCS#7**：SHA-256、RSA / ECDSA 対応、標準準拠（`[0] EXPLICIT OCTET STRING` eContent）
- **完全な Mach-O 対応**：fat（32/64）/ thin、両バイトオーダー、ロードコマンド走査、dylib 注入 / 削除
- **Apple コード署名のフォーマット詳細を正しく処理**（よくある落とし穴）：
  - コード署名領域（superblob / CodeDirectory / スロット表）は Mach-O 本体のバイトオーダーに関係なく **常にビッグエンディアン**
  - 32 ビット Mach-O ヘッダは 28 バイト（ロードコマンドは 28 から開始）
  - CMS の eContent は `[0] EXPLICIT OCTET STRING`
  - ipa の deflate 圧縮は `compress/flate`（生 deflate）を使う必要があり、zlib は不可
- **2 パス署名**：ページハッシュ計算 → CD / CMS 生成 → 最終サイズ確定 → `LC_CODE_SIGNATURE` の datasize をパッチ → もう一度ページハッシュを計算し、署名の自己整合性を保証

---

## クイックスタート

### ビルド

```bash
go build -o ysign ./cmd/ysign
```

### クロスコンパイル（対象 OS 不要）

```bash
# macOS（Apple Silicon）
GOOS=darwin GOARCH=arm64 go build -o ysign-darwin-arm64 ./cmd/ysign
# macOS（Intel）
GOOS=darwin GOARCH=amd64 go build -o ysign-darwin-amd64 ./cmd/ysign
# Linux
GOOS=linux GOARCH=amd64 go build -o ysign-linux-amd64 ./cmd/ysign
# Windows
GOOS=windows GOARCH=amd64 go build -o ysign.exe ./cmd/ysign
```

### 最小限の再署名

```bash
ysign -k cert.p12 -p あなたのパスワード -m dev.mobileprovision -b com.your.app -o signed.ipa input.ipa
```

---

## 全オプション

```
Usage: ysign [-options] [-k privkey.pem] [-m dev.prov] [-o output.ipa] file|folder

  -k, --pkey            秘密鍵または p12 ファイルのパス
  -m, --prov            プロビジョニングプロファイルのパス（拡張用に繰り返し指定可）
  -c, --cert            証明書ファイルのパス（PEM または DER）
  -a, --adhoc           ad-hoc 署名のみ実行
  -f, --force           キャッシュを使わず強制署名
  -o, --output          出力 ipa ファイルのパス
  -p, --password        秘密鍵または p12 のパスワード
  -b, --bundle_id       新しい bundle identifier
  -n, --bundle_name     新しい表示名
  -r, --bundle_version  新しいバージョン
  -e, --entitlements    新しい entitlements ファイル
  -I, --icon            新しいアプリアイコン（PNG）
  -z, --zip_level       圧縮レベル（0-9）
  -l, --dylib           注入する dylib（繰り返し指定可）
  -D, --rm_dylib        削除する dylib（繰り返し指定可）
  -w, --weak            dylib を weak として注入（繰り返し指定可）
  -i, --install         署名後に ideviceinstaller でインストール
  -t, --temp_folder     中間ファイルの一時 / キャッシュディレクトリ
  -2, --sha256_only     SHA256 のみの code directory を使用
  -C, --check           証明書 / プロファイル / 署名を検査
  -x, --metadata        メタデータとアイコンをディレクトリへ書き出し
  -R, --rm_provision    署名後にプロビジョニングプロファイルを削除
  -S, --enable_docs     UISupportsDocumentBrowser / UIFileSharingEnabled を有効化
  -M, --min_version     Info.plist の MinimumOSVersion を設定
  -E, --rm_extensions   すべての App 拡張（PlugIns）を削除
  -W, --rm_watch        Watch App を削除
  -U, --rm_uisd         UISupportedDevices を削除
  -P, --inject_extensions 拡張にも dylib を注入
  -q, --quiet           静かに実行
```

> 入力は `.ipa`、`.app`、または `Payload` を含むディレクトリ。`.app` はその場で署名、`.ipa` は一時ディレクトリに展開して署名後に再パックし、既定では現在のディレクトリへ `xxx-ysign.ipa` を出力します。

---

## 使用例

```bash
# 1) バンドル ID / 名前 / バージョンを変更して再署名
ysign -k dev.p12 -p 1234 -m dev.mobileprovision \
      -b com.example.app -n "My App" -r "2.1.0" \
      -o signed.ipa app.ipa

# 2) ad-hoc 署名（ローカルデバッグ用）
ysign -a -o adhoc.ipa app.ipa

# 3) dylib を注入
ysign -k dev.p12 -p 1234 -m dev.mobileprovision \
      -l Tweak.dylib -o signed.ipa app.ipa

# 4) dylib を削除
ysign -k dev.p12 -p 1234 -m dev.mobileprovision \
      -D Tweak.dylib -o signed.ipa app.ipa

# 5) 拡張付きアプリ：2 番目のプロファイルが appex に自動マッチ
ysign -k dev.p12 -p 1234 -m main.mobileprovision -m ext.mobileprovision \
      -b com.example.app -o signed.ipa app.ipa

# 6) 証明書を検査
ysign -C -p 1234 cert.p12

# 7) プロビジョニングプロファイルを検査
ysign -C dev.mobileprovision

# 8) メタデータとアイコンを書き出し
ysign -x outdir app.ipa
```

---

## 動作の仕組み

1. **展開**：`.ipa` を解凍（zip-slip 対策付き）、`Info.plist` を解析、すべての Mach-O バイナリ（メイン実行ファイル、framework、appex）を列挙。
2. **解析**：各バイナリの fat / thin とロードコマンドを解析し、`LC_CODE_SIGNATURE` を特定。
3. **CodeDirectory の再構築**：元バイナリの hashType / pageSize / version / flags から CD を再構築（ヘッダ → identifier → team → 特殊スロットハッシュ → コードページハッシュ）。
4. **CMS 生成**：自作の `SignedData`（SHA-256、RSA / ECDSA）、eContent は標準の `[0] EXPLICIT OCTET STRING`、署名者証明書チェーンを埋め込み。
5. **superblob の組み立て**：CodeDirectory + Requirements + Entitlements + Signature の各スロット。
6. **2 パス署名**：パス 1 でページハッシュを計算し最終サイズを確定して datasize をパッチ、パス 2 でパッチ後のコードを再ハッシュして自己整合性を確保。
7. **再パック**：設定可能な圧縮レベルで `.ipa` として再圧縮。

**メインバイナリ**は新しい bundle id / team に切り替え、特殊スロット `-1`（Info）と `-5`（Entitlements）を再計算します。**埋め込みバイナリ**（framework / appex）は自身の identifier と特殊スロットハッシュを保持します。

---

## キャッシュ

コンテンツアドレス方式で、以下のキーを使用：
- `ph_<sha256(コードバイト)>` → コードページハッシュ
- `cms_<sha256(CD)>_<証明書シリアル>` → CMS 署名

キャッシュディレクトリは既定でシステムの一時ディレクトリ。`-t` で指定、`-f` でバイパスできます。同じ成果物を繰り返し再署名する場合に有効です。

---

## テスト

```bash
go test ./...   # ユニット + 統合テスト
go vet ./...    # 静的解析
```

`internal/macho`、`internal/signing`、`internal/resign` をカバー。Mach-O 解析、CMS 往復、ディスクキャッシュ、プロファイル解析、エンドツーエンドの再署名フロー（ad-hoc と再署名キャッシュ経路を含む）を検証しています。

---

## プロジェクト構成

```
ysign/
├── cmd/ysign/main.go              # CLI エントリポイント
├── internal/
│   ├── macho/                     # Mach-O 解析（fat/thin、ロードコマンド、署名、dylib）
│   ├── signing/                   # CodeDirectory 再構築、自作 CMS、ディスクキャッシュ、プロファイル/ID
│   ├── resign/                    # 再署名オーケストレーションと 2 パス署名
│   ├── ipautil/                   # ipa の展開 / 再パック
│   ├── plistutil/                 # plist 読み書きヘルパー
│   └── inspect/                   # 証明書検査（OCSP 含む）とメタデータ書き出し
└── test/                          # テスト素材（証明書 / プロファイル / ipa）
```

---

## 安全性とコンプライアンス

- **署名する権限がある**アプリのみに本ツールを使用し、Apple Developer Program の契約と適用される法令を遵守してください。
- サードパーティ製アプリの再署名、DRM / 権限チェックの除去、App Store レビューの回避などは契約違反となる可能性があります。使用は自己責任です。
- 本ツールはクラッキングや脱獄機能を一切含みません。標準のコード署名機能のみを提供します。

---

## License

このプロジェクトは [MIT License](LICENSE) のもとで提供されます。Copyright (c) 2026 Amias。

---

*ysign — fast cross-platform iOS code signing tool (zsign-compatible).*
