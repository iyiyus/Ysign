<div align="center">

# ysign

**纯 Go 编写的跨平台 iOS 代码签名 / 重签名工具 · 对标 zsign 的功能平替**

无需 Xcode，无需 macOS，单文件二进制即可重签 `.ipa` / `.app`。

**Language / 语言 / 言語 / 언어**：
[简体中文](README.md) · [English](README_EN.md) · [日本語](README_JA.md) · [한국어](README_KO.md)

</div>

---

## 简介

`ysign` 是一个用 **纯 Go** 编写的跨平台 iOS 代码签名 / 重签名工具，作为 [zsign](https://github.com/zhlynn/zsign) 的功能平替实现。它不依赖 Xcode，也不依赖 macOS：一条命令即可用你的证书（`.p12` / PEM）与描述文件（`.mobileprovision`）对 `.ipa` 或 `.app` 完成重签名。

核心代码签名栈 **全部自研**：Mach-O（fat / thin）解析、SHA-256 CodeDirectory 重建、以及不依赖第三方库的 CMS / PKCS#7 签名生成（支持 RSA 与 ECDSA）。针对“签名要快”，做了 **多线程并行签名**（worker 池按 CPU 数同时处理每个二进制）与按内容寻址的磁盘缓存。23MB / 38 个二进制的整包重签，冷签约 **2.0 秒**，缓存命中约 **1.7 秒**。

---

## 特性

**Bundle 编辑**
- `-b` 修改 bundle id、`-n` 名称、`-r` 版本、`-M` 最低系统版本
- `-e` 指定新的 entitlements，`-I` 替换应用图标，`-S` 启用文件 App 集成（`UISupportsDocumentBrowser` / `UIFileSharingEnabled`）

**dylib**
- `-l` 注入 dylib、`-w` 以 weak 方式注入、`-D` 移除 dylib、`-P` 同时注入到扩展

**证书与描述文件**
- `-k` 私钥 / `.p12`，`-c` 证书，`-p` 密码
- `-m` 支持多个描述文件：第一个嵌入为 `embedded.mobileprovision`，其余按 `application-identifier` 自动匹配 `PlugIns/*.appex` 扩展
- `-a` adhoc 签名（无证书）

**检查与元数据**
- `-C` 检查证书 / 描述文件 / 代码签名（含 OCSP 尽力检查），支持 `.ipa`、`.p12`、`.mobileprovision`、`.cer`、Mach-O
- `-x` 导出 `metadata.json` 与应用图标
- `-v` 显示版本，`-d` 保留中间文件便于排查

**清理与打包**
- `-E` 删除扩展、`-W` 删除 Watch、`-U` 清空 `UISupportedDevices`、`-R` 删除描述文件
- `-z 0-9` 控制压缩级别，`-o` 指定输出，`-t` 指定临时 / 缓存目录

**性能**
- **多线程并行签名**：worker 池按 CPU 数同时处理多个二进制，冷签明显提速
- 按内容寻址的磁盘缓存（页哈希、CMS 签名），`-f` 强制绕过，`-t` 指定缓存目录
- `-2` 真正强制 SHA-256 CodeDirectory（特殊槽按真实数据重算，对齐 zsign）

---

## 技术亮点

- **纯 Go 标准库 + 少量依赖**，单文件交叉编译，Windows / macOS / Linux 通用
- **自研 CMS / PKCS#7**：SHA-256、RSA / ECDSA 均可，严格遵循标准（`[0] EXPLICIT OCTET STRING` eContent）
- **完整 Mach-O 支持**：fat（32/64）/ thin、双字节序、load commands 遍历、dylib 注入 / 移除
- **正确处理 Apple 代码签名格式细节**（这些是常见坑）：
  - 代码签名区（superblob / CodeDirectory / 槽表）**一律大端**，与 Mach-O 本体字节序无关
  - 32 位 Mach-O 头部是 28 字节（load command 从 28 开始）
  - CMS 的 eContent 是 `[0] EXPLICIT OCTET STRING`
  - ipa 的 deflate 压缩必须用 `compress/flate`（裸 deflate），而非 zlib
- **两遍签名算法**：先算页哈希→建 CD/CMS→得最终尺寸→patch `LC_CODE_SIGNATURE` datasize→再算一遍页哈希，保证签名自洽

---

## 快速开始

### 构建

```bash
go build -o ysign ./cmd/ysign
```

或用 `Makefile` 一键构建 / 交叉编译 / 测试：

```bash
make build      # 构建当前平台
make test       # 运行测试
make release    # 交叉编译 darwin + linux + windows
```

> 仓库含 GitHub Actions：`ci.yml` 在每次 push 自动跑 `go vet` + `go test`；`release.yml` 在打 `v*` tag 时自动构建 6 个平台的二进制并发布 GitHub Release；`docker.yml` 同步发布多架构 Docker 镜像到 GHCR。

### 交叉编译（无需目标平台）

```bash
# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o ysign-darwin-arm64 ./cmd/ysign
# macOS (Intel)
GOOS=darwin GOARCH=amd64 go build -o ysign-darwin-amd64 ./cmd/ysign
# Linux
GOOS=linux GOARCH=amd64 go build -o ysign-linux-amd64 ./cmd/ysign
# Windows
GOOS=windows GOARCH=amd64 go build -o ysign.exe ./cmd/ysign
```

> Windows 可执行文件已内嵌版本信息（产品名、版本号、版权），可降低部分杀软误报；发新版时更新 `cmd/ysign/versioninfo.json` 后执行 `make resources` 重新生成。

### Docker（CI/CD）

镜像发布在 GitHub Container Registry，支持 `linux/amd64` 与 `linux/arm64`：

```bash
# 拉取
docker pull ghcr.io/iyiyus/ysign:latest

# 签名：把当前目录挂载到容器的 /work
docker run --rm -v "$PWD":/work ghcr.io/iyiyus/ysign \
  -k cert.p12 -p 密码 -m dev.mobileprovision -o signed.ipa input.ipa
```

> 容器工作目录为 `/work`，证书、描述文件与 ipa 通过卷挂载传入。推送 `v*` tag 时 CI 自动发布 `latest` 与对应版本号镜像，`main` 分支发布 `edge`；也可本地执行 `make docker` 构建。

### 最简单的重签名

```bash
ysign -k cert.p12 -p 你的密码 -m dev.mobileprovision -b com.your.app -o signed.ipa input.ipa
```

---

## 完整参数

```
用法: ysign [-options] [-k privkey.pem] [-m dev.prov] [-o output.ipa] file|folder

  -k, --pkey            私钥或 p12 文件路径
  -m, --prov            描述文件路径（可重复，用于扩展）
  -c, --cert            证书文件路径（PEM 或 DER）
  -a, --adhoc           仅 adhoc 签名（无需证书）
  -d, --debug           保留中间文件并打印工作目录
  -f, --force           强制签名，绕过缓存
  -o, --output          输出 ipa 路径
  -p, --password        私钥或 p12 密码
  -b, --bundle_id       新的 bundle identifier
  -n, --bundle_name     新的显示名称
  -r, --bundle_version  新的版本号
  -e, --entitlements    新的 entitlements 文件
  -I, --icon            新的应用图标（PNG）
  -z, --zip_level       压缩级别（0-9）
  -l, --dylib           注入的 dylib（可重复）
  -D, --rm_dylib        移除的 dylib（可重复）
  -w, --weak            以 weak 方式注入 dylib（可重复）
  -i, --install         签名后调用 ideviceinstaller 安装
  -t, --temp_folder     临时 / 缓存目录
  -2, --sha256_only     强制 SHA256-only CodeDirectory（含特殊槽重算）
  -C, --check           检查证书 / 描述文件 / 签名（支持 ipa）
  -x, --metadata        导出元数据与图标到目录
  -R, --rm_provision    签名后移除描述文件
  -S, --enable_docs     启用 UISupportsDocumentBrowser / UIFileSharingEnabled
  -M, --min_version     设置 Info.plist 的 MinimumOSVersion
  -E, --rm_extensions   删除所有 App 扩展（PlugIns）
  -W, --rm_watch        删除 Watch App
  -U, --rm_uisd         移除 UISupportedDevices
  -P, --inject_extensions 同时向扩展注入 dylib
  -q, --quiet           安静模式
  -v, --version         显示版本
  -h, --help            显示帮助
```

> 输入可以是 `.ipa`、`.app`，或含 `Payload` 的目录。`.app` 就地签名；`.ipa` 解压到临时目录、签名后重新打包，默认输出 `xxx-ysign.ipa` 到当前目录。

---

## 使用示例

```bash
# 1) 修改 bundle id / 名称 / 版本并重签
ysign -k dev.p12 -p 1234 -m dev.mobileprovision \
      -b com.example.app -n "我的应用" -r "2.1.0" \
      -o signed.ipa app.ipa

# 2) adhoc 签名（用于本地调试）
ysign -a -o adhoc.ipa app.ipa

# 3) 注入 dylib
ysign -k dev.p12 -p 1234 -m dev.mobileprovision \
      -l Tweak.dylib -o signed.ipa app.ipa

# 4) 移除 dylib
ysign -k dev.p12 -p 1234 -m dev.mobileprovision \
      -D Tweak.dylib -o signed.ipa app.ipa

# 5) 带扩展的应用，第二个描述文件自动匹配 appex
ysign -k dev.p12 -p 1234 -m main.mobileprovision -m ext.mobileprovision \
      -b com.example.app -o signed.ipa app.ipa

# 6) 检查证书
ysign -C -p 1234 cert.p12

# 7) 检查描述文件
ysign -C dev.mobileprovision

# 8) 导出元数据与图标
ysign -x outdir app.ipa
```

---

## 工作原理

1. **解包**：解压 `.ipa`（带 zip-slip 防护），解析 `Info.plist`，枚举所有 Mach-O 二进制（主程序、framework、appex）。
2. **解析**：对每个二进制解析 fat / thin、load commands，定位 `LC_CODE_SIGNATURE`。
3. **重建 CodeDirectory**：按原二进制的 hashType / pageSize / version / flags 重建 CD（header → identifier → team → 特殊槽哈希 → 代码页哈希）。
4. **生成 CMS**：自研 `SignedData`（SHA-256，RSA / ECDSA），eContent 为标准 `[0] EXPLICIT OCTET STRING`，嵌入签名者证书链。
5. **组装 superblob**：CodeDirectory + Requirements + Entitlements + Signature 槽。
6. **两遍签名 + 并行**：各二进制相互独立，用 worker 池按 CPU 数并行签名；每个二进制内部先算页哈希得最终尺寸并 patch datasize，第二遍在 patch 后的代码上重算页哈希，保证签名自洽。
7. **重打包**：以可配置压缩级别重新打包为 `.ipa`。

**主二进制**会换用新的 bundle id / team 并重算 `-1`（Info）与 `-5`（Entitlements）特殊槽；**嵌入式二进制**（framework / appex）保留自身标识符与特殊槽哈希。

---

## 缓存

按内容寻址，键设计：
- `ph_<sha256(代码字节)>` → 代码页哈希
- `cms_<sha256(CD)>_<证书序列号>` → CMS 签名

缓存目录默认在系统临时目录，可用 `-t` 指定，用 `-f` 强制绕过。适合反复重签同一产物的场景。

---

## 测试

```bash
go test ./...   # 单元测试 + 集成测试
go vet ./...    # 静态检查
```

`internal/macho`、`internal/signing`、`internal/resign` 均有测试，覆盖 Mach-O 解析、CMS 往返、磁盘缓存、描述文件解析、以及端到端重签名流程（含 adhoc、并行与二次签名缓存路径）。CI（`.github/workflows/ci.yml`）会在每次 push 自动执行以上检查。

---

## 项目结构

```
ysign/
├── cmd/ysign/main.go              # CLI 入口
├── internal/
│   ├── macho/                     # Mach-O 解析（fat/thin、load commands、签名定位、dylib 增删）
│   ├── signing/                   # CodeDirectory 重建、自研 CMS、磁盘缓存、描述文件 / 身份解析
│   ├── resign/                    # 重签名编排与两遍签名算法
│   ├── ipautil/                   # ipa 解包 / 打包
│   ├── plistutil/                 # plist 读写封装
│   └── inspect/                   # 证书检查（含 OCSP）与元数据导出
└── test/                          # 测试素材（证书 / 描述文件 / ipa）
```

---

## 安全与合规声明

- 请仅对**你有权签名**的应用使用本工具，并遵守 Apple 的开发者计划协议与相关法律法规。
- 重签名第三方应用、移除 DRM / 权限校验、或用于绕过应用商店审核等行为可能违反协议，请自行承担相关责任。
- 本工具不包含任何破解或越狱功能，仅提供标准的代码签名能力。

---

## License

本项目采用 [MIT License](LICENSE)。Copyright (c) 2026 Amias。

---

*ysign —— fast cross-platform iOS code signing tool (zsign-compatible).*
