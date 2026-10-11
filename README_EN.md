<div align="center">

# ysign

**A fast, cross-platform iOS code signing / re-signing tool written in pure Go — a drop-in, zsign-compatible alternative.**

No Xcode, no macOS. A single binary re-signs `.ipa` / `.app`.

**Language / 语言 / 言語 / 언어**：
[简体中文](README.md) · [English](README_EN.md) · [日本語](README_JA.md) · [한국어](README_KO.md)

</div>

---

## Introduction

`ysign` is a **pure Go** cross-platform iOS code signing / re-signing tool, implemented as a feature-compatible replacement for [zsign](https://github.com/zhlynn/zsign). It does not depend on Xcode or macOS: with a single command you can re-sign an `.ipa` or `.app` using your certificate (`.p12` / PEM) and provisioning profile (`.mobileprovision`).

The core code-signing stack is **entirely self-built**: Mach-O (fat / thin) parsing, SHA-256 CodeDirectory rebuilding, and CMS / PKCS#7 signature generation without any third-party library (RSA and ECDSA supported). To make signing fast, it uses **multi-threaded parallel signing** (a worker pool sized to your CPU count) plus a content-addressed disk cache: re-signing a 23MB app with 38 binaries takes **~2.0 s** cold, **~1.7 s** with a warm cache.

---

## Features

**Bundle editing**
- `-b` change bundle id, `-n` name, `-r` version, `-M` minimum OS version
- `-e` set a new entitlements file, `-I` replace the app icon, `-S` enable Files-app integration (`UISupportsDocumentBrowser` / `UIFileSharingEnabled`)

**dylibs**
- `-l` inject a dylib, `-w` inject as weak, `-D` remove a dylib, `-P` also inject into extensions

**Certificates & profiles**
- `-k` private key / `.p12`, `-c` certificate, `-p` password
- `-m` accepts multiple profiles: the first is embedded as `embedded.mobileprovision`, the rest are matched to `PlugIns/*.appex` extensions by `application-identifier`
- `-a` ad-hoc signing (no certificate)

**Inspection & metadata**
- `-C` inspect certificate / profile / code signature (with best-effort OCSP), supporting `.ipa`, `.p12`, `.mobileprovision`, `.cer`, Mach-O
- `-x` export `metadata.json` and the app icon
- `-v` show version, `-d` keep intermediate files for debugging

**Cleanup & packaging**
- `-E` remove extensions, `-W` remove Watch, `-U` clear `UISupportedDevices`, `-R` remove the profile
- `-z 0-9` compression level, `-o` output path, `-t` temp / cache dir

**Performance**
- **Multi-threaded parallel signing**: a worker pool sized to the CPU count processes multiple binaries at once, noticeably speeding up cold signs
- Content-addressed disk cache (page hashes, CMS signatures), bypass with `-f`, custom dir with `-t`
- `-2` truly forces a SHA-256 CodeDirectory (special slots recomputed from real data, aligned with zsign)

---

## Technical Highlights

- **Pure Go standard library + a few deps**, single-binary cross-compilation, works on Windows / macOS / Linux
- **Self-built CMS / PKCS#7**: SHA-256, RSA / ECDSA, standards-compliant (`[0] EXPLICIT OCTET STRING` eContent)
- **Full Mach-O support**: fat (32/64) / thin, both byte orders, load-command traversal, dylib inject / remove
- **Apple code-signing format details handled correctly** (common pitfalls):
  - The code-signature region (superblob / CodeDirectory / slot table) is **always big-endian**, independent of the Mach-O's own byte order
  - The 32-bit Mach-O header is 28 bytes (load commands start at 28)
  - CMS eContent is `[0] EXPLICIT OCTET STRING`
  - ipa deflate compression must use `compress/flate` (raw deflate), not zlib
- **Two-pass signing**: hash pages → build CD/CMS → get final size → patch `LC_CODE_SIGNATURE` datasize → re-hash pages, so the signature is self-consistent

---

## Quick Start

### Build

```bash
go build -o ysign ./cmd/ysign
```

Or use the `Makefile` for one-shot build / cross-compile / test:

```bash
make build      # build for the host platform
make test       # run tests
make release    # cross-compile darwin + linux + windows
```

> The repo ships GitHub Actions: `ci.yml` runs `go vet` + `go test` on every push; `release.yml` builds 6 platform binaries and publishes a GitHub Release when a `v*` tag is pushed; `docker.yml` publishes multi-arch Docker images to GHCR.

### Cross-compile (no target platform needed)

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

> The Windows executable embeds version info (product name, version, copyright), which reduces false positives from some antivirus products. When cutting a new release, update `cmd/ysign/versioninfo.json` and run `make resources` to regenerate it.

### Docker (CI/CD)

Images are published to the GitHub Container Registry for `linux/amd64` and `linux/arm64`:

```bash
# Pull
docker pull ghcr.io/iyiyus/ysign:latest

# Sign: mount the current directory into the container's /work
docker run --rm -v "$PWD":/work ghcr.io/iyiyus/ysign \
  -k cert.p12 -p PASSWORD -m dev.mobileprovision -o signed.ipa input.ipa
```

> The container's work directory is `/work`; pass the certificate, profile, and ipa in via a volume mount. Pushing a `v*` tag publishes `latest` plus the versioned image, while `main` publishes `edge`. You can also build locally with `make docker`.

### Minimal re-sign

```bash
ysign -k cert.p12 -p YOUR_PASSWORD -m dev.mobileprovision -b com.your.app -o signed.ipa input.ipa
```

---

## Full Options

```
Usage: ysign [-options] [-k privkey.pem] [-m dev.prov] [-o output.ipa] file|folder

  -k, --pkey            Path to private key or p12 file
  -m, --prov            Path to provisioning profile (repeat for extensions)
  -c, --cert            Path to certificate file (PEM or DER)
  -a, --adhoc           Perform ad-hoc signature only
  -d, --debug           Keep intermediate files and print the work directory
  -f, --force           Force sign without cache
  -o, --output          Path to output ipa file
  -p, --password        Password for private key or p12 file
  -b, --bundle_id       New bundle identifier
  -n, --bundle_name     New bundle display name
  -r, --bundle_version  New bundle version
  -e, --entitlements    New entitlements file
  -I, --icon            New app icon (PNG)
  -z, --zip_level       Compression level (0-9)
  -l, --dylib           Dylib to inject (repeatable)
  -D, --rm_dylib        Dylib to remove (repeatable)
  -w, --weak            Inject dylib as weak (repeatable)
  -i, --install         Install via ideviceinstaller after signing
  -t, --temp_folder     Temp folder for intermediate files
  -2, --sha256_only     Force SHA256-only code directory (incl. special-slot recompute)
  -C, --check           Check certificate / signature (supports ipa)
  -x, --metadata        Extract metadata and icon to directory
  -R, --rm_provision    Remove provisioning profile after signing
  -S, --enable_docs     Enable UISupportsDocumentBrowser / UIFileSharingEnabled
  -M, --min_version     Set MinimumOSVersion in Info.plist
  -E, --rm_extensions   Remove all app extensions (PlugIns)
  -W, --rm_watch        Remove watch app
  -U, --rm_uisd         Remove UISupportedDevices
  -P, --inject_extensions Also inject dylibs into extensions
  -q, --quiet           Quiet operation
  -v, --version         Show version
  -h, --help            Show help
```

> The input can be an `.ipa`, an `.app`, or a directory containing `Payload`. `.app` is signed in place; `.ipa` is extracted to a temp dir, signed, and re-packed, by default to `xxx-ysign.ipa` in the current directory.

---

## Usage Examples

```bash
# 1) Change bundle id / name / version and re-sign
ysign -k dev.p12 -p 1234 -m dev.mobileprovision \
      -b com.example.app -n "My App" -r "2.1.0" \
      -o signed.ipa app.ipa

# 2) Ad-hoc signing (for local debugging)
ysign -a -o adhoc.ipa app.ipa

# 3) Inject a dylib
ysign -k dev.p12 -p 1234 -m dev.mobileprovision \
      -l Tweak.dylib -o signed.ipa app.ipa

# 4) Remove a dylib
ysign -k dev.p12 -p 1234 -m dev.mobileprovision \
      -D Tweak.dylib -o signed.ipa app.ipa

# 5) App with extensions: the second profile auto-matches the appex
ysign -k dev.p12 -p 1234 -m main.mobileprovision -m ext.mobileprovision \
      -b com.example.app -o signed.ipa app.ipa

# 6) Check a certificate
ysign -C -p 1234 cert.p12

# 7) Check a provisioning profile
ysign -C dev.mobileprovision

# 8) Export metadata and icon
ysign -x outdir app.ipa
```

---

## How It Works

1. **Extract**: unzip the `.ipa` (with zip-slip protection), parse `Info.plist`, enumerate all Mach-O binaries (main executable, frameworks, appex).
2. **Parse**: for each binary parse fat / thin and load commands, locate `LC_CODE_SIGNATURE`.
3. **Rebuild CodeDirectory**: rebuild the CD from the original hashType / pageSize / version / flags (header → identifier → team → special-slot hashes → code-page hashes).
4. **Generate CMS**: self-built `SignedData` (SHA-256, RSA / ECDSA), eContent as standard `[0] EXPLICIT OCTET STRING`, embedding the signer certificate chain.
5. **Assemble superblob**: CodeDirectory + Requirements + Entitlements + Signature slots.
6. **Two-pass signing + parallel**: binaries are independent, so a worker pool sized to the CPU count signs them in parallel; each binary first hashes pages, gets the final size, and patches the datasize, then pass 2 re-hashes the patched code so the signature is self-consistent.
7. **Re-pack**: re-zip as an `.ipa` with a configurable compression level.

The **main binary** switches to the new bundle id / team and recomputes special slots `-1` (Info) and `-5` (Entitlements). **Embedded binaries** (frameworks / appex) keep their own identifier and special-slot hashes.

---

## Cache

Content-addressed, keyed by:
- `ph_<sha256(code bytes)>` → code page hashes
- `cms_<sha256(CD)>_<cert serial>` → CMS signature

The cache directory defaults to the system temp dir; set it with `-t` and bypass it with `-f`. Useful when re-signing the same artifact repeatedly.

---

## Testing

```bash
go test ./...   # unit + integration tests
go vet ./...    # static analysis
```

`internal/macho`, `internal/signing`, and `internal/resign` are covered, including Mach-O parsing, CMS round-trip, disk cache, profile parsing, and an end-to-end re-sign flow (with ad-hoc, parallel, and second-sign cache paths). CI (`.github/workflows/ci.yml`) runs the checks above on every push.

---

## Project Layout

```
ysign/
├── cmd/ysign/main.go              # CLI entry
├── internal/
│   ├── macho/                     # Mach-O parsing (fat/thin, load commands, signature, dylib)
│   ├── signing/                   # CodeDirectory rebuild, self-built CMS, disk cache, profile/identity
│   ├── resign/                    # re-sign orchestration & two-pass signing
│   ├── ipautil/                   # ipa extract / repack
│   ├── plistutil/                 # plist read/write helpers
│   └── inspect/                   # certificate check (incl. OCSP) & metadata export
└── test/                          # test assets (cert / profile / ipa)
```

---

## Safety & Compliance

- Use this tool only on apps **you are authorized to sign**, and comply with Apple's Developer Program Agreement and applicable law.
- Re-signing third-party apps, removing DRM / permission checks, or circumventing App Store review may violate agreements; you are responsible for your own use.
- This tool contains no cracking or jailbreak functionality — it only provides standard code-signing capability.

---

## License

This project is licensed under the [MIT License](LICENSE). Copyright (c) 2026 Amias.

---

*ysign — fast cross-platform iOS code signing tool (zsign-compatible).*
