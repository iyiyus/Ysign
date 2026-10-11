<div align="center">

# ysign

**순수 Go로 작성된 크로스플랫폼 iOS 코드 서명 / 재서명 도구 — zsign 호환 기능 대체**

Xcode도 macOS도 필요 없습니다. 단일 바이너리로 `.ipa` / `.app`을 재서명할 수 있습니다.

**Language / 语言 / 言語 / 언어**：
[简体中文](README.md) · [English](README_EN.md) · [日本語](README_JA.md) · [한국어](README_KO.md)

</div>

---

## 소개

`ysign`은 **순수 Go**로 작성된 크로스플랫폼 iOS 코드 서명 / 재서명 도구로, [zsign](https://github.com/zhlynn/zsign)의 기능 호환 대체로 구현되었습니다. Xcode나 macOS에 의존하지 않으며, 사용자의 인증서(`.p12` / PEM)와 프로비저닝 프로파일(`.mobileprovision`)만으로 한 번의 명령으로 `.ipa` 또는 `.app`을 재서명할 수 있습니다.

코드 서명 스택은 **전부 자체 구현**입니다. Mach-O(fat/thin) 파싱, SHA-256 CodeDirectory 재구성, 그리고 서드파티 라이브러리에 의존하지 않는 CMS/PKCS#7 서명 생성(RSA·ECDSA 지원)을 갖추고 있습니다. "서명을 빠르게"라는 요구에 맞춰 **멀티스레드 병렬 서명**(CPU 수만큼의 워커 풀로 각 바이너리를 병렬 처리)과 콘텐츠 주소 기반 디스크 캐시를 구현했습니다. 23MB·38개 바이너리 앱을 콜드 서명 시 **약 2.0초**, 캐시 히트 시 **약 1.7초**입니다.

---

## 기능

**Bundle 편집**
- `-b` 번들 ID, `-n` 이름, `-r` 버전, `-M` 최소 OS 버전 변경
- `-e` 새 entitlements 지정, `-I` 앱 아이콘 교체, `-S` 파일 앱 연동(`UISupportsDocumentBrowser` / `UIFileSharingEnabled`) 활성화

**dylib**
- `-l` dylib 주입, `-w` weak 주입, `-D` dylib 제거, `-P` 확장에도 동시 주입

**인증서와 프로파일**
- `-k` 개인 키 / `.p12`, `-c` 인증서, `-p` 비밀번호
- `-m`은 여러 프로파일 지원. 첫 번째는 `embedded.mobileprovision`으로 임베드하고, 나머지는 `application-identifier`로 `PlugIns/*.appex` 확장에 자동 매칭
- `-a` ad-hoc 서명(인증서 불필요)

**검사와 메타데이터**
- `-C` 인증서 / 프로파일 / 코드 서명 검사(베스트에포트 OCSP 포함). `.ipa`, `.p12`, `.mobileprovision`, `.cer`, Mach-O 지원
- `-x` `metadata.json`과 앱 아이콘 내보내기
- `-v` 버전 표시, `-d` 중간 파일 유지로 디버깅

**정리와 패키징**
- `-E` 확장 제거, `-W` Watch 제거, `-U` `UISupportedDevices` 비우기, `-R` 프로파일 제거
- `-z 0-9` 압축 레벨, `-o` 출력 경로, `-t` 임시 / 캐시 디렉터리

**성능**
- **멀티스레드 병렬 서명**: CPU 수만큼의 워커 풀로 여러 바이너리를 동시 처리, 콜드 서명을 크게 단축
- 콘텐츠 주소 기반 디스크 캐시(페이지 해시, CMS 서명). `-f`로 우회, `-t`로 디렉터리 지정
- `-2`로 SHA-256 CodeDirectory를 실제로 강제(특수 슬롯을 실데이터에서 재계산, zsign에 맞춤)

---

## 기술적 특징

- **순수 Go 표준 라이브러리 + 소수의 의존성**, 단일 바이너리 크로스 컴파일, Windows / macOS / Linux 지원
- **자체 구현 CMS / PKCS#7**: SHA-256, RSA / ECDSA 지원, 표준 준수(`[0] EXPLICIT OCTET STRING` eContent)
- **완전한 Mach-O 지원**: fat(32/64) / thin, 양쪽 바이트 오더, 로드 커맨드 순회, dylib 주입 / 제거
- **Apple 코드 서명 형식의 세부 사항을 올바르게 처리**(흔한 함정):
  - 코드 서명 영역(superblob / CodeDirectory / 슬롯 테이블)은 Mach-O 자체의 바이트 오더와 무관하게 **항상 빅엔디언**
  - 32비트 Mach-O 헤더는 28바이트(로드 커맨드는 28부터 시작)
  - CMS의 eContent는 `[0] EXPLICIT OCTET STRING`
  - ipa의 deflate 압축은 `compress/flate`(raw deflate)를 사용해야 하며 zlib는 사용 불가
- **2-pass 서명**: 페이지 해시 계산 → CD/CMS 생성 → 최종 크기 확정 → `LC_CODE_SIGNATURE`의 datasize 패치 → 패치된 코드를 다시 해시하여 서명의 자기 일관성 보장

---

## 빠른 시작

### 빌드

```bash
go build -o ysign ./cmd/ysign
```

또는 `Makefile`로 한 번에 빌드 / 크로스 컴파일 / 테스트:

```bash
make build      # 현재 플랫폼용 빌드
make test       # 테스트 실행
make release    # darwin + linux + windows 크로스 컴파일
```

> 저장소에 GitHub Actions가 포함되어 있습니다: `ci.yml`은 push 때마다 `go vet` + `go test`를 실행하고, `release.yml`은 `v*` 태그 push 시 6개 플랫폼 바이너리를 빌드해 GitHub Release를 발행하며, `docker.yml`은 멀티 아키텍처 Docker 이미지를 GHCR에 공개합니다.

### 크로스 컴파일(대상 OS 불필요)

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

> Windows 실행 파일에는 버전 정보(제품명, 버전, 저작권)가 내장되어 있어 일부 백신의 오탐지를 줄입니다. 새 릴리스 시 `cmd/ysign/versioninfo.json`을 갱신한 뒤 `make resources`로 다시 생성하세요.

### Docker(CI/CD)

이미지는 GitHub Container Registry에 `linux/amd64`, `linux/arm64`로 공개됩니다:

```bash
# 가져오기
docker pull ghcr.io/iyiyus/ysign:latest

# 서명: 현재 디렉터리를 컨테이너의 /work에 마운트
docker run --rm -v "$PWD":/work ghcr.io/iyiyus/ysign \
  -k cert.p12 -p 비밀번호 -m dev.mobileprovision -o signed.ipa input.ipa
```

> 컨테이너 작업 디렉터리는 `/work`이며 인증서, 프로파일, ipa는 볼륨 마운트로 전달합니다. `v*` 태그 push 시 `latest`와 버전 이미지가, `main` 브랜치에서는 `edge`가 공개됩니다. 로컬에서는 `make docker`로 빌드할 수 있습니다.

### 최소 재서명

```bash
ysign -k cert.p12 -p 비밀번호 -m dev.mobileprovision -b com.your.app -o signed.ipa input.ipa
```

---

## 전체 옵션

```
Usage: ysign [-options] [-k privkey.pem] [-m dev.prov] [-o output.ipa] file|folder

  -k, --pkey            개인 키 또는 p12 파일 경로
  -m, --prov            프로비저닝 프로파일 경로(확장용으로 반복 지정 가능)
  -c, --cert            인증서 파일 경로(PEM 또는 DER)
  -a, --adhoc           ad-hoc 서명만 수행
  -d, --debug           중간 파일 유지 및 작업 디렉터리 출력
  -f, --force           캐시 없이 강제 서명
  -o, --output          출력 ipa 파일 경로
  -p, --password        개인 키 또는 p12 비밀번호
  -b, --bundle_id       새 bundle identifier
  -n, --bundle_name     새 표시 이름
  -r, --bundle_version  새 버전
  -e, --entitlements    새 entitlements 파일
  -I, --icon            새 앱 아이콘(PNG)
  -z, --zip_level       압축 레벨(0-9)
  -l, --dylib           주입할 dylib(반복 지정 가능)
  -D, --rm_dylib        제거할 dylib(반복 지정 가능)
  -w, --weak            dylib를 weak로 주입(반복 지정 가능)
  -i, --install         서명 후 ideviceinstaller로 설치
  -t, --temp_folder     중간 파일 임시 / 캐시 디렉터리
  -2, --sha256_only     SHA256 전용 code directory 강제(특수 슬롯 재계산 포함)
  -C, --check           인증서 / 프로파일 / 서명 검사(ipa 지원)
  -x, --metadata        메타데이터와 아이콘을 디렉터리로 내보내기
  -R, --rm_provision    서명 후 프로비저닝 프로파일 제거
  -S, --enable_docs     UISupportsDocumentBrowser / UIFileSharingEnabled 활성화
  -M, --min_version     Info.plist의 MinimumOSVersion 설정
  -E, --rm_extensions   모든 앱 확장(PlugIns) 제거
  -W, --rm_watch        Watch 앱 제거
  -U, --rm_uisd         UISupportedDevices 제거
  -P, --inject_extensions 확장에도 dylib 주입
  -q, --quiet           조용히 실행
  -v, --version         버전 표시
  -h, --help            도움말 표시
```

> 입력은 `.ipa`, `.app`, 또는 `Payload`를 포함한 디렉터리. `.app`은 그 자리에서 서명하고, `.ipa`는 임시 디렉터리에 풀어서 서명한 뒤 다시 패킹합니다. 기본적으로 현재 디렉터리에 `xxx-ysign.ipa`를 출력합니다.

---

## 사용 예시

```bash
# 1) 번들 ID / 이름 / 버전 변경 후 재서명
ysign -k dev.p12 -p 1234 -m dev.mobileprovision \
      -b com.example.app -n "My App" -r "2.1.0" \
      -o signed.ipa app.ipa

# 2) ad-hoc 서명(로컬 디버깅용)
ysign -a -o adhoc.ipa app.ipa

# 3) dylib 주입
ysign -k dev.p12 -p 1234 -m dev.mobileprovision \
      -l Tweak.dylib -o signed.ipa app.ipa

# 4) dylib 제거
ysign -k dev.p12 -p 1234 -m dev.mobileprovision \
      -D Tweak.dylib -o signed.ipa app.ipa

# 5) 확장이 있는 앱: 두 번째 프로파일이 appex에 자동 매칭
ysign -k dev.p12 -p 1234 -m main.mobileprovision -m ext.mobileprovision \
      -b com.example.app -o signed.ipa app.ipa

# 6) 인증서 검사
ysign -C -p 1234 cert.p12

# 7) 프로비저닝 프로파일 검사
ysign -C dev.mobileprovision

# 8) 메타데이터와 아이콘 내보내기
ysign -x outdir app.ipa
```

---

## 동작 원리

1. **해제**: `.ipa`를 압축 해제(zip-slip 방지 포함), `Info.plist`를 파싱, 모든 Mach-O 바이너리(메인 실행 파일, framework, appex)를 열거.
2. **파싱**: 각 바이너리의 fat/thin과 로드 커맨드를 파싱하고 `LC_CODE_SIGNATURE`를 식별.
3. **CodeDirectory 재구성**: 원본 바이너리의 hashType / pageSize / version / flags로 CD를 재구성(헤더 → identifier → team → 특수 슬롯 해시 → 코드 페이지 해시).
4. **CMS 생성**: 자체 구현 `SignedData`(SHA-256, RSA·ECDSA), eContent는 표준 `[0] EXPLICIT OCTET STRING`, 서명자 인증서 체인을 임베드.
5. **superblob 조립**: CodeDirectory + Requirements + Entitlements + Signature 슬롯.
6. **2-pass 서명 + 병렬**: 바이너리는 서로 독립적이므로 CPU 수만큼의 워커 풀로 병렬 서명. 각 바이너리는 1차로 페이지 해시를 계산해 최종 크기를 확정하고 datasize를 패치, 2차로 패치된 코드를 다시 해시하여 자기 일관성을 확보.
7. **재패킹**: 설정 가능한 압축 레벨로 `.ipa`로 다시 압축.

**메인 바이너리**는 새 bundle id / team으로 전환하고 특수 슬롯 `-1`(Info)과 `-5`(Entitlements)를 다시 계산합니다. **임베디드 바이너리**(framework / appex)는 자체 identifier와 특수 슬롯 해시를 유지합니다.

---

## 캐시

콘텐츠 주소 기반이며 다음 키를 사용합니다:
- `ph_<sha256(코드 바이트)>` → 코드 페이지 해시
- `cms_<sha256(CD)>_<인증서 일련번호>` → CMS 서명

캐시 디렉터리는 기본적으로 시스템 임시 디렉터리입니다. `-t`로 지정하고 `-f`로 우회할 수 있습니다. 같은 산출물을 반복해서 재서명할 때 유용합니다.

---

## 테스트

```bash
go test ./...   # 유닛 + 통합 테스트
go vet ./...    # 정적 분석
```

`internal/macho`, `internal/signing`, `internal/resign`을 다룹니다. Mach-O 파싱, CMS 왕복, 디스크 캐시, 프로파일 파싱, 그리고 엔드투엔드 재서명 흐름(ad-hoc, 병렬, 재서명 캐시 경로 포함)을 검증합니다. CI(`.github/workflows/ci.yml`)가 push 때마다 위 검사를 실행합니다.

---

## 프로젝트 구조

```
ysign/
├── cmd/ysign/main.go              # CLI 진입점
├── internal/
│   ├── macho/                     # Mach-O 파싱(fat/thin, 로드 커맨드, 서명, dylib)
│   ├── signing/                   # CodeDirectory 재구성, 자체 CMS, 디스크 캐시, 프로파일/ID
│   ├── resign/                    # 재서명 오케스트레이션 및 2-pass 서명
│   ├── ipautil/                   # ipa 해제 / 재패킹
│   ├── plistutil/                 # plist 읽기/쓰기 헬퍼
│   └── inspect/                   # 인증서 검사(OCSP 포함) 및 메타데이터 내보내기
└── test/                          # 테스트 자산(인증서 / 프로파일 / ipa)
```

---

## 안전 및 준수

- **서명할 권한이 있는** 앱에만 이 도구를 사용하고 Apple Developer Program 계약과 적용 법률을 준수하세요.
- 타사 앱 재서명, DRM / 권한 검사 제거, App Store 리뷰 우회 등은 계약 위반이 될 수 있습니다. 사용에 대한 책임은 본인에게 있습니다.
- 이 도구는 크래킹이나 탈옥 기능을 포함하지 않으며, 표준 코드 서명 기능만 제공합니다.

---

## License

이 프로젝트는 [MIT License](LICENSE) 하에 제공됩니다. Copyright (c) 2026 Amias.

---

*ysign — fast cross-platform iOS code signing tool (zsign-compatible).*
