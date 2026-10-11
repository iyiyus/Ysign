# ysign — cross-platform iOS code signing tool (pure Go)

BINARY  := ysign
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

IMAGE := ghcr.io/iyiyus/ysign
GOVERSIONINFO := github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.4.0

.PHONY: all build test vet darwin linux windows resources docker release clean

all: build

build: ## Build the host binary
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/ysign

resources: ## Regenerate Windows version-info resources (cmd/ysign/resource_windows_*.syso)
	cd cmd/ysign && go run $(GOVERSIONINFO) -platform-specific

docker: ## Build the Docker image locally
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

test: ## Run all tests
	go test ./...

vet: ## Run static analysis
	go vet ./...

darwin: ## Cross-compile for macOS (arm64 + amd64)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-darwin-arm64 ./cmd/ysign
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-darwin-amd64 ./cmd/ysign

linux: ## Cross-compile for Linux (amd64 + arm64)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-amd64 ./cmd/ysign
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-arm64 ./cmd/ysign

windows: ## Cross-compile for Windows (amd64 + arm64)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-windows-amd64.exe ./cmd/ysign
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-windows-arm64.exe ./cmd/ysign

release: darwin linux windows ## Build all release binaries

clean: ## Remove build artifacts
	rm -f $(BINARY) $(BINARY)-* $(BINARY).exe
	rm -rf dist dist-test
