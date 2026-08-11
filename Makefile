VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

.PHONY: build clean test docker install build-linux build-linux-arm64 build-all

# Build for current platform
build:
	go build -ldflags "$(LDFLAGS)" -tags "with_quic with_utls with_wireguard with_clash_api" -o xboard-node ./cmd/xboard-node
	go build -ldflags "$(LDFLAGS)" -o xbctl ./cmd/xbctl

# Build for Linux amd64
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -tags "with_quic with_utls with_wireguard with_acme with_clash_api" -o xboard-node-linux-amd64 ./cmd/xboard-node
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o xbctl-linux-amd64 ./cmd/xbctl

# Build for Linux arm64
build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -tags "with_quic with_utls with_wireguard with_acme with_clash_api" -o xboard-node-linux-arm64 ./cmd/xboard-node
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o xbctl-linux-arm64 ./cmd/xbctl

# Build all platforms
build-all: build-linux build-linux-arm64

# Run tests
test:
	go test -v -race -count=1 ./internal/...

# Clean build artifacts
clean:
	rm -f xboard-node xbctl xboard-node-linux-* xbctl-linux-*

# Build Docker image
docker:
	docker build -t xboard-node:$(VERSION) -t xboard-node:latest .

# 本机快速安装（单节点，历史遗留用法）。
#
# **给新面板（lb-panel）装 agent 请走 install.sh** —— 它才会用 lb-node 那套名字
# （/etc/lb-node、lb-node.service、lbctl、健康端口 65531），和现网跑着的
# xboard-node 不打架。这个 target 仍然按旧名装，会覆盖现网 agent 的文件。
install: build
	sudo cp xboard-node /usr/local/bin/
	sudo cp xbctl /usr/local/bin/
	sudo mkdir -p /etc/xboard-node
	@if [ ! -f /etc/xboard-node/config.yml ]; then \
		sudo cp config.yml.example /etc/xboard-node/config.yml; \
		echo "Config copied to /etc/xboard-node/config.yml - please edit it"; \
	fi
