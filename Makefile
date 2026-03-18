BINARY_DIR := bin
AGENT_BINARY := $(BINARY_DIR)/agent
CTL_BINARY := $(BINARY_DIR)/vpnctl
TUI_BINARY := $(BINARY_DIR)/vpn-tui
GO := go
GOFLAGS := -trimpath
LDFLAGS := -s -w

.PHONY: all build-agent build-ctl build-tui test fmt lint clean

all: build-agent build-ctl build-tui

build-agent:
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(AGENT_BINARY) ./cmd/agent

build-ctl:
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(CTL_BINARY) ./cmd/ctl

build-tui:
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(TUI_BINARY) ./cmd/tui

test:
	$(GO) test -v -race -count=1 ./...

fmt:
	$(GO) fmt ./...

lint:
	$(GO) vet ./...
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not installed, skipping (go install honnef.co/go/tools/cmd/staticcheck@latest)"; \
	fi

clean:
	rm -rf $(BINARY_DIR)
