BINARY_DIR := bin
API_BINARY := $(BINARY_DIR)/api
AGENT_BINARY := $(BINARY_DIR)/agent
GO := go
GOFLAGS := -trimpath
LDFLAGS := -s -w

.PHONY: all build-api build-agent test fmt lint clean tf-init tf-plan tf-apply tf-destroy

all: build-api build-agent

build-api:
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(API_BINARY) ./cmd/api

build-agent:
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(AGENT_BINARY) ./cmd/agent

test:
	$(GO) test -v -race -count=1 ./...

fmt:
	$(GO) fmt ./...
	terraform fmt -recursive terraform/

lint:
	$(GO) vet ./...
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not installed, skipping (go install honnef.co/go/tools/cmd/staticcheck@latest)"; \
	fi

clean:
	rm -rf $(BINARY_DIR)

tf-init:
	cd terraform && terraform init

tf-plan:
	cd terraform && terraform plan

tf-apply:
	cd terraform && terraform apply

tf-destroy:
	cd terraform && terraform destroy
