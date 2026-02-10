# ShareHound Go Makefile

BINARY_NAME=sharehound
VERSION=1.0.0
BUILD_DIR=build
GO=go

# Build flags
LDFLAGS=-ldflags "-s -w -X main.Version=$(VERSION)"

.PHONY: all build clean test lint fmt deps help

all: build

## build: Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/sharehound

## build-all: Build for all platforms
build-all: build-linux build-windows build-darwin

## build-linux: Build for Linux
build-linux:
	@echo "Building for Linux..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/sharehound
	GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/sharehound

## build-windows: Build for Windows
build-windows:
	@echo "Building for Windows..."
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/sharehound

## build-darwin: Build for macOS
build-darwin:
	@echo "Building for macOS..."
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/sharehound
	GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/sharehound

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	$(GO) clean

## test: Run tests
test:
	@echo "Running tests..."
	$(GO) test -v ./...

## test-coverage: Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GO) test -v -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

## lint: Run linter
lint:
	@echo "Running linter..."
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

## fmt: Format code
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...
	@if command -v goimports > /dev/null; then \
		goimports -w .; \
	fi

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GO) mod download
	$(GO) mod tidy

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GO) vet ./...

## run: Run the binary
run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

## install: Install the binary
install: build
	@echo "Installing $(BINARY_NAME)..."
	$(GO) install ./cmd/sharehound

## help: Show this help
help:
	@echo "ShareHound Go - Makefile targets:"
	@echo ""
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
