# ==============================================================================
# DHCP Monitor Service - Makefile
# Build automation for Go binary compilation, protobuf generation, and testing
# ==============================================================================

# ------------------------------------------------------------------------------
# VARIABLES AND CONFIGURATION
# ------------------------------------------------------------------------------

BINARY_NAME := dhcp_monitor.exe
VERSION := 2.0.0
BUILD_TIME := $(shell powershell -Command "Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>nul || echo "unknown")

# Go build configuration
GOOS := windows
GOARCH := amd64
CGO_ENABLED := 1
GOFLAGS := -mod=readonly

# Linker flags for version injection
LDFLAGS := -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)

# Directories
BIN_DIR := bin
PROTO_DIR := proto
PROTO_GEN_DIR := proto/gen
CMD_DIR := cmd/dhcp_monitor
CONFIG_FILE := config/dhcp_monitor.yaml

# Default target
.DEFAULT_GOAL := build

# ------------------------------------------------------------------------------
# BUILD TARGETS
# ------------------------------------------------------------------------------

## build: Compile DHCP Monitor binary with CGO support
build:
	@echo "Building DHCP Monitor $(VERSION)..."
	@if not exist $(BIN_DIR) mkdir $(BIN_DIR)
	set CGO_ENABLED=1&& set GOOS=$(GOOS)&& set GOARCH=$(GOARCH)&& go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) ./$(CMD_DIR)
	@echo "Build complete: $(BIN_DIR)/$(BINARY_NAME)"

## build-linux: Cross-compile for Linux (no CGO)
build-linux:
	@echo "Building DHCP Monitor $(VERSION) for Linux..."
	@if not exist $(BIN_DIR) mkdir $(BIN_DIR)
	set CGO_ENABLED=0&& set GOOS=linux&& set GOARCH=amd64&& go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/dhcp_monitor_linux ./$(CMD_DIR)
	@echo "Build complete: $(BIN_DIR)/dhcp_monitor_linux"

## clean: Remove build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@if exist $(BIN_DIR) rmdir /s /q $(BIN_DIR)
	@if exist coverage.out del /f coverage.out
	@if exist coverage.html del /f coverage.html
	@echo "Clean complete"

# ------------------------------------------------------------------------------
# PROTOBUF TARGETS
# ------------------------------------------------------------------------------

## proto: Generate Protocol Buffer code
proto:
	@echo "Generating Protocol Buffer code..."
	@if not exist $(PROTO_GEN_DIR) mkdir $(PROTO_GEN_DIR)
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative $(PROTO_DIR)/dhcp_monitor.proto
	@echo "Protobuf generation complete"

## proto-clean: Remove generated protobuf code
proto-clean:
	@echo "Cleaning generated protobuf code..."
	@if exist $(PROTO_GEN_DIR)\*.go del /f $(PROTO_GEN_DIR)\*.go
	@echo "Protobuf clean complete"

# ------------------------------------------------------------------------------
# TEST TARGETS
# ------------------------------------------------------------------------------

## test: Run unit tests with race detector
test:
	@echo "Running unit tests..."
	go test -v -race -coverprofile=coverage.out ./...
	@echo "Tests complete"

## test-cover: Run tests and generate HTML coverage report
test-cover: test
	@echo "Generating coverage report..."
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## test-integration: Run integration tests (requires database)
test-integration:
	@echo "Running integration tests..."
	go test -v -tags=integration ./...
	@echo "Integration tests complete"

## test-short: Run fast unit tests only
test-short:
	@echo "Running short tests..."
	go test -short ./...
	@echo "Short tests complete"

# ------------------------------------------------------------------------------
# CODE QUALITY TARGETS
# ------------------------------------------------------------------------------

## lint: Run golangci-lint code quality checks
lint:
	@echo "Running linter..."
	golangci-lint run ./...
	@echo "Lint complete"

## fmt: Format Go code
fmt:
	@echo "Formatting Go code..."
	go fmt ./...
	@echo "Format complete"

## vet: Run go vet
vet:
	@echo "Running go vet..."
	go vet ./...
	@echo "Vet complete"

## check: Run all code quality checks
check: fmt vet lint
	@echo "All code quality checks passed"

# ------------------------------------------------------------------------------
# DATABASE TARGETS
# ------------------------------------------------------------------------------

## db-init: Initialize PostgreSQL database
db-init:
	@echo "Initializing database..."
	psql -U postgres -c "CREATE DATABASE safeops_network;" 2>nul || echo "Database may already exist"
	psql -U postgres -c "CREATE USER safeops_admin WITH PASSWORD 'changeme';" 2>nul || echo "User may already exist"
	psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE safeops_network TO safeops_admin;"
	@echo "Database initialization complete"

## db-migrate: Apply database migrations
db-migrate: build
	@echo "Running database migrations..."
	$(BIN_DIR)/$(BINARY_NAME) --migrate-only --config=$(CONFIG_FILE)
	@echo "Migrations complete"

## db-reset: Drop and recreate database
db-reset:
	@echo "Resetting database..."
	psql -U postgres -c "DROP DATABASE IF EXISTS safeops_network;"
	psql -U postgres -c "CREATE DATABASE safeops_network;"
	psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE safeops_network TO safeops_admin;"
	@echo "Database reset complete"

# ------------------------------------------------------------------------------
# RUN TARGETS
# ------------------------------------------------------------------------------

## run: Build and run DHCP Monitor
run: build
	@echo "Starting DHCP Monitor..."
	$(BIN_DIR)/$(BINARY_NAME) --config=$(CONFIG_FILE)

## run-debug: Run with debug logging
run-debug: build
	@echo "Starting DHCP Monitor in debug mode..."
	set LOG_LEVEL=DEBUG&& $(BIN_DIR)/$(BINARY_NAME) --config=$(CONFIG_FILE)

## run-validate: Validate configuration and exit
run-validate: build
	@echo "Validating configuration..."
	$(BIN_DIR)/$(BINARY_NAME) --validate --config=$(CONFIG_FILE)

# ------------------------------------------------------------------------------
# DEPENDENCY TARGETS
# ------------------------------------------------------------------------------

## deps: Install Go module dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod verify
	@echo "Dependencies installed"

## deps-tools: Install development tool dependencies
deps-tools:
	@echo "Installing development tools..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "Development tools installed"

## tidy: Clean up go.mod and go.sum
tidy:
	@echo "Tidying Go modules..."
	go mod tidy
	@echo "Tidy complete"

# ------------------------------------------------------------------------------
# VERSION AND INFO TARGETS
# ------------------------------------------------------------------------------

## version: Display version information
version:
	@echo DHCP Monitor Version Information
	@echo ================================
	@echo Version:    $(VERSION)
	@echo Build Time: $(BUILD_TIME)
	@echo Git Commit: $(GIT_COMMIT)
	@echo Go Version: $(shell go version)

## info: Display build configuration
info:
	@echo DHCP Monitor Build Configuration
	@echo =================================
	@echo Binary:     $(BINARY_NAME)
	@echo Version:    $(VERSION)
	@echo OS/Arch:    $(GOOS)/$(GOARCH)
	@echo CGO:        $(CGO_ENABLED)
	@echo Config:     $(CONFIG_FILE)

# ------------------------------------------------------------------------------
# DOCKER TARGETS (Future)
# ------------------------------------------------------------------------------

## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t dhcp-monitor:$(VERSION) .
	docker tag dhcp-monitor:$(VERSION) dhcp-monitor:latest
	@echo "Docker build complete"

## docker-run: Run in Docker container
docker-run:
	@echo "Running Docker container..."
	docker run --rm -e DB_PASSWORD=$(DB_PASSWORD) -p 50055:50055 dhcp-monitor:$(VERSION)

# ------------------------------------------------------------------------------
# COMPOSITE TARGETS
# ------------------------------------------------------------------------------

## all: Complete build workflow (clean, proto, build, test)
all: clean proto build test
	@echo "Full build complete"

## ci: CI/CD pipeline workflow
ci: deps proto build test lint
	@echo "CI pipeline complete"

## dev-setup: Complete development environment setup
dev-setup: deps deps-tools proto build
	@echo "Development environment ready"

# ------------------------------------------------------------------------------
# HELP TARGET
# ------------------------------------------------------------------------------

## help: Display available make targets
help:
	@echo.
	@echo DHCP Monitor - Available Make Targets
	@echo ======================================
	@echo.
	@echo BUILD:
	@echo   build           Compile DHCP Monitor binary with CGO support
	@echo   build-linux     Cross-compile for Linux (no CGO)
	@echo   clean           Remove build artifacts
	@echo.
	@echo PROTOBUF:
	@echo   proto           Generate Protocol Buffer code
	@echo   proto-clean     Remove generated protobuf code
	@echo.
	@echo TESTING:
	@echo   test            Run unit tests with race detector
	@echo   test-cover      Run tests and generate HTML coverage
	@echo   test-integration Run integration tests (requires DB)
	@echo   test-short      Run fast unit tests only
	@echo.
	@echo CODE QUALITY:
	@echo   lint            Run golangci-lint code quality checks
	@echo   fmt             Format Go code
	@echo   vet             Run go vet
	@echo   check           Run all code quality checks
	@echo.
	@echo DATABASE:
	@echo   db-init         Initialize PostgreSQL database
	@echo   db-migrate      Apply database migrations
	@echo   db-reset        Drop and recreate database
	@echo.
	@echo RUN:
	@echo   run             Build and run DHCP Monitor
	@echo   run-debug       Run with debug logging
	@echo   run-validate    Validate configuration and exit
	@echo.
	@echo DEPENDENCIES:
	@echo   deps            Install Go module dependencies
	@echo   deps-tools      Install development tool dependencies
	@echo   tidy            Clean up go.mod and go.sum
	@echo.
	@echo INFO:
	@echo   version         Display version information
	@echo   info            Display build configuration
	@echo   help            Display this help message
	@echo.
	@echo COMPOSITE:
	@echo   all             Complete build workflow
	@echo   ci              CI/CD pipeline workflow
	@echo   dev-setup       Complete development environment setup
	@echo.

# ------------------------------------------------------------------------------
# PHONY TARGETS
# ------------------------------------------------------------------------------

.PHONY: build build-linux clean proto proto-clean \
        test test-cover test-integration test-short \
        lint fmt vet check \
        db-init db-migrate db-reset \
        run run-debug run-validate \
        deps deps-tools tidy \
        version info help \
        docker-build docker-run \
        all ci dev-setup
