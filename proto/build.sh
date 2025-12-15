#!/bin/bash

################################################################################
# SafeOps Proto Build Script (Linux/Mac)
################################################################################
# Purpose: Generate Go and Rust code from Protocol Buffers (.proto) files
# Usage:
#   ./build.sh              - Generate both Go and Rust code
#   ./build.sh --go-only    - Generate only Go code
#   ./build.sh --rust-only  - Generate only Rust code
#   ./build.sh --clean      - Clean generated code before building
#   ./build.sh --help       - Display this help message
################################################################################

set -e  # Exit on error

# Color codes for terminal output
readonly COLOR_RESET='\033[0m'
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[0;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_BOLD='\033[1m'

################################################################################
# Configuration Variables
################################################################################

PROTO_DIR="$(cd "$(dirname "$0")" && pwd)"
GRPC_DIR="$PROTO_DIR/grpc"
GO_OUT_DIR="$PROTO_DIR/gen/go"
RUST_OUT_DIR="$PROTO_DIR/gen/rust"

################################################################################
# Command Line Flags
################################################################################

FLAG_CLEAN=false
FLAG_GO_ONLY=false
FLAG_RUST_ONLY=false
FLAG_HELP=false

################################################################################
# Helper Functions
################################################################################

print_info() {
    echo -e "${COLOR_BLUE}ℹ ${1}${COLOR_RESET}"
}

print_success() {
    echo -e "${COLOR_GREEN}✓ ${1}${COLOR_RESET}"
}

print_warning() {
    echo -e "${COLOR_YELLOW}⚠ ${1}${COLOR_RESET}"
}

print_error() {
    echo -e "${COLOR_RED}✗ ${1}${COLOR_RESET}" >&2
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

show_help() {
    cat << EOF
${COLOR_BOLD}SafeOps Proto Build Script${COLOR_RESET}

${COLOR_BOLD}Usage:${COLOR_RESET}
    $0 [OPTIONS]

${COLOR_BOLD}Options:${COLOR_RESET}
    --clean         Remove previously generated code before building
    --go-only       Generate only Go code (skip Rust)
    --rust-only     Generate only Rust code (skip Go)
    --help          Display this help message

${COLOR_BOLD}Examples:${COLOR_RESET}
    $0                      # Generate both Go and Rust code
    $0 --clean --go-only    # Clean and generate only Go code
    $0 --rust-only          # Generate only Rust code

${COLOR_BOLD}Requirements:${COLOR_RESET}
    - protoc (Protocol Buffers compiler)
    - protoc-gen-go (Go plugin)
    - protoc-gen-go-grpc (Go gRPC plugin)
    - protoc-gen-rust (Rust plugin, optional)

EOF
}

################################################################################
# Parse Command Line Arguments
################################################################################

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            FLAG_CLEAN=true
            shift
            ;;
        --go-only)
            FLAG_GO_ONLY=true
            shift
            ;;
        --rust-only)
            FLAG_RUST_ONLY=true
            shift
            ;;
        --help)
            FLAG_HELP=true
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Show help and exit if requested
if [ "$FLAG_HELP" = true ]; then
    show_help
    exit 0
fi

# Validate conflicting flags
if [ "$FLAG_GO_ONLY" = true ] && [ "$FLAG_RUST_ONLY" = true ]; then
    print_error "Cannot use both --go-only and --rust-only flags"
    exit 1
fi

################################################################################
# Banner
################################################################################

echo ""
echo -e "${COLOR_BOLD}════════════════════════════════════════════════════════════${COLOR_RESET}"
echo -e "${COLOR_BOLD}   SafeOps Protocol Buffers Code Generation${COLOR_RESET}"
echo -e "${COLOR_BOLD}════════════════════════════════════════════════════════════${COLOR_RESET}"
echo ""

################################################################################
# Dependency Checking
################################################################################

print_info "Checking required dependencies..."
echo ""

GENERATE_GO=true
GENERATE_RUST=true

# Adjust based on flags
if [ "$FLAG_RUST_ONLY" = true ]; then
    GENERATE_GO=false
fi

if [ "$FLAG_GO_ONLY" = true ]; then
    GENERATE_RUST=false
fi

# Check protoc
if ! command_exists protoc; then
    print_error "protoc not found"
    echo "Install with:"
    echo "  Ubuntu/Debian: sudo apt-get install protobuf-compiler"
    echo "  macOS: brew install protobuf"
    exit 1
fi
PROTOC_VERSION=$(protoc --version | awk '{print $2}')
print_success "protoc found (version $PROTOC_VERSION)"

# Check Go tools
if [ "$GENERATE_GO" = true ]; then
    if ! command_exists protoc-gen-go; then
        print_error "protoc-gen-go not found"
        echo "Install with: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"
        exit 1
    fi
    print_success "protoc-gen-go found"

    if ! command_exists protoc-gen-go-grpc; then
        print_error "protoc-gen-go-grpc not found"
        echo "Install with: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"
        exit 1
    fi
    print_success "protoc-gen-go-grpc found"
fi

# Check Rust tools (optional)
if [ "$GENERATE_RUST" = true ]; then
    if ! command_exists protoc-gen-rust; then
        print_warning "protoc-gen-rust not found (skipping Rust generation)"
        echo "Install with: cargo install protobuf-codegen"
        GENERATE_RUST=false
    else
        print_success "protoc-gen-rust found"
    fi
fi

echo ""

################################################################################
# Clean Operation
################################################################################

if [ "$FLAG_CLEAN" = true ]; then
    print_info "Cleaning previously generated code..."
    
    if [ "$GENERATE_GO" = true ] && [ -d "$GO_OUT_DIR" ]; then
        rm -rf "$GO_OUT_DIR"
        print_success "Removed Go output directory: $GO_OUT_DIR"
    fi
    
    if [ "$GENERATE_RUST" = true ] && [ -d "$RUST_OUT_DIR" ]; then
        rm -rf "$RUST_OUT_DIR"
        print_success "Removed Rust output directory: $RUST_OUT_DIR"
    fi
    
    echo ""
fi

################################################################################
# Directory Creation
################################################################################

print_info "Creating output directories..."

if [ "$GENERATE_GO" = true ]; then
    mkdir -p "$GO_OUT_DIR"
    print_success "Created Go output directory: $GO_OUT_DIR"
fi

if [ "$GENERATE_RUST" = true ]; then
    mkdir -p "$RUST_OUT_DIR"
    print_success "Created Rust output directory: $RUST_OUT_DIR"
fi

echo ""

################################################################################
# Proto File Discovery
################################################################################

print_info "Discovering .proto files..."

if [ ! -d "$GRPC_DIR" ]; then
    print_error "gRPC directory not found: $GRPC_DIR"
    exit 1
fi

# Find all .proto files and sort them
PROTO_FILES=($(find "$GRPC_DIR" -name "*.proto" | sort))
PROTO_COUNT=${#PROTO_FILES[@]}

if [ $PROTO_COUNT -eq 0 ]; then
    print_error "No .proto files found in $GRPC_DIR"
    exit 1
fi

print_success "Found $PROTO_COUNT .proto file(s)"
echo ""

################################################################################
# Go Code Generation
################################################################################

if [ "$GENERATE_GO" = true ]; then
    print_info "Generating Go code..."
    echo ""
    
    GO_SUCCESS_COUNT=0
    GO_FAIL_COUNT=0
    
    for proto_file in "${PROTO_FILES[@]}"; do
        filename=$(basename "$proto_file")
        echo -n "  Processing $filename... "
        
        if protoc \
            --proto_path="$GRPC_DIR" \
            --go_out="$GO_OUT_DIR" \
            --go_opt=paths=source_relative \
            --go-grpc_out="$GO_OUT_DIR" \
            --go-grpc_opt=paths=source_relative \
            "$proto_file" 2>/dev/null; then
            echo -e "${COLOR_GREEN}✓${COLOR_RESET}"
            ((GO_SUCCESS_COUNT++))
        else
            echo -e "${COLOR_RED}✗${COLOR_RESET}"
            ((GO_FAIL_COUNT++))
            print_error "Failed to generate Go code for $filename"
        fi
    done
    
    echo ""
    
    if [ $GO_FAIL_COUNT -eq 0 ]; then
        GO_FILE_COUNT=$(find "$GO_OUT_DIR" -name "*.pb.go" | wc -l)
        print_success "Go code generation complete: $GO_FILE_COUNT file(s) generated"
    else
        print_error "Go code generation completed with $GO_FAIL_COUNT error(s)"
        exit 1
    fi
    
    echo ""
fi

################################################################################
# Rust Code Generation
################################################################################

if [ "$GENERATE_RUST" = true ]; then
    print_info "Generating Rust code..."
    echo ""
    
    RUST_SUCCESS_COUNT=0
    RUST_FAIL_COUNT=0
    
    for proto_file in "${PROTO_FILES[@]}"; do
        filename=$(basename "$proto_file")
        echo -n "  Processing $filename... "
        
        if protoc \
            --proto_path="$GRPC_DIR" \
            --rust_out="$RUST_OUT_DIR" \
            "$proto_file" 2>/dev/null; then
            echo -e "${COLOR_GREEN}✓${COLOR_RESET}"
            ((RUST_SUCCESS_COUNT++))
        else
            echo -e "${COLOR_RED}✗${COLOR_RESET}"
            ((RUST_FAIL_COUNT++))
            print_error "Failed to generate Rust code for $filename"
        fi
    done
    
    echo ""
    
    if [ $RUST_FAIL_COUNT -eq 0 ]; then
        RUST_FILE_COUNT=$(find "$RUST_OUT_DIR" -name "*.rs" | wc -l)
        print_success "Rust code generation complete: $RUST_FILE_COUNT file(s) generated"
        
        # Generate mod.rs file
        print_info "Generating mod.rs..."
        MOD_RS_FILE="$RUST_OUT_DIR/mod.rs"
        echo "// Auto-generated module file" > "$MOD_RS_FILE"
        echo "// Generated on: $(date)" >> "$MOD_RS_FILE"
        echo "" >> "$MOD_RS_FILE"
        
        for rs_file in $(find "$RUST_OUT_DIR" -name "*.rs" -not -name "mod.rs" | sort); do
            module_name=$(basename "$rs_file" .rs)
            echo "pub mod $module_name;" >> "$MOD_RS_FILE"
        done
        
        print_success "Generated mod.rs with $RUST_FILE_COUNT module(s)"
    else
        print_error "Rust code generation completed with $RUST_FAIL_COUNT error(s)"
        exit 1
    fi
    
    echo ""
fi

################################################################################
# Build Summary
################################################################################

echo ""
echo -e "${COLOR_BOLD}════════════════════════════════════════════════════════════${COLOR_RESET}"
echo -e "${COLOR_BOLD}   Build Summary${COLOR_RESET}"
echo -e "${COLOR_BOLD}════════════════════════════════════════════════════════════${COLOR_RESET}"
echo ""
echo "  Proto files processed: $PROTO_COUNT"

if [ "$GENERATE_GO" = true ]; then
    echo "  Go files generated:    $GO_FILE_COUNT"
    echo "  Go output directory:   $GO_OUT_DIR"
fi

if [ "$GENERATE_RUST" = true ]; then
    echo "  Rust files generated:  $RUST_FILE_COUNT"
    echo "  Rust output directory: $RUST_OUT_DIR"
fi

echo ""
echo -e "${COLOR_GREEN}${COLOR_BOLD}✓ Build completed successfully!${COLOR_RESET}"
echo "  Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

exit 0
