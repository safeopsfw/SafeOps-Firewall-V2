#!/usr/bin/env bash
#
# SafeOps Protocol Buffers Build Script for Linux/Unix
#
# This script automates the protocol buffer compilation process on POSIX-compliant systems.
# It generates Go code from all .proto files, handles dependency resolution, validates tools,
# and provides comprehensive error reporting for development and CI/CD environments.
#
# Usage:
#   ./build.sh [OPTIONS]
#
# Options:
#   --clean         Remove previously generated code before building
#   --verbose       Enable detailed output during compilation
#   --check         Validate proto syntax without generating code
#   --proto-dir     Custom proto source directory (default: proto/grpc)
#   --output-dir    Custom output directory (default: build/proto/go)
#   --parallel      Enable parallel compilation using GNU parallel
#   --help          Display this help message
#
# Requirements:
#   - bash 4.0+
#   - protoc v3.19.0+
#   - protoc-gen-go v1.28.0+
#   - protoc-gen-go-grpc v1.2.0+
#   - Go 1.19+
#

set -euo pipefail

################################################################################
# Configuration Variables
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PROTO_DIR="${PROTO_SOURCE_DIR:-${SCRIPT_DIR}/grpc}"
BUILD_DIR="${PROJECT_ROOT}/build"
OUTPUT_DIR="${PROTO_OUTPUT_DIR:-${BUILD_DIR}/proto/go}"
RUST_OUTPUT_DIR="${BUILD_DIR}/proto/rust"

# Version requirements
MIN_PROTOC_VERSION="3.19.0"
MIN_GO_PLUGIN_VERSION="1.28.0"

# Build flags
CLEAN_BUILD=false
VERBOSE=false
CHECK_ONLY=false
PARALLEL_BUILD=false

# Tracking variables
PROTO_FILES=()
FAILED_FILES=()
SUCCESS_COUNT=0
FAIL_COUNT=0
START_TIME=$(date +%s)

################################################################################
# Color Output Functions
################################################################################

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${CYAN}[INFO]${NC} $*"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

################################################################################
# Helper Functions
################################################################################

print_help() {
    cat << EOF

============================================================
   SafeOps Protocol Buffers Build Script (Linux/Unix)
============================================================

USAGE:
    ./build.sh [OPTIONS]

OPTIONS:
    --clean         Remove previously generated code before building
    --verbose       Enable detailed output during compilation
    --check         Validate proto syntax without generating code
    --proto-dir     Custom proto source directory
    --output-dir    Custom output directory for generated code
    --parallel      Enable parallel compilation (requires GNU parallel)
    --help          Display this help message

EXAMPLES:
    ./build.sh                      # Full build
    ./build.sh --clean --verbose    # Clean build with details
    ./build.sh --check              # Syntax validation only

REQUIREMENTS:
    - bash 4.0+
    - protoc v$MIN_PROTOC_VERSION+
    - protoc-gen-go v$MIN_GO_PLUGIN_VERSION+
    - protoc-gen-go-grpc v1.2.0+
    - Go 1.19+

OUTPUT STRUCTURE:
    build/proto/go/       - Generated Go code
    build/proto/rust/     - Generated Rust code

EOF
}

check_tool() {
    local tool=$1
    if ! command -v "$tool" &> /dev/null; then
        return 1
    fi
    return 0
}

parse_version() {
    echo "$1" | sed -E 's/[^0-9.]*([0-9]+\.[0-9]+\.[0-9]+).*/\1/'
}

version_compare() {
    # Compare two semantic versions
    # Returns 0 if $1 >= $2, 1 otherwise
    local ver1=$1
    local ver2=$2
    
    if [ "$(printf '%s\n' "$ver1" "$ver2" | sort -V | head -n1)" = "$ver2" ]; then
        return 0
    else
        return 1
    fi
}

cleanup() {
    # Trap handler for script interruption
    print_warning "Build interrupted"
    exit 130
}

################################################################################
# Command-Line Argument Parsing
################################################################################

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN_BUILD=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --check)
            CHECK_ONLY=true
            shift
            ;;
        --proto-dir)
            PROTO_DIR="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --parallel)
            PARALLEL_BUILD=true
            shift
            ;;
        --help)
            print_help
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            print_help
            exit 1
            ;;
    esac
done

# Set up trap for cleanup
trap cleanup SIGINT SIGTERM

################################################################################
# Banner
################################################################################

echo ""
echo "============================================================"
echo "   SafeOps Protocol Buffers Code Generation (Linux)"
echo "============================================================"
echo ""

################################################################################
# Environment Validation
################################################################################

print_info "Validating build environment..."
echo ""

# Check bash version
BASH_VERSION_NUM="${BASH_VERSION%%[^0-9.]*}"
if ! version_compare "$BASH_VERSION_NUM" "4.0.0"; then
    print_error "Bash 4.0+ required (found $BASH_VERSION_NUM)"
    exit 1
fi
print_success "Bash version: $BASH_VERSION_NUM"

# Check protoc
if ! check_tool protoc; then
    print_error "protoc compiler not found in PATH"
    echo "Install with:"
    echo "  Ubuntu/Debian: sudo apt-get install protobuf-compiler"
    echo "  macOS: brew install protobuf"
    echo "  Or download from: https://github.com/protocolbuffers/protobuf/releases"
    exit 1
fi

PROTOC_VERSION_OUTPUT=$(protoc --version)
PROTOC_VERSION=$(parse_version "$PROTOC_VERSION_OUTPUT")
if ! version_compare "$PROTOC_VERSION" "$MIN_PROTOC_VERSION"; then
    print_warning "protoc version $MIN_PROTOC_VERSION+ recommended (found $PROTOC_VERSION)"
fi
print_success "protoc compiler: v$PROTOC_VERSION"

# Check protoc-gen-go
if ! check_tool protoc-gen-go; then
    print_error "protoc-gen-go plugin not found in PATH"
    echo "Install with: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"
    exit 1
fi

GO_PLUGIN_VERSION=$(protoc-gen-go --version 2>&1 | parse_version)
if [ -n "$GO_PLUGIN_VERSION" ]; then
    print_success "protoc-gen-go: v$GO_PLUGIN_VERSION"
else
    print_success "protoc-gen-go: installed"
fi

# Check protoc-gen-go-grpc
if ! check_tool protoc-gen-go-grpc; then
    print_error "protoc-gen-go-grpc plugin not found in PATH"
    echo "Install with: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"
    exit 1
fi
print_success "protoc-gen-go-grpc: installed"

# Check Go installation
if check_tool go; then
    GO_VERSION=$(go version | sed -E 's/.*go([0-9]+\.[0-9]+).*/\1/')
    print_success "Go compiler: v$GO_VERSION"
else
    print_warning "Go not found in PATH (recommended for module management)"
fi

# Check for parallel if requested
if [ "$PARALLEL_BUILD" = true ]; then
    if ! check_tool parallel; then
        print_warning "GNU parallel not found, falling back to sequential compilation"
        PARALLEL_BUILD=false
    else
        print_success "GNU parallel: available"
    fi
fi

echo ""

################################################################################
# Directory Structure Setup
################################################################################

print_info "Setting up directory structure..."

# Create build directory
mkdir -p "$BUILD_DIR"

# Clean operation
if [ "$CLEAN_BUILD" = true ]; then
    print_info "Cleaning previously generated code..."
    
    if [ -d "$OUTPUT_DIR" ]; then
        rm -rf "$OUTPUT_DIR"
        print_success "Removed: $OUTPUT_DIR"
    fi
    
    if [ -d "$RUST_OUTPUT_DIR" ]; then
        rm -rf "$RUST_OUTPUT_DIR"
        print_success "Removed: $RUST_OUTPUT_DIR"
    fi
fi

# Create output directories
mkdir -p "$OUTPUT_DIR"
print_success "Created Go output directory: $OUTPUT_DIR"

mkdir -p "$RUST_OUTPUT_DIR"
print_success "Created Rust output directory: $RUST_OUTPUT_DIR"

echo ""

################################################################################
# Proto File Discovery
################################################################################

print_info "Discovering proto files..."

if [ ! -d "$PROTO_DIR" ]; then
    print_error "Proto directory not found: $PROTO_DIR"
    exit 1
fi

# Find all .proto files
while IFS= read -r -d '' file; do
    PROTO_FILES+=("$file")
done < <(find "$PROTO_DIR" -name "*.proto" -type f -print0 | sort -z)

if [ ${#PROTO_FILES[@]} -eq 0 ]; then
    print_warning "No proto files found in: $PROTO_DIR"
    exit 0
fi

print_success "Found ${#PROTO_FILES[@]} proto files"

if [ "$VERBOSE" = true ]; then
    for file in "${PROTO_FILES[@]}"; do
        echo "  - $(basename "$file")"
    done
fi

echo ""

################################################################################
# Compilation Function
################################################################################

compile_proto() {
    local proto_file=$1
    local file_name=$(basename "$proto_file")
    
    # Extract service name for per-service subdirectory
    local service_name=$(basename "$proto_file" .proto)
    local service_out_dir="$OUTPUT_DIR/$service_name"
    
    # Create service-specific output directory
    mkdir -p "$service_out_dir"
    
    if [ "$VERBOSE" = true ]; then
        print_info "Compiling: $file_name -> $service_name/"
    fi
    
    local protoc_args=(
        "--proto_path=$PROTO_DIR"
        "--go_out=$service_out_dir"
        "--go_opt=paths=source_relative"
        "--go-grpc_out=$service_out_dir"
        "--go-grpc_opt=paths=source_relative"
        "$proto_file"
    )
    
    if [ "$CHECK_ONLY" = true ]; then
        # Syntax check only
        protoc_args=(
            "--proto_path=$PROTO_DIR"
            "--descriptor_set_out=/dev/null"
            "$proto_file"
        )
    fi
    
    # Execute protoc
    local error_output
    if error_output=$(protoc "${protoc_args[@]}" 2>&1); then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        if [ "$VERBOSE" = true ]; then
            print_success "  ✓ $file_name"
        fi
        return 0
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_FILES+=("$file_name: $error_output")
        print_error "Failed to compile: $file_name"
        echo "$error_output" >&2
        return 1
    fi
}

################################################################################
# Main Compilation Loop
################################################################################

print_info "Compiling proto files to Go..."
echo ""

if [ "$PARALLEL_BUILD" = true ]; then
    # Parallel compilation
    export -f compile_proto print_info print_success print_error
    export PROTO_DIR OUTPUT_DIR CHECK_ONLY VERBOSE SUCCESS_COUNT FAIL_COUNT
    
    printf '%s\n' "${PROTO_FILES[@]}" | parallel --will-cite compile_proto
else
    # Sequential compilation
    for proto_file in "${PROTO_FILES[@]}"; do
        compile_proto "$proto_file" || true
    done
fi

echo ""

################################################################################
# Rust Code Generation (Template Creation)
################################################################################

if [ "$CHECK_ONLY" = false ]; then
    print_info "Setting up Rust proto integration..."
    
    cat > "$RUST_OUTPUT_DIR/build.rs.template" << 'EOF'
// Rust Proto Build Template for SafeOps
// This file provides guidance for Rust services to use tonic-build for proto compilation.
// 
// USAGE: Copy this to your Rust service's build.rs file and customize as needed.
//
// Example build.rs:
// ```rust
// fn main() -> Result<(), Box<dyn std::error::Error>> {
//     tonic_build::configure()
//         .build_server(true)
//         .build_client(true)
//         .compile(
//             &[
//                 "../../proto/grpc/common.proto",
//                 "../../proto/grpc/firewall.proto",
//                 // Add your proto files here
//             ],
//             &["../../proto/grpc/"],
//         )?;
//     Ok(())
// }
// ```
//
// Add to Cargo.toml:
// [build-dependencies]
// tonic-build = "0.10"
// 
// [dependencies]
// tonic = "0.10"
// prost = "0.12"
EOF
    
    print_success "Created Rust build template: $RUST_OUTPUT_DIR/build.rs.template"
    echo ""
fi

################################################################################
# Post-Build Actions
################################################################################

if [ "$CHECK_ONLY" = false ] && [ $SUCCESS_COUNT -gt 0 ]; then
    print_info "Running go fmt on generated files..."
    
    if check_tool gofmt; then
        find "$OUTPUT_DIR" -name "*.pb.go" -exec gofmt -w {} \; 2>/dev/null || true
        print_success "Formatted generated Go files"
    fi
    
    echo ""
fi

################################################################################
# Build Summary
################################################################################

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "============================================================"
echo "   Build Summary"
echo "============================================================"
echo ""

if [ "$CHECK_ONLY" = true ]; then
    print_success "Syntax Validation Complete"
else
    print_success "Code Generation Complete"
fi

echo ""
print_info "Proto files processed: ${#PROTO_FILES[@]}"
print_success "Successfully compiled: $SUCCESS_COUNT"

if [ $FAIL_COUNT -gt 0 ]; then
    print_error "Failed to compile: $FAIL_COUNT"
    echo ""
    print_error "Errors encountered:"
    for error in "${FAILED_FILES[@]}"; do
        echo "  $error"
    done
fi

print_info "Build time: ${DURATION} seconds"

echo ""

# Generated files validation
if [ "$CHECK_ONLY" = false ]; then
    GO_FILES_COUNT=$(find "$OUTPUT_DIR" -name "*.pb.go" -type f | wc -l)
    GRPC_FILES_COUNT=$(find "$OUTPUT_DIR" -name "*_grpc.pb.go" -type f | wc -l)
    
    print_info "Generated Go files:"
    echo "  - Protocol buffer files: $GO_FILES_COUNT"
    echo "  - gRPC service files: $GRPC_FILES_COUNT"
    
    if [ "$VERBOSE" = true ]; then
        echo ""
        print_info "Output locations:"
        echo "  - Go code: $OUTPUT_DIR"
        echo "  - Rust template: $RUST_OUTPUT_DIR"
    fi
fi

echo ""

# Next steps
if [ $FAIL_COUNT -eq 0 ] && [ "$CHECK_ONLY" = false ]; then
    print_info "Next steps:"
    echo "  1. Run 'go mod tidy' to update Go dependencies"
    echo "  2. Import generated packages in your Go services"
    echo "  3. For Rust services, use the template in build/proto/rust/"
    echo ""
fi

# Exit with appropriate code
if [ $FAIL_COUNT -gt 0 ]; then
    exit 1
fi

exit 0
