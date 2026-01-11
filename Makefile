# SafeOps Makefile
# Cross-platform build automation

.PHONY: all clean build test proto database help

all: proto database build

help:
	@echo "SafeOps Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build everything (proto + database + services)"
	@echo "  proto      - Generate code from Protocol Buffers"
	@echo "  database   - Initialize database schemas"
	@echo "  build      - Build all services"
	@echo "  test       - Run all tests"
	@echo "  clean      - Clean build artifacts"
	@echo ""

proto:
	@echo "Generating Protocol Buffer code..."
	# Add protoc commands here

database:
	@echo "Setting up database schemas..."
	# Add database init commands here

build:
	@echo "Building SafeOps services..."
	# Add build commands here

test:
	@echo "Running tests..."
	# Add test commands here

clean:
	@echo "Cleaning build artifacts..."
	rm -rf build/bin/*
	rm -rf build/lib/*
	rm -rf target/
