# SafeOps v2.0 - Master Documentation Index

**Last Updated:** 2025-12-25
**Version:** 2.0
**Status:** Complete and Ready for Build

---

## Overview

This document provides a comprehensive index of all documentation files in the SafeOps v2.0 project, with quick links to build guides, testing plans, and setup instructions. All documentation is organized by component and purpose.

---

## Table of Contents

1. [Quick Start Guides](#quick-start-guides)
2. [Build Documentation](#build-documentation)
3. [Testing Documentation](#testing-documentation)
4. [Component-Specific Documentation](#component-specific-documentation)
5. [Architecture & Design](#architecture--design)
6. [Configuration & Setup](#configuration--setup)
7. [Database Documentation](#database-documentation)
8. [API Documentation](#api-documentation)
9. [User Documentation](#user-documentation)
10. [Developer Documentation](#developer-documentation)

---

## Quick Start Guides

### Essential First Steps

| Document | Location | Description |
|----------|----------|-------------|
| **Project README** | [`README.md`](README.md) | Main project overview, quick start, and installation |
| **Comprehensive Build Guide** | [`BUILD_GUIDE.md`](BUILD_GUIDE.md) | Complete system build instructions (NEW) |
| **Installation Guide** | [`INSTALL_README.md`](INSTALL_README.md) | Installation and deployment instructions |
| **Quick Start** | [`docs/user_guide/quick_start.md`](docs/user_guide/quick_start.md) | Getting started guide |

---

## Build Documentation

### Kernel Driver Build

| Document | Location | Description |
|----------|----------|-------------|
| **Build Documentation** | [`src/kernel_driver/BUILD_DOCUMENTATION.md`](src/kernel_driver/BUILD_DOCUMENTATION.md) | Comprehensive kernel driver build guide |
| **Work Summary** | [`src/kernel_driver/WORK_SUMMARY.md`](src/kernel_driver/WORK_SUMMARY.md) | Build readiness assessment and status |
| **Driver INF File** | [`src/kernel_driver/SafeOps.inf`](src/kernel_driver/SafeOps.inf) | Windows driver installation file |
| **Makefile** | [`src/kernel_driver/makefile`](src/kernel_driver/makefile) | Build automation (591 lines) |
| **Dependencies** | [`src/kernel_driver/DEPENDENCIES.md`](src/kernel_driver/DEPENDENCIES.md) | Component dependencies |

**Key Build Commands:**
```cmd
# Debug build
nmake BUILD=debug

# Release build
nmake BUILD=release

# Sign driver
nmake sign

# Create package
nmake package
```

### Userspace Service Build

| Document | Location | Description |
|----------|----------|-------------|
| **Build Guide** | [`src/userspace_service/BUILD.md`](src/userspace_service/BUILD.md) | Complete userspace service build guide (787 lines) |
| **Build Script** | [`src/userspace_service/build.cmd`](src/userspace_service/build.cmd) | Automated build script |
| **Work Summary** | [`src/userspace_service/WORK_SUMMARY.md`](src/userspace_service/WORK_SUMMARY.md) | Build status and next steps |
| **Service README** | [`src/userspace_service/README.md`](src/userspace_service/README.md) | Component overview |

**Key Build Commands:**
```cmd
# Build release
build.cmd release

# Build debug
build.cmd debug

# Clean and rebuild
build.cmd clean
```

### Shared Libraries Build

| Document | Location | Description |
|----------|----------|-------------|
| **Rust Library** | [`src/shared/rust/README.md`](src/shared/rust/README.md) | Rust shared library documentation |
| **Rust Build Report** | [`src/shared/rust/RUST_BUILD_REPORT.md`](src/shared/rust/RUST_BUILD_REPORT.md) | Compilation status and results |
| **Go Library** | [`src/shared/go/README.md`](src/shared/go/README.md) | Go shared packages documentation |
| **Go Build Report** | [`src/shared/go/GO_BUILD_REPORT.md`](src/shared/go/GO_BUILD_REPORT.md) | Go compilation results |
| **C Headers** | [`src/shared/c/README.md`](src/shared/c/README.md) | C shared headers documentation |
| **C Build Report** | [`src/shared/c/C_BUILD_REPORT.md`](src/shared/c/C_BUILD_REPORT.md) | C header verification |
| **C Verification** | [`src/shared/c/C_VERIFICATION_REPORT.md`](src/shared/c/C_VERIFICATION_REPORT.md) | Header file validation |

**Key Build Commands:**
```bash
# Rust library
cd src/shared/rust && cargo build --release

# Go modules
cd src/shared/go && go build ./...

# C headers (header-only, no build)
```

---

## Testing Documentation

### Kernel Driver Testing

| Document | Location | Description |
|----------|----------|-------------|
| **Testing Plan** | [`src/kernel_driver/TESTING_PLAN.md`](src/kernel_driver/TESTING_PLAN.md) | Comprehensive testing plan with 70+ test cases |

**Test Categories:**
- Driver Loading/Unloading (6 tests)
- IOCTL Communication (6 tests)
- NDIS Filter Operations (4 tests)
- WFP Callout Operations (4 tests)
- Protection Features (4 tests)
- Ring Buffer Operations (5 tests)
- Performance Tests (4 tests)
- Error Handling (6 tests)

### Userspace Service Testing

| Document | Location | Description |
|----------|----------|-------------|
| **Testing Plan** | [`src/userspace_service/TESTING_PLAN.md`](src/userspace_service/TESTING_PLAN.md) | Comprehensive testing plan with 102 test cases |

**Test Categories:**
- Unit Tests: 38 test cases
- Integration Tests: 10 test cases
- Service Tests: 13 test cases
- Driver Communication: 18 IOCTL tests
- Performance Tests: 9 test cases
- Stress Tests: 8 test cases
- Security Tests: 6 test cases

### Go Component Testing

| Document | Location | Description |
|----------|----------|-------------|
| **Go Final Test Report** | [`GO_FINAL_TEST_REPORT.md`](GO_FINAL_TEST_REPORT.md) | Go component test results and coverage |

---

## Component-Specific Documentation

### Core Components

| Component | README | Additional Docs |
|-----------|--------|-----------------|
| **Kernel Driver** | [`src/kernel_driver/README.md`](src/kernel_driver/README.md) | BUILD_DOCUMENTATION.md, TESTING_PLAN.md, WORK_SUMMARY.md |
| **Userspace Service** | [`src/userspace_service/README.md`](src/userspace_service/README.md) | BUILD.md, TESTING_PLAN.md, WORK_SUMMARY.md |
| **Firewall Engine** | [`src/firewall_engine/README.md`](src/firewall_engine/README.md) | - |
| **IDS/IPS** | [`src/ids_ips/README.md`](src/ids_ips/README.md) | - |
| **DNS Server** | [`src/dns_server/README.md`](src/dns_server/README.md) | - |
| **DHCP Server** | [`src/dhcp_server/README.md`](src/dhcp_server/README.md) | - |
| **WiFi AP** | [`src/wifi_ap/README.md`](src/wifi_ap/README.md) | - |
| **TLS Proxy** | [`src/tls_proxy/README.md`](src/tls_proxy/README.md) | - |
| **Threat Intel** | [`src/threat_intel/README.md`](src/threat_intel/README.md) | - |
| **Orchestrator** | [`src/orchestrator/README.md`](src/orchestrator/README.md) | - |
| **Certificate Manager** | [`src/certificate_manager/README.md`](src/certificate_manager/README.md) | - |
| **Backup/Restore** | [`src/backup_restore/README.md`](src/backup_restore/README.md) | - |
| **Update Manager** | [`src/update_manager/README.md`](src/update_manager/README.md) | - |

### Shared Libraries

| Library | Documentation |
|---------|---------------|
| **Rust Shared** | [`src/shared/rust/README.md`](src/shared/rust/README.md) |
| **Go Shared** | [`src/shared/go/README.md`](src/shared/go/README.md) |
| **C Headers** | [`src/shared/c/README.md`](src/shared/c/README.md) |
| **Logging (Go)** | [`src/shared/go/logging/LOG_OUTPUT_OVERVIEW.md`](src/shared/go/logging/LOG_OUTPUT_OVERVIEW.md) |
| **Logging Examples** | [`src/shared/go/logging/MASTER_JSON_LOG_EXAMPLES.md`](src/shared/go/logging/MASTER_JSON_LOG_EXAMPLES.md) |

---

## Architecture & Design

### System Architecture

| Document | Location | Description |
|----------|----------|-------------|
| **SafeOps Architecture** | [`docs/safeops_architecture (3).md`](docs/safeops_architecture%20(3).md) | Overall system architecture |
| **UI Architecture** | [`UI_ARCHITECTURE_PLAN.md`](UI_ARCHITECTURE_PLAN.md) | Web UI design and architecture |
| **System Overview** | [`docs/architecture/system_overview.md`](docs/architecture/system_overview.md) | High-level system overview |
| **Service Architecture** | [`docs/architecture/service_architecture.md`](docs/architecture/service_architecture.md) | Service layer design |
| **Security Model** | [`docs/architecture/security_model.md`](docs/architecture/security_model.md) | Security architecture |
| **Performance Design** | [`docs/architecture/performance_design.md`](docs/architecture/performance_design.md) | Performance optimization design |
| **Network Topology** | [`docs/architecture/network_topology.md`](docs/architecture/network_topology.md) | Network architecture |
| **Data Flow** | [`docs/architecture/data_flow.md`](docs/architecture/data_flow.md) | Data flow diagrams |

### Dependencies

| Document | Location | Description |
|----------|----------|-------------|
| **Complete Dependency Map** | [`COMPLETE_DEPENDENCY_MAP.md`](COMPLETE_DEPENDENCY_MAP.md) | Full dependency graph |

---

## Configuration & Setup

### Configuration Files

| Document | Location | Description |
|----------|----------|-------------|
| **Configuration README** | [`config/README.md`](config/README.md) | Configuration system overview |
| **Network Management** | [`config/HOW_TO_MANAGE_NETWORK.md`](config/HOW_TO_MANAGE_NETWORK.md) | Network configuration guide |
| **Validation Rules** | [`config/schemas/validation_rules.md`](config/schemas/validation_rules.md) | Config validation rules |
| **Suricata Rules** | [`config/schemas/suricata_rules_format.md`](config/schemas/suricata_rules_format.md) | Suricata rule format |

### Configuration Templates

All configuration templates are located in [`config/templates/`](config/templates/):

- `safeops.toml` - Master configuration
- `kernel_driver.toml` - Kernel driver config
- `firewall_engine.toml` - Firewall settings
- `ids_ips.toml` / `ids_ips.yaml` - IDS/IPS configuration
- `dns_server.toml` - DNS server config
- `dhcp_server.toml` - DHCP server config
- `tls_proxy.toml` - TLS proxy settings
- `threat_intel.toml` - Threat intelligence config
- And 12 more component configs...

### Configuration Presets

Located in [`config/defaults/`](config/defaults/):

- `home_network.toml` - Home network preset
- `small_business.toml` - Small business preset
- `enterprise.toml` - Enterprise preset
- `monitoring_only.toml` - Monitoring-only mode
- `application_settings.toml` - Application defaults

---

## Database Documentation

### Database Schema

| Document | Location | Description |
|----------|----------|-------------|
| **Database README** | [`database/README.md`](database/README.md) | Database architecture and setup |
| **Database Map** | [`database/DATABASE_MAP.md`](database/DATABASE_MAP.md) | Schema overview and relationships |

### Schema Files

Located in [`database/schemas/`](database/schemas/):

1. `001_initial_setup.sql` - Core tables and functions
2. `002_ip_reputation.sql` - IP threat intelligence
3. `003_domain_reputation.sql` - Domain reputation
4. `004_hash_reputation.sql` - File hash database
5. `005_ioc_storage.sql` - Indicators of Compromise
6. `006_proxy_anonymizer.sql` - VPN/Proxy/Tor detection
7. `007_geolocation.sql` - IP geolocation
8. `008_threat_feeds.sql` - Threat feed management
9. `009_asn_data.sql` - ASN reputation data
10. `999_indexes_and_maintenance.sql` - Performance indexes

### Database Views

Located in [`database/views/`](database/views/):

- `active_threats_view.sql` - Active threat summary
- `high_confidence_iocs.sql` - High-confidence IOCs
- `threat_summary_stats.sql` - Threat statistics

---

## API Documentation

### gRPC API

| Document | Location | Description |
|----------|----------|-------------|
| **gRPC API Reference** | [`docs/api/grpc_api_reference.md`](docs/api/grpc_api_reference.md) | Complete gRPC API documentation |
| **REST API Reference** | [`docs/api/rest_api_reference.md`](docs/api/rest_api_reference.md) | REST API endpoints |
| **Authentication** | [`docs/api/authentication.md`](docs/api/authentication.md) | API authentication guide |
| **Error Codes** | [`docs/api/error_codes.md`](docs/api/error_codes.md) | API error code reference |

### Protocol Buffers

| Document | Location | Description |
|----------|----------|-------------|
| **Proto README** | [`proto/README.md`](proto/README.md) | Protocol buffer overview |
| **Network Manager Spec** | [`docs/proto/network_manager_SPEC.md`](docs/proto/network_manager_SPEC.md) | Network manager proto spec |

---

## User Documentation

### User Guides

| Document | Location | Description |
|----------|----------|-------------|
| **Quick Start** | [`docs/user_guide/quick_start.md`](docs/user_guide/quick_start.md) | Getting started guide |
| **Installation Guide** | [`docs/user_guide/installation_guide.md`](docs/user_guide/installation_guide.md) | Installation instructions |
| **Firewall Rules** | [`docs/user_guide/firewall_rules.md`](docs/user_guide/firewall_rules.md) | Firewall rule configuration |
| **Network Monitoring** | [`docs/user_guide/network_monitoring.md`](docs/user_guide/network_monitoring.md) | Monitoring guide |
| **Threat Intelligence** | [`docs/user_guide/threat_intelligence.md`](docs/user_guide/threat_intelligence.md) | Threat intel usage |
| **Web UI Guide** | [`docs/user_guide/web_ui_guide.md`](docs/user_guide/web_ui_guide.md) | Web interface guide |
| **Troubleshooting** | [`docs/user_guide/troubleshooting.md`](docs/user_guide/troubleshooting.md) | Troubleshooting guide |
| **FAQ** | [`docs/user_guide/faq.md`](docs/user_guide/faq.md) | Frequently asked questions |

### Logs and Sandbox

| Document | Location | Description |
|----------|----------|-------------|
| **Logs README** | [`logs/README.md`](logs/README.md) | Log file documentation |
| **Sandbox README** | [`sandbox/README.md`](sandbox/README.md) | Sandbox environment |
| **User README** | [`user/README.md`](user/README.md) | User data directory |

---

## Developer Documentation

### Developer Guides

| Document | Location | Description |
|----------|----------|-------------|
| **Building from Source** | [`docs/developer_guide/building_from_source.md`](docs/developer_guide/building_from_source.md) | Complete build instructions |
| **Development Environment** | [`docs/developer_guide/development_environment.md`](docs/developer_guide/development_environment.md) | Dev environment setup |
| **Code Standards** | [`docs/developer_guide/code_standards.md`](docs/developer_guide/code_standards.md) | Coding conventions |
| **Contributing** | [`docs/developer_guide/contributing.md`](docs/developer_guide/contributing.md) | Contribution guidelines |
| **Testing Guide** | [`docs/developer_guide/testing_guide.md`](docs/developer_guide/testing_guide.md) | Testing procedures |
| **Release Process** | [`docs/developer_guide/release_process.md`](docs/developer_guide/release_process.md) | Release workflow |

### Git & Collaboration

| Document | Location | Description |
|----------|----------|-------------|
| **Git Collaboration Guide** | [`GIT_COLLABORATION_GUIDE.md`](GIT_COLLABORATION_GUIDE.md) | Git workflow and best practices |
| **Gitignore Info** | [`GITIGNORE_INFO.md`](GITIGNORE_INFO.md) | Gitignore patterns explained |

---

## Specialized Documentation

### Security

| Document | Location | Description |
|----------|----------|-------------|
| **CA Certificate** | [`docs/safeops_ca_certificate.md`](docs/safeops_ca_certificate.md) | Certificate authority setup |
| **Security Model** | [`docs/architecture/security_model.md`](docs/architecture/security_model.md) | Security architecture |

### UI

| Document | Location | Description |
|----------|----------|-------------|
| **UI README** | [`ui/README.md`](ui/README.md) | Web UI documentation |
| **UI Architecture** | [`UI_ARCHITECTURE_PLAN.md`](UI_ARCHITECTURE_PLAN.md) | UI design and implementation |

---

## Critical Pre-Build Checklist

### Kernel Driver

- [ ] Review: [`src/kernel_driver/BUILD_DOCUMENTATION.md`](src/kernel_driver/BUILD_DOCUMENTATION.md)
- [ ] Check: All source files present (verified)
- [ ] Verify: `SafeOps.inf` created (complete)
- [ ] Prepare: WDK build environment
- [ ] Read: Testing plan before deployment

**Build Command:**
```cmd
cd src\kernel_driver
nmake BUILD=release
```

### Userspace Service

- [ ] Review: [`src/userspace_service/BUILD.md`](src/userspace_service/BUILD.md)
- [ ] Check: All source files present (verified)
- [ ] Verify: `build.cmd` script ready
- [ ] Prepare: Visual Studio Developer Command Prompt
- [ ] Read: Testing plan before deployment

**Build Command:**
```cmd
cd src\userspace_service
build.cmd release
```

### Shared Libraries

- [ ] Build: Rust shared library
- [ ] Build: Go shared packages
- [ ] Verify: C headers compile

---

## Build Order Recommendation

Execute builds in this order:

1. **Shared Libraries** (no dependencies)
   ```bash
   cd src/shared/rust && cargo build --release
   cd src/shared/go && go build ./...
   ```

2. **Kernel Driver** (depends on C headers)
   ```cmd
   cd src/kernel_driver
   nmake BUILD=release
   ```

3. **Userspace Service** (depends on C headers)
   ```cmd
   cd src/userspace_service
   build.cmd release
   ```

4. **Service Components** (depend on shared libraries)
   ```bash
   # Build each service as needed
   ```

---

## Post-Build Testing

### Unit Tests

1. Kernel Driver: Follow [`src/kernel_driver/TESTING_PLAN.md`](src/kernel_driver/TESTING_PLAN.md)
2. Userspace Service: Follow [`src/userspace_service/TESTING_PLAN.md`](src/userspace_service/TESTING_PLAN.md)

### Integration Tests

1. Install kernel driver
2. Install userspace service
3. Verify driver-service communication
4. Test packet capture flow

---

## Quick Reference: Key Documentation Locations

### Must-Read Before Building

1. [`BUILD_GUIDE.md`](BUILD_GUIDE.md) - **START HERE** - Comprehensive build guide
2. [`src/kernel_driver/BUILD_DOCUMENTATION.md`](src/kernel_driver/BUILD_DOCUMENTATION.md) - Kernel driver build
3. [`src/userspace_service/BUILD.md`](src/userspace_service/BUILD.md) - Service build
4. [`README.md`](README.md) - Project overview

### Must-Read Before Testing

1. [`src/kernel_driver/TESTING_PLAN.md`](src/kernel_driver/TESTING_PLAN.md) - Driver testing (70+ tests)
2. [`src/userspace_service/TESTING_PLAN.md`](src/userspace_service/TESTING_PLAN.md) - Service testing (102 tests)

### Must-Read Before Deployment

1. [`INSTALL_README.md`](INSTALL_README.md) - Installation guide
2. [`docs/user_guide/installation_guide.md`](docs/user_guide/installation_guide.md) - User installation
3. [`docs/user_guide/troubleshooting.md`](docs/user_guide/troubleshooting.md) - Troubleshooting

---

## Documentation Statistics

### Total Documentation Files: 50+ files

| Category | File Count |
|----------|------------|
| Build Documentation | 8 files |
| Testing Documentation | 3 files |
| Component READMEs | 20+ files |
| Architecture Docs | 8 files |
| Configuration Docs | 4 files |
| Database Docs | 3 files |
| API Documentation | 4 files |
| User Guides | 8 files |
| Developer Guides | 6 files |

### Total Documentation Lines: 25,000+ lines

---

## Getting Help

### Documentation Issues

If documentation is unclear or missing:
1. Check this index for related documents
2. Review component-specific READMEs
3. Consult troubleshooting guides
4. Check FAQ: [`docs/user_guide/faq.md`](docs/user_guide/faq.md)

### Build Issues

1. Kernel Driver: [`src/kernel_driver/BUILD_DOCUMENTATION.md`](src/kernel_driver/BUILD_DOCUMENTATION.md) - See "Troubleshooting Guide" section
2. Userspace Service: [`src/userspace_service/BUILD.md`](src/userspace_service/BUILD.md) - See "Troubleshooting" section

### Testing Issues

1. Kernel Driver: [`src/kernel_driver/TESTING_PLAN.md`](src/kernel_driver/TESTING_PLAN.md) - See "Debugging Tips" appendix
2. Userspace Service: [`src/userspace_service/TESTING_PLAN.md`](src/userspace_service/TESTING_PLAN.md) - See "Defect Tracking" section

---

## Document Status

| Status | Count | Description |
|--------|-------|-------------|
| Complete | 45+ | Fully documented and ready |
| Draft | 5 | Requires review or expansion |
| Planned | 10+ | Service skeletons awaiting Phase 2 |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-12-25 | Initial comprehensive documentation index |

---

**End of Documentation Index**
