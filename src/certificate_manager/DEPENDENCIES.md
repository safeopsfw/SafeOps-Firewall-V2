# Certificate Manager - Dependencies & Integration Guide

## 📁 Existing Project Files to Use

### 1️⃣ Proto/gRPC (Service Definition)

| File                                            | Purpose                          |
| ----------------------------------------------- | -------------------------------- |
| `proto/grpc/certificate_manager.proto`          | gRPC service definition          |
| `proto/grpc/common.proto`                       | Shared types (Timestamp, Status) |
| `build/proto/go/certificate_manager.pb.go`      | Generated Go types               |
| `build/proto/go/certificate_manager_grpc.pb.go` | Generated gRPC server/client     |

### 2️⃣ Shared Go Libraries (`src/shared/go/`)

| Package     | Import Path             | Use In                                 |
| ----------- | ----------------------- | -------------------------------------- |
| config      | `shared/go/config`      | `config/config.go`                     |
| logging     | `shared/go/logging`     | All files for logs                     |
| health      | `shared/go/health`      | `cmd/main.go`                          |
| metrics     | `shared/go/metrics`     | `cmd/main.go`                          |
| postgres    | `shared/go/postgres`    | `internal/storage/database.go`         |
| redis       | `shared/go/redis`       | Optional caching                       |
| grpc_client | `shared/go/grpc_client` | `internal/distribution/grpc_server.go` |
| errors      | `shared/go/errors`      | All error handling                     |
| utils       | `shared/go/utils`       | Common utilities                       |

### 3️⃣ Configuration

| File                                        | Purpose               |
| ------------------------------------------- | --------------------- |
| `config/templates/certificate_manager.toml` | Runtime configuration |

### 4️⃣ Database Schema (TO CREATE)

```sql
-- Create: database/schemas/011_certificate_manager.sql
CREATE TABLE certificates (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    certificate BYTEA NOT NULL,
    private_key BYTEA NOT NULL,
    chain BYTEA,
    not_before TIMESTAMP NOT NULL,
    not_after TIMESTAMP NOT NULL,
    serial VARCHAR(255),
    issuer VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_cert_domain ON certificates(domain);
CREATE INDEX idx_cert_expiry ON certificates(not_after);
```

---

## 📝 File → Import Mapping

```
cmd/main.go
  → shared/go/config
  → shared/go/logging
  → shared/go/health
  → shared/go/metrics
  → shared/go/postgres
  → build/proto/go (gRPC server)

config/config.go
  → shared/go/config

internal/storage/database.go
  → shared/go/postgres

internal/distribution/grpc_server.go
  → build/proto/go/certificate_manager_grpc.pb.go
  → shared/go/grpc_client

internal/ca/renewal.go
  → shared/go/logging

pkg/client/client.go
  → build/proto/go/certificate_manager_grpc.pb.go
```

---

## 🚀 Quick Start Commands

```bash
# Build certificate_manager
cd src/certificate_manager
go mod init certificate_manager
go mod tidy
go build ./...

# Run
go run ./cmd/main.go -config config/templates/certificate_manager.toml
```
