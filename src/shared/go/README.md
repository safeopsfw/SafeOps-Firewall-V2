# SafeOps Shared Go Library

Service infrastructure utilities for SafeOps microservices.

## Packages

- **config**: Configuration management with hot-reload
- **logging**: Structured logging with log rotation
- **grpc_client**: gRPC client with retry and load balancing
- **redis**: Redis connection pool with pub/sub
- **postgres**: PostgreSQL utilities with migrations
- **errors**: Error handling with codes
- **metrics**: Prometheus metrics helpers
- **health**: Health check framework
- **utils**: Misc utilities (retry, rate limit, validation)

## Usage

```bash
go get github.com/safeops/shared
```

```go
import (
    "github.com/safeops/shared/config"
    "github.com/safeops/shared/logging"
)

func main() {
    cfg, _ := config.Load("config.yaml")
    logger := logging.New(cfg.LogLevel)
    logger.Info("Service started")
}
```
