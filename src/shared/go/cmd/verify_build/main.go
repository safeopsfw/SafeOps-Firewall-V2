package main

import (
	"fmt"

	"github.com/safeops/shared/go/config"
	"github.com/safeops/shared/go/errors"
	"github.com/safeops/shared/go/grpc_client"
	"github.com/safeops/shared/go/health"
	"github.com/safeops/shared/go/logging"
	"github.com/safeops/shared/go/metrics"
	"github.com/safeops/shared/go/postgres"
	"github.com/safeops/shared/go/redis"
	"github.com/safeops/shared/go/utils"
)

func main() {
	fmt.Println("==================================================")
	fmt.Println("SafeOps Shared Library - Build Verification Tool")
	fmt.Println("==================================================")

	// 1. Verify Logging
	logger := logging.New()
	logger.Info("Logging package: OK")

	// 2. Verify Config
	_ = config.NewLoader()
	fmt.Println("Config package: OK")

	// 3. Verify Errors
	err := errors.New(errors.ErrUnknown, "test error")
	if err.Error() != "" {
		fmt.Println("Errors package: OK")
	}

	// 4. Verify Utils
	if utils.IsSafePath("/tmp/safe", "/tmp") {
		fmt.Println("Utils package: OK")
	}

	// 5. Verify Health
	checker := health.NewChecker()
	if checker != nil {
		fmt.Println("Health package: OK")
	}

	// 6. Verify Metrics
	reg := metrics.NewRegistry("test_service")
	if reg != nil {
		fmt.Println("Metrics package: OK")
	}

	// 7. Verify Redis (Struct check only, no connection)
	redisCfg := redis.DefaultConfig()
	if redisCfg.PoolSize > 0 {
		fmt.Println("Redis package: OK")
	}

	// 8. Verify Postgres (Struct check only)
	pgCfg := postgres.DefaultConfig()
	if pgCfg.MaxOpenConns > 0 {
		fmt.Println("Postgres package: OK")
	}

	// 9. Verify gRPC Client (Struct check only)
	grpcCfg := grpc_client.DefaultConfig()
	if grpcCfg.Timeout > 0 {
		fmt.Println("gRPC Client package: OK")
	}

	fmt.Println("==================================================")
	fmt.Println("SUCCESS: All 9 shared packages compiled and linked.")
	fmt.Println("==================================================")
}
