module safeops/nic_management

go 1.24.0

replace safeops/build/proto/go => ../../build/proto/go

// =============================================================================
// CORE gRPC DEPENDENCIES
// Libraries for gRPC service implementation and protocol buffer handling
// =============================================================================
require (
	google.golang.org/grpc v1.78.0
	google.golang.org/protobuf v1.36.11 // indirect
)

// =============================================================================
// CONFIGURATION MANAGEMENT
// Libraries for YAML/TOML parsing and validation
// =============================================================================
require (
	github.com/fsnotify/fsnotify v1.7.0
	github.com/spf13/viper v1.18.0
	gopkg.in/yaml.v3 v3.0.1
)

// =============================================================================
// NETWORK AND SYSTEM LIBRARIES
// Low-level network interface access and system calls
// =============================================================================
require golang.org/x/sys v0.39.0

// =============================================================================
// INDIRECT DEPENDENCIES
// Transitive dependencies required by direct dependencies
// =============================================================================
require (
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pelletier/go-toml/v2 v2.1.1 // indirect
	github.com/sagikazarmark/locafero v0.4.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20231214170342-aacd6d4b4611 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251029180050-ab9386a59fda // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
)

require (
	github.com/StackExchange/wmi v1.2.1
	github.com/google/uuid v1.6.0
)

require (
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)
