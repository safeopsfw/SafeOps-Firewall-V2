module github.com/safeops/threat-intel

go 1.25.5

require (
	github.com/safeops/shared/go/postgres v0.0.0
	golang.org/x/net v0.48.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/pgx/v5 v5.5.0 // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/safeops/shared/go/errors v0.0.0 // indirect
	github.com/safeops/shared/go/logging v0.0.0 // indirect
	github.com/safeops/shared/go/metrics v0.0.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/term v0.38.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)

replace (
	github.com/safeops/shared/go/errors => ../shared/go/errors
	github.com/safeops/shared/go/logging => ../shared/go/logging
	github.com/safeops/shared/go/metrics => ../shared/go/metrics
	github.com/safeops/shared/go/postgres => ../shared/go/postgres
)
