module firewall_engine

go 1.25.5

require safeops-engine v0.0.0

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/google/uuid v1.6.0
	google.golang.org/grpc v1.78.0
)

require (
	github.com/wiresock/ndisapi-go v1.0.1 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251029180050-ab9386a59fda // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace safeops-engine => ../safeops-engine
