module tinycloud

go 1.26.4

require (
	github.com/wendylabsinc/wendy/go/proto/gen/litepb v0.0.0-00010101000000-000000000000
	github.com/wendylabsinc/wendy/go/proto/gen/tunnelpb v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.71.0
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af
)

require (
	golang.org/x/net v0.34.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250115164207-1a7da9e5054f // indirect
)

replace github.com/wendylabsinc/wendy/go/proto/gen/litepb => ../console/wendypb

replace github.com/wendylabsinc/wendy/go/proto/gen/tunnelpb => ../tunnelpb
