module github.com/wendylabsinc/wendy/go/console

go 1.26.4

require (
	github.com/wendylabsinc/wendy/go/internal/shared/seriallock v0.0.0-00010101000000-000000000000
	github.com/wendylabsinc/wendy/go/proto/gen/litepb v0.0.0-00010101000000-000000000000
	github.com/wendylabsinc/wendy/go/proto/gen/tunnelpb v0.0.0-00010101000000-000000000000
	go.bug.st/serial v1.6.4
	golang.org/x/term v0.44.0
	google.golang.org/grpc v1.71.0
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af
)

replace github.com/wendylabsinc/wendy/go/proto/gen/litepb => ./wendypb

replace github.com/wendylabsinc/wendy/go/proto/gen/tunnelpb => ../tunnelpb

require (
	github.com/creack/goselect v0.1.3 // indirect
	golang.org/x/net v0.34.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250115164207-1a7da9e5054f // indirect
)

replace github.com/wendylabsinc/wendy/go/internal/shared/seriallock => ../internal/shared/seriallock
