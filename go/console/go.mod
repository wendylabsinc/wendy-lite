module console

go 1.26.4

require (
	github.com/wendylabsinc/wendy/go/proto/gen/litepb v0.0.0-00010101000000-000000000000
	go.bug.st/serial v1.6.4
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af
)

replace github.com/wendylabsinc/wendy/go/proto/gen/litepb => ./wendypb

require (
	github.com/creack/goselect v0.1.3 // indirect
	golang.org/x/sys v0.46.0 // indirect
)
