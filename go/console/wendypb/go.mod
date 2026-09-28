module github.com/wendylabsinc/wendy/go/proto/gen/litepb

go 1.26.4

require (
	github.com/wendylabsinc/wendy/go/proto/gen/sensorlinkpb v0.0.0-00010101000000-000000000000
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af
)

replace github.com/wendylabsinc/wendy/go/proto/gen/sensorlinkpb => ../sensorlinkpb
