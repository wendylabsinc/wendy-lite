package broker

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	wendypb "github.com/wendylabsinc/wendy/go/proto/gen/litepb"
	"github.com/wendylabsinc/wendy/go/proto/gen/tunnelpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	"tinycloud/internal/wcomframe"
)

type testEnv struct {
	broker *Broker
	client tunnelpb.WendyComTunnelBrokerServiceClient
	device net.Conn // fake-device side of the pipe
	dev    *deviceConn
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	b := New()

	devSide, brokerSide := net.Pipe()
	d := b.registerDevice(brokerSide)
	go d.readLoop()
	t.Cleanup(func() { devSide.Close() })

	ln := bufconn.Listen(1 << 20)
	s := grpc.NewServer()
	tunnelpb.RegisterWendyComTunnelBrokerServiceServer(s, NewTunnelServer(b))
	go s.Serve(ln)
	t.Cleanup(s.Stop)

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return ln.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	return &testEnv{
		broker: b,
		client: tunnelpb.NewWendyComTunnelBrokerServiceClient(conn),
		device: devSide,
		dev:    d,
	}
}

func readFrame(t *testing.T, c net.Conn) (wcomframe.Header, []byte) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, wcomframe.HeaderSize)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatalf("read header: %v", err)
	}
	h, err := wcomframe.DecodeHeader(hdr)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, h.BodyLen)
	if _, err := io.ReadFull(c, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return h, body
}

func writeFrame(t *testing.T, c net.Conn, channel uint8, body []byte) {
	t.Helper()
	frame, err := wcomframe.Encode(channel, body)
	if err != nil {
		t.Fatal(err)
	}
	c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(frame); err != nil {
		t.Fatal(err)
	}
}

func decodeService(t *testing.T, body []byte) *wendypb.WendyComService {
	t.Helper()
	var msg wendypb.WendyComMessage
	if err := proto.Unmarshal(body, &msg); err != nil {
		t.Fatal(err)
	}
	svc := msg.GetService()
	if svc == nil {
		t.Fatalf("expected service message, got %v", &msg)
	}
	return svc
}

func channelStateBody(t *testing.T, state *wendypb.WendyComChannelState) []byte {
	t.Helper()
	body, err := proto.Marshal(&wendypb.WendyComMessage{
		Msg: &wendypb.WendyComMessage_Service{
			Service: &wendypb.WendyComService{
				Cmd: &wendypb.WendyComService_ChannelState{ChannelState: state},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func openAckBody(t *testing.T) []byte {
	return channelStateBody(t, &wendypb.WendyComChannelState{
		State: &wendypb.WendyComChannelState_Open{Open: &wendypb.WendyComChannelOpen{}},
	})
}

func closeStateBody(t *testing.T) []byte {
	return channelStateBody(t, &wendypb.WendyComChannelState{
		State: &wendypb.WendyComChannelState_Close{Close: &wendypb.WendyComChannelClose{}},
	})
}

func errorStateBody(t *testing.T, reason wendypb.WendyComChannelErrorReason) []byte {
	return channelStateBody(t, &wendypb.WendyComChannelState{
		State: &wendypb.WendyComChannelState_Error{Error: &wendypb.WendyComChannelError{Reason: reason}},
	})
}

// sendTunnelOpen starts a stream, sends the tunnel Open, and returns the
// stream plus the channel on which the device received OpenChannel. It does
// NOT send the device's ChannelState reply — the broker is still gating.
func sendTunnelOpen(t *testing.T, env *testEnv, ctx context.Context) (tunnelpb.WendyComTunnelBrokerService_WendyComTunnelClient, uint8) {
	t.Helper()
	stream, err := env.client.WendyComTunnel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = stream.Send(&tunnelpb.WendyComTunnelMessage{
		Msg: &tunnelpb.WendyComTunnelMessage_Open{
			Open: &tunnelpb.WendyComTunnelOpen{AssetId: hardcodedAssetID},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h, body := readFrame(t, env.device)
	if h.Channel == 0 {
		t.Fatal("OpenChannel arrived on channel 0")
	}
	if decodeService(t, body).GetOpenChannel() == nil {
		t.Fatal("expected OpenChannel as first frame")
	}
	return stream, h.Channel
}

func openTunnel(t *testing.T, env *testEnv, ctx context.Context) (tunnelpb.WendyComTunnelBrokerService_WendyComTunnelClient, uint8) {
	t.Helper()
	stream, ch := sendTunnelOpen(t, env, ctx)
	writeFrame(t, env.device, ch, openAckBody(t)) // device confirms the channel
	return stream, ch
}

// drainCloseChannel reads the CloseChannel frame the broker sends on
// teardown. The test pipe is unbuffered, so the broker's handler cannot
// finish (and end the gRPC stream) until the fake device reads this frame.
func drainCloseChannel(t *testing.T, env *testEnv, ch uint8) {
	t.Helper()
	h, body := readFrame(t, env.device)
	if h.Channel != ch || decodeService(t, body).GetCloseChannel() == nil {
		t.Fatalf("expected CloseChannel on channel %d, got channel %d", ch, h.Channel)
	}
}

func payloadMsg(b []byte) *tunnelpb.WendyComTunnelMessage {
	return &tunnelpb.WendyComTunnelMessage{
		Msg: &tunnelpb.WendyComTunnelMessage_Payload{
			Payload: &tunnelpb.WendyComTunnelPayload{Bytes: b},
		},
	}
}

func TestTunnelBridging(t *testing.T) {
	env := newTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, ch := openTunnel(t, env, ctx)

	// client -> device
	if err := stream.Send(payloadMsg([]byte("hello"))); err != nil {
		t.Fatal(err)
	}
	h, body := readFrame(t, env.device)
	if h.Channel != ch || string(body) != "hello" {
		t.Fatalf("device got channel %d body %q", h.Channel, body)
	}

	// device -> client
	writeFrame(t, env.device, ch, []byte("world"))
	msg, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if string(msg.GetPayload().GetBytes()) != "world" {
		t.Fatalf("client got %v", msg)
	}

	// client closes -> device sees CloseChannel, id quarantined
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	h, body = readFrame(t, env.device)
	if h.Channel != ch {
		t.Fatalf("CloseChannel on channel %d, want %d", h.Channel, ch)
	}
	if decodeService(t, body).GetCloseChannel() == nil {
		t.Fatal("expected CloseChannel frame")
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}

	env.dev.alloc.mu.Lock()
	_, quarantined := env.dev.alloc.freeAt[ch]
	inUse := env.dev.alloc.inUse[ch]
	env.dev.alloc.mu.Unlock()
	if inUse || !quarantined {
		t.Fatalf("channel %d not quarantined after close (inUse=%v)", ch, inUse)
	}
}

func TestTwoTunnelsDistinctChannels(t *testing.T) {
	env := newTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream1, ch1 := openTunnel(t, env, ctx)
	stream2, ch2 := openTunnel(t, env, ctx)
	if ch1 == ch2 {
		t.Fatalf("both tunnels got channel %d", ch1)
	}

	// device frames route to the right stream
	writeFrame(t, env.device, ch2, []byte("two"))
	writeFrame(t, env.device, ch1, []byte("one"))
	msg, err := stream2.Recv()
	if err != nil || string(msg.GetPayload().GetBytes()) != "two" {
		t.Fatalf("stream2 got %v, %v", msg, err)
	}
	msg, err = stream1.Recv()
	if err != nil || string(msg.GetPayload().GetBytes()) != "one" {
		t.Fatalf("stream1 got %v, %v", msg, err)
	}
}

func TestOpenUnknownAsset(t *testing.T) {
	env := newTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := env.client.WendyComTunnel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = stream.Send(&tunnelpb.WendyComTunnelMessage{
		Msg: &tunnelpb.WendyComTunnelMessage_Open{
			Open: &tunnelpb.WendyComTunnelOpen{AssetId: 999},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Recv(); status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
}

func TestFirstMessageMustBeOpen(t *testing.T) {
	env := newTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := env.client.WendyComTunnel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(payloadMsg([]byte("x"))); err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Recv(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestOpenRejectedFailsTunnel(t *testing.T) {
	env := newTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, ch := sendTunnelOpen(t, env, ctx)
	writeFrame(t, env.device, ch, errorStateBody(t,
		wendypb.WendyComChannelErrorReason_WENDY_COM_CHANNEL_ERROR_REASON_REJECTED))
	drainCloseChannel(t, env, ch)
	if _, err := stream.Recv(); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected ResourceExhausted, got %v", err)
	}
}

func TestDeviceClosesChannel(t *testing.T) {
	env := newTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, ch := openTunnel(t, env, ctx)
	writeFrame(t, env.device, ch, closeStateBody(t))
	drainCloseChannel(t, env, ch)
	// The close report is consumed by the broker (never forwarded); the
	// stream ends cleanly.
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestNotOpenErrorAbortsTunnel(t *testing.T) {
	env := newTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, ch := openTunnel(t, env, ctx)
	writeFrame(t, env.device, ch, errorStateBody(t,
		wendypb.WendyComChannelErrorReason_WENDY_COM_CHANNEL_ERROR_REASON_NOT_OPEN))
	drainCloseChannel(t, env, ch)
	if _, err := stream.Recv(); status.Code(err) != codes.Aborted {
		t.Fatalf("expected Aborted, got %v", err)
	}
}

func TestDeviceDisconnectEndsTunnel(t *testing.T) {
	env := newTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, _ := openTunnel(t, env, ctx)
	env.device.Close()
	if _, err := stream.Recv(); status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable, got %v", err)
	}
	// device deregistered: a new open fails with NotFound
	deadline := time.Now().Add(5 * time.Second)
	for env.broker.device(hardcodedAssetID) != nil {
		if time.Now().After(deadline) {
			t.Fatal("device still registered after disconnect")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
