package liteclient

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	wendypb "github.com/wendylabsinc/wendy/go/proto/gen/litepb"
	"github.com/wendylabsinc/wendy/go/proto/gen/wcomrelaypb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type innerEnvelopeStream struct {
	grpc.ClientStream
	ctx      context.Context
	messages chan *wcomrelaypb.WendyComRelayMessage
	onSend   func(*wcomrelaypb.WendyComRelayMessage) error
}

func (s *innerEnvelopeStream) Send(message *wcomrelaypb.WendyComRelayMessage) error {
	if s.onSend != nil {
		return s.onSend(message)
	}
	return nil
}

func (s *innerEnvelopeStream) Recv() (*wcomrelaypb.WendyComRelayMessage, error) {
	select {
	case message, ok := <-s.messages:
		if !ok {
			return nil, io.EOF
		}
		return message, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func newInnerEnvelopeLink(t *testing.T) (*tunnelLink, *innerEnvelopeStream) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stream := &innerEnvelopeStream{ctx: ctx, messages: make(chan *wcomrelaypb.WendyComRelayMessage, 8)}
	link := &tunnelLink{stream: stream, ctx: ctx, msgs: make(chan *wendypb.WendyComMessage, 8)}
	go link.recvLoop()
	return link, stream
}

func relayInnerBody(body []byte) *wcomrelaypb.WendyComRelayMessage {
	return &wcomrelaypb.WendyComRelayMessage{Msg: &wcomrelaypb.WendyComRelayMessage_Payload{
		Payload: &wcomrelaypb.WendyComRelayPayload{Bytes: body},
	}}
}

func futureInnerBody(t *testing.T) []byte {
	t.Helper()
	body := []byte{0x7a, 0x01, 0x01} // future length-delimited oneof field15
	var message wendypb.WendyComMessage
	if err := proto.Unmarshal(body, &message); err != nil || message.GetMsg() != nil || len(message.ProtoReflect().GetUnknown()) == 0 {
		t.Fatalf("future inner fixture = %v, %v", &message, err)
	}
	return body
}

func TestTunnelHandshakeSkipsFutureInnerEnvelope(t *testing.T) {
	link, stream := newInnerEnvelopeLink(t)
	future := futureInnerBody(t)
	stream.onSend = func(request *wcomrelaypb.WendyComRelayMessage) error {
		var message wendypb.WendyComMessage
		if err := proto.Unmarshal(request.GetPayload().GetBytes(), &message); err != nil {
			return err
		}
		hs := message.GetHandshake()
		if hs == nil {
			t.Fatal("client did not send handshake")
		}
		body, err := proto.Marshal(&wendypb.WendyComMessage{Msg: &wendypb.WendyComMessage_Handshake{
			Handshake: &wendypb.WendyComHandshake{HandshakeId: hs.GetHandshakeId(),
				Version: &wendypb.WendyComProtocolVersion{Major: versionMajor, Minor: 99}},
		}})
		if err != nil {
			return err
		}
		stream.messages <- relayInnerBody(future)
		stream.messages <- relayInnerBody(body)
		close(stream.messages)
		return nil
	}
	client := &WendyLiteClient{link: link}
	if err := client.handshake(); err != nil {
		t.Fatalf("handshake after future inner envelope = %v", err)
	}
	if client.peerProtocolVersion.Major != versionMajor || client.peerProtocolVersion.Minor != 99 {
		t.Fatalf("peer protocol = %+v", client.peerProtocolVersion)
	}
	if _, err := link.recv(time.Second); err != io.EOF {
		t.Fatalf("receive after handshake = %v, want EOF", err)
	}
}

func TestTunnelFutureInnerEnvelopeKeepsReceiveTimeout(t *testing.T) {
	link, stream := newInnerEnvelopeLink(t)
	stream.messages <- relayInnerBody(futureInnerBody(t))
	started := time.Now()
	if _, err := link.recv(20 * time.Millisecond); err == nil || !strings.Contains(err.Error(), "read timeout") {
		t.Fatalf("future-only receive = %v, want original read timeout", err)
	}
	if elapsed := time.Since(started); elapsed < 15*time.Millisecond || elapsed > time.Second {
		t.Fatalf("future-only receive took %v", elapsed)
	}
}

func TestTunnelInnerEnvelopeRetainsProtocolErrors(t *testing.T) {
	for _, test := range []struct {
		name  string
		body  []byte
		outer *wcomrelaypb.WendyComRelayMessage
		want  string
	}{
		{name: "malformed", body: []byte{0xff}, want: "unmarshal:"},
		{name: "known-wrong-direction", outer: &wcomrelaypb.WendyComRelayMessage{
			Msg: &wcomrelaypb.WendyComRelayMessage_Open{Open: &wcomrelaypb.WendyComRelayOpen{}},
		}, want: "unexpected tunnel message"},
	} {
		t.Run(test.name, func(t *testing.T) {
			link, stream := newInnerEnvelopeLink(t)
			message := test.outer
			if message == nil {
				message = relayInnerBody(test.body)
			}
			stream.messages <- message
			if _, err := link.recv(time.Second); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("receive = %v, want %q", err, test.want)
			}
		})
	}
}

func TestTunnelHandshakeRetainsKnownReplyErrors(t *testing.T) {
	for _, test := range []struct {
		name         string
		wrongVersion bool
		want         string
	}{
		{name: "known-wrong-inner", want: "unexpected reply message type"},
		{name: "wrong-version", wrongVersion: true, want: "unsupported device protocol version"},
	} {
		t.Run(test.name, func(t *testing.T) {
			link, stream := newInnerEnvelopeLink(t)
			stream.onSend = func(request *wcomrelaypb.WendyComRelayMessage) error {
				var incoming wendypb.WendyComMessage
				if err := proto.Unmarshal(request.GetPayload().GetBytes(), &incoming); err != nil {
					return err
				}
				reply := &wendypb.WendyComMessage{Msg: &wendypb.WendyComMessage_Response{Response: &wendypb.WendyComResponse{RequestId: 1}}}
				if test.wrongVersion {
					reply.Msg = &wendypb.WendyComMessage_Handshake{Handshake: &wendypb.WendyComHandshake{
						HandshakeId: incoming.GetHandshake().GetHandshakeId(), Version: &wendypb.WendyComProtocolVersion{Major: versionMajor + 1},
					}}
				}
				body, err := proto.Marshal(reply)
				if err != nil {
					return err
				}
				stream.messages <- relayInnerBody(body)
				return nil
			}
			client := &WendyLiteClient{link: link}
			if err := client.handshake(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("handshake = %v, want %q", err, test.want)
			}
		})
	}
}
