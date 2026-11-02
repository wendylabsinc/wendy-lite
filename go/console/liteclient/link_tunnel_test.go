package liteclient

import (
	"context"
	"io"
	"testing"
	"time"

	wendypb "github.com/wendylabsinc/wendy/go/proto/gen/litepb"
	"github.com/wendylabsinc/wendy/go/proto/gen/wcomrelaypb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type relaySequenceStream struct {
	grpc.ClientStream
	messages []*wcomrelaypb.WendyComRelayMessage
}

func (s *relaySequenceStream) Send(*wcomrelaypb.WendyComRelayMessage) error { return nil }

func (s *relaySequenceStream) Recv() (*wcomrelaypb.WendyComRelayMessage, error) {
	if len(s.messages) == 0 {
		return nil, io.EOF
	}
	message := s.messages[0]
	s.messages = s.messages[1:]
	return message, nil
}

func TestTunnelSkipsUnknownRelayKind(t *testing.T) {
	future := &wcomrelaypb.WendyComRelayMessage{}
	// Field15 is a future length-delimited relay oneof arm. Decode actual
	// wire bytes rather than constructing an otherwise empty envelope.
	if err := proto.Unmarshal([]byte{0x7a, 0x01, 0x01}, future); err != nil {
		t.Fatal(err)
	}
	known := &wendypb.WendyComMessage{Msg: &wendypb.WendyComMessage_Response{
		Response: &wendypb.WendyComResponse{RequestId: 42},
	}}
	body, err := proto.Marshal(known)
	if err != nil {
		t.Fatal(err)
	}
	payload := &wcomrelaypb.WendyComRelayPayload{Bytes: body}
	payload.ProtoReflect().SetUnknown([]byte{0x78, 0x01})
	message := &wcomrelaypb.WendyComRelayMessage{Msg: &wcomrelaypb.WendyComRelayMessage_Payload{Payload: payload}}
	message.ProtoReflect().SetUnknown([]byte{0x78, 0x01})
	link := &tunnelLink{
		stream: &relaySequenceStream{messages: []*wcomrelaypb.WendyComRelayMessage{future, message}},
		ctx:    context.Background(),
		msgs:   make(chan *wendypb.WendyComMessage, 1),
	}
	link.recvLoop()
	got, err := link.recv(time.Second)
	if err != nil || !proto.Equal(got, known) {
		t.Fatalf("message after future relay kind = %v, %v; want %v", got, err, known)
	}
	if _, err := link.recv(time.Second); err != io.EOF {
		t.Fatalf("stream end = %v, want EOF", err)
	}
}

func TestTunnelRejectsKnownWrongDirectionMessage(t *testing.T) {
	link := &tunnelLink{
		stream: &relaySequenceStream{messages: []*wcomrelaypb.WendyComRelayMessage{{
			Msg: &wcomrelaypb.WendyComRelayMessage_Open{Open: &wcomrelaypb.WendyComRelayOpen{}},
		}}},
		ctx:  context.Background(),
		msgs: make(chan *wendypb.WendyComMessage, 1),
	}
	link.recvLoop()
	if _, err := link.recv(time.Second); err == nil || err == io.EOF {
		t.Fatalf("known wrong-direction Open = %v, want protocol error", err)
	}
}
