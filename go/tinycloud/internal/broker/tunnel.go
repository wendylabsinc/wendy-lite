package broker

import (
	"log"
	"sync"
	"time"

	wendypb "github.com/wendylabsinc/wendy/go/proto/gen/litepb"
	"github.com/wendylabsinc/wendy/go/proto/gen/tunnelpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// How long to wait for the device's ChannelState reply to OpenChannel before
// giving up on the tunnel.
const openAckTimeout = 10 * time.Second

type tunnelServer struct {
	tunnelpb.UnimplementedWendyComTunnelBrokerServiceServer
	broker *Broker
}

func NewTunnelServer(b *Broker) tunnelpb.WendyComTunnelBrokerServiceServer {
	return &tunnelServer{broker: b}
}

// tunnel is one live gRPC stream bound to one device channel.
type tunnel struct {
	channel    uint8
	fromDevice chan []byte // frame bodies routed by deviceConn.readLoop
	done       chan struct{}
	closeOnce  sync.Once
}

func (t *tunnel) closeDone() {
	t.closeOnce.Do(func() { close(t.done) })
}

type recvResult struct {
	payload []byte
	err     error
}

func serviceFrame(msg *wendypb.WendyComService) []byte {
	body, err := proto.Marshal(&wendypb.WendyComMessage{
		Msg: &wendypb.WendyComMessage_Service{Service: msg},
	})
	if err != nil {
		panic(err) // static message, cannot fail
	}
	return body
}

var (
	openChannelBody = serviceFrame(&wendypb.WendyComService{
		Cmd: &wendypb.WendyComService_OpenChannel{OpenChannel: &wendypb.WendyComOpenChannel{}},
	})
	closeChannelBody = serviceFrame(&wendypb.WendyComService{
		Cmd: &wendypb.WendyComService_CloseChannel{CloseChannel: &wendypb.WendyComCloseChannel{}},
	})
)

// channelState extracts the ChannelState report from a device frame body, or
// returns nil if the body is anything else (including undecodable bytes —
// those are relayed untouched, like any payload).
func channelState(body []byte) *wendypb.WendyComChannelState {
	var msg wendypb.WendyComMessage
	if err := proto.Unmarshal(body, &msg); err != nil {
		return nil
	}
	return msg.GetService().GetChannelState()
}

func (s *tunnelServer) WendyComTunnel(stream tunnelpb.WendyComTunnelBrokerService_WendyComTunnelServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	open := first.GetOpen()
	if open == nil {
		return status.Error(codes.InvalidArgument, "first message must be open")
	}

	dev := s.broker.device(open.AssetId)
	if dev == nil {
		return status.Errorf(codes.NotFound, "device %d not connected", open.AssetId)
	}
	ch, err := dev.alloc.allocate()
	if err != nil {
		return status.Error(codes.ResourceExhausted, err.Error())
	}

	t := &tunnel{
		channel:    ch,
		fromDevice: make(chan []byte, 16),
		done:       make(chan struct{}),
	}
	if err := dev.addTunnel(t); err != nil {
		dev.alloc.release(ch)
		return status.Error(codes.Unavailable, err.Error())
	}
	log.Printf("device %d: tunnel opened on channel %d", dev.assetID, ch)

	defer func() {
		t.closeDone()
		dev.removeTunnel(ch, t)
		// best effort: the device may already be gone
		if err := dev.writeFrame(ch, closeChannelBody); err == nil {
			log.Printf("device %d: tunnel closed on channel %d", dev.assetID, ch)
		}
		dev.alloc.release(ch) // quarantined for a minute
	}()

	// The device sees OpenChannel before any forwarded payload: both go
	// through the same ordered socket from this handler.
	if err := dev.writeFrame(ch, openChannelBody); err != nil {
		return status.Error(codes.Unavailable, "device write failed")
	}

	// Hold client payloads back until the device confirms the channel: the
	// recv goroutine is not started yet, so the stream applies backpressure.
	ackTimer := time.NewTimer(openAckTimeout)
	defer ackTimer.Stop()
waitAck:
	for {
		select {
		case body := <-t.fromDevice:
			st := channelState(body)
			if st == nil {
				log.Printf("device %d: dropping frame on channel %d received before open ack", dev.assetID, ch)
				continue
			}
			if st.GetOpen() != nil {
				break waitAck
			}
			if e := st.GetError(); e != nil {
				return status.Errorf(codes.ResourceExhausted, "device rejected channel open: %s", e.GetReason())
			}
			return status.Error(codes.Aborted, "unexpected channel state from device")
		case <-ackTimer.C:
			return status.Error(codes.Unavailable, "timeout waiting for device to open channel")
		case <-t.done:
			return status.Error(codes.Unavailable, "device disconnected")
		case <-stream.Context().Done():
			return nil // client went away
		}
	}

	recvC := make(chan recvResult)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				recvC <- recvResult{err: err}
				return
			}
			payload := msg.GetPayload()
			if payload == nil {
				recvC <- recvResult{err: status.Error(codes.InvalidArgument, "expected payload")}
				return
			}
			select {
			case recvC <- recvResult{payload: payload.Bytes}:
			case <-t.done:
				return
			}
		}
	}()

	for {
		select {
		case r := <-recvC:
			if r.err != nil {
				if status.Code(r.err) == codes.InvalidArgument {
					return r.err
				}
				return nil // client ended the stream
			}
			if err := dev.writeFrame(ch, r.payload); err != nil {
				return status.Error(codes.Unavailable, "device write failed")
			}
		case body := <-t.fromDevice:
			// ChannelState reports are consumed here — channels are the
			// broker's business, the gRPC client never sees them.
			if st := channelState(body); st != nil {
				if st.GetClose() != nil {
					log.Printf("device %d: channel %d closed by device", dev.assetID, ch)
					return nil
				}
				if e := st.GetError(); e != nil {
					return status.Errorf(codes.Aborted, "device channel error: %s", e.GetReason())
				}
				continue
			}
			err := stream.Send(&tunnelpb.WendyComTunnelMessage{
				Msg: &tunnelpb.WendyComTunnelMessage_Payload{
					Payload: &tunnelpb.WendyComTunnelPayload{Bytes: body},
				},
			})
			if err != nil {
				return err
			}
		case <-t.done:
			return status.Error(codes.Unavailable, "device disconnected")
		}
	}
}
