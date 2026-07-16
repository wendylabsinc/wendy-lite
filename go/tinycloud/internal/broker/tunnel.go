package broker

import (
	"log"
	"sync"

	wendypb "github.com/wendylabsinc/wendy/go/proto/gen/litepb"
	"github.com/wendylabsinc/wendy/go/proto/gen/tunnelpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

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
