package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"github.com/wendylabsinc/wendy/go/proto/gen/litepb"
	"github.com/wendylabsinc/wendy/go/proto/gen/sensorlinkpb"
	"google.golang.org/protobuf/proto"
	"io"
	"os"
)

func init() { nativeComposedApplication = composedWendyCom }

func composedWendyCom(secure *tls.Conn, operator bool) {
	send := func(channel byte, message *litepb.WendyComMessage) {
		body, err := proto.Marshal(message)
		must(err)
		header := []byte{0xa5, 2, 0, channel, 0, 0, 0, 0}
		binary.BigEndian.PutUint16(header[6:], uint16(len(body)))
		wire := append(header, body...)
		for len(wire) > 0 {
			n := len(wire)
			if n > 7 {
				n = 7
			}
			written, err := secure.Write(wire[:n])
			must(err)
			wire = wire[written:]
		}
	}
	receive := func() (byte, *litepb.WendyComMessage) {
		var header [8]byte
		_, err := io.ReadFull(secure, header[:])
		must(err)
		if header[0] != 0xa5 || header[1] != 2 {
			panic("invalid actual WendyCom framing")
		}
		body := make([]byte, binary.BigEndian.Uint16(header[6:]))
		_, err = io.ReadFull(secure, body)
		must(err)
		var message litepb.WendyComMessage
		must(proto.Unmarshal(body, &message))
		return header[3], &message
	}
	send(0, &litepb.WendyComMessage{Msg: &litepb.WendyComMessage_Handshake{Handshake: &litepb.WendyComHandshake{
		HandshakeId: 71, Version: &litepb.WendyComProtocolVersion{Major: 2}}}})
	channel, hello := receive()
	if channel != 0 || hello.GetHandshake().GetHandshakeId() != 71 || hello.GetHandshake().GetVersion().GetMajor() != 2 {
		panic("actual HELLO mismatch")
	}
	if operator {
		send(0, &litepb.WendyComMessage{Msg: &litepb.WendyComMessage_Command{Command: &litepb.WendyComCommand{
			RequestId: 72, Params: &litepb.WendyComCommand_Ping{Ping: &litepb.WendyComPingParams{}}}}})
		_, response := receive()
		if response.GetResponse().GetRequestId() != 72 || response.GetResponse().GetResult() != litepb.WendyComResult_WENDY_COM_RESULT_OK {
			panic("actual Ping mismatch")
		}
	}
	send(0, &litepb.WendyComMessage{Msg: &litepb.WendyComMessage_Command{Command: &litepb.WendyComCommand{
		RequestId: 73, Params: &litepb.WendyComCommand_SensorLinkGetManifest{SensorLinkGetManifest: &sensorlinkpb.GetSensorManifest{}}}}})
	_, manifest := receive()
	if manifest.GetResponse().GetRequestId() != 73 || manifest.GetResponse().GetResult() != litepb.WendyComResult_WENDY_COM_RESULT_OK || len(manifest.GetResponse().GetSensorLinkManifest().GetSensors()) != 1 {
		panic("actual SensorLink manifest mismatch")
	}
	send(7, &litepb.WendyComMessage{Msg: &litepb.WendyComMessage_Service{Service: &litepb.WendyComService{
		Cmd: &litepb.WendyComService_OpenChannel{OpenChannel: &litepb.WendyComOpenChannel{}}}}})
	channel, opened := receive()
	if channel != 7 || opened.GetService().GetChannelState() == nil {
		panic("actual sensor channel mismatch")
	}
	send(7, &litepb.WendyComMessage{Msg: &litepb.WendyComMessage_Command{Command: &litepb.WendyComCommand{
		RequestId: 74, Params: &litepb.WendyComCommand_SensorLinkSubscribe{SensorLinkSubscribe: &sensorlinkpb.Subscribe{ChannelId: []uint32{7}}}}}})
	expectedBytes := 6000
	if os.Getenv("WENDY_TLS_COMPOSED_LARGE_SAMPLE") == "1" {
		expectedBytes = 16384
	}
	var frame []byte
	var frameSeq, nextChunk uint32
	gotReply, gotSamples := false, false
	for !gotReply || !gotSamples {
		channel, message := receive()
		if channel != 7 {
			panic("actual sensor data channel mismatch")
		}
		if data := message.GetSensorData(); data != nil {
			if len(frame) == 0 {
				frameSeq = data.GetFrameSeq()
			}
			if data.GetChannelId() != 7 || data.GetFrameSeq() != frameSeq || data.GetChunkSeq() != nextChunk || data.GetFlags()&1 == 0 || len(frame)+len(data.GetPayload()) > expectedBytes {
				panic("actual SensorLink chunk mismatch")
			}
			nextChunk++
			frame = append(frame, data.GetPayload()...)
			if data.GetFlags()&2 != 0 {
				if len(frame) != expectedBytes {
					panic("actual SensorLink frame size mismatch")
				}
				for i, b := range frame {
					if b != byte(i*13) {
						panic("actual SensorLink payload mismatch")
					}
				}
				gotSamples = true
			}
		} else if response := message.GetResponse(); response != nil {
			if response.GetRequestId() != 74 || response.GetResult() != litepb.WendyComResult_WENDY_COM_RESULT_OK {
				panic("actual subscribe reply mismatch")
			}
			gotReply = true
		} else {
			panic("unexpected actual sensor message")
		}
	}
	send(7, &litepb.WendyComMessage{Msg: &litepb.WendyComMessage_Command{Command: &litepb.WendyComCommand{
		RequestId: 75, Params: &litepb.WendyComCommand_SensorLinkUnsubscribe{SensorLinkUnsubscribe: &sensorlinkpb.Unsubscribe{ChannelId: []uint32{7}}}}}})
	_, done := receive()
	if done.GetResponse().GetRequestId() != 75 || done.GetResponse().GetResult() != litepb.WendyComResult_WENDY_COM_RESULT_OK {
		panic("actual unsubscribe mismatch")
	}
	if operator {
		send(0, &litepb.WendyComMessage{Msg: &litepb.WendyComMessage_Command{Command: &litepb.WendyComCommand{
			RequestId: 76, Params: &litepb.WendyComCommand_ConsoleAttach{ConsoleAttach: &litepb.WendyComConsoleAttachParams{EventId: 77, Duration: 1000}}}}})
		channel, attached := receive()
		if channel != 0 || attached.GetResponse().GetRequestId() != 76 || attached.GetResponse().GetResult() != litepb.WendyComResult_WENDY_COM_RESULT_OK {
			panic("actual ConsoleAttach mismatch")
		}
	}
	fmt.Printf("PASS COMPOSED actual HELLO/Ping=%t/SensorLink%d/ConsoleAttach=%t operator=%t\n", operator, expectedBytes, operator, operator)
}
