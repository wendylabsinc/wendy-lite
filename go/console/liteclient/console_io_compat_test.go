package liteclient

import (
	"bytes"
	"io"
	"testing"
	"time"

	wendypb "github.com/wendylabsinc/wendy/go/proto/gen/litepb"
)

type consoleIOTestLink struct {
	client   *WendyLiteClient
	eventID  uint32
	detaches int
}

func (*consoleIOTestLink) linkHandshake() error                                 { return nil }
func (*consoleIOTestLink) recv(time.Duration) (*wendypb.WendyComMessage, error) { return nil, io.EOF }
func (*consoleIOTestLink) preferredChunkSize() int                              { return chunkSize }
func (*consoleIOTestLink) close() error                                         { return nil }
func (l *consoleIOTestLink) send(message *wendypb.WendyComMessage) error {
	command := message.GetCommand()
	if attach := command.GetConsoleAttach(); attach != nil {
		l.eventID = attach.GetEventId()
	}
	if command.GetConsoleDetach() != nil {
		l.detaches++
	}
	l.client.dispatch(&wendypb.WendyComMessage{Msg: &wendypb.WendyComMessage_Response{
		Response: &wendypb.WendyComResponse{RequestId: command.GetRequestId()},
	}})
	return nil
}

func TestConsoleAttachSkipsUnknownAndInputIO(t *testing.T) {
	client := &WendyLiteClient{}
	link := &consoleIOTestLink{client: client}
	client.link = link
	chunks, detach, err := client.ConsoleAttach(false, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = detach(true) })
	send := func(stream wendypb.WendyComConsoleIo, gap bool, data []byte) {
		client.dispatch(&wendypb.WendyComMessage{Msg: &wendypb.WendyComMessage_Event{
			Event: &wendypb.WendyComEvent{EventId: link.eventID,
				Data: &wendypb.WendyComEvent_ConsoleData{ConsoleData: &wendypb.WendyComConsoleData{
					Io: stream, Gap: gap, Data: data,
				}},
			},
		}})
	}
	stdout := []byte{0x00, 0xff, 0x10, 0x0a}
	stderr := []byte{0xfe, 0x00, 0x0d}
	send(wendypb.WendyComConsoleIo_WENDY_COM_CONSOLE_IO_STANDARD_INPUT, true, []byte("not-output"))
	send(wendypb.WendyComConsoleIo(99), true, []byte("future-kind"))
	send(wendypb.WendyComConsoleIo_WENDY_COM_CONSOLE_IO_STANDARD_OUTPUT, true, stdout)
	send(wendypb.WendyComConsoleIo(-1), false, []byte("future-negative-kind"))
	send(wendypb.WendyComConsoleIo_WENDY_COM_CONSOLE_IO_STANDARD_ERROR, false, stderr)
	send(wendypb.WendyComConsoleIo_WENDY_COM_CONSOLE_IO_STANDARD_OUTPUT, false, []byte("continued"))
	for index, want := range []ConsoleChunk{
		{Gap: true, Data: stdout},
		{Stderr: true, Data: stderr},
		{Data: []byte("continued")},
	} {
		select {
		case got, ok := <-chunks:
			if !ok || got.Gap != want.Gap || got.Stderr != want.Stderr || !bytes.Equal(got.Data, want.Data) {
				t.Fatalf("chunk%d = %+v, open=%v; want %+v", index, got, ok, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("chunk%d was not delivered", index)
		}
	}
	if err := detach(false); err != nil {
		t.Fatalf("detach = %v", err)
	}
	if err := detach(false); err != nil {
		t.Fatalf("second detach = %v", err)
	}
	if link.detaches != 1 {
		t.Fatalf("detach commands = %d, want1", link.detaches)
	}
	select {
	case _, ok := <-chunks:
		if ok {
			t.Fatal("unexpected output after detach")
		}
	case <-time.After(time.Second):
		t.Fatal("output not closed after detach")
	}
}
