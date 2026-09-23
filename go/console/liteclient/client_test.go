package liteclient

import (
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	wendypb "github.com/wendylabsinc/wendy/go/proto/gen/litepb"
	"github.com/wendylabsinc/wendy/go/proto/gen/sensorlinkpb"
)

func sensorFrameMsg(seq uint32) *wendypb.WendyComMessage {
	return &wendypb.WendyComMessage{
		Msg: &wendypb.WendyComMessage_SensorFrame{
			SensorFrame: &sensorlinkpb.SensorFrame{Seq: seq},
		},
	}
}

func TestSensorFrameListeners(t *testing.T) {
	// dispatch of a frame touches neither the link nor mu, so a zero-value
	// client is enough to drive it.
	c := &WendyLiteClient{}

	var got []string
	record := func(tag string) func(*sensorlinkpb.SensorFrame) {
		return func(f *sensorlinkpb.SensorFrame) { got = append(got, fmt.Sprintf("%s%d", tag, f.GetSeq())) }
	}

	removeA := c.AddSensorFrameListener(record("a"))
	removeB := c.AddSensorFrameListener(record("b"))

	c.dispatch(sensorFrameMsg(1))
	if want := []string{"a1", "b1"}; !slices.Equal(got, want) {
		t.Errorf("both listeners: got %v, want %v", got, want)
	}

	got = nil
	removeA()
	c.dispatch(sensorFrameMsg(2))
	if want := []string{"b2"}; !slices.Equal(got, want) {
		t.Errorf("after removing a: got %v, want %v", got, want)
	}

	got = nil
	removeA() // removal is idempotent and must not disturb b
	c.dispatch(sensorFrameMsg(3))
	if want := []string{"b3"}; !slices.Equal(got, want) {
		t.Errorf("after removing a twice: got %v, want %v", got, want)
	}

	got = nil
	removeB()
	c.dispatch(sensorFrameMsg(4))
	if len(got) != 0 {
		t.Errorf("after removing all: got %v, want none", got)
	}
}

// Delivery deliberately takes no lock, so registration has to publish a fresh
// slice instead of mutating the one dispatch is ranging over. Only -race
// proves it.
func TestSensorFrameListenersRace(t *testing.T) {
	c := &WendyLiteClient{}
	var calls atomic.Int64

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // stands in for the read loop
		defer wg.Done()
		msg := sensorFrameMsg(1)
		for {
			select {
			case <-stop:
				return
			default:
				c.dispatch(msg)
			}
		}
	}()

	for range 100 {
		remove := c.AddSensorFrameListener(func(*sensorlinkpb.SensorFrame) { calls.Add(1) })
		remove()
	}
	close(stop)
	wg.Wait()
}
