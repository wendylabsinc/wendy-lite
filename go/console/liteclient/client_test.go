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

func sensorDataMsg(frameSeq uint32) *wendypb.WendyComMessage {
	return &wendypb.WendyComMessage{
		Msg: &wendypb.WendyComMessage_SensorData{
			SensorData: &sensorlinkpb.SensorData{FrameSeq: frameSeq},
		},
	}
}

func TestSensorDataListeners(t *testing.T) {
	// dispatch of sensor data touches neither the link nor mu, so a
	// zero-value client is enough to drive it.
	c := &WendyLiteClient{}

	var got []string
	record := func(tag string) func(*sensorlinkpb.SensorData) {
		return func(d *sensorlinkpb.SensorData) { got = append(got, fmt.Sprintf("%s%d", tag, d.GetFrameSeq())) }
	}

	removeA := c.AddSensorDataListener(record("a"))
	removeB := c.AddSensorDataListener(record("b"))

	c.dispatch(sensorDataMsg(1))
	if want := []string{"a1", "b1"}; !slices.Equal(got, want) {
		t.Errorf("both listeners: got %v, want %v", got, want)
	}

	got = nil
	removeA()
	c.dispatch(sensorDataMsg(2))
	if want := []string{"b2"}; !slices.Equal(got, want) {
		t.Errorf("after removing a: got %v, want %v", got, want)
	}

	got = nil
	removeA() // removal is idempotent and must not disturb b
	c.dispatch(sensorDataMsg(3))
	if want := []string{"b3"}; !slices.Equal(got, want) {
		t.Errorf("after removing a twice: got %v, want %v", got, want)
	}

	got = nil
	removeB()
	c.dispatch(sensorDataMsg(4))
	if len(got) != 0 {
		t.Errorf("after removing all: got %v, want none", got)
	}
}

// Delivery deliberately takes no lock, so registration has to publish a fresh
// slice instead of mutating the one dispatch is ranging over. Only -race
// proves it.
func TestSensorDataListenersRace(t *testing.T) {
	c := &WendyLiteClient{}
	var calls atomic.Int64

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // stands in for the read loop
		defer wg.Done()
		msg := sensorDataMsg(1)
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
		remove := c.AddSensorDataListener(func(*sensorlinkpb.SensorData) { calls.Add(1) })
		remove()
	}
	close(stop)
	wg.Wait()
}
