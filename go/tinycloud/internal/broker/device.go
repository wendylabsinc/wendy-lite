package broker

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"tinycloud/internal/wcomframe"
)

// deviceConn is one reverse-connected device link. The channel namespace
// (allocator + routing table) lives and dies with the link: a reconnect
// starts fresh.
type deviceConn struct {
	assetID uint32
	conn    net.Conn
	broker  *Broker
	alloc   *channelAllocator

	writeMu sync.Mutex // serializes whole frames onto the socket

	mu      sync.Mutex
	tunnels map[uint8]*tunnel // channel -> owning tunnel
	closed  bool
}

// writeFrame sends one framed WendyCom message body on the given channel.
func (d *deviceConn) writeFrame(channel uint8, body []byte) error {
	frame, err := wcomframe.Encode(channel, body)
	if err != nil {
		return err
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err = d.conn.Write(frame)
	return err
}

// readLoop reads frames from the device and routes bodies by channel to the
// owning tunnel. Runs until the connection dies, then tears everything down.
func (d *deviceConn) readLoop() {
	defer d.shutdown()
	hdr := make([]byte, wcomframe.HeaderSize)
	for {
		if _, err := io.ReadFull(d.conn, hdr); err != nil {
			log.Printf("device %d: read: %v", d.assetID, err)
			return
		}
		h, err := wcomframe.DecodeHeader(hdr)
		if err != nil {
			// link-level corruption: no way to resync, drop the connection
			log.Printf("device %d: %v", d.assetID, err)
			return
		}
		body := make([]byte, h.BodyLen)
		if _, err := io.ReadFull(d.conn, body); err != nil {
			log.Printf("device %d: read body: %v", d.assetID, err)
			return
		}

		d.mu.Lock()
		t := d.tunnels[h.Channel]
		d.mu.Unlock()
		if t == nil {
			// includes channel 0 (no server-side peer) and quarantined ids
			log.Printf("device %d: dropping frame on unknown channel %d (%d bytes)",
				d.assetID, h.Channel, len(body))
			continue
		}
		select {
		case t.fromDevice <- body:
			// blocking (rather than dropping) preserves ordering and applies
			// backpressure while the tunnel is alive
		case <-t.done:
			// tunnel dying; drop the frame rather than stall the device link
		}
	}
}

func (d *deviceConn) addTunnel(t *tunnel) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return fmt.Errorf("device %d disconnected", d.assetID)
	}
	d.tunnels[t.channel] = t
	return nil
}

func (d *deviceConn) removeTunnel(ch uint8, t *tunnel) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.tunnels[ch] == t {
		delete(d.tunnels, ch)
	}
}

// shutdown closes the connection and ends every tunnel on it. Idempotent.
func (d *deviceConn) shutdown() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	tunnels := make([]*tunnel, 0, len(d.tunnels))
	for _, t := range d.tunnels {
		tunnels = append(tunnels, t)
	}
	d.tunnels = make(map[uint8]*tunnel)
	d.mu.Unlock()

	d.conn.Close()
	d.broker.dropDevice(d)
	for _, t := range tunnels {
		t.closeDone()
	}
	log.Printf("device %d disconnected", d.assetID)
}
