// Host-only interoperability driver. Use -modfile with a local Go Babel replace.
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"github.com/wendylabsinc/WendyOS/go/babel"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(r io.Reader, n int) []byte {
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	must(err)
	return p
}
func put64(p []byte, n uint64) []byte { return binary.BigEndian.AppendUint64(p, n) }
func address(n int) netip.Addr {
	p := [16]byte{0xfe, 0x80}
	p[15] = byte(n)
	return netip.AddrFrom16(p)
}
func prefix(n int) netip.Prefix {
	p := [16]byte{0xfd, 0x45, 0xb8, 0x91, 0x56, 0x7f}
	p[15] = byte(n)
	return netip.PrefixFrom(netip.AddrFrom16(p), 128)
}
func encodePrefix(p netip.Prefix) []byte {
	return append(append([]byte{}, p.Addr().AsSlice()...), byte(p.Bits()), 6)
}
func decodeAddress(p []byte, af byte) netip.Addr {
	if af == 4 {
		return netip.AddrFrom4([4]byte(p[:4]))
	}
	if af == 6 {
		return netip.AddrFrom16([16]byte(p[:16]))
	}
	return netip.Addr{}
}

type cNode struct {
	input   io.WriteCloser
	output  *bufio.Reader
	command *exec.Cmd
	routes  []babel.Route
	seq     uint16
}
type datagram struct {
	from, to int
	data     []byte
}

var queued []datagram
var links [3][3]uint64
var monotonic time.Duration
var c *cNode
var nodes [3]*babel.Engine
var denied bool

func start(path string) *cNode {
	cmd := exec.Command(path)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	must(err)
	out, err := cmd.StdoutPipe()
	must(err)
	must(cmd.Start())
	return &cNode{input: in, output: bufio.NewReader(out), command: cmd}
}
func (c *cNode) step(op byte, now uint64, payload []byte) {
	data := put64([]byte{op}, now)
	data = append(data, payload...)
	_, err := c.input.Write(data)
	must(err)
	header := read(c.output, 6)
	if status := int16(binary.BigEndian.Uint16(header)); status != 0 {
		panic(fmt.Sprintf("C status %d op %c time %d", status, op, now))
	}
	c.seq = binary.BigEndian.Uint16(header[2:])
	count := int(binary.BigEndian.Uint16(header[4:]))
	c.routes = nil
	for i := 0; i < count; i++ {
		r := read(c.output, 56)
		a := decodeAddress(r[:16], r[17])
		route := babel.Route{Prefix: netip.PrefixFrom(a, int(r[16])), RouterID: babel.RouterID(binary.BigEndian.Uint64(r[18:])), Seqno: binary.BigEndian.Uint16(r[26:]), Metric: binary.BigEndian.Uint16(r[28:]), Link: babel.LinkID(binary.BigEndian.Uint64(r[30:])), Local: r[38]&1 != 0, Unreachable: r[38]&2 != 0, NextHop: decodeAddress(r[40:], r[39])}
		c.routes = append(c.routes, route)
	}
	for {
		n := int(binary.BigEndian.Uint16(read(c.output, 2)))
		if n == 0 {
			break
		}
		id := binary.BigEndian.Uint64(read(c.output, 8))
		p := read(c.output, n)
		queued = append(queued, datagram{1, int((id - 1) % 3), p})
	}
}
func goStep(index int, event babel.Event) {
	out, err := nodes[index].Step(monotonic, event)
	must(err)
	if out.Revision != 0 {
		committed, err := nodes[index].Commit(out.Revision, true)
		must(err)
		out.Datagrams = append(out.Datagrams, committed.Datagrams...)
	}
	for _, p := range out.Datagrams {
		queued = append(queued, datagram{index, int((uint64(p.Link) - 1) % 3), p.Payload})
	}
}
func tick(index int) {
	if index == 1 {
		c.step('t', uint64(monotonic/time.Millisecond), nil)
	} else {
		goStep(index, babel.Tick{})
	}
}
func deliver() {
	for sent := 0; len(queued) > 0; sent++ {
		if sent > 10000 {
			panic("packet storm")
		}
		p := queued[0]
		queued = queued[1:]
		if p.to == 1 {
			body := put64(nil, links[p.to][p.from])
			body = binary.BigEndian.AppendUint16(body, uint16(len(p.data)))
			body = append(body, p.data...)
			c.step('r', uint64(monotonic/time.Millisecond), body)
		} else {
			goStep(p.to, babel.Receive{ID: babel.LinkID(links[p.to][p.from]), Packet: p.data})
		}
	}
}
func connect(a, b int, cost uint16, generation uint64) {
	for _, pair := range [][2]int{{a, b}, {b, a}} {
		self, peer := pair[0], pair[1]
		id := generation*3 + uint64(peer+1)
		links[self][peer] = id
		if self == 1 {
			p := put64(nil, id)
			p = append(p, address(self+1).AsSlice()...)
			p = append(p, address(peer+1).AsSlice()...)
			p = binary.BigEndian.AppendUint16(p, cost)
			c.step('a', uint64(monotonic/time.Millisecond), p)
		} else {
			goStep(self, babel.AddLink{Link: babel.Link{ID: babel.LinkID(id), Local: address(self + 1), Peer: address(peer + 1), Cost: cost, MaxPacket: 1099}})
		}
	}
	deliver()
}
func advance(end time.Duration) {
	for monotonic < end {
		monotonic += 20 * time.Millisecond
		for i := 0; i < 3; i++ {
			tick(i)
		}
		deliver()
	}
}
func routes(index int) []babel.Route {
	if index == 1 {
		return c.routes
	}
	return nodes[index].Snapshot().Routes
}
func check(node, dest int, metric uint16, via int) {
	for _, r := range routes(node) {
		if r.Prefix == prefix(dest+1) && !r.Unreachable && r.Metric == metric && r.Link == babel.LinkID(links[node][via]) {
			return
		}
	}
	panic(fmt.Sprintf("node %d expected destination %d metric %d via %d; routes=%+v", node, dest, metric, via, routes(node)))
}
func remove(a, b int) {
	for _, p := range [][2]int{{a, b}, {b, a}} {
		self, peer := p[0], p[1]
		if self == 1 {
			c.step('d', uint64(monotonic/time.Millisecond), put64(nil, links[self][peer]))
		} else {
			goStep(self, babel.RemoveLink{ID: babel.LinkID(links[self][peer])})
		}
	}
	deliver()
}
func main() {
	if len(os.Args) != 2 {
		panic("pass path to native C babel_driver")
	}
	c = start(os.Args[1])
	defer func() { must(c.input.Close()); must(c.command.Wait()) }()
	c.step('i', 2, nil)
	for _, i := range []int{0, 2} {
		var err error
		nodes[i], err = babel.New(babel.Config{RouterID: babel.RouterID(i + 1), HelloInterval: time.Second, UpdateInterval: 4 * time.Second, MaxLinks: 4, MaxRoutes: 32, MaxSources: 64, MaxRequests: 8, AcceptRoute: func(babel.RouterID, netip.Prefix) bool { return !denied }})
		must(err)
	}
	for i := 0; i < 3; i++ {
		if i == 1 {
			c.step('o', 0, encodePrefix(prefix(i+1)))
		} else {
			goStep(i, babel.Originate{Prefix: prefix(i + 1)})
		}
	}
	connect(0, 1, 128, 1)
	connect(1, 2, 128, 2)
	advance(12 * time.Second)
	check(0, 2, 256, 1)
	check(2, 0, 256, 1)
	check(1, 0, 128, 0)
	check(1, 2, 128, 2)
	fmt.Println("Go → native C → Go transit converged in both directions")
	connect(0, 2, 2048, 3)
	advance(22 * time.Second)
	check(0, 2, 256, 1)
	remove(1, 2)
	advance(42 * time.Second)
	check(0, 2, 2048, 2)
	check(1, 2, 2176, 0)
	fmt.Println("Higher-cost direct path and C-router withdrawal converged without a loop")
	denied = true
	c.step('p', uint64(monotonic/time.Millisecond), nil)
	for _, i := range []int{0, 2} {
		tick(i)
	}
	deliver()
	for i := 0; i < 3; i++ {
		for _, r := range routes(i) {
			if !r.Local && !r.Unreachable {
				panic("authorization expiry retained forwarding")
			}
		}
	}
	denied = false
	c.step('p', uint64(monotonic/time.Millisecond), nil)
	advance(54 * time.Second)
	check(0, 2, 2048, 2)
	fmt.Println("Origin authorization expiry and renewal converged")
}
