package tuic

// UDP relay over TUIC's `Packet` command, carried in QUIC datagrams (the `native` UDP
// relay mode).
//
// ⚠ UDP IS NOT OPTIONAL HERE, and it is worth saying why since it is most of this file.
// On Android the tunnel is a TUN device: tun2socks hands xray every flow the device
// makes, and xray routes them all through the selected outbound. A `socks` outbound that
// cannot do UDP ASSOCIATE means DNS fails the moment this member is picked — the tunnel
// "connects" and nothing resolves, which is the failure shape this project has already
// paid for twice.
//
// ⚠ FRAGMENTATION IS IMPLEMENTED, NOT SKIPPED. QUIC datagrams cannot exceed the path MTU,
// while a UDP payload may be up to 64 KB. The reference implementation splits across
// `fragmentTotal`/`fragmentID` and the SERVER reassembles; a client that ignores this and
// sends one oversized datagram gets a silent `SendDatagram` error and drops the packet.
// DNS would still work — which is exactly what makes the omission dangerous, because the
// tunnel looks healthy while anything with a big datagram is broken.

import (
	"context"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	quic "github.com/apernet/quic-go"
)

// packetHeaderFixed is the size of a Packet header up to (but excluding) the address:
// version, command, sessionID(2), packetID(2), fragTotal, fragID, size(2).
const packetHeaderFixed = 2 + 2 + 2 + 1 + 1 + 2

type inboundPacket struct {
	host string
	port uint16
	data []byte
}

// udpSession is one association: xray asks for one, we allocate a session id, and every
// datagram carrying that id is routed back to it.
type udpSession struct {
	client    *Client
	id        uint16
	in        chan inboundPacket
	closeOnce sync.Once
	done      chan struct{}

	// Reassembly buffers, keyed by packet id. Bounded: a peer that never completes a
	// fragment set must not be able to grow this without limit.
	fragMu sync.Mutex
	frags  map[uint16]*fragSet
}

type fragSet struct {
	parts    [][]byte
	got      int
	total    uint8
	host     string
	port     uint16
	deadline time.Time
}

const maxPendingFragSets = 32

// OpenUDP allocates a new association.
func (c *Client) OpenUDP() (*udpSession, error) {
	c.udpMu.Lock()
	defer c.udpMu.Unlock()
	if len(c.udpConns) >= 1024 {
		return nil, errors.New("tuic: too many UDP associations")
	}
	c.udpNext++
	id := c.udpNext
	s := &udpSession{
		client: c,
		id:     id,
		in:     make(chan inboundPacket, 64),
		done:   make(chan struct{}),
		frags:  make(map[uint16]*fragSet),
	}
	c.udpConns[id] = s
	return s, nil
}

func (s *udpSession) close() {
	s.closeOnce.Do(func() { close(s.done) })
}

// Close removes the association and tells the server to drop its state.
func (s *udpSession) Close() error {
	s.client.udpMu.Lock()
	delete(s.client.udpConns, s.id)
	s.client.udpMu.Unlock()
	s.close()
	// Best effort: the connection may already be gone, and a failure here costs the
	// server one idle association that its own timeout reaps.
	s.client.mu.Lock()
	conn := s.client.conn
	s.client.mu.Unlock()
	if conn != nil {
		var b [4]byte
		b[0], b[1] = version, cmdDissociate
		binary.BigEndian.PutUint16(b[2:], s.id)
		_ = conn.SendDatagram(b[:])
	}
	return nil
}

// WriteTo relays one UDP payload to host:port, fragmenting if the datagram would not fit.
func (s *udpSession) WriteTo(payload []byte, host string, port uint16) error {
	conn, err := s.client.offer(context.Background())
	if err != nil {
		return err
	}
	maxDatagram := 1200
	if m := conn.ConnectionState().MaxDatagramSize; m > 0 {
		maxDatagram = int(m)
	}
	head := packetHeaderFixed + addrLen(host)
	room := maxDatagram - head
	if room <= 0 {
		return fmt.Errorf("tuic: datagram budget %d too small for a %d-byte header", maxDatagram, head)
	}

	s.client.udpMu.Lock()
	s.client.packetSeq++
	pktID := uint16(s.client.packetSeq)
	s.client.udpMu.Unlock()

	total := (len(payload) + room - 1) / room
	if total == 0 {
		total = 1 // a zero-length UDP payload is legal and must still be relayed
	}
	if total > 255 {
		// 255 * ~1150 bytes is far past any real datagram; refusing beats sending a set
		// the peer can never reassemble.
		return fmt.Errorf("tuic: payload %d bytes needs %d fragments", len(payload), total)
	}
	for i := 0; i < total; i++ {
		start := i * room
		end := start + room
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[start:end]
		buf := make([]byte, 0, head+len(chunk))
		buf = append(buf, version, cmdPacket)
		buf = binary.BigEndian.AppendUint16(buf, s.id)
		buf = binary.BigEndian.AppendUint16(buf, pktID)
		buf = append(buf, byte(total), byte(i))
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(chunk)))
		buf = appendAddr(buf, host, port)
		buf = append(buf, chunk...)
		if err := conn.SendDatagram(buf); err != nil {
			return err
		}
	}
	return nil
}

// ReadFrom returns the next relayed reply, or an error once the session is closed.
func (s *udpSession) ReadFrom(deadline time.Time) (inboundPacket, error) {
	var timer <-chan time.Time
	if !deadline.IsZero() {
		t := time.NewTimer(time.Until(deadline))
		defer t.Stop()
		timer = t.C
	}
	select {
	case p := <-s.in:
		return p, nil
	case <-s.done:
		return inboundPacket{}, net.ErrClosed
	case <-timer:
		return inboundPacket{}, errTimeout{}
	}
}

type errTimeout struct{}

func (errTimeout) Error() string { return "tuic: read timeout" }
func (errTimeout) Timeout() bool { return true }

// readDatagrams is the single reader for the connection: it demultiplexes every inbound
// Packet to its association and answers heartbeats by ignoring them.
func (c *Client) readDatagrams(conn *quic.Conn) {
	for {
		msg, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		if len(msg) < 2 || msg[0] != version {
			continue
		}
		switch msg[1] {
		case cmdHeartbeat:
			continue
		case cmdPacket:
			c.handlePacket(msg[2:])
		}
	}
}

func (c *Client) handlePacket(b []byte) {
	if len(b) < packetHeaderFixed-2 {
		return
	}
	sessionID := binary.BigEndian.Uint16(b[0:2])
	packetID := binary.BigEndian.Uint16(b[2:4])
	fragTotal := b[4]
	fragID := b[5]
	size := binary.BigEndian.Uint16(b[6:8])
	host, port, n, err := readAddr(b[8:])
	if err != nil {
		return
	}
	data := b[8+n:]
	if len(data) != int(size) {
		return
	}
	c.udpMu.RLock()
	s := c.udpConns[sessionID]
	c.udpMu.RUnlock()
	if s == nil {
		return
	}
	if fragTotal <= 1 {
		s.deliver(inboundPacket{host: host, port: port, data: append([]byte(nil), data...)})
		return
	}
	s.reassemble(packetID, fragTotal, fragID, host, port, data)
}

func (s *udpSession) reassemble(pktID uint16, total, id uint8, host string, port uint16, data []byte) {
	if id >= total {
		return
	}
	s.fragMu.Lock()
	now := time.Now()
	// Reap abandoned sets before admitting a new one — a peer that starts fragment sets
	// and never finishes them is otherwise an unbounded allocation.
	for k, v := range s.frags {
		if now.After(v.deadline) {
			delete(s.frags, k)
		}
	}
	set := s.frags[pktID]
	if set == nil {
		if len(s.frags) >= maxPendingFragSets {
			s.fragMu.Unlock()
			return
		}
		set = &fragSet{
			parts:    make([][]byte, total),
			total:    total,
			host:     host,
			port:     port,
			deadline: now.Add(10 * time.Second),
		}
		s.frags[pktID] = set
	}
	if set.total != total || set.parts[id] != nil {
		s.fragMu.Unlock()
		return
	}
	set.parts[id] = append([]byte(nil), data...)
	set.got++
	if set.got < int(set.total) {
		s.fragMu.Unlock()
		return
	}
	delete(s.frags, pktID)
	s.fragMu.Unlock()

	whole := make([]byte, 0, 1500)
	for _, p := range set.parts {
		whole = append(whole, p...)
	}
	s.deliver(inboundPacket{host: set.host, port: set.port, data: whole})
}

// deliver never blocks: a stalled consumer must cost its own packets, not the shared
// datagram reader that every other association depends on.
func (s *udpSession) deliver(p inboundPacket) {
	select {
	case s.in <- p:
	default:
	}
}

// decodeFirstPEM returns the DER bytes of the first CERTIFICATE block in a PEM string.
func decodeFirstPEM(s string) ([]byte, error) {
	rest := []byte(s)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("tuic: no PEM certificate block found")
		}
		if block.Type == "CERTIFICATE" {
			return block.Bytes, nil
		}
	}
}
