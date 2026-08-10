package tuic

// A minimal SOCKS5 server that fronts the TUIC client on 127.0.0.1.
//
// WHY A SOCKS HOP AND NOT A NEW XRAY OUTBOUND. Registering `tuic` as a first-class xray
// protocol would mean forking xray-core itself: the JSON config loader maps protocol
// names through a package-private `ConfigCreatorCache` built at init
// (`infra/conf/xray.go`), with no exported way to add one from outside the module. A
// local SOCKS5 hop needs no core change at all — xray dials `{"protocol":"socks",
// "settings":{"servers":[{"address":"127.0.0.1","port":N}]}}`, which its own parser has
// always understood, and everything downstream (the balancer, per-outbound byte counters
// the plugin reads, routing rules) keeps working untouched.
//
// The cost is one loopback hop per connection. On a transport measured at 4047 KB/s that
// is not the bottleneck, and it buys a core we do not have to fork.
//
// ⚠ BOUND TO 127.0.0.1 ONLY, and it must stay that way. This is an UNAUTHENTICATED proxy
// into the user's tunnel; on 0.0.0.0 it would be an open relay for every app on the
// device and for anything else on the same Wi-Fi.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	socksVersion = 0x05
	cmdTCPConnect = 0x01
	cmdUDPAssoc   = 0x03

	repSuccess         = 0x00
	repGeneralFailure  = 0x01
	repCmdNotSupported = 0x07
)

// Server is the local SOCKS5 listener plus the UDP relay socket that a UDP ASSOCIATE
// client sends its datagrams to.
type Server struct {
	client *Client

	tcpLn net.Listener
	udpLn *net.UDPConn

	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// Listen starts the SOCKS5 server on 127.0.0.1:port. Port 0 picks a free one; the chosen
// address is available from Addr().
func Listen(c *Client, port int) (*Server, error) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return nil, fmt.Errorf("tuic-socks: listen tcp: %w", err)
	}
	// ⚠ THE UDP SOCKET SHARES THE TCP PORT ON PURPOSE. A SOCKS5 client is told where to
	// send datagrams in the ASSOCIATE reply, and xray honours it — but reusing the port
	// keeps the two halves inseparable in logs, in `ss` output and in a firewall rule, and
	// removes a second number that could drift.
	tcpAddr := tcpLn.Addr().(*net.TCPAddr)
	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: tcpAddr.Port})
	if err != nil {
		tcpLn.Close()
		return nil, fmt.Errorf("tuic-socks: listen udp: %w", err)
	}
	s := &Server{client: c, tcpLn: tcpLn, udpLn: udpLn, done: make(chan struct{})}
	s.wg.Add(2)
	go func() { defer s.wg.Done(); s.acceptLoop() }()
	go func() { defer s.wg.Done(); s.udpLoop() }()
	return s, nil
}

// Addr is the loopback endpoint xray should be pointed at.
func (s *Server) Addr() string { return s.tcpLn.Addr().String() }

// Port is the same thing, for building the xray outbound.
func (s *Server) Port() int { return s.tcpLn.Addr().(*net.TCPAddr).Port }

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.tcpLn.Close()
		s.udpLn.Close()
	})
	s.wg.Wait()
	return s.client.Close()
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.tcpLn.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			// A transient accept error must not kill the listener for the whole session.
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	// The whole negotiation has to finish promptly; a half-open handshake otherwise
	// holds a goroutine and a socket for as long as the peer likes.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	if head[0] != socksVersion {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	// No authentication: the listener is loopback-only (see the file header).
	if _, err := conn.Write([]byte{socksVersion, 0x00}); err != nil {
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[0] != socksVersion {
		return
	}
	host, port, err := readSocksAddr(conn, req[3])
	if err != nil {
		return
	}

	switch req[1] {
	case cmdTCPConnect:
		s.handleConnect(conn, host, port)
	case cmdUDPAssoc:
		s.handleAssociate(conn)
	default:
		_ = writeSocksReply(conn, repCmdNotSupported, net.IPv4zero, 0)
	}
}

func (s *Server) handleConnect(conn net.Conn, host string, port uint16) {
	remote, err := s.client.DialTCP(context.Background(), host, port)
	if err != nil {
		log.Printf("doft-tuic: connect %s:%d failed: %v", host, port, err)
		_ = writeSocksReply(conn, repGeneralFailure, net.IPv4zero, 0)
		return
	}
	defer remote.Close()
	if err := writeSocksReply(conn, repSuccess, net.IPv4zero, 0); err != nil {
		return
	}
	// The handshake deadline must go, or a long-lived tunnelled connection dies at 30 s.
	_ = conn.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(remote, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, remote); done <- struct{}{} }()
	<-done
}

// handleAssociate answers a UDP ASSOCIATE and then holds the TCP control connection open:
// per RFC 1928 the association lives exactly as long as this connection, which is how
// xray signals that it is finished with it.
func (s *Server) handleAssociate(conn net.Conn) {
	addr := s.udpLn.LocalAddr().(*net.UDPAddr)
	if err := writeSocksReply(conn, repSuccess, addr.IP, uint16(addr.Port)); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	// Block until the peer closes. Reads return immediately on close; anything the peer
	// actually sends on the control connection is not part of the protocol and ignored.
	buf := make([]byte, 256)
	for {
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}

// udpAssoc pairs one client datagram source with one TUIC association.
type udpAssoc struct {
	session *udpSession
	last    time.Time
}

// udpLoop relays datagrams both ways. Each distinct client source address gets its own
// TUIC association, so replies can be routed back to the right sender.
func (s *Server) udpLoop() {
	assocs := make(map[string]*udpAssoc)
	var mu sync.Mutex

	// Reap idle associations; without this a long session leaks one per DNS client port.
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-t.C:
				mu.Lock()
				for k, a := range assocs {
					if time.Since(a.last) > s.client.cfg.UDPTimeout {
						a.session.Close()
						delete(assocs, k)
					}
				}
				mu.Unlock()
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, src, err := s.udpLn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			continue
		}
		host, port, payload, err := parseUDPRequest(buf[:n])
		if err != nil {
			continue
		}
		key := src.String()
		mu.Lock()
		a := assocs[key]
		if a == nil {
			sess, oerr := s.client.OpenUDP()
			if oerr != nil {
				mu.Unlock()
				continue
			}
			a = &udpAssoc{session: sess}
			assocs[key] = a
			go s.udpReplies(sess, src)
		}
		a.last = time.Now()
		sess := a.session
		mu.Unlock()

		if err := sess.WriteTo(payload, host, port); err != nil {
			log.Printf("doft-tuic: udp relay to %s:%d failed: %v", host, port, err)
		}
	}
}

func (s *Server) udpReplies(sess *udpSession, dst *net.UDPAddr) {
	for {
		pkt, err := sess.ReadFrom(time.Time{})
		if err != nil {
			return
		}
		out := make([]byte, 0, 10+len(pkt.data))
		out = append(out, 0x00, 0x00, 0x00) // RSV RSV FRAG
		out = appendSocksAddr(out, pkt.host, pkt.port)
		out = append(out, pkt.data...)
		if _, err := s.udpLn.WriteToUDP(out, dst); err != nil {
			return
		}
	}
}

// ── SOCKS5 wire helpers ──────────────────────────────────────────────────────

func readSocksAddr(r io.Reader, atyp byte) (string, uint16, error) {
	switch atyp {
	case 0x01:
		b := make([]byte, 4+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		return net.IP(b[:4]).String(), binary.BigEndian.Uint16(b[4:]), nil
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", 0, err
		}
		b := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		return string(b[:l[0]]), binary.BigEndian.Uint16(b[l[0]:]), nil
	case 0x04:
		b := make([]byte, 16+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		return net.IP(b[:16]).String(), binary.BigEndian.Uint16(b[16:]), nil
	default:
		return "", 0, fmt.Errorf("tuic-socks: unknown address type 0x%02x", atyp)
	}
}

func appendSocksAddr(dst []byte, host string, port uint16) []byte {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			dst = append(dst, 0x01)
			dst = append(dst, v4...)
		} else {
			dst = append(dst, 0x04)
			dst = append(dst, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			host = host[:255]
		}
		dst = append(dst, 0x03, byte(len(host)))
		dst = append(dst, host...)
	}
	return binary.BigEndian.AppendUint16(dst, port)
}

func writeSocksReply(w io.Writer, rep byte, bnd net.IP, port uint16) error {
	out := []byte{socksVersion, rep, 0x00}
	if v4 := bnd.To4(); v4 != nil {
		out = append(out, 0x01)
		out = append(out, v4...)
	} else {
		out = append(out, 0x04)
		out = append(out, bnd.To16()...)
	}
	out = binary.BigEndian.AppendUint16(out, port)
	_, err := w.Write(out)
	return err
}

// parseUDPRequest unwraps the SOCKS5 UDP header: RSV(2) FRAG(1) ADDR PORT DATA.
func parseUDPRequest(b []byte) (string, uint16, []byte, error) {
	if len(b) < 5 {
		return "", 0, nil, io.ErrUnexpectedEOF
	}
	// ⚠ FRAGMENTED SOCKS5 DATAGRAMS ARE REFUSED, not silently forwarded. FRAG != 0 means
	// the client split one payload across datagrams and expects US to reassemble; passing
	// a fragment through as a whole packet would corrupt it in a way that looks like
	// packet loss. No mainstream client uses this, xray included.
	if b[2] != 0 {
		return "", 0, nil, errors.New("tuic-socks: fragmented UDP request")
	}
	var host string
	var port uint16
	var n int
	switch b[3] {
	case 0x01:
		if len(b) < 4+4+2 {
			return "", 0, nil, io.ErrUnexpectedEOF
		}
		host, port, n = net.IP(b[4:8]).String(), binary.BigEndian.Uint16(b[8:10]), 10
	case 0x03:
		l := int(b[4])
		if len(b) < 5+l+2 {
			return "", 0, nil, io.ErrUnexpectedEOF
		}
		host, port, n = string(b[5:5+l]), binary.BigEndian.Uint16(b[5+l:]), 5+l+2
	case 0x04:
		if len(b) < 4+16+2 {
			return "", 0, nil, io.ErrUnexpectedEOF
		}
		host, port, n = net.IP(b[4:20]).String(), binary.BigEndian.Uint16(b[20:22]), 22
	default:
		return "", 0, nil, fmt.Errorf("tuic-socks: unknown address type 0x%02x", b[3])
	}
	return host, port, b[n:], nil
}
