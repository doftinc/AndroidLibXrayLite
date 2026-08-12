// Package tuic is a TUIC v5 CLIENT, written against the quic-go fork xray-core already
// depends on (github.com/apernet/quic-go), so adding it to this AAR costs no new module
// and no second QUIC stack.
//
// WHY THIS EXISTS. xray-core has NO TUIC — 0 occurrences of the string in the shipped
// arm64 `libv2jni.so`, against 572 for hysteria and 1019 for reality. So on Android the
// protocol is not "off", it is absent: the core cannot construct that outbound in any
// position, primary or balancer member. The Apple/Windows engines run sing-box, which
// has it, and measure 4047 KB/s on the Krasnodar line — the fastest transport this fleet
// has anywhere. Android was the only platform that could not reach it.
//
// The shape is deliberate: this speaks TUIC to the server and SOCKS5 to xray (see
// socks.go), so xray dials it as an ordinary `socks` outbound and every existing
// mechanism — the balancer, per-outbound byte counters, routing — keeps working with no
// change to the core.
//
// ⚠ NOT A PORT OF sing-quic. That package is written against sagernet's quic-go fork and
// sing's own buffer/metadata/dialer abstractions; pulling it in would drag a SECOND
// quic-go and a sing version that conflicts with the one xray-core pins. What is
// reproduced here is the WIRE PROTOCOL, read off sing-quic and Xray's own server, not the
// code.
package tuic

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	quic "github.com/apernet/quic-go"
)

// Protocol constants. TUIC v5.
const (
	version = 5

	cmdAuthenticate = 0x00
	cmdConnect      = 0x01
	cmdPacket       = 0x02
	cmdDissociate   = 0x03
	cmdHeartbeat    = 0x04

	atypDomain = 0x00
	atypIPv4   = 0x01
	atypIPv6   = 0x02
	atypNone   = 0xff
)

// Config is everything needed to reach one TUIC server.
type Config struct {
	Server   string // IP or hostname to dial
	Port     int
	UUID     string // the device's VPN uuid, as published in /v1/config
	Password string // hex sha256 of the uuid — the fleet's derivation
	SNI      string
	CertPEM  string // PINNED server certificate; empty is REFUSED, never "insecure"
	// UDPTimeout bounds how long an idle UDP association is kept. 0 → 5 minutes.
	UDPTimeout time.Duration

	// Control runs on the raw UDP socket BEFORE it sends anything — on Android this is
	// `VpnService.protect(fd)`.
	//
	// ⚠ WITHOUT IT THIS TRANSPORT EATS ITSELF, and nothing else in the build can supply
	// it. doft_protect.go protects every socket the CORE opens by registering a dialer
	// controller with `internet.RegisterDialerController` — but that seam belongs to
	// xray's dialer, and this client does not use it: quic-go opens its own UDP socket.
	// So once VpnService is up, the packets carrying the tunnel would be routed INTO the
	// tunnel, and the shape on the device is the expensive one this stack keeps
	// producing — "connected, no internet", with a healthy-looking handshake in the log.
	//
	// It cannot be caught off-device either: the CI interop test dials the production
	// node from a Linux box with no VpnService, where an unprotected socket is simply a
	// normal socket and every assertion passes. Nil is correct there and only there.
	Control func(fd uintptr) error
}

// Client owns one QUIC connection to the server and multiplexes every stream over it.
type Client struct {
	cfg       Config
	uuid      [16]byte
	tlsConfig *tls.Config
	quicConf  *quic.Config

	mu     sync.Mutex
	conn   *quic.Conn
	pconn  net.PacketConn
	closed bool

	// UDP associations, keyed by the session id we allocate.
	udpMu     sync.RWMutex
	udpNext   uint16
	udpConns  map[uint16]*udpSession
	packetSeq uint32

	// The largest datagram payload the peer will currently accept, learned from the
	// first refusal rather than guessed. See udpSession.WriteTo.
	maxDatagram atomic.Int64
}

// New validates the config and prepares the TLS/QUIC parameters. It does NOT dial: the
// connection is established lazily on first use and re-established after a failure, so a
// tunnel that starts before the network is up still works.
func New(cfg Config) (*Client, error) {
	if cfg.Server == "" || cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("tuic: bad endpoint %q:%d", cfg.Server, cfg.Port)
	}
	uuid, err := parseUUID(cfg.UUID)
	if err != nil {
		return nil, err
	}
	// ⚠ NO INSECURE FALLBACK, EVER. The node's QUIC certificate is self-signed and shared
	// by hysteria2, tuic and xhttp; pinning it BY VALUE is the only thing between this
	// transport and handing sha256(device uuid) to whatever answers on that port. The
	// Apple engine's TuicConfig refuses to exist without a plausible PEM for the same
	// reason, and this refuses to construct without one.
	if cfg.CertPEM == "" {
		return nil, errors.New("tuic: no pinned certificate")
	}
	pinned, err := pinnedVerifier(cfg.CertPEM)
	if err != nil {
		return nil, err
	}
	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Server
	}
	if cfg.UDPTimeout <= 0 {
		cfg.UDPTimeout = 5 * time.Minute
	}
	return &Client{
		cfg:  cfg,
		uuid: uuid,
		tlsConfig: &tls.Config{
			ServerName: sni,
			// ⚠ ALPN h3, matching what the node's sing-box tuic inbound offers and what
			// the Apple client already sends. A mismatch fails the handshake with an
			// error that names neither side.
			NextProtos: []string{"h3"},
			MinVersion: tls.VersionTLS13,
			// Verification is done by the pin below, not by the system roots — the cert
			// is self-signed, so the roots would reject it and `InsecureSkipVerify`
			// alone would accept anything.
			InsecureSkipVerify:    true,
			VerifyPeerCertificate: pinned,
		},
		quicConf: &quic.Config{
			EnableDatagrams:       true,
			MaxIncomingUniStreams: 1 << 20,
			MaxIdleTimeout:        30 * time.Second,
			KeepAlivePeriod:       10 * time.Second,
		},
		udpConns: make(map[uint16]*udpSession),
	}, nil
}

// pinnedVerifier accepts exactly the certificate whose DER matches the pinned PEM.
func pinnedVerifier(pemStr string) (func([][]byte, [][]*x509.Certificate) error, error) {
	block, err := decodeFirstPEM(pemStr)
	if err != nil {
		return nil, err
	}
	want := sha256.Sum256(block)
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		for _, raw := range rawCerts {
			if sha256.Sum256(raw) == want {
				return nil
			}
		}
		return fmt.Errorf("tuic: server certificate does not match the pin %s",
			hex.EncodeToString(want[:8]))
	}, nil
}

// offer returns a live QUIC connection, dialing and authenticating if needed.
func (c *Client) offer(ctx context.Context) (*quic.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if c.conn != nil {
		select {
		case <-c.conn.Context().Done():
			c.conn = nil
		default:
			return c.conn, nil
		}
	}
	addr := net.JoinHostPort(c.cfg.Server, strconv.Itoa(c.cfg.Port))
	// ⚠ WE OPEN THE SOCKET, NOT quic-go. `quic.DialAddr` calls net.ListenUDP itself and
	// offers no seam to touch the fd first, so it cannot be protected — see Config.Control.
	pc, raddr, err := c.listenUDP(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := quic.Dial(ctx, pc, raddr, c.tlsConfig, c.quicConf)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("tuic: dial %s: %w", addr, err)
	}
	if err := c.authenticate(conn); err != nil {
		_ = conn.CloseWithError(0, "")
		_ = pc.Close()
		return nil, err
	}
	c.conn = conn
	// ⚠ WE OWN IT, SO WE CLOSE IT. quic-go closes a PacketConn it created and leaves one
	// it was handed; without this every re-dial after a network change leaks a UDP socket
	// for the life of the process, on the transport most likely to re-dial.
	old := c.pconn
	c.pconn = pc
	if old != nil {
		_ = old.Close()
	}
	go c.readDatagrams(conn)
	go c.heartbeat(conn)
	return conn, nil
}

// listenUDP opens the local UDP socket the QUIC connection will run on and applies
// Config.Control to it before a single packet leaves.
func (c *Client) listenUDP(ctx context.Context) (net.PacketConn, *net.UDPAddr, error) {
	lc := net.ListenConfig{}
	if c.cfg.Control != nil {
		lc.Control = func(_, _ string, rc syscall.RawConn) error {
			var inner error
			// ⚠ BOTH ERRORS MATTER AND THEY MEAN DIFFERENT THINGS. A failure from
			// rc.Control means we never saw the fd; a failure from the callback means
			// protect() itself refused. Either way the socket would carry the tunnel's
			// own packets into the tunnel, so unlike the core's controller — which
			// tolerates a refusal because it also runs before establish() — this one
			// fails the dial. A TUIC dial that fails is retried by the balancer; a TUIC
			// dial that loops is a dead tunnel that reports itself healthy.
			if err := rc.Control(func(fd uintptr) { inner = c.cfg.Control(fd) }); err != nil {
				return err
			}
			return inner
		}
	}
	// Bind the wildcard address of the right family — the kernel picks the source
	// address and port when the first packet is sent.
	network := "udp4"
	if ip := net.ParseIP(c.cfg.Server); ip != nil && ip.To4() == nil {
		network = "udp6"
	}
	pc, err := lc.ListenPacket(ctx, network, ":0")
	if err != nil {
		return nil, nil, fmt.Errorf("tuic: listen %s: %w", network, err)
	}
	// ⚠ RESOLUTION IS NOT PROTECTED, SO PREFER NOT TO NEED IT. Every endpoint this fleet
	// publishes for tuic is a literal IP, which takes the first branch and performs no
	// lookup at all. A hostname would be resolved by the system resolver over a socket
	// this code does not own — on Android, inside the tunnel — so it is allowed but
	// deliberately narrow: if it ever starts happening, this is the line to find.
	if ip := net.ParseIP(c.cfg.Server); ip != nil {
		return pc, &net.UDPAddr{IP: ip, Port: c.cfg.Port}, nil
	}
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(c.cfg.Server, strconv.Itoa(c.cfg.Port)))
	if err != nil {
		_ = pc.Close()
		return nil, nil, fmt.Errorf("tuic: resolve %s: %w", c.cfg.Server, err)
	}
	return pc, raddr, nil
}

// authenticate performs the TUIC v5 handshake on a fresh unidirectional stream.
//
// ⚠ THE TOKEN IS DERIVED FROM THE TLS SESSION, NOT SENT. RFC 5705 exported keying
// material with the raw 16 uuid bytes as the label and the password as the context. A
// replayed token is worthless on another connection, which is the property the design
// is for — and it is why the password never travels.
func (c *Client) authenticate(conn *quic.Conn) error {
	stream, err := conn.OpenUniStream()
	if err != nil {
		return fmt.Errorf("tuic: open auth stream: %w", err)
	}
	defer stream.Close()
	// ⚠ ExportKeyingMaterial is a POINTER method, and ConnectionState() returns a value —
	// so it has to land in an addressable variable first. Calling it inline does not
	// compile, which is a kinder failure than most of what this handshake can do.
	tlsState := conn.ConnectionState().TLS
	token, err := tlsState.ExportKeyingMaterial(
		string(c.uuid[:]), []byte(c.cfg.Password), 32)
	if err != nil {
		return fmt.Errorf("tuic: export keying material: %w", err)
	}
	buf := make([]byte, 0, 2+16+32)
	buf = append(buf, version, cmdAuthenticate)
	buf = append(buf, c.uuid[:]...)
	buf = append(buf, token...)
	if _, err := stream.Write(buf); err != nil {
		return fmt.Errorf("tuic: write auth: %w", err)
	}
	return nil
}

func (c *Client) heartbeat(conn *quic.Conn) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-conn.Context().Done():
			return
		case <-t.C:
			if err := conn.SendDatagram([]byte{version, cmdHeartbeat}); err != nil {
				return
			}
		}
	}
}

// DialTCP opens a relayed TCP connection. The CONNECT header is written lazily with the
// first payload write, exactly as the reference client does — one round trip instead of
// two, and it keeps a stream that is opened and never used from reaching the server.
func (c *Client) DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("tuic: open stream: %w", err)
	}
	return &tcpConn{stream: stream, host: host, port: port}, nil
}

type tcpConn struct {
	stream  *quic.Stream
	host    string
	port    uint16
	written bool
}

func (t *tcpConn) Read(b []byte) (int, error) { return t.stream.Read(b) }

func (t *tcpConn) Write(b []byte) (int, error) {
	if !t.written {
		head := make([]byte, 0, 2+len(t.host)+8+len(b))
		head = append(head, version, cmdConnect)
		head = appendAddr(head, t.host, t.port)
		head = append(head, b...)
		if _, err := t.stream.Write(head); err != nil {
			return 0, err
		}
		t.written = true
		return len(b), nil
	}
	return t.stream.Write(b)
}

func (t *tcpConn) Close() error {
	t.stream.CancelRead(0)
	err := t.stream.Close()
	// quic-go's Close does not unblock a Write parked on flow control; a deadline in the
	// past does, and buffered data plus the FIN are unaffected.
	_ = t.stream.SetWriteDeadline(time.Now())
	return err
}

func (t *tcpConn) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (t *tcpConn) RemoteAddr() net.Addr { return &net.TCPAddr{} }

func (t *tcpConn) SetDeadline(d time.Time) error      { return t.stream.SetDeadline(d) }
func (t *tcpConn) SetReadDeadline(d time.Time) error  { return t.stream.SetReadDeadline(d) }
func (t *tcpConn) SetWriteDeadline(d time.Time) error { return t.stream.SetWriteDeadline(d) }

// Close tears down the QUIC connection and every association on it.
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	conn := c.conn
	pc := c.pconn
	c.conn, c.pconn = nil, nil
	c.mu.Unlock()
	c.udpMu.Lock()
	for _, s := range c.udpConns {
		s.close()
	}
	c.udpConns = make(map[uint16]*udpSession)
	c.udpMu.Unlock()
	var err error
	if conn != nil {
		err = conn.CloseWithError(0, "")
	}
	// After the QUIC teardown, not before: closing the socket first turns the CONNECTION_CLOSE
	// frame into a write on a closed fd, so the server learns of the departure only by idle
	// timeout and holds the association open for 30 more seconds.
	if pc != nil {
		_ = pc.Close()
	}
	return err
}

// ── address codec ────────────────────────────────────────────────────────────

func appendAddr(dst []byte, host string, port uint16) []byte {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			dst = append(dst, atypIPv4)
			dst = append(dst, v4...)
		} else {
			dst = append(dst, atypIPv6)
			dst = append(dst, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			host = host[:255]
		}
		dst = append(dst, atypDomain, byte(len(host)))
		dst = append(dst, host...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	return append(dst, p[:]...)
}

// readAddr parses one TUIC address from b, returning it and the number of bytes consumed.
func readAddr(b []byte) (host string, port uint16, n int, err error) {
	if len(b) < 1 {
		return "", 0, 0, io.ErrUnexpectedEOF
	}
	switch b[0] {
	case atypNone:
		return "", 0, 1, nil
	case atypDomain:
		if len(b) < 2 {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		return string(b[2 : 2+l]), binary.BigEndian.Uint16(b[2+l:]), 2 + l + 2, nil
	case atypIPv4:
		if len(b) < 1+4+2 {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		return net.IP(b[1:5]).String(), binary.BigEndian.Uint16(b[5:]), 7, nil
	case atypIPv6:
		if len(b) < 1+16+2 {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		return net.IP(b[1:17]).String(), binary.BigEndian.Uint16(b[17:]), 19, nil
	default:
		return "", 0, 0, fmt.Errorf("tuic: unknown address type 0x%02x", b[0])
	}
}

func addrLen(host string) int {
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return 1 + 4 + 2
		}
		return 1 + 16 + 2
	}
	return 1 + 1 + len(host) + 2
}

func parseUUID(s string) ([16]byte, error) {
	var out [16]byte
	clean := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			clean = append(clean, s[i])
		}
	}
	if len(clean) != 32 {
		return out, fmt.Errorf("tuic: bad uuid %q", s)
	}
	raw, err := hex.DecodeString(string(clean))
	if err != nil {
		return out, fmt.Errorf("tuic: bad uuid %q: %w", s, err)
	}
	copy(out[:], raw)
	return out, nil
}
