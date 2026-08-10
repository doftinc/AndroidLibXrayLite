// Command interop dials a REAL production TUIC endpoint through the client in
// doft/tuic and pulls a real URL through it.
//
// WHY THIS EXISTS. Everything else about this transport can be green while it is still
// wrong: the Go compiles, `go vet` passes, the AAR builds, the Java surface matches — and
// the first byte on the wire is rejected because the auth token, the address encoding or
// the ALPN is off by one field. A protocol implemented from a reading of somebody else's
// code is not verified until a server that did not write it answers.
//
// It runs on a Linux runner, not a phone, and that is the point: it isolates the PROTOCOL
// from the Android integration, so a failure here is unambiguous.
//
//	go run ./doft/interop -server 204.3.207.89 -port 8446 -uuid <registered-uuid> \
//	  -sni www.bing.com -url http://cp.cloudflare.com/generate_204
//
// The password is derived, never passed: hex sha256 of the uuid, the fleet's own rule
// (lib/ios_tunnel_bridge.dart builds the tuic member the same way). The certificate is
// fetched from the PUBLIC /v1/config, so no secret is needed to run this beyond a
// registered device uuid.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/2dust/AndroidLibXrayLite/doft/tuic"
)

func main() {
	var (
		server  = flag.String("server", "", "TUIC server address")
		port    = flag.Int("port", 8446, "TUIC server port")
		uuidStr = flag.String("uuid", "", "a REGISTERED device uuid")
		sni     = flag.String("sni", "www.bing.com", "TLS server name")
		cert    = flag.String("cert", "", "pinned certificate PEM (default: fetch from -config)")
		cfgURL  = flag.String("config", "https://49u55rs537.execute-api.us-east-1.amazonaws.com/v1/config", "where to read the tuic endpoint from")
		target  = flag.String("url", "http://cp.cloudflare.com/generate_204", "URL to fetch through the tunnel")
		udpTest = flag.Bool("udp", true, "also relay a DNS query, to exercise the datagram path")
	)
	flag.Parse()
	if *uuidStr == "" {
		fail("-uuid is required and must be REGISTERED (POST /v1/session mints one)")
	}

	pem := *cert
	if pem == "" || *server == "" {
		s, p, sn, c := fromConfig(*cfgURL)
		if *server == "" {
			*server, *port = s, p
		}
		if *sni == "" {
			*sni = sn
		}
		if pem == "" {
			pem = c
		}
	}
	if pem == "" {
		fail("no pinned certificate: pass -cert or let -config supply it")
	}
	sum := sha256.Sum256([]byte(*uuidStr))
	password := hex.EncodeToString(sum[:])

	fmt.Printf("interop: %s:%d sni=%s uuid=%s…\n", *server, *port, *sni, (*uuidStr)[:8])

	client, err := tuic.New(tuic.Config{
		Server: *server, Port: *port, UUID: *uuidStr,
		Password: password, SNI: *sni, CertPEM: pem,
	})
	if err != nil {
		fail("client: %v", err)
	}
	// ── stage 0: dial the TUIC layer DIRECTLY, before any SOCKS5 is involved ──
	// ⚠ WITHOUT THIS THE FAILURE HAS NO NAME. Going straight to the SOCKS5 path turns
	// every possible fault — QUIC handshake, certificate pin, auth token, address
	// encoding — into one `EOF` from the HTTP client, because OpenStream succeeds
	// locally and the CONNECT header does not travel until the first write. Dialling the
	// client directly puts each stage on its own line.
	direct, err := client.DialTCP(context.Background(), "cp.cloudflare.com", 80)
	if err != nil {
		fail("QUIC/auth: %v", err)
	}
	fmt.Println("interop: QUIC connected, certificate pin matched, auth written")
	_ = direct.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := direct.Write([]byte("GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nConnection: close\r\n\r\n")); err != nil {
		fail("relay write: %v", err)
	}
	head := make([]byte, 64)
	n0, err := direct.Read(head)
	if err != nil && n0 == 0 {
		fail("relay read (the server accepted the stream and then said nothing — "+
			"auth rejected, or the CONNECT header is malformed): %v", err)
	}
	fmt.Printf("interop: direct relay OK — %q\n", strings.TrimSpace(string(head[:n0])))
	direct.Close()

	srv, err := tuic.Listen(client, 0)
	if err != nil {
		fail("listen: %v", err)
	}
	defer srv.Close()
	fmt.Printf("interop: local socks5 on %s\n", srv.Addr())

	// ── TCP: fetch a URL through the relay ────────────────────────────────────
	proxyURL, _ := url.Parse("socks5://" + srv.Addr())
	httpClient := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   25 * time.Second,
	}
	start := time.Now()
	resp, err := httpClient.Get(*target)
	if err != nil {
		fail("TCP relay: %v", err)
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	fmt.Printf("interop: TCP OK — %s → %d, %d bytes in %s\n",
		*target, resp.StatusCode, n, time.Since(start).Round(time.Millisecond))
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		fail("TCP relay: unexpected status %s", resp.Status)
	}

	// ── UDP: relay one DNS query, which is what actually breaks if the datagram
	//        path is wrong, and breaks INVISIBLY because TCP keeps working.
	if *udpTest {
		if err := dnsThroughSocks(srv.Addr()); err != nil {
			fail("UDP relay: %v", err)
		}
		fmt.Println("interop: UDP OK — DNS answered through the datagram path")
	}
	fmt.Println("interop: PASS")
}

// dnsThroughSocks sends an A query for example.com over SOCKS5 UDP ASSOCIATE.
func dnsThroughSocks(socksAddr string) error {
	ctrl, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		return err
	}
	defer ctrl.Close()
	_ = ctrl.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := ctrl.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, buf); err != nil {
		return err
	}
	// UDP ASSOCIATE with an all-zero requested address: we do not know our source port
	// until we send, which is the normal case and what every real client does.
	if _, err := ctrl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(ctrl, rep); err != nil {
		return err
	}
	if rep[1] != 0 {
		return fmt.Errorf("associate refused: rep=0x%02x", rep[1])
	}
	relay := net.JoinHostPort(net.IP(rep[4:8]).String(), strconv.Itoa(int(rep[8])<<8|int(rep[9])))

	uc, err := net.Dial("udp", relay)
	if err != nil {
		return err
	}
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(15 * time.Second))

	// SOCKS5 UDP header (RSV RSV FRAG ATYP ADDR PORT) + a minimal DNS query.
	pkt := []byte{0, 0, 0, 1, 1, 1, 1, 1, 0, 53}
	pkt = append(pkt, dnsQuery("example.com")...)
	if _, err := uc.Write(pkt); err != nil {
		return err
	}
	in := make([]byte, 1500)
	n, err := uc.Read(in)
	if err != nil {
		return err
	}
	if n < 10+12 {
		return fmt.Errorf("short reply: %d bytes", n)
	}
	// Byte 3 of the DNS header carries QR|Opcode|AA|TC|RD; the top bit must be a response.
	if in[10+2]&0x80 == 0 {
		return fmt.Errorf("not a DNS response")
	}
	return nil
}

func dnsQuery(name string) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

func fromConfig(u string) (server string, port int, sni string, cert string) {
	resp, err := http.Get(u)
	if err != nil {
		fail("read %s: %v", u, err)
	}
	defer resp.Body.Close()
	var cfg struct {
		Tuic struct {
			Server string `json:"server"`
			Port   int    `json:"port"`
			SNI    string `json:"sni"`
			Cert   string `json:"cert"`
		} `json:"tuic"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		fail("decode %s: %v", u, err)
	}
	if cfg.Tuic.Server == "" {
		fail("%s serves no tuic endpoint (a cc= filter, or the min_build gate)", u)
	}
	return cfg.Tuic.Server, cfg.Tuic.Port, cfg.Tuic.SNI, cfg.Tuic.Cert
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "interop: FAIL — "+format+"\n", a...)
	os.Exit(1)
}
