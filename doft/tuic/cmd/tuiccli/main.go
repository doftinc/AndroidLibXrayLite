// doft-tuic-cli — the AAR's OWN TUIC client, off the device.
//
// WHY THIS EXISTS. `ops/ru-probe/measure-matrix.py` measures every transport on both
// engines, and TUIC-on-Android was the one cell it had to leave blank: xray-core has no
// TUIC in any version, so Android reaches it through THIS package compiled into our AAR,
// behind a loopback SOCKS5 listener. The rig could dial sing-box's TUIC and call it
// "TUIC", which is a statement about a different implementation.
//
// This binary is the same two calls the Java side makes — `tuic.New` then `tuic.Listen`
// — so a probe pointed at the port it prints is measuring the code Android actually runs,
// including the loopback SOCKS5 hop, whose UDP path had never been measured at all.
//
// ⚠ WHAT IT STILL DOES NOT COVER, and the difference matters. `StartTuic` passes
// `Control: protectSocket` — VpnService.protect(fd) — because quic-go opens its own UDP
// socket outside xray's dialer, and without it the packets carrying the tunnel are routed
// INTO the tunnel. There is no VpnService here, so that field is nil and cannot be
// exercised off-device. This measures the protocol, the SOCKS5 front end and the UDP
// relay; it does not and cannot measure socket protection.
//
//	go run ./doft/tuic/cmd/tuiccli -config tuic.json
//	{"server":"…","port":8446,"uuid":"…","password":"…","sni":"…","cert":"-----BEGIN…"}
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/2dust/AndroidLibXrayLite/doft/tuic"
)

type request struct {
	Server        string `json:"server"`
	Port          int    `json:"port"`
	UUID          string `json:"uuid"`
	Password      string `json:"password"`
	SNI           string `json:"sni"`
	Cert          string `json:"cert"`
	ListenPort    int    `json:"listen_port"`
	UDPTimeoutSec int    `json:"udp_timeout_sec"`
}

func main() {
	path := flag.String("config", "", "path to the same JSON the Dart side hands StartTuic")
	// ⚠ WITHOUT THIS, ON THE ONE VANTAGE THAT MATTERS, THIS BINARY MEASURES NOTHING.
	// quic-go opens its OWN UDP socket, outside xray's dialer — which is the whole reason
	// `Control` exists on Android. On the operator's Mac the tunnel under test is usually
	// UP, so that socket takes the default route and dials the node THROUGH the node:
	// first run from Krasnodar returned 0 KB/s, udp DEAD, 0/36 fan-out and 0 of 500
	// datagrams, and none of it was about TUIC. Pinning the socket to the physical NIC is
	// the same discipline every engine config in this rig already uses
	// (`bind_interface` / xray `sockopt.interface`), applied through the same seam
	// Android uses for VpnService.protect.
	iface := flag.String("bind-interface", "",
		"pin the QUIC socket to this NIC (en0) — required when a tunnel is up locally")
	flag.Parse()
	if *path == "" {
		fmt.Fprintln(os.Stderr, "-config is required")
		os.Exit(2)
	}
	// ⚠ READ FROM A FILE, NEVER FROM A FLAG. The password is sha256 of the device's VPN
	// uuid; a flag puts it in `ps` output for every process on the box.
	blob, err := os.ReadFile(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(2)
	}
	var req request
	if err := json.Unmarshal(blob, &req); err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(2)
	}
	client, err := tuic.New(tuic.Config{
		Server:     req.Server,
		Port:       req.Port,
		UUID:       req.UUID,
		Password:   req.Password,
		SNI:        req.SNI,
		CertPEM:    req.Cert,
		UDPTimeout: time.Duration(req.UDPTimeoutSec) * time.Second,
		// The SAME seam Android hands VpnService.protect. Here it pins the socket to a
		// NIC instead; nil when no interface is asked for, which is correct on a vantage
		// with no tunnel of its own.
		Control: bindToInterface(*iface),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "tuic: %v\n", err)
		os.Exit(1)
	}
	srv, err := tuic.Listen(client, req.ListenPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		_ = client.Close()
		os.Exit(1)
	}
	// The port, on its own line, first — a caller scripts against this.
	fmt.Printf("%d\n", srv.Port())
	os.Stdout.Sync()
	fmt.Fprintf(os.Stderr, "doft-tuic-cli: socks5 on %s -> %s:%d\n", srv.Addr(), req.Server, req.Port)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	_ = srv.Close()
	_ = client.Close()
}

// bindToInterface returns a Control hook that pins the raw socket to [name], or nil.
//
// ⚠ NOT SO_BINDTODEVICE ON DARWIN. That option does not exist there; the equivalent is
// IP_BOUND_IF with the interface INDEX, and getting it wrong is silent — the socket simply
// keeps taking the default route, which is the failure this exists to prevent.
func bindToInterface(name string) func(uintptr) error {
	if name == "" {
		return nil
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bind-interface %q: %v\n", name, err)
		os.Exit(2)
	}
	return func(fd uintptr) error {
		if runtime.GOOS == "darwin" {
			// IP_BOUND_IF = 25 on darwin.
			return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 25, ifi.Index)
		}
		return syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, 25, name) // SO_BINDTODEVICE
	}
}
