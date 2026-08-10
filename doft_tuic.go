package libv2ray

// TUIC v5 for Android, exported to Java.
//
// xray-core has no TUIC at all — 0 occurrences of the string in the shipped arm64
// `libv2jni.so` against 572 for hysteria and 1019 for reality — so the protocol was not
// switched off on Android, it was absent. The Apple and Windows builds run sing-box, which
// has it, and it is the fastest transport this fleet has measured anywhere: 4047 KB/s from
// Beeline Krasnodar, against hysteria2's 774 and Reality's 549 on the same line.
//
// The client lives in doft/tuic and speaks SOCKS5 on 127.0.0.1, so xray reaches it through
// an ordinary `socks` outbound. Nothing in the core changes, and every mechanism built
// around outbounds — the balancer, the per-tag byte counters the plugin reads for the
// free-data cap, routing — keeps working.
//
// ⚠ START IT BEFORE THE CORE AND STOP IT AFTER. The xray config names 127.0.0.1:<port>;
// if the listener is not up when the core starts, the outbound is still valid and every
// dial through it fails until it is. StartTuic returns the port it actually bound so the
// caller builds the config from a fact rather than a guess.

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/2dust/AndroidLibXrayLite/doft/tuic"
)

var (
	tuicMu     sync.Mutex
	tuicServer *tuic.Server
)

// tuicRequest is the JSON the Dart side already has in hand: the fields /v1/config
// publishes for `tuic`, plus the device's own credentials.
type tuicRequest struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	UUID     string `json:"uuid"`
	Password string `json:"password"`
	SNI      string `json:"sni"`
	Cert     string `json:"cert"`
	// Listen port for the local SOCKS5 front end. 0 → the OS picks one, which is the
	// safe default: a fixed port can collide with whatever else the device is running.
	ListenPort int `json:"listen_port"`
	// Idle timeout for a UDP association, seconds. 0 → 300.
	UDPTimeoutSec int `json:"udp_timeout_sec"`
}

// StartTuic brings up the local SOCKS5 front end for one TUIC endpoint and returns the
// port it bound, or a negative value on failure. Idempotent per process: a second call
// replaces the first.
//
// Returns:
//
//	> 0  the loopback port to point the xray `socks` outbound at
//	 -1  the request could not be parsed
//	 -2  the endpoint or credentials are unusable (including: no pinned certificate)
//	 -3  the local listener could not be bound
func StartTuic(requestJSON string) int {
	var req tuicRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		log.Printf("doft-tuic: bad request: %v", err)
		return -1
	}
	client, err := tuic.New(tuic.Config{
		Server:     req.Server,
		Port:       req.Port,
		UUID:       req.UUID,
		Password:   req.Password,
		SNI:        req.SNI,
		CertPEM:    req.Cert,
		UDPTimeout: time.Duration(req.UDPTimeoutSec) * time.Second,
	})
	if err != nil {
		log.Printf("doft-tuic: %v", err)
		return -2
	}
	srv, err := tuic.Listen(client, req.ListenPort)
	if err != nil {
		log.Printf("doft-tuic: %v", err)
		_ = client.Close()
		return -3
	}

	tuicMu.Lock()
	old := tuicServer
	tuicServer = srv
	tuicMu.Unlock()
	if old != nil {
		// Replacing rather than refusing: a reconnect must not be blocked by the
		// previous session's listener, and leaving both up would leave a stale one
		// holding a QUIC connection to a node we may have just failed away from.
		_ = old.Close()
	}
	log.Printf("doft-tuic: listening on %s -> %s:%d", srv.Addr(), req.Server, req.Port)
	return srv.Port()
}

// StopTuic tears down the listener and the QUIC connection. Safe to call when nothing
// is running.
func StopTuic() {
	tuicMu.Lock()
	srv := tuicServer
	tuicServer = nil
	tuicMu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

// TuicPort reports the port the current listener is bound to, or 0. Lets the Java side
// rebuild a config after a process restart without keeping its own copy of the number.
func TuicPort() int {
	tuicMu.Lock()
	defer tuicMu.Unlock()
	if tuicServer == nil {
		return 0
	}
	return tuicServer.Port()
}

// TuicProbe dials one destination through the local front end and reports the outcome as
// a human-readable string — used by CI's interop test against the production node, and by
// the on-device checklist. Empty means success.
func TuicProbe(host string, port int) string {
	tuicMu.Lock()
	srv := tuicServer
	tuicMu.Unlock()
	if srv == nil {
		return "tuic: not running"
	}
	return fmt.Sprintf("tuic: listening on %s; dial %s:%d through it with any SOCKS5 client",
		srv.Addr(), host, port)
}
