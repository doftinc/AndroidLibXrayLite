package libv2ray

// Android VpnService socket protection.
//
// WHY THIS FILE EXISTS. The AAR this project shipped before building its own carried a
// `V2RayProtector` interface, `UseProtector` and `SetProtectorServer`, and the Flutter
// plugin's `V2rayCoreManager` calls all three by name. Upstream AndroidLibXrayLite does
// not have them — its only Android-specific export is `RegisterProcessFinder` — so a
// build straight from upstream produces an AAR that is API-INCOMPATIBLE with the Java
// already in the app: `Libv2ray.useProtector` would not resolve and the plugin would not
// compile. Restoring the three symbols here is what makes our AAR a drop-in.
//
// ⚠ WITHOUT PROTECTION THE TUNNEL EATS ITSELF. `VpnService` routes the whole device
// through the TUN interface, including the sockets xray opens to reach the server. Each
// outbound would be routed back into the tunnel that is trying to establish it. The fix
// is `VpnService.protect(fd)`, which must be called on the raw file descriptor BEFORE
// connect(2) — which is exactly what xray's dialer-controller seam offers.
//
// ⚠ THIS PROTECTS EVERY OUTBOUND SOCKET, not just the one to the proxy server. That is
// deliberate and it is what the old ProtectedDialer effectively did: DNS lookups the core
// performs, health probes, and the proxy connection itself all have to leave outside the
// tunnel. An inbound listener is unaffected — controllers registered here run on dials.

import (
	"log"
	"sync"
	"syscall"

	"github.com/xtls/xray-core/transport/internet"
)

// V2RayProtector is implemented on the Java side by an object that calls
// `VpnService.protect(int)`. gomobile maps `Protect(int64) bool` to `protect(long)`,
// which is the signature the shipped plugin already implements.
type V2RayProtector interface {
	Protect(fd int64) bool
}

var (
	protectorMu         sync.RWMutex
	protector           V2RayProtector
	protectorServer     string
	protectorPreferIPv6 bool

	// ⚠ REGISTERED EXACTLY ONCE. `internet.RegisterDialerController` APPENDS to a global
	// slice on the default system dialer, and `V2rayCoreManager` calls `useProtector` on
	// every single tunnel start. Registering per call would stack a new controller each
	// time, so by the tenth connect of a session every socket would run ten identical
	// protect calls — and the slice would grow for the life of the process. The
	// controller therefore reads the CURRENT protector through the mutex instead of
	// closing over the one that happened to be installed first.
	controllerOnce sync.Once
	controllerErr  error
)

// UseProtector installs the Java-side protector. Safe to call repeatedly; the last one
// wins. Pass nil to detach (the controller stays registered and becomes a no-op).
func UseProtector(p V2RayProtector) {
	protectorMu.Lock()
	protector = p
	protectorMu.Unlock()

	controllerOnce.Do(func() {
		controllerErr = internet.RegisterDialerController(func(network, address string, conn syscall.RawConn) error {
			protectorMu.RLock()
			current := protector
			protectorMu.RUnlock()
			if current == nil {
				return nil
			}
			var protected bool
			// ⚠ THE ERROR FROM Control IS RETURNED, THE ONE FROM protect() IS NOT.
			// A failed Control means we never saw the fd, so the socket would be routed
			// into the tunnel — failing the dial is strictly better than a loop that
			// presents as "connected, no internet", this stack's most expensive failure
			// shape. A protect() that returns false is a different thing: the VpnService
			// may simply not be up yet (the plugin protects before establish() on some
			// paths), and refusing the dial there would break startup. Log and continue.
			if err := conn.Control(func(fd uintptr) {
				protected = current.Protect(int64(fd))
			}); err != nil {
				return err
			}
			if !protected {
				log.Printf("doft-protect: VpnService.protect() refused %s %s", network, address)
			}
			return nil
		})
		if controllerErr != nil {
			// Only possible when something has replaced the system dialer, which nothing
			// in this build does. Loud, because every socket silently leaks into the
			// tunnel if it ever happens.
			log.Printf("doft-protect: FAILED to register the dialer controller: %v", controllerErr)
		}
	})
}

// SetProtectorServer records the proxy endpoint the tunnel is about to dial.
//
// ⚠ IT IS NOT WHAT IT WAS IN THE OLD AAR, and the difference is worth stating rather than
// pretending. There, a `ProtectedDialer` resolved the server's DOMAIN over its own
// protected socket before the core started, because the core's own resolver would
// otherwise have gone through the tunnel. Here every dial the core makes is protected by
// the controller above — DNS included — so there is nothing left to pre-resolve, and a
// second resolution path would just be a second place for the address to be wrong.
//
// The value is kept for diagnostics and to answer `IsVServerReady`, and the signature is
// preserved because the shipped Java calls it.
func SetProtectorServer(server string, preferIPv6 bool) {
	protectorMu.Lock()
	protectorServer, protectorPreferIPv6 = server, preferIPv6
	protectorMu.Unlock()
	log.Printf("doft-protect: server=%s preferIPv6=%v", server, preferIPv6)
}

// ProtectedDialer exists so the AAR's exported Java surface still contains the class the
// previous one did. It is a thin holder: the actual protection is the dialer controller
// installed by UseProtector.
type ProtectedDialer struct{}

// Protect forwards to the installed protector, so a caller holding this object behaves
// like one holding the interface.
func (d *ProtectedDialer) Protect(fd int64) bool {
	protectorMu.RLock()
	current := protector
	protectorMu.RUnlock()
	if current == nil {
		return false
	}
	return current.Protect(fd)
}

// IsVServerReady reports whether a server endpoint has been handed to
// SetProtectorServer yet.
func (d *ProtectedDialer) IsVServerReady() bool {
	protectorMu.RLock()
	defer protectorMu.RUnlock()
	return protectorServer != ""
}
