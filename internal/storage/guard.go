package storage

import (
	"net"
	"time"

	"github.com/morche/backend/internal/dbmon"
)

// guardedDialer reaches a storage from Morche itself, refusing link-local and
// cloud metadata addresses (checked after DNS, on every connection, FTP data
// connections and HTTP redirects included). Private networks and loopback
// stay reachable: in-house MinIO, a NAS, the dev MinIO on localhost.
func guardedDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
		Control:   dbmon.RefuseUnreachable,
	}
}
