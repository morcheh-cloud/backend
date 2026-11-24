package ansible

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
)

// serveTunnels listens, for every host reached through a tunnel, on the
// unix socket its ProxyCommand connects to, and carries each connection
// through the tunnel. stop closes them.
func serveTunnels(ctx context.Context, dir string, hosts []Host) (stop func(), err error) {
	var lns []net.Listener
	stop = func() {
		for _, l := range lns {
			l.Close()
		}
	}
	for _, h := range hosts {
		if h.Dial == nil {
			continue
		}
		if len(lns) == 0 {
			if _, err := exec.LookPath("nc"); err != nil {
				return stop, errors.New("netcat (nc) isn't installed on the machine Morche runs on; it carries ssh through tunnels")
			}
			if err := os.MkdirAll(filepath.Join(dir, "tunnels"), 0o700); err != nil {
				return stop, err
			}
		}
		ln, err := net.Listen("unix", tunnelSocket(dir, h))
		if err != nil {
			stop()
			return func() {}, err
		}
		lns = append(lns, ln)
		addr := net.JoinHostPort(h.Address, strconv.Itoa(h.Port))
		go func(h Host) {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					up, err := h.Dial(ctx, "tcp", addr)
					if err != nil {
						return
					}
					defer up.Close()
					var wg sync.WaitGroup
					wg.Add(2)
					go func() { defer wg.Done(); _, _ = io.Copy(up, c); closeWrite(up) }()
					go func() { defer wg.Done(); _, _ = io.Copy(c, up); closeWrite(c) }()
					wg.Wait()
				}()
			}
		}(h)
	}
	return stop, nil
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
