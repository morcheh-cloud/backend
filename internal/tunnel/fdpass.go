package tunnel

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"syscall"
)

// Messages between Morche and its helpers travel over a unix socket as one
// JSON message per datagram (SOCK_SEQPACKET), sometimes with a file
// descriptor attached.

const maxMsg = 1 << 20

func sendMsg(c *net.UnixConn, v any, f *os.File) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var oob []byte
	if f != nil {
		oob = syscall.UnixRights(int(f.Fd()))
	}
	_, _, err = c.WriteMsgUnix(b, oob, nil)
	return err
}

// recvMsg reads one message; the file is nil when none came with it.
func recvMsg(c *net.UnixConn, v any) (*os.File, error) {
	buf := make([]byte, maxMsg)
	oob := make([]byte, syscall.CmsgSpace(4*4))
	n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, err
	}
	if n == 0 && oobn == 0 {
		return nil, errors.New("closed")
	}
	var f *os.File
	if oobn > 0 {
		msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err == nil {
			for _, m := range msgs {
				fds, err := syscall.ParseUnixRights(&m)
				if err != nil {
					continue
				}
				for i, fd := range fds {
					if i == 0 && f == nil {
						f = os.NewFile(uintptr(fd), "passed")
					} else {
						syscall.Close(fd)
					}
				}
			}
		}
	}
	if err := json.Unmarshal(buf[:n], v); err != nil {
		if f != nil {
			f.Close()
		}
		return nil, err
	}
	return f, nil
}

// socketpair makes a connected SOCK_SEQPACKET pair: ours as a UnixConn,
// theirs as a file to hand to a child.
func socketpair() (*net.UnixConn, *os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	ours := os.NewFile(uintptr(fds[0]), "control")
	theirs := os.NewFile(uintptr(fds[1]), "control")
	c, err := net.FileConn(ours)
	ours.Close()
	if err != nil {
		theirs.Close()
		return nil, nil, err
	}
	return c.(*net.UnixConn), theirs, nil
}

// fileConn turns a passed socket into a net.Conn.
func fileConn(f *os.File) (net.Conn, error) {
	defer f.Close()
	return net.FileConn(f)
}
