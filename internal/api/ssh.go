package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/sshpool"
	"github.com/morcheh/backend/internal/sshprobe"
)

// connVersion summarises what a connection depends on, so a pooled one is
// replaced once the server's address, credentials or trusted key change.
func connVersion(s sqlc.Server) string {
	sum := sha256.New()
	for _, part := range [][]byte{
		[]byte(s.Host), []byte(strconv.Itoa(int(s.Port))), []byte(s.Username),
		[]byte(s.AuthMethod), s.PasswordEnc, s.PrivateKeyEnc, s.PassphraseEnc,
		[]byte(s.HostKey),
	} {
		sum.Write(part)
		sum.Write([]byte{0})
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// conn returns a live SSH connection to a stored server, shared with other
// requests. A server never checked before is checked first, so its host key
// is trusted the same way a check would (TOFU).
func (h *serverHandler) conn(ctx context.Context, rawID string) (*sshpool.Conn, error) {
	if _, err := uuid.Parse(rawID); err != nil {
		return nil, huma.Error404NotFound("server not found")
	}
	s, err := h.get(ctx, rawID)
	if err != nil {
		return nil, err
	}
	if s.HostKey == "" {
		if s, err = h.check(ctx, s); err != nil {
			return nil, err
		}
		if s.Status != sshprobe.StatusOnline {
			return nil, dialError(&sshprobe.DialError{Status: s.Status, Message: s.StatusMessage})
		}
	}
	t, err := h.target(s)
	if err != nil {
		return nil, internalError(err)
	}
	c, err := h.pool.Get(ctx, rawID, connVersion(s), func(ctx context.Context) (*ssh.Client, error) {
		client, _, err := sshprobe.Dial(ctx, t)
		return client, err
	})
	if err != nil {
		return nil, dialError(err)
	}
	return c, nil
}

// dialError explains a failed connection: 409 when the host key changed (the
// user has to review it), 502 for everything else about the server.
func dialError(err error) error {
	var de *sshprobe.DialError
	if !errors.As(err, &de) {
		return huma.Error502BadGateway("Couldn't connect to the server: " + err.Error())
	}
	switch de.Status {
	case sshprobe.StatusHostKeyMismatch:
		return huma.Error409Conflict(de.Message)
	case sshprobe.StatusAuthFailed:
		return huma.Error502BadGateway("Login failed: " + de.Message)
	default:
		return huma.Error502BadGateway(de.Message)
	}
}

// withSFTP runs fn on the server's SFTP session. If the pooled connection
// turns out to be dead (the server rebooted, a NAT dropped it), it retries
// once on a fresh one.
func (h *serverHandler) withSFTP(ctx context.Context, rawID string, fn func(c *sshpool.Conn, s *sftp.Client) error) error {
	for attempt := 0; ; attempt++ {
		c, err := h.conn(ctx, rawID)
		if err != nil {
			return err
		}
		s, err := c.SFTP()
		if err != nil {
			if attempt == 0 {
				h.pool.Drop(rawID)
				continue
			}
			return huma.Error502BadGateway("The server doesn't offer SFTP: " + err.Error())
		}
		err = fn(c, s)
		if err != nil && attempt == 0 && sshpool.Lost(err) {
			h.pool.Drop(rawID)
			continue
		}
		return err
	}
}

// withConn runs fn on the server's pooled connection, retrying once on a
// fresh one if the pooled one turns out to be dead.
func (h *serverHandler) withConn(ctx context.Context, rawID string, fn func(c *sshpool.Conn) error) error {
	for attempt := 0; ; attempt++ {
		c, err := h.conn(ctx, rawID)
		if err != nil {
			return err
		}
		err = fn(c)
		if err != nil && attempt == 0 && sshpool.Lost(err) {
			h.pool.Drop(rawID)
			continue
		}
		return err
	}
}
