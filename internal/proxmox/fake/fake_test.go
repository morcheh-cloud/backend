package fake_test

import (
	"context"
	"crypto/des"
	"encoding/binary"
	"io"
	"math/bits"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/morcheh/backend/internal/proxmox"
	"github.com/morcheh/backend/internal/proxmox/fake"
)

func setup(t *testing.T) (*proxmox.Client, context.Context) {
	t.Helper()
	f := fake.New(fake.Options{TokenID: "root@pam!test", Secret: "s3cret", Speed: 0.01})
	srv := httptest.NewTLSServer(f.Handler())
	t.Cleanup(srv.Close)
	c := proxmox.New(proxmox.Config{URL: srv.URL, TokenID: "root@pam!test", Secret: "s3cret", Fingerprint: proxmox.FingerprintOf(srv.Certificate().Raw)})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c, ctx
}

func TestCheckAndResources(t *testing.T) {
	c, ctx := setup(t)
	info, err := c.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Version == "" {
		t.Fatalf("no version: %+v", info)
	}
	vms, err := c.Resources(ctx, "vm")
	if err != nil {
		t.Fatal(err)
	}
	if len(vms) < 8 {
		t.Fatalf("want the seeded guests, got %d", len(vms))
	}
	bad := proxmox.New(proxmox.Config{URL: c.BaseURL(), TokenID: "root@pam!test", Secret: "nope", SkipVerify: true})
	if _, err := bad.Check(ctx); err == nil {
		t.Fatal("a wrong secret passed")
	} else if _, ok := err.(*proxmox.AuthError); !ok {
		t.Fatalf("want AuthError, got %T %v", err, err)
	}
}

func find(t *testing.T, c *proxmox.Client, ctx context.Context, vmid int) proxmox.Resource {
	t.Helper()
	r, err := c.Find(ctx, vmid)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPowerSnapshotsClone(t *testing.T) {
	c, ctx := setup(t)
	vms, _ := c.Resources(ctx, "vm")
	var stopped proxmox.Resource
	for _, r := range vms {
		if r.Type == "qemu" && r.Status == "stopped" && r.Template == 0 {
			stopped = r
			break
		}
	}
	if stopped.VMID == 0 {
		t.Fatal("no stopped VM in the seed")
	}
	upid, err := c.Power(ctx, stopped.Node, proxmox.QEMU, stopped.VMID, "start", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Run(ctx, upid, nil); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.GuestStatus(ctx, stopped.Node, proxmox.QEMU, stopped.VMID); st.Status != "running" {
		t.Fatalf("still %q after start", st.Status)
	}

	upid, err = c.CreateSnapshot(ctx, stopped.Node, proxmox.QEMU, stopped.VMID, "test_one", "from a test", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Run(ctx, upid, nil); err != nil {
		t.Fatal(err)
	}
	snaps, err := c.Snapshots(ctx, stopped.Node, proxmox.QEMU, stopped.VMID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range snaps {
		found = found || s.Name == "test_one"
	}
	if !found {
		t.Fatalf("snapshot missing: %+v", snaps)
	}

	id, _ := c.NextID(ctx)
	upid, err = c.Clone(ctx, stopped.Node, proxmox.QEMU, 9000, proxmox.CloneOptions{NewID: id, Name: "clone-test", Full: true})
	if err != nil {
		// template 9000 may live on another node
		tpl := find(t, c, ctx, 9000)
		upid, err = c.Clone(ctx, tpl.Node, proxmox.QEMU, 9000, proxmox.CloneOptions{NewID: id, Name: "clone-test", Full: true})
		if err != nil {
			t.Fatal(err)
		}
	}
	var lines int
	if err := c.Run(ctx, upid, func(l []proxmox.LogLine) { lines += len(l) }); err != nil {
		t.Fatal(err)
	}
	if lines == 0 {
		t.Fatal("no task log")
	}
	if r := find(t, c, ctx, id); r.Name != "clone-test" || r.Lock != "" {
		t.Fatalf("clone: %+v", r)
	}
}

func TestBackupAndContent(t *testing.T) {
	c, ctx := setup(t)
	g := find(t, c, ctx, 100)
	before, err := c.Content(ctx, g.Node, "pbs", "backup", 100)
	if err != nil {
		t.Fatal(err)
	}
	upid, err := c.Vzdump(ctx, g.Node, 100, proxmox.BackupOptions{Storage: "pbs", Notes: "{{guestname}} by test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Run(ctx, upid, nil); err != nil {
		t.Fatal(err)
	}
	after, err := c.Content(ctx, g.Node, "pbs", "backup", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before)+1 {
		t.Fatalf("backups %d → %d", len(before), len(after))
	}
	last := after[len(after)-1]
	if !strings.HasSuffix(last.Notes, " by test") || strings.Contains(last.Notes, "{{") {
		t.Fatalf("notes: %q", last.Notes)
	}
	isos, err := c.Content(ctx, g.Node, "nfs-iso", "iso", 0)
	if err != nil || len(isos) == 0 {
		t.Fatalf("isos: %v %d", err, len(isos))
	}
}

func TestTermConsole(t *testing.T) {
	c, ctx := setup(t)
	vms, _ := c.Resources(ctx, "vm")
	var ct proxmox.Resource
	for _, r := range vms {
		if r.Type == "lxc" && r.Status == "running" {
			ct = r
		}
	}
	if ct.VMID == 0 {
		t.Fatal("no running container in the seed")
	}
	tk, err := c.TermProxy(ctx, ct.Node, proxmox.LXC, ct.VMID, "")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := c.DialConsole(ctx, ct.Node, proxmox.LXC, ct.VMID, tk)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	if err := conn.Write(ctx, websocket.MessageBinary, []byte(tk.User+":"+tk.Ticket+"\n")); err != nil {
		t.Fatal(err)
	}
	_, first, err := conn.Read(ctx)
	if err != nil || !strings.HasPrefix(string(first), "OK") {
		t.Fatalf("handshake: %q %v", first, err)
	}
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("0:9:hostname\r")); err != nil {
		t.Fatal(err)
	}
	_, out, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), ct.Name) {
		t.Fatalf("hostname answered %q, want %q", out, ct.Name)
	}
	// a ticket works once
	if _, err := c.DialConsole(ctx, ct.Node, proxmox.LXC, ct.VMID, tk); err == nil {
		t.Fatal("a used ticket connected again")
	}
}

func TestVNCConsole(t *testing.T) {
	c, ctx := setup(t)
	g := find(t, c, ctx, 100)
	tk, err := c.VNCProxy(ctx, g.Node, proxmox.QEMU, 100)
	if err != nil {
		t.Fatal(err)
	}
	if tk.Password == "" {
		t.Fatal("no generated password")
	}
	ws, err := c.DialConsole(ctx, g.Node, proxmox.QEMU, 100, tk)
	if err != nil {
		t.Fatal(err)
	}
	conn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer conn.Close()
	read := func(n int) []byte {
		b := make([]byte, n)
		if _, err := io.ReadFull(conn, b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	if v := string(read(12)); v != "RFB 003.008\n" {
		t.Fatalf("version %q", v)
	}
	_, _ = conn.Write([]byte("RFB 003.008\n"))
	if sec := read(2); sec[0] != 1 || sec[1] != 2 {
		t.Fatalf("security %v", sec)
	}
	_, _ = conn.Write([]byte{2})
	challenge := read(16)
	key := make([]byte, 8)
	copy(key, tk.Password)
	for i := range key {
		key[i] = bits.Reverse8(key[i])
	}
	cipher, _ := des.NewCipher(key)
	resp := make([]byte, 16)
	cipher.Encrypt(resp[:8], challenge[:8])
	cipher.Encrypt(resp[8:], challenge[8:])
	_, _ = conn.Write(resp)
	if r := binary.BigEndian.Uint32(read(4)); r != 0 {
		t.Fatalf("auth result %d", r)
	}
	_, _ = conn.Write([]byte{1})
	init := read(24)
	w, h := binary.BigEndian.Uint16(init), binary.BigEndian.Uint16(init[2:])
	read(int(binary.BigEndian.Uint32(init[20:])))
	_, _ = conn.Write([]byte{3, 0, 0, 0, 0, 0, byte(w >> 8), byte(w), byte(h >> 8), byte(h)})
	head := read(16)
	rw, rh := binary.BigEndian.Uint16(head[8:]), binary.BigEndian.Uint16(head[10:])
	if head[0] != 0 || rw != w || rh != h {
		t.Fatalf("frame header %v", head)
	}
	read(int(rw) * int(rh) * 4)
}
