package fake

import (
	"bufio"
	"context"
	"crypto/des"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"io"
	"math/bits"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

// A minimal RFB 3.8 server: VNC authentication, raw encoding, a text screen
// that runs the same tiny shell as the text console behind a login prompt.

const (
	screenW, screenH = 640, 30 * 13
	cellW, cellH     = 7, 13
	cols, rows       = screenW / cellW, screenH / cellH
)

var (
	screenBG = color.RGBA{12, 12, 14, 255}
	screenFG = color.RGBA{204, 204, 204, 255}
)

type pixelFormat struct {
	bpp                    uint8
	bigEndian              bool
	rMax, gMax, bMax       uint16
	rShift, gShift, bShift uint8
}

// textScreen is a character grid with a cursor, fed with terminal output.
type textScreen struct {
	cells      [rows][cols]rune
	x, y       int
	dirtyFrom  int
	dirtyTo    int // exclusive; dirtyFrom >= dirtyTo = clean
	cursorShow bool
}

func newTextScreen() *textScreen {
	t := &textScreen{cursorShow: true}
	t.clear()
	return t
}

func (t *textScreen) clear() {
	for y := range t.cells {
		for x := range t.cells[y] {
			t.cells[y][x] = ' '
		}
	}
	t.x, t.y = 0, 0
	t.mark(0, rows)
}

func (t *textScreen) mark(from, to int) {
	if t.dirtyFrom >= t.dirtyTo {
		t.dirtyFrom, t.dirtyTo = from, to
		return
	}
	t.dirtyFrom, t.dirtyTo = min(t.dirtyFrom, from), max(t.dirtyTo, to)
}

func (t *textScreen) newline() {
	t.y++
	if t.y >= rows {
		copy(t.cells[:], t.cells[1:])
		for x := range t.cells[rows-1] {
			t.cells[rows-1][x] = ' '
		}
		t.y = rows - 1
		t.mark(0, rows)
	}
}

func (t *textScreen) write(s string) {
	t.mark(t.y, t.y+1)
	for i := 0; i < len(s); {
		if strings.HasPrefix(s[i:], "\x1b[H\x1b[2J") {
			t.clear()
			i += len("\x1b[H\x1b[2J")
			continue
		}
		r := rune(s[i])
		size := 1
		if r >= 0x80 {
			r, size = []rune(s[i:])[0], len(string([]rune(s[i:])[0]))
		}
		i += size
		switch r {
		case '\r':
			t.x = 0
		case '\n':
			t.newline()
		case '\b':
			if t.x > 0 {
				t.x--
			}
		case 0x1b:
		default:
			if t.x >= cols {
				t.x = 0
				t.newline()
			}
			t.cells[t.y][t.x] = r
			t.x++
		}
		t.mark(t.y, t.y+1)
	}
}

// draw renders rows [from, to) as an image of the full width.
func (t *textScreen) draw(from, to int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, screenW, (to-from)*cellH))
	draw.Draw(img, img.Bounds(), image.NewUniform(screenBG), image.Point{}, draw.Src)
	d := font.Drawer{Dst: img, Src: image.NewUniform(screenFG), Face: basicfont.Face7x13}
	for y := from; y < to; y++ {
		d.Dot = fixed.P(0, (y-from)*cellH+basicfont.Face7x13.Ascent)
		d.DrawString(strings.TrimRight(string(t.cells[y][:]), " "))
	}
	if t.cursorShow && t.y >= from && t.y < to {
		cx, cy := min(t.x, cols-1)*cellW, (t.y-from)*cellH
		draw.Draw(img, image.Rect(cx, cy+cellH-2, cx+cellW, cy+cellH), image.NewUniform(screenFG), image.Point{}, draw.Src)
	}
	return img
}

func vncResponse(password string, challenge []byte) []byte {
	key := make([]byte, 8)
	copy(key, password)
	for i := range key {
		key[i] = bits.Reverse8(key[i])
	}
	c, _ := des.NewCipher(key)
	out := make([]byte, 16)
	c.Encrypt(out[:8], challenge[:8])
	c.Encrypt(out[8:], challenge[8:])
	return out
}

func serveVNC(ctx context.Context, conn net.Conn, password, ticket string, info screenInfo) error {
	defer conn.Close()
	br := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	flush := func() error { return w.Flush() }

	// Version
	if _, err := w.WriteString("RFB 003.008\n"); err != nil || flush() != nil {
		return nil
	}
	ver := make([]byte, 12)
	if _, err := io.ReadFull(br, ver); err != nil {
		return nil
	}
	// Security: VNC authentication only, like Proxmox.
	_, _ = w.Write([]byte{1, 2})
	if flush() != nil {
		return nil
	}
	choice, err := br.ReadByte()
	if err != nil || choice != 2 {
		return errors.New("unsupported security type")
	}
	challenge := make([]byte, 16)
	copy(challenge, randHex(8))
	_, _ = w.Write(challenge)
	if flush() != nil {
		return nil
	}
	resp := make([]byte, 16)
	if _, err := io.ReadFull(br, resp); err != nil {
		return nil
	}
	secret := password
	if secret == "" {
		secret = ticket
	}
	if subtle.ConstantTimeCompare(resp, vncResponse(secret, challenge)) != 1 {
		reason := "Authentication failed"
		_ = binary.Write(w, binary.BigEndian, uint32(1))
		_ = binary.Write(w, binary.BigEndian, uint32(len(reason)))
		_, _ = w.WriteString(reason)
		_ = flush()
		return nil
	}
	_ = binary.Write(w, binary.BigEndian, uint32(0))
	if flush() != nil {
		return nil
	}
	if _, err := br.ReadByte(); err != nil { // ClientInit (shared flag)
		return nil
	}
	pf := pixelFormat{bpp: 32, rMax: 255, gMax: 255, bMax: 255, rShift: 16, gShift: 8, bShift: 0}
	_ = binary.Write(w, binary.BigEndian, uint16(screenW))
	_ = binary.Write(w, binary.BigEndian, uint16(screenH))
	_, _ = w.Write([]byte{32, 24, 0, 1})
	_ = binary.Write(w, binary.BigEndian, []uint16{255, 255, 255})
	_, _ = w.Write([]byte{16, 8, 0, 0, 0, 0})
	title := info.name
	if title == "" {
		title = "guest"
	}
	title = "VM " + strconv.Itoa(info.vmid) + " ('" + title + "')"
	_ = binary.Write(w, binary.BigEndian, uint32(len(title)))
	_, _ = w.WriteString(title)
	if flush() != nil {
		return nil
	}

	var mu sync.Mutex
	scr := newTextScreen()
	sh := newShell(info)
	sh.login = 0
	if info.kind == "qemu" {
		scr.write("SeaBIOS (version rel-1.16.3-0-ga6ed6b701f0a-prebuilt.qemu.org)\r\n\r\nBooting from Hard Disk...\r\n")
	}
	scr.write(sh.banner() + sh.prompt())
	wake := make(chan struct{}, 1)
	notify := func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	want := false // an update request is waiting
	full := false

	readErr := make(chan error, 1)
	go func() {
		readErr <- func() error {
			for {
				typ, err := br.ReadByte()
				if err != nil {
					return nil
				}
				switch typ {
				case 0: // SetPixelFormat
					b := make([]byte, 19)
					if _, err := io.ReadFull(br, b); err != nil {
						return nil
					}
					f := b[3:]
					mu.Lock()
					pf = pixelFormat{bpp: f[0], bigEndian: f[2] != 0,
						rMax: binary.BigEndian.Uint16(f[4:]), gMax: binary.BigEndian.Uint16(f[6:]), bMax: binary.BigEndian.Uint16(f[8:]),
						rShift: f[10], gShift: f[11], bShift: f[12]}
					full = true
					mu.Unlock()
				case 2: // SetEncodings
					b := make([]byte, 3)
					if _, err := io.ReadFull(br, b); err != nil {
						return nil
					}
					if _, err := io.CopyN(io.Discard, br, int64(binary.BigEndian.Uint16(b[1:]))*4); err != nil {
						return nil
					}
				case 3: // FramebufferUpdateRequest
					b := make([]byte, 9)
					if _, err := io.ReadFull(br, b); err != nil {
						return nil
					}
					mu.Lock()
					want = true
					if b[0] == 0 {
						full = true
					}
					mu.Unlock()
					notify()
				case 4: // KeyEvent
					b := make([]byte, 7)
					if _, err := io.ReadFull(br, b); err != nil {
						return nil
					}
					if b[0] == 0 {
						continue
					}
					text := keyText(binary.BigEndian.Uint32(b[3:]))
					if text == "" {
						continue
					}
					mu.Lock()
					out, exit := sh.input(text)
					if exit {
						out += "\r\n" + sh.distro() + " " + sh.host() + "\r\n\r\n"
						sh = newShell(info)
						sh.login = 0
						out += sh.prompt()
					}
					scr.write(out)
					scr.cursorShow = true
					mu.Unlock()
					notify()
				case 5: // PointerEvent
					if _, err := io.CopyN(io.Discard, br, 5); err != nil {
						return nil
					}
				case 6: // ClientCutText
					b := make([]byte, 7)
					if _, err := io.ReadFull(br, b); err != nil {
						return nil
					}
					n := int64(binary.BigEndian.Uint32(b[3:]))
					if n > 1<<20 {
						return errors.New("clipboard too big")
					}
					if _, err := io.CopyN(io.Discard, br, n); err != nil {
						return nil
					}
				default:
					return errors.New("unknown client message")
				}
			}
		}()
	}()

	blink := time.NewTicker(530 * time.Millisecond)
	defer blink.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-readErr:
			return err
		case <-blink.C:
			mu.Lock()
			scr.cursorShow = !scr.cursorShow
			scr.mark(scr.y, scr.y+1)
			mu.Unlock()
		case <-wake:
		}
		mu.Lock()
		if !want || (!full && scr.dirtyFrom >= scr.dirtyTo) {
			mu.Unlock()
			continue
		}
		from, to := scr.dirtyFrom, scr.dirtyTo
		if full {
			from, to = 0, rows
		}
		img := scr.draw(from, to)
		f := pf
		want, full = false, false
		scr.dirtyFrom, scr.dirtyTo = 0, 0
		mu.Unlock()
		if err := writeFrame(w, img, from*cellH, f); err != nil {
			return nil
		}
	}
}

func writeFrame(w *bufio.Writer, img *image.RGBA, y int, f pixelFormat) error {
	b := img.Bounds()
	_, _ = w.Write([]byte{0, 0})
	_ = binary.Write(w, binary.BigEndian, uint16(1))
	_ = binary.Write(w, binary.BigEndian, []uint16{0, uint16(y), uint16(b.Dx()), uint16(b.Dy())})
	_ = binary.Write(w, binary.BigEndian, int32(0)) // raw
	bpp := int(f.bpp) / 8
	if bpp != 1 && bpp != 2 && bpp != 4 {
		bpp = 4
	}
	px := make([]byte, 4)
	for yy := 0; yy < b.Dy(); yy++ {
		for xx := 0; xx < b.Dx(); xx++ {
			c := img.RGBAAt(xx, yy)
			v := uint32(c.R)*uint32(f.rMax)/255<<f.rShift | uint32(c.G)*uint32(f.gMax)/255<<f.gShift | uint32(c.B)*uint32(f.bMax)/255<<f.bShift
			switch bpp {
			case 1:
				px[0] = byte(v)
			case 2:
				if f.bigEndian {
					binary.BigEndian.PutUint16(px, uint16(v))
				} else {
					binary.LittleEndian.PutUint16(px, uint16(v))
				}
			default:
				if f.bigEndian {
					binary.BigEndian.PutUint32(px, v)
				} else {
					binary.LittleEndian.PutUint32(px, v)
				}
			}
			if _, err := w.Write(px[:bpp]); err != nil {
				return err
			}
		}
	}
	return w.Flush()
}

// keyText turns an X keysym into what the shell reads.
func keyText(sym uint32) string {
	switch sym {
	case 0xff0d, 0xff8d:
		return "\r"
	case 0xff08:
		return "\x7f"
	case 0xff09:
		return "\t"
	}
	if sym >= 0x20 && sym <= 0x7e {
		return string(rune(sym))
	}
	if sym >= 0x1000100 && sym <= 0x110ffff {
		return string(rune(sym - 0x1000000))
	}
	return ""
}
