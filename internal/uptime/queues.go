package uptime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// open dials host:port and starts TLS when TLSMode is "tls".
func open(ctx context.Context, c MonitorConfig, env Env, plain, secure int) (net.Conn, error) {
	port := plain
	if c.TLSMode == "tls" {
		port = secure
	}
	conn, err := dial(ctx, env, "tcp", addr(c, port))
	if err != nil {
		return nil, err
	}
	return wrapTLS(ctx, conn, c, c.TLSMode)
}

// ---- RabbitMQ (AMQP 0-9-1) ----

func checkAMQP(ctx context.Context, c MonitorConfig, s MonitorSecrets, env Env) CheckResult {
	start := time.Now()
	conn, err := open(ctx, c, env, 5672, 5671)
	if err != nil {
		return down("%s", errText(err))
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("AMQP\x00\x00\x09\x01")); err != nil {
		return down("Couldn't send: %s", errText(err))
	}
	br := bufio.NewReader(conn)
	class, method, args, err := amqpFrame(br)
	if err != nil {
		return down("That isn't an AMQP 0-9-1 server: %s", errText(err))
	}
	if class != 10 || method != 10 {
		return down("Unexpected first answer (%d.%d)", class, method)
	}
	product := tableString(args, "product")
	version := tableString(args, "version")
	r := CheckResult{Status: Up, Code: "AMQP 0-9-1"}
	r.Message = "Connected"
	if product != "" {
		r.Message = "Connected to " + strings.TrimSpace(product+" "+version)
	}
	if c.Username != "" {
		var b bytes.Buffer
		binary.Write(&b, binary.BigEndian, uint16(10))
		binary.Write(&b, binary.BigEndian, uint16(11))
		binary.Write(&b, binary.BigEndian, uint32(0)) // client properties: empty table
		shortStr(&b, "PLAIN")
		longStr(&b, "\x00"+c.Username+"\x00"+s.Password)
		shortStr(&b, "en_US")
		if err := amqpWrite(conn, b.Bytes()); err != nil {
			return down("Couldn't send the login: %s", errText(err))
		}
		class, method, args, err = amqpFrame(br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return CheckResult{Status: Down, Code: "403", Message: "Sign-in was refused"}
			}
			return down("No answer to the login: %s", errText(err))
		}
		switch {
		case class == 10 && method == 30:
			r.Message += ", signed in"
		case class == 10 && method == 50:
			code := binary.BigEndian.Uint16(args)
			text := ""
			if len(args) > 2 {
				n := int(args[2])
				if 3+n <= len(args) {
					text = string(args[3 : 3+n])
				}
			}
			return CheckResult{Status: Down, Code: fmt.Sprint(code), Message: "Refused: " + text}
		default:
			return down("Unexpected answer to the login (%d.%d)", class, method)
		}
	}
	r.took(start)
	return r
}

func amqpWrite(w io.Writer, payload []byte) error {
	var b bytes.Buffer
	b.WriteByte(1)
	binary.Write(&b, binary.BigEndian, uint16(0))
	binary.Write(&b, binary.BigEndian, uint32(len(payload)))
	b.Write(payload)
	b.WriteByte(0xCE)
	_, err := w.Write(b.Bytes())
	return err
}

// amqpFrame reads one method frame on channel 0.
func amqpFrame(r *bufio.Reader) (class, method uint16, args []byte, err error) {
	head := make([]byte, 7)
	if _, err = io.ReadFull(r, head); err != nil {
		return
	}
	if string(head[:4]) == "AMQP" {
		err = fmt.Errorf("the server speaks AMQP %d-%d-%d", head[5], head[6], head[4])
		return
	}
	if head[0] != 1 {
		err = fmt.Errorf("unexpected frame type %d", head[0])
		return
	}
	size := binary.BigEndian.Uint32(head[3:])
	if size > 1<<20 {
		err = errors.New("frame too large")
		return
	}
	body := make([]byte, size+1)
	if _, err = io.ReadFull(r, body); err != nil {
		return
	}
	if body[size] != 0xCE || size < 4 {
		err = errors.New("bad frame")
		return
	}
	return binary.BigEndian.Uint16(body), binary.BigEndian.Uint16(body[2:]), body[4:size], nil
}

// tableString finds a long-string value by key in an AMQP start method's
// server properties (good enough for product and version).
func tableString(args []byte, key string) string {
	needle := append([]byte{byte(len(key))}, key...)
	needle = append(needle, 'S')
	i := bytes.Index(args, needle)
	if i < 0 {
		return ""
	}
	p := i + len(needle)
	if p+4 > len(args) {
		return ""
	}
	n := int(binary.BigEndian.Uint32(args[p:]))
	if p+4+n > len(args) || n > 200 {
		return ""
	}
	return string(args[p+4 : p+4+n])
}

func shortStr(b *bytes.Buffer, s string) {
	b.WriteByte(byte(len(s)))
	b.WriteString(s)
}

func longStr(b *bytes.Buffer, s string) {
	binary.Write(b, binary.BigEndian, uint32(len(s)))
	b.WriteString(s)
}

// ---- Kafka ----

func checkKafka(ctx context.Context, c MonitorConfig, env Env) CheckResult {
	start := time.Now()
	conn, err := open(ctx, c, env, 9092, 9093)
	if err != nil {
		return down("%s", errText(err))
	}
	defer conn.Close()
	// ApiVersions v0: every broker since 0.10 answers it, before any login.
	var req bytes.Buffer
	binary.Write(&req, binary.BigEndian, int16(18)) // api key
	binary.Write(&req, binary.BigEndian, int16(0))  // version
	binary.Write(&req, binary.BigEndian, int32(7))  // correlation id
	binary.Write(&req, binary.BigEndian, int16(len("morcheh")))
	req.WriteString("morcheh")
	var frame bytes.Buffer
	binary.Write(&frame, binary.BigEndian, int32(req.Len()))
	frame.Write(req.Bytes())
	if _, err := conn.Write(frame.Bytes()); err != nil {
		return down("Couldn't send: %s", errText(err))
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return down("No answer (is it Kafka? SASL-only listeners close the connection): %s", errText(err))
	}
	size := binary.BigEndian.Uint32(head)
	if size < 6 || size > 1<<20 {
		return down("That isn't a Kafka answer")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return down("The answer was cut off: %s", errText(err))
	}
	r := CheckResult{}
	r.took(start)
	if binary.BigEndian.Uint32(body) != 7 {
		return down("That isn't a Kafka answer")
	}
	code := int16(binary.BigEndian.Uint16(body[4:]))
	r.Code = fmt.Sprint(code)
	if code != 0 {
		r.Status = Down
		r.Message = fmt.Sprintf("The broker answered with error %d", code)
		return r
	}
	apis := 0
	if len(body) >= 10 {
		apis = int(binary.BigEndian.Uint32(body[6:]))
	}
	r.Status = Up
	r.Message = fmt.Sprintf("Broker answered (%d APIs)", apis)
	return r
}

// ---- NATS ----

func checkNATS(ctx context.Context, c MonitorConfig, s MonitorSecrets, env Env) CheckResult {
	start := time.Now()
	conn, err := dial(ctx, env, "tcp", addr(c, 4222))
	if err != nil {
		return down("%s", errText(err))
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "INFO ") {
		return down("That isn't a NATS server")
	}
	var info struct {
		Name         string `json:"server_name"`
		Version      string `json:"version"`
		AuthRequired bool   `json:"auth_required"`
		TLSRequired  bool   `json:"tls_required"`
		JetStream    bool   `json:"jetstream"`
	}
	_ = json.Unmarshal([]byte(strings.TrimSpace(line[5:])), &info)
	var rw io.ReadWriter = struct {
		io.Reader
		io.Writer
	}{br, conn}
	if c.TLSMode == "tls" || info.TLSRequired {
		cc := c
		cc.TLSMode = "tls"
		tc, err := wrapTLS(ctx, conn, cc, "tls")
		if err != nil {
			return down("TLS failed: %s", errText(err))
		}
		br = bufio.NewReader(tc)
		rw = struct {
			io.Reader
			io.Writer
		}{br, tc}
	}
	opts := map[string]any{"verbose": false, "pedantic": false, "name": "morcheh-uptime", "lang": "go", "version": "1.0", "protocol": 1}
	if c.Username != "" {
		opts["user"] = c.Username
		opts["pass"] = s.Password
	}
	if s.Token != "" {
		opts["auth_token"] = s.Token
	}
	raw, _ := json.Marshal(opts)
	if _, err := fmt.Fprintf(rw, "CONNECT %s\r\nPING\r\n", raw); err != nil {
		return down("Couldn't send: %s", errText(err))
	}
	for {
		line, err = br.ReadString('\n')
		if err != nil {
			return down("No answer: %s", errText(err))
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "PONG":
			r := CheckResult{Status: Up, Code: "PONG", Message: "Connected"}
			if info.Version != "" {
				r.Message = "Connected to NATS " + info.Version
			}
			if info.JetStream {
				r.Message += " (JetStream)"
			}
			r.took(start)
			return r
		case strings.HasPrefix(line, "-ERR"):
			msg := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "-ERR")), "'")
			return CheckResult{Status: Down, Code: "ERR", Message: "Refused: " + msg}
		case strings.HasPrefix(line, "PING"):
			fmt.Fprint(rw, "PONG\r\n")
		}
	}
}

// ---- MQTT ----

var connackText = map[byte]string{
	1: "the broker doesn't speak MQTT 3.1.1",
	2: "the client id was refused",
	3: "the broker is unavailable",
	4: "bad username or password",
	5: "not authorised",
}

func checkMQTT(ctx context.Context, c MonitorConfig, s MonitorSecrets, env Env) CheckResult {
	start := time.Now()
	conn, err := open(ctx, c, env, 1883, 8883)
	if err != nil {
		return down("%s", errText(err))
	}
	defer conn.Close()
	var vh bytes.Buffer
	mqttStr(&vh, "MQTT")
	vh.WriteByte(4) // 3.1.1
	flags := byte(0x02)
	if c.Username != "" {
		flags |= 0x80
		if s.Password != "" {
			flags |= 0x40
		}
	}
	vh.WriteByte(flags)
	binary.Write(&vh, binary.BigEndian, uint16(30))
	mqttStr(&vh, "morcheh-"+randomID())
	if c.Username != "" {
		mqttStr(&vh, c.Username)
		if s.Password != "" {
			mqttStr(&vh, s.Password)
		}
	}
	var pkt bytes.Buffer
	pkt.WriteByte(0x10)
	n := vh.Len()
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		pkt.WriteByte(b)
		if n == 0 {
			break
		}
	}
	pkt.Write(vh.Bytes())
	if _, err := conn.Write(pkt.Bytes()); err != nil {
		return down("Couldn't send: %s", errText(err))
	}
	ack := make([]byte, 4)
	if _, err := io.ReadFull(conn, ack); err != nil {
		return down("No answer (is it MQTT?): %s", errText(err))
	}
	if ack[0] != 0x20 || ack[1] != 2 {
		return down("That isn't an MQTT answer")
	}
	_, _ = conn.Write([]byte{0xE0, 0})
	r := CheckResult{Code: fmt.Sprint(ack[3])}
	r.took(start)
	if ack[3] != 0 {
		r.Status = Down
		r.Message = "Refused: " + connackText[ack[3]]
		return r
	}
	r.Status = Up
	r.Message = "Connected"
	if c.Username != "" {
		r.Message = "Connected and signed in"
	}
	return r
}

func mqttStr(b *bytes.Buffer, s string) {
	binary.Write(b, binary.BigEndian, uint16(len(s)))
	b.WriteString(s)
}

func randomID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano()&0xffffffff)
}

// ---- Memcached ----

func checkMemcached(ctx context.Context, c MonitorConfig, env Env) CheckResult {
	start := time.Now()
	conn, err := open(ctx, c, env, 11211, 11211)
	if err != nil {
		return down("%s", errText(err))
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("version\r\n")); err != nil {
		return down("Couldn't send: %s", errText(err))
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return down("No answer: %s", errText(err))
	}
	r := CheckResult{}
	r.took(start)
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "VERSION ") {
		r.Status = Down
		r.Message = "That isn't a memcached answer: " + clip(line, 100)
		return r
	}
	r.Status = Up
	r.Code = strings.TrimPrefix(line, "VERSION ")
	r.Message = "memcached " + r.Code
	return r
}
