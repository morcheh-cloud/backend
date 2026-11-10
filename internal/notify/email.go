package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

func sendEmail(ctx context.Context, ch Channel, m Message) error {
	c := ch.Config
	from, err := mail.ParseAddress(strings.TrimSpace(c.From))
	if err != nil {
		return fmt.Errorf("the sender %q isn't an email address", c.From)
	}
	var to []string
	for _, raw := range c.To {
		a, err := mail.ParseAddress(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("%q isn't an email address", raw)
		}
		to = append(to, a.Address)
	}
	security := c.Security
	if security == "" {
		security = "starttls"
	}
	port := c.Port
	if port == 0 {
		port = map[string]int{"starttls": 587, "tls": 465, "none": 25}[security]
	}
	host := strings.TrimSpace(c.Host)
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	dial := ch.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 15 * time.Second}).DialContext
	}
	raw, err := dial(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	conf := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	conn := raw
	if security == "tls" {
		tc := tls.Client(raw, conf)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return err
		}
		conn = tc
	}
	cl, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer cl.Close()
	if err := cl.Hello("morcheh"); err != nil {
		return err
	}
	if security == "starttls" {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return errors.New("the server doesn't offer STARTTLS; pick TLS or None")
		}
		if err := cl.StartTLS(conf); err != nil {
			return err
		}
	}
	if c.Username != "" {
		if ok, _ := cl.Extension("AUTH"); !ok {
			return errors.New("the server doesn't take a login; clear the username")
		}
		if err := cl.Auth(smtp.PlainAuth("", c.Username, ch.Secrets.Password, host)); err != nil {
			return err
		}
	}
	if err := cl.Mail(from.Address); err != nil {
		return err
	}
	for _, a := range to {
		if err := cl.Rcpt(a); err != nil {
			return fmt.Errorf("%s: %w", a, err)
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(emailBody(from, to, m)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

func emailBody(from *mail.Address, to []string, m Message) []byte {
	var b bytes.Buffer
	boundary := randomHex(12)
	subject := emoji(m.Event) + " " + m.Title
	fmt.Fprintf(&b, "From: %s\r\n", from.String())
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&b, "Date: %s\r\n", m.At.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@morcheh>\r\n", randomHex(16))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Auto-Submitted: auto-generated\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)

	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n", boundary)
	b.WriteString(strings.ReplaceAll(Plain(m), "\n", "\r\n") + "\r\n")

	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n", boundary)
	b.WriteString(emailHTML(m))
	fmt.Fprintf(&b, "\r\n--%s--\r\n", boundary)
	return b.Bytes()
}

func emailHTML(m Message) string {
	col := fmt.Sprintf("#%06x", colour(m.Event))
	var b strings.Builder
	b.WriteString(`<div style="font-family:Inter,Segoe UI,Arial,sans-serif;max-width:560px;margin:0 auto;color:#1c2024">`)
	fmt.Fprintf(&b, `<div style="border-inline-start:4px solid %s;padding:4px 0 4px 16px;margin:16px 0">`, col)
	fmt.Fprintf(&b, `<div style="font-size:18px;font-weight:500">%s %s</div>`, emoji(m.Event), htmlEscape(m.Title))
	if m.Text != "" {
		fmt.Fprintf(&b, `<div style="font-size:14px;color:#60646c;margin-top:6px;white-space:pre-wrap">%s</div>`, htmlEscape(m.Text))
	}
	b.WriteString(`</div>`)
	if len(m.Fields) > 0 {
		b.WriteString(`<table style="font-size:14px;border-collapse:collapse">`)
		for _, f := range m.Fields {
			fmt.Fprintf(&b, `<tr><td style="color:#8b8d98;padding:3px 16px 3px 0">%s</td><td style="padding:3px 0">%s</td></tr>`, htmlEscape(f.Name), htmlEscape(f.Value))
		}
		b.WriteString(`</table>`)
	}
	if m.URL != "" {
		fmt.Fprintf(&b, `<p style="margin-top:20px"><a href="%s" style="background:#3e63dd;color:#fff;text-decoration:none;padding:8px 14px;border-radius:8px;font-size:14px">Open in Morcheh</a></p>`, htmlEscape(m.URL))
	}
	b.WriteString(`<p style="font-size:12px;color:#8b8d98;margin-top:24px">Sent by Morcheh</p></div>`)
	return b.String()
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// sendWebhook posts the message as JSON. With a signing key every body is
// signed: X-Morcheh-Signature = "sha256=" + HMAC-SHA256(key, timestamp + "." + body).
func sendWebhook(ctx context.Context, ch Channel, m Message) error {
	fields := map[string]string{}
	for _, f := range m.Fields {
		fields[f.Name] = f.Value
	}
	payload := map[string]any{
		"event":  m.Event,
		"title":  m.Title,
		"text":   m.Text,
		"url":    m.URL,
		"at":     m.At.UTC().Format(time.RFC3339),
		"fields": fields,
	}
	for k, v := range m.Data {
		payload[k] = v
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	method := ch.Config.Method
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSpace(ch.Config.URL), bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Morcheh")
	req.Header.Set("X-Morcheh-Event", m.Event)
	if key := ch.Secrets.SigningKey; key != "" {
		ts := strconv.FormatInt(m.At.Unix(), 10)
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write([]byte(ts + "."))
		mac.Write(raw)
		req.Header.Set("X-Morcheh-Timestamp", ts)
		req.Header.Set("X-Morcheh-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	for k, v := range ch.Secrets.Headers {
		if k = strings.TrimSpace(k); k != "" {
			req.Header.Set(k, v)
		}
	}
	_, err = do(ch, req)
	return err
}
