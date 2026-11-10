// Package notify sends alerts to the places a team reads them: email,
// Telegram, Bale, chat webhooks (Slack, Discord, Mattermost, Teams), push
// services (ntfy, Gotify, Pushover) and plain signed webhooks. It knows
// nothing about monitors or the database: the caller builds a Message and
// hands it a channel's settings.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Kinds of channel.
const (
	Email      = "email"
	Telegram   = "telegram"
	Bale       = "bale"
	Webhook    = "webhook"
	Slack      = "slack"
	Discord    = "discord"
	Ntfy       = "ntfy"
	Gotify     = "gotify"
	Mattermost = "mattermost"
	Teams      = "teams"
	Pushover   = "pushover"
)

// Kinds lists every kind, in the order the UI offers them.
var Kinds = []string{Email, Telegram, Bale, Webhook, Slack, Discord, Mattermost, Teams, Ntfy, Gotify, Pushover}

// Events a message can be about; they pick its colour and emoji.
const (
	EventDown     = "down"
	EventUp       = "up"
	EventDegraded = "degraded"
	EventReminder = "reminder"
	EventTest     = "test"
)

// Field is one labelled fact under the text.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Message is what gets sent, independent of where.
type Message struct {
	Event  string
	Title  string
	Text   string
	URL    string
	Fields []Field
	At     time.Time
	// Data is added as is to a webhook's JSON body.
	Data map[string]any
}

// Config holds a channel's plain settings; each kind reads its own.
type ChannelConfig struct {
	// Email
	Host     string   `json:"host,omitempty" maxLength:"255" doc:"Email: the SMTP server"`
	Port     int      `json:"port,omitempty" minimum:"0" maximum:"65535" doc:"Email: 587 for STARTTLS, 465 for TLS, 25 for none"`
	Security string   `json:"security,omitempty" enum:"starttls,tls,none," doc:"Email: how the connection is encrypted"`
	Username string   `json:"username,omitempty" maxLength:"255" doc:"Email: the SMTP login, blank for none"`
	From     string   `json:"from,omitempty" maxLength:"255" doc:"Email: the sender, e.g. Morcheh <alerts@example.com>"`
	To       []string `json:"to,omitempty" maxItems:"50" doc:"Email: who gets it"`
	// Telegram and Bale
	ChatID string `json:"chat_id,omitempty" maxLength:"100" doc:"Telegram/Bale: the chat, group or channel id (or @channelname)"`
	APIURL string `json:"api_url,omitempty" maxLength:"500" doc:"Telegram/Bale: another Bot API address (a self-hosted or relay Bot API); blank for the official one"`
	Silent bool   `json:"silent,omitempty" doc:"Telegram/Bale/Pushover: deliver without a sound"`
	// Webhook, ntfy, Gotify
	URL    string `json:"url,omitempty" maxLength:"1000" doc:"Webhook: where to POST; ntfy/Gotify: the server"`
	Method string `json:"method,omitempty" enum:"POST,PUT,PATCH," doc:"Webhook: the HTTP method"`
	// ntfy
	Topic string `json:"topic,omitempty" maxLength:"200" doc:"ntfy: the topic"`
	// ntfy, Gotify, Pushover: 0 picks one by the event.
	Priority int `json:"priority,omitempty" minimum:"0" maximum:"10" doc:"ntfy (1–5), Gotify (0–10), Pushover (-2–2 as 0–4): 0 = by the event"`
}

// Secrets holds a channel's secret settings; they're sealed at rest and never
// sent back.
type ChannelSecrets struct {
	Password   string `json:"password,omitempty" maxLength:"500" doc:"Email: the SMTP password"`
	Token      string `json:"token,omitempty" maxLength:"500" doc:"Telegram/Bale: the bot token; ntfy: an access token; Gotify: the app token; Pushover: the app token"`
	WebhookURL string `json:"webhook_url,omitempty" maxLength:"1000" doc:"Slack/Discord/Mattermost/Teams: the incoming webhook address"`
	SigningKey string `json:"signing_key,omitempty" maxLength:"500" doc:"Webhook: signs each body (X-Morcheh-Signature: sha256=…)"`
	UserKey    string `json:"user_key,omitempty" maxLength:"100" doc:"Pushover: the user or group key"`
	// Header values often carry a login (Authorization, X-Api-Key), so they
	// are sealed like the rest; only the names are listed back.
	Headers map[string]string `json:"headers,omitempty" maxProperties:"20" doc:"Webhook: extra request headers. Left out = keep the saved ones; sent = exactly these names, a blank value keeps that header's saved value"`
}

// Names lists which secrets are set, for the API to say so without
// showing them.
func (s ChannelSecrets) Names() []string {
	out := []string{}
	for _, f := range []struct {
		name, v string
	}{{"password", s.Password}, {"token", s.Token}, {"webhook_url", s.WebhookURL}, {"signing_key", s.SigningKey}, {"user_key", s.UserKey}} {
		if f.v != "" {
			out = append(out, f.name)
		}
	}
	names := make([]string, 0, len(s.Headers))
	for k := range s.Headers {
		names = append(names, "header:"+k)
	}
	sort.Strings(names)
	return append(out, names...)
}

// Merge keeps a saved secret where the new one is blank.
func (s ChannelSecrets) Merge(saved ChannelSecrets) ChannelSecrets {
	keep := func(v, old string) string {
		if v == "" {
			return old
		}
		return v
	}
	return ChannelSecrets{
		Password:   keep(s.Password, saved.Password),
		Token:      keep(s.Token, saved.Token),
		WebhookURL: keep(s.WebhookURL, saved.WebhookURL),
		SigningKey: keep(s.SigningKey, saved.SigningKey),
		UserKey:    keep(s.UserKey, saved.UserKey),
		Headers:    mergeHeaders(s.Headers, saved.Headers),
	}
}

// mergeHeaders: nil keeps every saved header; otherwise the names sent are
// the new set, and a blank value takes that header's saved value (a new
// name with no value is dropped).
func mergeHeaders(sent, saved map[string]string) map[string]string {
	if sent == nil {
		return saved
	}
	out := map[string]string{}
	for k, v := range sent {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if v == "" {
			v = saved[k]
		}
		if v != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Dialer opens network connections; the caller decides whether private
// addresses are allowed.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Channel is one destination, ready to send to.
type Channel struct {
	Kind    string
	Config  ChannelConfig
	Secrets ChannelSecrets
	Dial    Dialer
}

// FieldError is a setting that's missing or wrong, keyed like the API body
// ("config.chat_id", "secrets.token").
type FieldError struct {
	Field   string
	Message string
}

func (e *FieldError) Error() string { return e.Message }

// Check says what a channel is missing before it's saved.
func Check(kind string, c ChannelConfig, s ChannelSecrets) *FieldError {
	need := func(field, v, msg string) *FieldError {
		if strings.TrimSpace(v) == "" {
			return &FieldError{field, msg}
		}
		return nil
	}
	httpURL := func(field, v string) *FieldError {
		u, err := url.Parse(strings.TrimSpace(v))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return &FieldError{field, "Enter an http:// or https:// address"}
		}
		return nil
	}
	switch kind {
	case Email:
		if e := need("config.host", c.Host, "Enter the SMTP server"); e != nil {
			return e
		}
		if e := need("config.from", c.From, "Enter who the email is from"); e != nil {
			return e
		}
		if len(c.To) == 0 {
			return &FieldError{"config.to", "Add at least one address"}
		}
		for _, to := range c.To {
			if !strings.Contains(to, "@") {
				return &FieldError{"config.to", fmt.Sprintf("%q isn't an email address", to)}
			}
		}
	case Telegram, Bale:
		if e := need("secrets.token", s.Token, "Enter the bot token"); e != nil {
			return e
		}
		if e := need("config.chat_id", c.ChatID, "Enter the chat id"); e != nil {
			return e
		}
		if c.APIURL != "" {
			return httpURL("config.api_url", c.APIURL)
		}
	case Webhook:
		for k, v := range s.Headers {
			if !validHeaderName(k) {
				return &FieldError{Field: "secrets.headers", Message: "“" + k + "” isn't a valid header name"}
			}
			if strings.ContainsAny(v, "\r\n") {
				return &FieldError{Field: "secrets.headers", Message: "A header value can't hold a line break"}
			}
		}
		return httpURL("config.url", c.URL)
	case Slack, Discord, Mattermost, Teams:
		if e := need("secrets.webhook_url", s.WebhookURL, "Paste the webhook address"); e != nil {
			return e
		}
		return httpURL("secrets.webhook_url", s.WebhookURL)
	case Ntfy:
		if e := need("config.topic", c.Topic, "Enter the topic"); e != nil {
			return e
		}
		if c.URL != "" {
			return httpURL("config.url", c.URL)
		}
	case Gotify:
		if e := httpURL("config.url", c.URL); e != nil {
			return e
		}
		return need("secrets.token", s.Token, "Enter the app token")
	case Pushover:
		if e := need("secrets.token", s.Token, "Enter the app token"); e != nil {
			return e
		}
		return need("secrets.user_key", s.UserKey, "Enter the user or group key")
	default:
		return &FieldError{"kind", "Unknown kind of channel"}
	}
	return nil
}

// Send delivers one message. The error says what the destination answered.
func Send(ctx context.Context, ch Channel, m Message) error {
	if m.At.IsZero() {
		m.At = time.Now()
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	switch ch.Kind {
	case Email:
		return sendEmail(ctx, ch, m)
	case Telegram:
		return sendBot(ctx, ch, m, "https://api.telegram.org", true)
	case Bale:
		return sendBot(ctx, ch, m, "https://tapi.bale.ai", false)
	case Webhook:
		return sendWebhook(ctx, ch, m)
	case Slack:
		return postJSON(ctx, ch, ch.Secrets.WebhookURL, slackBody(m), nil)
	case Mattermost:
		return postJSON(ctx, ch, ch.Secrets.WebhookURL, map[string]any{"text": markdown(m), "username": "Morcheh"}, nil)
	case Discord:
		return postJSON(ctx, ch, ch.Secrets.WebhookURL, discordBody(m), nil)
	case Teams:
		return postJSON(ctx, ch, ch.Secrets.WebhookURL, teamsBody(m), nil)
	case Ntfy:
		return sendNtfy(ctx, ch, m)
	case Gotify:
		return sendGotify(ctx, ch, m)
	case Pushover:
		return sendPushover(ctx, ch, m)
	}
	return fmt.Errorf("unknown kind of channel %q", ch.Kind)
}

// ---- Formatting ----

func emoji(event string) string {
	switch event {
	case EventDown:
		return "🔴"
	case EventUp:
		return "🟢"
	case EventDegraded:
		return "🟠"
	case EventReminder:
		return "🔁"
	}
	return "🔔"
}

// colour is the event's colour as 0xRRGGBB (Discord, Teams).
func colour(event string) int {
	switch event {
	case EventDown, EventReminder:
		return 0xe5484d
	case EventUp:
		return 0x30a46c
	case EventDegraded:
		return 0xf76b15
	}
	return 0x3e63dd
}

// Plain is the message as plain text.
func Plain(m Message) string {
	var b strings.Builder
	b.WriteString(emoji(m.Event) + " " + m.Title)
	if m.Text != "" {
		b.WriteString("\n\n" + m.Text)
	}
	if len(m.Fields) > 0 {
		b.WriteString("\n")
		for _, f := range m.Fields {
			b.WriteString("\n" + f.Name + ": " + f.Value)
		}
	}
	if m.URL != "" {
		b.WriteString("\n\n" + m.URL)
	}
	return b.String()
}

// bodyText is the text and fields without the title (for services that show
// the title on their own), and the link when withURL.
func bodyText(m Message, withURL bool) string {
	var parts []string
	if m.Text != "" {
		parts = append(parts, m.Text)
	}
	if len(m.Fields) > 0 {
		lines := make([]string, 0, len(m.Fields))
		for _, f := range m.Fields {
			lines = append(lines, f.Name+": "+f.Value)
		}
		parts = append(parts, strings.Join(lines, "\n"))
	}
	if withURL && m.URL != "" {
		parts = append(parts, m.URL)
	}
	if len(parts) == 0 {
		return m.Title
	}
	return strings.Join(parts, "\n\n")
}

func markdown(m Message) string {
	var b strings.Builder
	b.WriteString(emoji(m.Event) + " **" + m.Title + "**")
	if m.Text != "" {
		b.WriteString("\n" + m.Text)
	}
	for _, f := range m.Fields {
		b.WriteString("\n**" + f.Name + ":** " + f.Value)
	}
	if m.URL != "" {
		b.WriteString("\n[Open in Morcheh](" + m.URL + ")")
	}
	return b.String()
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func telegramHTML(m Message) string {
	var b strings.Builder
	b.WriteString(emoji(m.Event) + " <b>" + htmlEscape(m.Title) + "</b>")
	if m.Text != "" {
		b.WriteString("\n" + htmlEscape(m.Text))
	}
	if len(m.Fields) > 0 {
		b.WriteString("\n")
		for _, f := range m.Fields {
			b.WriteString("\n<b>" + htmlEscape(f.Name) + ":</b> " + htmlEscape(f.Value))
		}
	}
	if m.URL != "" {
		b.WriteString("\n\n<a href=\"" + htmlEscape(m.URL) + "\">Open in Morcheh</a>")
	}
	return b.String()
}

func slackBody(m Message) map[string]any {
	text := emoji(m.Event) + " *" + m.Title + "*"
	if m.Text != "" {
		text += "\n" + m.Text
	}
	for _, f := range m.Fields {
		text += "\n*" + f.Name + ":* " + f.Value
	}
	if m.URL != "" {
		text += "\n<" + m.URL + "|Open in Morcheh>"
	}
	return map[string]any{"text": text}
}

func discordBody(m Message) map[string]any {
	fields := []map[string]any{}
	for _, f := range m.Fields {
		fields = append(fields, map[string]any{"name": f.Name, "value": f.Value, "inline": true})
	}
	embed := map[string]any{
		"title":       emoji(m.Event) + " " + m.Title,
		"description": m.Text,
		"color":       colour(m.Event),
		"fields":      fields,
		"timestamp":   m.At.UTC().Format(time.RFC3339),
	}
	if m.URL != "" {
		embed["url"] = m.URL
	}
	return map[string]any{"username": "Morcheh", "embeds": []any{embed}}
}

func teamsBody(m Message) map[string]any {
	facts := []map[string]string{}
	for _, f := range m.Fields {
		facts = append(facts, map[string]string{"title": f.Name, "value": f.Value})
	}
	body := []any{
		map[string]any{"type": "TextBlock", "text": emoji(m.Event) + " " + m.Title, "weight": "Bolder", "size": "Medium", "wrap": true},
	}
	if m.Text != "" {
		body = append(body, map[string]any{"type": "TextBlock", "text": m.Text, "wrap": true})
	}
	if len(facts) > 0 {
		body = append(body, map[string]any{"type": "FactSet", "facts": facts})
	}
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard", "version": "1.4", "body": body,
	}
	if m.URL != "" {
		card["actions"] = []any{map[string]any{"type": "Action.OpenUrl", "title": "Open in Morcheh", "url": m.URL}}
	}
	return map[string]any{
		"type":        "message",
		"attachments": []any{map[string]any{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}},
	}
}

// ---- HTTP ----

func client(ch Channel) *http.Client {
	t := &http.Transport{
		Proxy:               nil,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	if ch.Dial != nil {
		t.DialContext = ch.Dial
	}
	return &http.Client{
		Transport: t,
		Timeout:   20 * time.Second,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

// do sends a request and turns a non-2xx answer into an error carrying the
// start of the body, where services explain what was wrong.
func do(ch Channel, req *http.Request) ([]byte, error) {
	res, err := client(ch).Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if res.StatusCode < 200 || res.StatusCode > 299 {
		msg := strings.TrimSpace(string(body))
		var j struct {
			Description string `json:"description"`
			Message     string `json:"message"`
			Error       any    `json:"error"`
			Errors      []any  `json:"errors"`
		}
		if json.Unmarshal(body, &j) == nil {
			switch {
			case j.Description != "":
				msg = j.Description
			case j.Message != "":
				msg = j.Message
			case j.Error != nil:
				msg = fmt.Sprint(j.Error)
			case len(j.Errors) > 0:
				msg = fmt.Sprint(j.Errors[0])
			}
		}
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		if msg == "" {
			return body, fmt.Errorf("the service answered %s", res.Status)
		}
		return body, fmt.Errorf("the service answered %s: %s", res.Status, msg)
	}
	return body, nil
}

func postJSON(ctx context.Context, ch Channel, target string, body any, headers map[string]string) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(target), bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Morcheh")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	_, err = do(ch, req)
	return err
}

// sendBot posts to a Telegram-style Bot API (Telegram itself, or Bale, whose
// API has the same shape).
func sendBot(ctx context.Context, ch Channel, m Message, base string, html bool) error {
	if ch.Config.APIURL != "" {
		base = strings.TrimRight(strings.TrimSpace(ch.Config.APIURL), "/")
	}
	body := map[string]any{
		"chat_id":              strings.TrimSpace(ch.Config.ChatID),
		"disable_notification": ch.Config.Silent,
	}
	if html {
		body["text"] = telegramHTML(m)
		body["parse_mode"] = "HTML"
		body["link_preview_options"] = map[string]any{"is_disabled": true}
	} else {
		body["text"] = Plain(m)
	}
	err := postJSON(ctx, ch, base+"/bot"+strings.TrimSpace(ch.Secrets.Token)+"/sendMessage", body, nil)
	if err != nil {
		// Never echo the token, which sits in the URL.
		return errors.New(strings.ReplaceAll(err.Error(), ch.Secrets.Token, "…"))
	}
	return nil
}

func priority(event string, set, low, normal, high int) int {
	if set > 0 {
		return set
	}
	switch event {
	case EventDown, EventReminder:
		return high
	case EventUp, EventTest:
		return normal
	}
	return low
}

func sendNtfy(ctx context.Context, ch Channel, m Message) error {
	base := strings.TrimRight(strings.TrimSpace(ch.Config.URL), "/")
	if base == "" {
		base = "https://ntfy.sh"
	}
	tag := map[string]string{EventDown: "red_circle", EventUp: "green_circle", EventDegraded: "orange_circle", EventReminder: "repeat"}[m.Event]
	body := map[string]any{
		"topic":    strings.TrimSpace(ch.Config.Topic),
		"title":    m.Title,
		"message":  bodyText(m, false),
		"priority": min(priority(m.Event, ch.Config.Priority, 2, 3, 5), 5),
	}
	if tag != "" {
		body["tags"] = []string{tag}
	}
	if m.URL != "" {
		body["click"] = m.URL
	}
	var headers map[string]string
	if ch.Secrets.Token != "" {
		headers = map[string]string{"Authorization": "Bearer " + ch.Secrets.Token}
	}
	return postJSON(ctx, ch, base, body, headers)
}

func sendGotify(ctx context.Context, ch Channel, m Message) error {
	base := strings.TrimRight(strings.TrimSpace(ch.Config.URL), "/")
	body := map[string]any{
		"title":    emoji(m.Event) + " " + m.Title,
		"message":  markdown(Message{Text: m.Text, Fields: m.Fields, URL: m.URL}),
		"priority": priority(m.Event, ch.Config.Priority, 2, 5, 8),
		"extras": map[string]any{
			"client::display": map[string]any{"contentType": "text/markdown"},
		},
	}
	if m.URL != "" {
		body["extras"].(map[string]any)["client::notification"] = map[string]any{"click": map[string]any{"url": m.URL}}
	}
	return postJSON(ctx, ch, base+"/message", body, map[string]string{"X-Gotify-Key": ch.Secrets.Token})
}

func sendPushover(ctx context.Context, ch Channel, m Message) error {
	form := url.Values{
		"token":   {ch.Secrets.Token},
		"user":    {ch.Secrets.UserKey},
		"title":   {emoji(m.Event) + " " + m.Title},
		"message": {bodyText(m, false)},
	}
	// Pushover priorities run -2..2; ours 0..4 map onto them.
	p := priority(m.Event, ch.Config.Priority, 1, 2, 3) - 2
	if ch.Config.Silent && p > -1 {
		p = -1
	}
	form.Set("priority", fmt.Sprint(p))
	if m.URL != "" {
		form.Set("url", m.URL)
		form.Set("url_title", "Open in Morcheh")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.pushover.net/1/messages.json", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err = do(ch, req)
	return err
}

// validHeaderName: an HTTP token (RFC 9110), as net/http would send it.
func validHeaderName(k string) bool {
	if k == "" {
		return false
	}
	for _, r := range k {
		if r > 0x7e || r <= ' ' || strings.ContainsRune(`"(),/:;<=>?@[\\]{}`, r) {
			return false
		}
	}
	return true
}
