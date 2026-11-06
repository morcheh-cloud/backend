package api

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/morcheh/backend/internal/technitium"
)

// DNSRecord is one record, flat whatever its type. Value is the address,
// target or text; MX and SRV add Priority, SRV adds Weight and Port, and CAA
// has Flags and Tag with Value as its value. Types Morcheh can't edit carry
// their data as text in Value, with Editable false.
type DNSRecord struct {
	Name     string `json:"name" doc:"Full name, like www.example.com"`
	Type     string `json:"type"`
	TTL      int64  `json:"ttl"`
	Disabled bool   `json:"disabled"`
	Comments string `json:"comments"`
	Value    string `json:"value"`
	Priority *int   `json:"priority,omitempty"`
	Weight   *int   `json:"weight,omitempty"`
	Port     *int   `json:"port,omitempty"`
	Flags    *int   `json:"flags,omitempty"`
	Tag      string `json:"tag,omitempty"`
	Editable bool   `json:"editable"`
}

// DNSRecordBody is a record to add, or what to change one to.
type DNSRecordBody struct {
	Name     string `json:"name" minLength:"1" maxLength:"255" doc:"Full name, like www.example.com"`
	Type     string `json:"type" enum:"A,AAAA,CNAME,ANAME,NS,PTR,MX,TXT,SRV,CAA"`
	TTL      int64  `json:"ttl,omitempty" minimum:"0" maximum:"2147483647" doc:"Seconds. 3600 when left out."`
	Disabled bool   `json:"disabled,omitempty"`
	Comments string `json:"comments,omitempty" maxLength:"500"`
	Value    string `json:"value" minLength:"1" maxLength:"8192"`
	Priority *int   `json:"priority,omitempty" minimum:"0" maximum:"65535"`
	Weight   *int   `json:"weight,omitempty" minimum:"0" maximum:"65535"`
	Port     *int   `json:"port,omitempty" minimum:"0" maximum:"65535"`
	Flags    *int   `json:"flags,omitempty" minimum:"0" maximum:"255"`
	Tag      string `json:"tag,omitempty" maxLength:"32"`
}

// editableTypes are the record types the forms and the writes cover.
var editableTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "ANAME": true, "NS": true, "PTR": true,
	"MX": true, "TXT": true, "SRV": true, "CAA": true,
}

// Which rData key holds a type's main value.
var valueKeys = map[string]string{
	"A": "ipAddress", "AAAA": "ipAddress", "CNAME": "cname", "ANAME": "aname",
	"NS": "nameServer", "PTR": "ptrName", "MX": "exchange", "TXT": "text",
	"SRV": "target", "CAA": "value",
}

func toDNSRecord(r technitium.RawRecord) DNSRecord {
	out := DNSRecord{
		Name: r.Name, Type: r.Type, TTL: r.TTL, Disabled: r.Disabled, Comments: r.Comments,
		Editable: editableTypes[r.Type],
	}
	if !out.Editable {
		out.Value = rdataText(r.RData)
		return out
	}
	out.Value = rdataString(r.RData, valueKeys[r.Type])
	switch r.Type {
	case "MX":
		out.Priority = rdataInt(r.RData, "preference")
	case "SRV":
		out.Priority = rdataInt(r.RData, "priority")
		out.Weight = rdataInt(r.RData, "weight")
		out.Port = rdataInt(r.RData, "port")
	case "CAA":
		out.Flags = rdataInt(r.RData, "flags")
		out.Tag = rdataString(r.RData, "tag")
	}
	return out
}

func rdataString(d map[string]any, key string) string {
	switch v := d[key].(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func rdataInt(d map[string]any, key string) *int {
	v, ok := d[key].(float64)
	if !ok {
		return nil
	}
	n := int(v)
	return &n
}

// rdataText shows a type Morcheh has no form for: "key: value" pairs in a
// stable order.
func rdataText(d map[string]any) string {
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		var v string
		switch t := d[k].(type) {
		case string:
			v = t
		default:
			b, err := json.Marshal(t)
			if err != nil {
				continue
			}
			v = string(b)
		}
		parts = append(parts, k+": "+v)
	}
	return strings.Join(parts, "  ")
}

// normalize checks a record against its zone, and tidies it. Errors point at
// the field, under the given location ("body", "body.new"…).
func (b *DNSRecordBody) normalize(zone, at string) error {
	field := func(name, msg string, value any) error {
		return fieldError(at+"."+name, msg, value)
	}
	b.Name = strings.TrimSuffix(strings.TrimSpace(b.Name), ".")
	if zone != "." && b.Name != zone && !strings.HasSuffix(strings.ToLower(b.Name), "."+strings.ToLower(zone)) {
		return field("name", "The name must be inside the zone "+zone, b.Name)
	}
	if b.Name == "" && zone != "." {
		return field("name", "Enter a name", b.Name)
	}
	if strings.ContainsAny(b.Name, " \t\r\n") {
		return field("name", "A name can't contain spaces", b.Name)
	}
	if b.TTL == 0 {
		b.TTL = 3600
	}
	if b.Type != "TXT" {
		b.Value = strings.TrimSpace(b.Value)
	}
	if b.Value == "" {
		return field("value", "Enter a value", b.Value)
	}
	switch b.Type {
	case "A", "AAAA":
		ip, err := netip.ParseAddr(b.Value)
		if err != nil || (b.Type == "A") != ip.Is4() {
			kind := "IPv4"
			if b.Type == "AAAA" {
				kind = "IPv6"
			}
			return field("value", "Enter an "+kind+" address", b.Value)
		}
	case "CNAME", "ANAME", "NS", "PTR", "MX", "SRV":
		b.Value = strings.TrimSuffix(b.Value, ".")
		if strings.ContainsAny(b.Value, " \t\r\n") {
			return field("value", "Enter a host name", b.Value)
		}
	}
	switch b.Type {
	case "MX":
		if b.Priority == nil {
			return field("priority", "Enter a priority", nil)
		}
	case "SRV":
		switch {
		case b.Priority == nil:
			return field("priority", "Enter a priority", nil)
		case b.Weight == nil:
			return field("weight", "Enter a weight", nil)
		case b.Port == nil:
			return field("port", "Enter a port", nil)
		}
	case "CAA":
		if b.Flags == nil {
			zero := 0
			b.Flags = &zero
		}
		if b.Tag == "" {
			return field("tag", "Choose a tag", b.Tag)
		}
	}
	return nil
}

// identity fills in the fields the DNS server finds a record by, which delete
// needs and update needs as "the current value".
func (b *DNSRecordBody) identity(form url.Values) {
	set := func(k, v string) { form.Set(k, v) }
	setInt := func(k string, v *int) {
		if v != nil {
			form.Set(k, strconv.Itoa(*v))
		}
	}
	switch b.Type {
	case "A", "AAAA":
		set("ipAddress", b.Value)
	case "CNAME":
		set("cname", b.Value)
	case "ANAME":
		set("aname", b.Value)
	case "NS":
		set("nameServer", b.Value)
	case "PTR":
		set("ptrName", b.Value)
	case "MX":
		set("exchange", b.Value)
		setInt("preference", b.Priority)
	case "TXT":
		set("text", b.Value)
		set("splitText", strconv.FormatBool(strings.Contains(b.Value, "\n")))
	case "SRV":
		set("target", b.Value)
		setInt("priority", b.Priority)
		setInt("weight", b.Weight)
		setInt("port", b.Port)
	case "CAA":
		set("value", b.Value)
		set("tag", b.Tag)
		setInt("flags", b.Flags)
	}
}

// changeTo fills in the "new" side of an update.
func (b *DNSRecordBody) changeTo(form url.Values) {
	set := func(k, v string) { form.Set(k, v) }
	setInt := func(k string, v *int) {
		if v != nil {
			form.Set(k, strconv.Itoa(*v))
		}
	}
	switch b.Type {
	case "A", "AAAA":
		set("newIpAddress", b.Value)
	case "CNAME":
		// There's only one CNAME at a name: "cname" is its new value.
		set("cname", b.Value)
	case "ANAME":
		set("newAName", b.Value)
	case "NS":
		set("newNameServer", b.Value)
	case "PTR":
		set("newPtrName", b.Value)
	case "MX":
		set("newExchange", b.Value)
		setInt("newPreference", b.Priority)
	case "TXT":
		set("newText", b.Value)
		set("newSplitText", strconv.FormatBool(strings.Contains(b.Value, "\n")))
	case "SRV":
		set("newTarget", b.Value)
		setInt("newPriority", b.Priority)
		setInt("newWeight", b.Weight)
		setInt("newPort", b.Port)
	case "CAA":
		set("newValue", b.Value)
		set("newTag", b.Tag)
		setInt("newFlags", b.Flags)
	}
}

// common is what every record write sends.
func recordForm(zone, name, kind string) url.Values {
	z := zone
	if z == "." {
		z = ""
	}
	return url.Values{"domain": {name}, "zone": {z}, "type": {kind}}
}

func (b *DNSRecordBody) addForm(zone string) url.Values {
	form := recordForm(zone, b.Name, b.Type)
	b.identity(form)
	form.Set("ttl", strconv.FormatInt(b.TTL, 10))
	form.Set("comments", b.Comments)
	form.Set("overwrite", "false")
	return form
}

func deleteForm(zone string, cur *DNSRecordBody) url.Values {
	form := recordForm(zone, cur.Name, cur.Type)
	cur.identity(form)
	return form
}

func updateForm(zone string, cur, next *DNSRecordBody) url.Values {
	form := recordForm(zone, cur.Name, cur.Type)
	cur.identity(form)
	next.changeTo(form)
	if !strings.EqualFold(cur.Name, next.Name) {
		form.Set("newDomain", next.Name)
	}
	form.Set("ttl", strconv.FormatInt(next.TTL, 10))
	form.Set("disable", strconv.FormatBool(next.Disabled))
	form.Set("comments", next.Comments)
	return form
}
