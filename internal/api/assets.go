package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morche/backend/internal/auth"
	"github.com/morche/backend/internal/database/sqlc"
	"github.com/morche/backend/internal/secrets"
)

// The asset inventory (tag Assets): every thing the organisation owns or pays
// for, in one list. Things Morche manages get a linked asset kept in step by
// syncAssets; hardware, licences, domains, subscriptions… are entered by
// hand. Ownership is information: it grants no access.

// Kinds Morche keeps in step with a section of its own.
var linkedAssetKinds = []string{"server", "database", "storage", "dns_server", "proxy", "website", "vm_cluster", "cloud_account", "web_service", "compose_project", "application"}

// Kinds the team enters by hand.
var manualAssetKinds = []string{"hardware", "virtual_machine", "cloud_resource", "software", "service", "license", "domain", "certificate", "subscription", "contract", "other"}

var assetRelationKinds = []string{"runs_on", "uses", "depends_on", "stored_in", "backs_up_to", "points_to", "connects_to", "part_of", "licensed_for", "assigned_to"}

type assetHandler struct {
	q       *sqlc.Queries
	box     *secrets.Box
	authz   *authz
	servers *serverHandler
	pve     *pveHandler
	cloud   *cloudHandler
	dns     *dnsHandler
	up      *uptimeHandler

	mu     sync.Mutex
	synced map[uuid.UUID]time.Time
}

func newAssetHandler(servers *serverHandler, a *authz) *assetHandler {
	return &assetHandler{q: servers.q, box: servers.box, authz: a, servers: servers, synced: map[uuid.UUID]time.Time{}}
}

// AssetLink is a link kept with an asset: a runbook, the vendor's portal…
type AssetLink struct {
	Label string `json:"label" maxLength:"100"`
	URL   string `json:"url" maxLength:"1000"`
}

// AssetOwner is who answers for an asset, and where that comes from.
type AssetOwner struct {
	UserID     string `json:"user_id,omitempty" format:"uuid"`
	UserName   string `json:"user_name,omitempty"`
	UserStatus string `json:"user_status,omitempty" doc:"blocked = the owner can't sign in any more"`
	GroupID    string `json:"group_id,omitempty" format:"uuid"`
	GroupName  string `json:"group_name,omitempty"`
	DeputyID   string `json:"deputy_id,omitempty" format:"uuid"`
	DeputyName string `json:"deputy_name,omitempty"`
	From       string `json:"from" enum:"asset,rule,none" doc:"asset: set on the asset; rule: from an owner rule; none: nobody"`
	RuleName   string `json:"rule_name,omitempty"`
}

// Asset is one entry of the inventory.
type Asset struct {
	ID             string            `json:"id" format:"uuid"`
	WorkspaceID    string            `json:"workspace_id" format:"uuid"`
	Kind           string            `json:"kind"`
	Category       string            `json:"category"`
	Name           string            `json:"name"`
	Description    string            `json:"description"`
	SourceKind     string            `json:"source_kind" doc:"The Morche section it mirrors; empty = entered by hand"`
	SourceRef      string            `json:"source_ref" doc:"Its id there (server/project for a compose project)"`
	SourceGone     bool              `json:"source_gone" doc:"It was removed from Morche; the asset stays for its history"`
	Facts          map[string]any    `json:"facts" doc:"What Morche knows about the source: status, address, versions…"`
	LastSeenAt     *time.Time        `json:"last_seen_at,omitempty"`
	OwnerUserID    string            `json:"owner_user_id,omitempty" format:"uuid"`
	OwnerGroupID   string            `json:"owner_group_id,omitempty" format:"uuid"`
	DeputyUserID   string            `json:"deputy_user_id,omitempty" format:"uuid"`
	Owner          AssetOwner        `json:"owner" doc:"Who answers for it after owner rules"`
	AssignedUserID string            `json:"assigned_user_id,omitempty" format:"uuid"`
	AssignedName   string            `json:"assigned_user_name,omitempty"`
	Environment    string            `json:"environment"`
	Criticality    int               `json:"criticality" doc:"1 = most critical … 4 = least; 0 = not set"`
	Classification string            `json:"classification"`
	Lifecycle      string            `json:"lifecycle"`
	Tags           []string          `json:"tags"`
	Vendor         string            `json:"vendor"`
	Model          string            `json:"model"`
	SerialNumber   string            `json:"serial_number"`
	AssetTag       string            `json:"asset_tag"`
	Location       string            `json:"location"`
	Cost           *float64          `json:"cost,omitempty"`
	Currency       string            `json:"currency"`
	Billing        string            `json:"billing"`
	CostCenter     string            `json:"cost_center"`
	PurchasedOn    string            `json:"purchased_on" doc:"YYYY-MM-DD"`
	WarrantyUntil  string            `json:"warranty_until" doc:"YYYY-MM-DD"`
	ExpiresOn      string            `json:"expires_on" doc:"YYYY-MM-DD: licence, domain, contract or subscription end"`
	AutoRenew      bool              `json:"auto_renew"`
	Seats          *int              `json:"seats,omitempty"`
	SeatsUsed      *int              `json:"seats_used,omitempty"`
	HasLicenseKey  bool              `json:"has_license_key"`
	Links          []AssetLink       `json:"links"`
	Fields         map[string]string `json:"fields" doc:"The team's own fields"`
	Notes          string            `json:"notes" doc:"Deprecated: notes are their own list now (list-asset-notes)"`
	NoteCount      int               `json:"note_count"`
	ChannelIDs     []string          `json:"channel_ids" doc:"Channels for reminders and owner alerts about it"`
	ReviewDays     int               `json:"review_days" doc:"Ask the owner to confirm it every N days; 0 = never"`
	ReviewedAt     *time.Time        `json:"reviewed_at,omitempty"`
	ReviewedByName string            `json:"reviewed_by_name"`
	CreatedByName  string            `json:"created_by_name"`
	UpdatedByName  string            `json:"updated_by_name"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at" doc:"Send it back as revision when saving"`
}

func idString(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

type assetRow struct {
	a                                                           sqlc.Asset
	ownerName, ownerStatus, groupName, deputyName, assignedName string
	hasKey                                                      bool
}

func rowOfList(r sqlc.ListAssetsRow) assetRow {
	return assetRow{r.Asset, r.OwnerUserName, r.OwnerUserStatus, r.OwnerGroupName, r.DeputyUserName, r.AssignedUserName, r.HasLicenseKey}
}

func rowOfGet(r sqlc.GetAssetRow) assetRow {
	return assetRow{r.Asset, r.OwnerUserName, r.OwnerUserStatus, r.OwnerGroupName, r.DeputyUserName, r.AssignedUserName, r.HasLicenseKey}
}

func toAsset(r assetRow, rules []sqlc.ListAssetOwnerRulesRow) Asset {
	a := r.a
	out := Asset{
		ID: a.ID.String(), WorkspaceID: a.WorkspaceID.String(), Kind: a.Kind, Category: a.Category,
		Name: a.Name, Description: a.Description, SourceKind: a.SourceKind, SourceRef: a.SourceRef,
		SourceGone: a.SourceGone, Facts: map[string]any{}, LastSeenAt: a.LastSeenAt,
		OwnerUserID: idString(a.OwnerUserID), OwnerGroupID: idString(a.OwnerGroupID), DeputyUserID: idString(a.DeputyUserID),
		AssignedUserID: idString(a.AssignedUserID), AssignedName: r.assignedName,
		Environment: a.Environment, Criticality: int(a.Criticality), Classification: a.Classification,
		Lifecycle: a.Lifecycle, Tags: a.Tags, Vendor: a.Vendor, Model: a.Model, SerialNumber: a.SerialNumber,
		AssetTag: a.AssetTag, Location: a.Location, Currency: a.Currency, Billing: a.Billing, CostCenter: a.CostCenter,
		PurchasedOn: a.PurchasedOn, WarrantyUntil: a.WarrantyUntil, ExpiresOn: a.ExpiresOn, AutoRenew: a.AutoRenew,
		HasLicenseKey: r.hasKey, Links: []AssetLink{}, Fields: map[string]string{}, Notes: a.Notes,
		ChannelIDs: []string{}, ReviewDays: int(a.ReviewDays), ReviewedAt: a.ReviewedAt, ReviewedByName: a.ReviewedByName,
		CreatedByName: a.CreatedByName, UpdatedByName: a.UpdatedByName, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
	}
	_ = json.Unmarshal(a.Facts, &out.Facts)
	_ = json.Unmarshal(a.Links, &out.Links)
	_ = json.Unmarshal(a.Fields, &out.Fields)
	if out.Tags == nil {
		out.Tags = []string{}
	}
	if a.CostCents != nil {
		c := float64(*a.CostCents) / 100
		out.Cost = &c
	}
	if a.Seats != nil {
		n := int(*a.Seats)
		out.Seats = &n
	}
	if a.SeatsUsed != nil {
		n := int(*a.SeatsUsed)
		out.SeatsUsed = &n
	}
	for _, c := range a.ChannelIds {
		out.ChannelIDs = append(out.ChannelIDs, c.String())
	}
	out.Owner = effectiveOwner(r, out, rules)
	return out
}

// assetTags is the asset's own tags plus its source's (a server's tags).
func assetTags(a Asset) []string {
	tags := slices.Clone(a.Tags)
	if raw, ok := a.Facts["tags"].([]any); ok {
		for _, t := range raw {
			if s, ok := t.(string); ok && !slices.Contains(tags, s) {
				tags = append(tags, s)
			}
		}
	}
	return tags
}

func ruleMatches(r sqlc.ListAssetOwnerRulesRow, a Asset) bool {
	if len(r.Kinds) > 0 && !slices.Contains(r.Kinds, a.Kind) {
		return false
	}
	if len(r.Environments) > 0 && !slices.Contains(r.Environments, a.Environment) {
		return false
	}
	if len(r.Tags) > 0 {
		tags := assetTags(a)
		if !slices.ContainsFunc(r.Tags, func(t string) bool { return slices.Contains(tags, t) }) {
			return false
		}
	}
	if r.NamePattern != "" {
		pat := strings.ToLower(r.NamePattern)
		if !strings.ContainsAny(pat, "*?[") {
			pat = "*" + pat + "*"
		}
		if ok, _ := path.Match(pat, strings.ToLower(a.Name)); !ok {
			return false
		}
	}
	return true
}

func effectiveOwner(r assetRow, a Asset, rules []sqlc.ListAssetOwnerRulesRow) AssetOwner {
	o := AssetOwner{From: "none", DeputyID: a.DeputyUserID, DeputyName: r.deputyName}
	if a.OwnerUserID != "" || a.OwnerGroupID != "" {
		o.From = "asset"
		o.UserID, o.UserName, o.UserStatus = a.OwnerUserID, r.ownerName, r.ownerStatus
		o.GroupID, o.GroupName = a.OwnerGroupID, r.groupName
		return o
	}
	for _, rule := range rules {
		if (rule.OwnerUserID == nil && rule.OwnerGroupID == nil) || !ruleMatches(rule, a) {
			continue
		}
		o.From, o.RuleName = "rule", cmpOr(rule.Name, "Owner rule")
		o.UserID, o.UserName = idString(rule.OwnerUserID), rule.OwnerUserName
		o.GroupID, o.GroupName = idString(rule.OwnerGroupID), rule.OwnerGroupName
		if o.DeputyID == "" {
			o.DeputyID, o.DeputyName = idString(rule.DeputyUserID), rule.DeputyUserName
		}
		return o
	}
	return o
}

// AssetBody is what the team writes about an asset. On a linked asset kind
// and name come from its source and are ignored.
type AssetBody struct {
	Kind           string            `json:"kind" maxLength:"40"`
	Category       string            `json:"category,omitempty" maxLength:"60"`
	Name           string            `json:"name" maxLength:"200"`
	Description    string            `json:"description,omitempty" maxLength:"2000"`
	OwnerUserID    string            `json:"owner_user_id,omitempty"`
	OwnerGroupID   string            `json:"owner_group_id,omitempty"`
	DeputyUserID   string            `json:"deputy_user_id,omitempty"`
	AssignedUserID string            `json:"assigned_user_id,omitempty"`
	Environment    string            `json:"environment,omitempty" enum:",production,staging,development,test"`
	Criticality    int               `json:"criticality,omitempty" minimum:"0" maximum:"4"`
	Classification string            `json:"classification,omitempty" enum:",public,internal,confidential,restricted"`
	Lifecycle      string            `json:"lifecycle,omitempty" enum:",planned,active,maintenance,deprecated,retired"`
	Tags           []string          `json:"tags,omitempty" maxItems:"50"`
	Vendor         string            `json:"vendor,omitempty" maxLength:"200"`
	Model          string            `json:"model,omitempty" maxLength:"200"`
	SerialNumber   string            `json:"serial_number,omitempty" maxLength:"200"`
	AssetTag       string            `json:"asset_tag,omitempty" maxLength:"100"`
	Location       string            `json:"location,omitempty" maxLength:"200"`
	Cost           *float64          `json:"cost,omitempty" minimum:"0"`
	Currency       string            `json:"currency,omitempty" maxLength:"8"`
	Billing        string            `json:"billing,omitempty" enum:",once,monthly,yearly"`
	CostCenter     string            `json:"cost_center,omitempty" maxLength:"100"`
	PurchasedOn    string            `json:"purchased_on,omitempty"`
	WarrantyUntil  string            `json:"warranty_until,omitempty"`
	ExpiresOn      string            `json:"expires_on,omitempty"`
	AutoRenew      bool              `json:"auto_renew,omitempty"`
	Seats          *int              `json:"seats,omitempty" minimum:"0"`
	SeatsUsed      *int              `json:"seats_used,omitempty" minimum:"0"`
	LicenseKey     string            `json:"license_key,omitempty" maxLength:"10000" doc:"Empty = keep the saved one"`
	ClearKey       bool              `json:"clear_license_key,omitempty"`
	Links          []AssetLink       `json:"links,omitempty" maxItems:"20"`
	Fields         map[string]string `json:"fields,omitempty"`
	Notes          string            `json:"notes,omitempty" maxLength:"20000"`
	ChannelIDs     []string          `json:"channel_ids,omitempty" maxItems:"20"`
	ReviewDays     int               `json:"review_days,omitempty" minimum:"0" maximum:"3650"`
	Revision       *time.Time        `json:"revision,omitempty" doc:"The asset's updated_at when you loaded it: 409 when someone saved in between"`
}

type assetValues struct {
	owner, group, deputy, assigned *uuid.UUID
	cost                           *int64
	seats, used                    *int32
	links, fields                  []byte
	channels                       []uuid.UUID
	tags                           []string
}

func assetID(s, field string) (*uuid.UUID, error) {
	if s == "" {
		return nil, nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return nil, fieldError("body."+field, "Pick from the list", s)
	}
	return &id, nil
}

func checkDate(s, field string) error {
	if s == "" {
		return nil
	}
	if _, err := time.Parse(time.DateOnly, s); err != nil {
		return fieldError("body."+field, "Use a date like 2027-03-31", s)
	}
	return nil
}

// checkAsset validates a body and turns it into column values. linked =
// the kind and name are not the body's to set.
func (h *assetHandler) checkAsset(ctx context.Context, ws uuid.UUID, b *AssetBody, linked bool) (assetValues, error) {
	var v assetValues
	b.Name = strings.TrimSpace(b.Name)
	if !linked {
		if !slices.Contains(manualAssetKinds, b.Kind) {
			return v, fieldError("body.kind", "Pick what kind of asset this is", b.Kind)
		}
		if b.Name == "" {
			return v, fieldError("body.name", "Give it a name", nil)
		}
	}
	if b.Lifecycle == "" {
		b.Lifecycle = "active"
	}
	var err error
	if v.owner, err = assetID(b.OwnerUserID, "owner_user_id"); err != nil {
		return v, err
	}
	if v.group, err = assetID(b.OwnerGroupID, "owner_group_id"); err != nil {
		return v, err
	}
	if v.deputy, err = assetID(b.DeputyUserID, "deputy_user_id"); err != nil {
		return v, err
	}
	if v.assigned, err = assetID(b.AssignedUserID, "assigned_user_id"); err != nil {
		return v, err
	}
	for f, d := range map[string]string{"purchased_on": b.PurchasedOn, "warranty_until": b.WarrantyUntil, "expires_on": b.ExpiresOn} {
		if err := checkDate(d, f); err != nil {
			return v, err
		}
	}
	if b.Seats != nil && b.SeatsUsed != nil && *b.SeatsUsed > *b.Seats*10+1000 {
		return v, fieldError("body.seats_used", "That's far more than the seats bought", *b.SeatsUsed)
	}
	if b.Cost != nil {
		c := int64(*b.Cost*100 + 0.5)
		v.cost = &c
	}
	if b.Seats != nil {
		n := int32(*b.Seats)
		v.seats = &n
	}
	if b.SeatsUsed != nil {
		n := int32(*b.SeatsUsed)
		v.used = &n
	}
	links := []AssetLink{}
	for i, l := range b.Links {
		l.Label, l.URL = strings.TrimSpace(l.Label), strings.TrimSpace(l.URL)
		if l.URL == "" {
			continue
		}
		if !strings.HasPrefix(l.URL, "https://") && !strings.HasPrefix(l.URL, "http://") {
			return v, fieldError(fmt.Sprintf("body.links[%d].url", i), "Start the address with https://", l.URL)
		}
		links = append(links, l)
	}
	v.links, _ = json.Marshal(links)
	fields := map[string]string{}
	if len(b.Fields) > 50 {
		return v, fieldError("body.fields", "Keep it to 50 fields", nil)
	}
	for k, val := range b.Fields {
		k = strings.TrimSpace(k)
		if k == "" || len(k) > 60 || len(val) > 1000 {
			continue
		}
		fields[k] = val
	}
	v.fields, _ = json.Marshal(fields)
	v.tags = []string{}
	for _, t := range b.Tags {
		t = strings.TrimSpace(t)
		if t != "" && len(t) <= 40 && !slices.Contains(v.tags, t) {
			v.tags = append(v.tags, t)
		}
	}
	v.channels = []uuid.UUID{}
	if len(b.ChannelIDs) > 0 {
		ids := make([]uuid.UUID, 0, len(b.ChannelIDs))
		for _, s := range b.ChannelIDs {
			id, err := uuid.Parse(s)
			if err != nil {
				return v, fieldError("body.channel_ids", "Pick channels from the list", s)
			}
			ids = append(ids, id)
		}
		found, err := h.q.AssetReminderChannels(ctx, sqlc.AssetReminderChannelsParams{WorkspaceID: ws, Ids: ids})
		if err != nil {
			return v, internalError(err)
		}
		for _, c := range found {
			v.channels = append(v.channels, c.ID)
		}
		if len(v.channels) != len(ids) {
			return v, fieldError("body.channel_ids", "A channel isn't in this workspace or is turned off", nil)
		}
	}
	return v, nil
}

func byName(p *principal) string {
	if p == nil {
		return "Morche"
	}
	return cmpOr(p.User.FullName, p.User.Username)
}

// AssetChange is one field changed in an asset's history.
type AssetChange struct {
	Field string `json:"field"`
	From  string `json:"from"`
	To    string `json:"to"`
}

// AssetEvent is one entry of an asset's history.
type AssetEvent struct {
	ID      string        `json:"id" format:"uuid"`
	At      time.Time     `json:"at"`
	ByName  string        `json:"by_name"`
	Action  string        `json:"action" doc:"created, updated, found, gone, back, reviewed, key-shown, related, unrelated"`
	Changes []AssetChange `json:"changes"`
}

func (h *assetHandler) event(ctx context.Context, id uuid.UUID, by, action string, changes []AssetChange) {
	if changes == nil {
		changes = []AssetChange{}
	}
	raw, _ := json.Marshal(changes)
	if err := h.q.AddAssetEvent(ctx, sqlc.AddAssetEventParams{AssetID: id, ByName: by, Action: action, Changes: raw}); err != nil {
		slog.Warn("assets: add event", "asset", id, "error", err)
	}
}

// diffAssets lists what a save changed, for the history. Names stand in for
// ids, so the trail stays readable after people leave.
func diffAssets(old, next Asset) []AssetChange {
	str := func(v any) string {
		switch x := v.(type) {
		case nil:
			return ""
		case *float64:
			if x == nil {
				return ""
			}
			return strconv.FormatFloat(*x, 'f', 2, 64)
		case *int:
			if x == nil {
				return ""
			}
			return strconv.Itoa(*x)
		case []string:
			return strings.Join(x, ", ")
		case bool:
			if x {
				return "yes"
			}
			return "no"
		case int:
			return strconv.Itoa(x)
		case string:
			return x
		default:
			b, _ := json.Marshal(x)
			return string(b)
		}
	}
	owner := func(a Asset) string {
		return strings.Trim(a.Owner.UserName+" / "+a.Owner.GroupName, " /")
	}
	pairs := []struct {
		f    string
		a, b any
	}{
		{"kind", old.Kind, next.Kind}, {"category", old.Category, next.Category}, {"name", old.Name, next.Name},
		{"description", old.Description, next.Description}, {"owner", owner(old), owner(next)},
		{"deputy", old.Owner.DeputyName, next.Owner.DeputyName}, {"assigned to", old.AssignedName, next.AssignedName},
		{"environment", old.Environment, next.Environment}, {"criticality", old.Criticality, next.Criticality},
		{"classification", old.Classification, next.Classification}, {"lifecycle", old.Lifecycle, next.Lifecycle},
		{"tags", old.Tags, next.Tags}, {"vendor", old.Vendor, next.Vendor}, {"model", old.Model, next.Model},
		{"serial number", old.SerialNumber, next.SerialNumber}, {"asset tag", old.AssetTag, next.AssetTag},
		{"location", old.Location, next.Location}, {"cost", old.Cost, next.Cost}, {"currency", old.Currency, next.Currency},
		{"billing", old.Billing, next.Billing}, {"cost center", old.CostCenter, next.CostCenter},
		{"purchased", old.PurchasedOn, next.PurchasedOn}, {"warranty until", old.WarrantyUntil, next.WarrantyUntil},
		{"expires", old.ExpiresOn, next.ExpiresOn}, {"auto renew", old.AutoRenew, next.AutoRenew},
		{"seats", old.Seats, next.Seats}, {"seats used", old.SeatsUsed, next.SeatsUsed},
		{"licence key", old.HasLicenseKey, next.HasLicenseKey}, {"links", old.Links, next.Links},
		{"fields", old.Fields, next.Fields}, {"review every (days)", old.ReviewDays, next.ReviewDays},
		{"channels", len(old.ChannelIDs), len(next.ChannelIDs)},
	}
	out := []AssetChange{}
	for _, p := range pairs {
		a, b := str(p.a), str(p.b)
		if a != b {
			if len(a) > 200 {
				a = a[:200] + "…"
			}
			if len(b) > 200 {
				b = b[:200] + "…"
			}
			out = append(out, AssetChange{Field: p.f, From: a, To: b})
		}
	}
	if old.Notes != next.Notes {
		out = append(out, AssetChange{Field: "notes", From: "", To: "changed"})
	}
	return out
}

// syncAssets brings the linked assets of a workspace in step with Morche,
// at most every 20 seconds unless forced.
func (h *assetHandler) syncAssets(ctx context.Context, ws uuid.UUID, force bool) {
	h.mu.Lock()
	if !force && time.Since(h.synced[ws]) < 20*time.Second {
		h.mu.Unlock()
		return
	}
	h.synced[ws] = time.Now()
	h.mu.Unlock()
	rows, err := h.q.SyncAssetSources(ctx, ws)
	if err != nil {
		slog.Warn("assets: sync", "workspace", ws, "error", err)
		return
	}
	for _, r := range rows {
		if r.Inserted {
			h.event(ctx, r.ID, "Morche", "found", nil)
		}
	}
	gone, err := h.q.MarkGoneAssets(ctx, ws)
	if err != nil {
		slog.Warn("assets: mark gone", "workspace", ws, "error", err)
	}
	for _, id := range gone {
		h.event(ctx, id, "Morche", "gone", nil)
	}
	if err := h.q.SyncAssetRelations(ctx, ws); err != nil {
		slog.Warn("assets: sync relations", "workspace", ws, "error", err)
	}
	if err := h.q.PruneAssetRelations(ctx, ws); err != nil {
		slog.Warn("assets: prune relations", "workspace", ws, "error", err)
	}
}

func (h *assetHandler) rules(ctx context.Context, ws uuid.UUID) []sqlc.ListAssetOwnerRulesRow {
	rules, err := h.q.ListAssetOwnerRules(ctx, ws)
	if err != nil {
		slog.Warn("assets: owner rules", "error", err)
	}
	return rules
}

func (h *assetHandler) load(ctx context.Context, rawID string) (Asset, sqlc.Asset, error) {
	row, err := h.q.GetAsset(ctx, uuid.MustParse(rawID))
	if isNotFound(err) {
		return Asset{}, sqlc.Asset{}, huma.Error404NotFound("asset not found")
	}
	if err != nil {
		return Asset{}, sqlc.Asset{}, internalError(err)
	}
	return toAsset(rowOfGet(row), h.rules(ctx, row.Asset.WorkspaceID)), row.Asset, nil
}

// AssetRelation is a link between two assets.
type AssetRelation struct {
	ID        string    `json:"id" format:"uuid"`
	FromID    string    `json:"from_id" format:"uuid"`
	ToID      string    `json:"to_id" format:"uuid"`
	Kind      string    `json:"kind" enum:"runs_on,uses,depends_on,stored_in,backs_up_to,points_to,connects_to,part_of,licensed_for,assigned_to"`
	Note      string    `json:"note"`
	Origin    string    `json:"origin" enum:"manual,discovered"`
	CreatedAt time.Time `json:"created_at"`
}

func toAssetRelation(r sqlc.AssetRelation) AssetRelation {
	return AssetRelation{ID: r.ID.String(), FromID: r.FromID.String(), ToID: r.ToID.String(), Kind: r.Kind, Note: r.Note, Origin: r.Origin, CreatedAt: r.CreatedAt}
}

type AssetIDPath struct {
	ID string `path:"id" format:"uuid"`
}

type AssetRelationPath struct {
	ID       string `path:"id" format:"uuid"`
	Relation string `path:"relation" format:"uuid"`
}

type AssetOutput struct{ Body Asset }

type assetList struct {
	Items []Asset `json:"items"`
}

type AssetDetail struct {
	Asset     Asset           `json:"asset"`
	Relations []AssetRelation `json:"relations"`
	Related   []Asset         `json:"related" doc:"The assets at the other end of its relations"`
	Events    []AssetEvent    `json:"events"`
}

func (h *assetHandler) create(ctx context.Context, ws uuid.UUID, b AssetBody) (uuid.UUID, error) {
	v, err := h.checkAsset(ctx, ws, &b, false)
	if err != nil {
		return uuid.Nil, err
	}
	var key []byte
	if b.LicenseKey != "" {
		key = h.box.Seal(b.LicenseKey)
	}
	by := byName(principalOf(ctx))
	id, err := h.q.CreateAsset(ctx, sqlc.CreateAssetParams{
		WorkspaceID: ws, Kind: b.Kind, Category: strings.TrimSpace(b.Category), Name: b.Name, Description: b.Description,
		OwnerUserID: v.owner, OwnerGroupID: v.group, DeputyUserID: v.deputy, AssignedUserID: v.assigned,
		Environment: b.Environment, Criticality: int16(b.Criticality), Classification: b.Classification,
		Lifecycle: b.Lifecycle, Tags: v.tags, Vendor: b.Vendor, Model: b.Model, SerialNumber: b.SerialNumber,
		AssetTag: b.AssetTag, Location: b.Location, CostCents: v.cost, Currency: strings.ToUpper(b.Currency),
		Billing: b.Billing, CostCenter: b.CostCenter, PurchasedOn: b.PurchasedOn, WarrantyUntil: b.WarrantyUntil,
		ExpiresOn: b.ExpiresOn, AutoRenew: b.AutoRenew, Seats: v.seats, SeatsUsed: v.used, LicenseKeyEnc: key,
		Links: v.links, Fields: v.fields, Notes: "", ChannelIds: v.channels, ReviewDays: int32(b.ReviewDays),
		CreatedByName: by,
	})
	if isForeignKeyViolation(err) {
		return uuid.Nil, huma.Error422UnprocessableEntity("A person or group you picked no longer exists")
	}
	if err != nil {
		return uuid.Nil, internalError(err)
	}
	h.event(ctx, id, by, "created", nil)
	// Text in the old notes field (a CSV column) becomes the first note.
	if strings.TrimSpace(b.Notes) != "" {
		p := principalOf(ctx)
		var uid *uuid.UUID
		if p != nil {
			uid = p.ID()
		}
		if _, err := h.q.CreateAssetNote(ctx, sqlc.CreateAssetNoteParams{
			AssetID: id, Body: b.Notes, CreatedBy: uid, CreatedByName: by,
		}); err != nil {
			slog.Warn("assets: first note", "asset", id, "error", err)
		}
	}
	return id, nil
}

// saveAsset writes b over the stored asset, keeping what a linked asset
// takes from its source, and records the change.
func (h *assetHandler) saveAsset(ctx context.Context, old Asset, stored sqlc.Asset, b AssetBody, action string) (Asset, error) {
	linked := stored.SourceKind != ""
	if linked {
		b.Kind, b.Name = stored.Kind, stored.Name
	}
	v, err := h.checkAsset(ctx, stored.WorkspaceID, &b, linked)
	if err != nil {
		return Asset{}, err
	}
	by := byName(principalOf(ctx))
	err = h.q.UpdateAsset(ctx, sqlc.UpdateAssetParams{
		ID: stored.ID, Kind: b.Kind, Category: strings.TrimSpace(b.Category), Name: b.Name, Description: b.Description,
		OwnerUserID: v.owner, OwnerGroupID: v.group, DeputyUserID: v.deputy, AssignedUserID: v.assigned,
		Environment: b.Environment, Criticality: int16(b.Criticality), Classification: b.Classification,
		Lifecycle: b.Lifecycle, Tags: v.tags, Vendor: b.Vendor, Model: b.Model, SerialNumber: b.SerialNumber,
		AssetTag: b.AssetTag, Location: b.Location, CostCents: v.cost, Currency: strings.ToUpper(b.Currency),
		Billing: b.Billing, CostCenter: b.CostCenter, PurchasedOn: b.PurchasedOn, WarrantyUntil: b.WarrantyUntil,
		ExpiresOn: b.ExpiresOn, AutoRenew: b.AutoRenew, Seats: v.seats, SeatsUsed: v.used,
		Links: v.links, Fields: v.fields, Notes: b.Notes, ChannelIds: v.channels, ReviewDays: int32(b.ReviewDays),
		UpdatedByName: by,
	})
	if isForeignKeyViolation(err) {
		return Asset{}, huma.Error422UnprocessableEntity("A person or group you picked no longer exists")
	}
	if err != nil {
		return Asset{}, internalError(err)
	}
	if b.ClearKey {
		err = h.q.SetAssetLicenseKey(ctx, sqlc.SetAssetLicenseKeyParams{ID: stored.ID})
	} else if b.LicenseKey != "" {
		err = h.q.SetAssetLicenseKey(ctx, sqlc.SetAssetLicenseKeyParams{ID: stored.ID, LicenseKeyEnc: h.box.Seal(b.LicenseKey)})
	}
	if err != nil {
		return Asset{}, internalError(err)
	}
	next, _, err := h.load(ctx, stored.ID.String())
	if err != nil {
		return Asset{}, err
	}
	if changes := diffAssets(old, next); len(changes) > 0 {
		h.event(ctx, stored.ID, by, action, changes)
	}
	return next, nil
}

// bodyOf is the stored asset as a body, for partial (bulk) changes.
func bodyOf(a Asset) AssetBody {
	b := AssetBody{
		Kind: a.Kind, Category: a.Category, Name: a.Name, Description: a.Description,
		OwnerUserID: a.OwnerUserID, OwnerGroupID: a.OwnerGroupID, DeputyUserID: a.DeputyUserID, AssignedUserID: a.AssignedUserID,
		Environment: a.Environment, Criticality: a.Criticality, Classification: a.Classification, Lifecycle: a.Lifecycle,
		Tags: a.Tags, Vendor: a.Vendor, Model: a.Model, SerialNumber: a.SerialNumber, AssetTag: a.AssetTag,
		Location: a.Location, Cost: a.Cost, Currency: a.Currency, Billing: a.Billing, CostCenter: a.CostCenter,
		PurchasedOn: a.PurchasedOn, WarrantyUntil: a.WarrantyUntil, ExpiresOn: a.ExpiresOn, AutoRenew: a.AutoRenew,
		Seats: a.Seats, SeatsUsed: a.SeatsUsed, Links: a.Links, Fields: a.Fields, Notes: a.Notes,
		ChannelIDs: a.ChannelIDs, ReviewDays: a.ReviewDays,
	}
	return b
}

// AssetBulkBody changes several assets at once; a field left out is kept.
type AssetBulkBody struct {
	IDs            []string `json:"ids" minItems:"1" maxItems:"1000"`
	OwnerUserID    *string  `json:"owner_user_id,omitempty" doc:"Empty string = clear"`
	OwnerGroupID   *string  `json:"owner_group_id,omitempty" doc:"Empty string = clear"`
	DeputyUserID   *string  `json:"deputy_user_id,omitempty" doc:"Empty string = clear"`
	Environment    *string  `json:"environment,omitempty" enum:",production,staging,development,test"`
	Criticality    *int     `json:"criticality,omitempty" minimum:"0" maximum:"4"`
	Classification *string  `json:"classification,omitempty" enum:",public,internal,confidential,restricted"`
	Lifecycle      *string  `json:"lifecycle,omitempty" enum:"planned,active,maintenance,deprecated,retired"`
	ReviewDays     *int     `json:"review_days,omitempty" minimum:"0" maximum:"3650"`
	AddTags        []string `json:"add_tags,omitempty" maxItems:"20"`
	RemoveTags     []string `json:"remove_tags,omitempty" maxItems:"20"`
}

// AssetImportError is a row that couldn't be imported.
type AssetImportError struct {
	Row     int    `json:"row" doc:"Index in items"`
	Message string `json:"message"`
}

func assetProblemText(err error) string {
	if se, ok := err.(huma.StatusError); ok {
		if m, ok := err.(*huma.ErrorModel); ok {
			msg := m.Detail
			for _, e := range m.Errors {
				if e != nil && e.Message != "" && e.Message != msg {
					msg += ": " + e.Message
				}
			}
			return msg
		}
		return se.Error()
	}
	return err.Error()
}

// AssetPerson is someone who can own or hold an asset.
type AssetPerson struct {
	ID       string `json:"id" format:"uuid"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Status   string `json:"status"`
}

type AssetGroup struct {
	ID      string `json:"id" format:"uuid"`
	Name    string `json:"name"`
	Members int    `json:"members"`
}

// AssetOwnerRule gives an owner to assets that have none of their own.
type AssetOwnerRule struct {
	ID           string   `json:"id,omitempty" format:"uuid" readOnly:"true"`
	Name         string   `json:"name" maxLength:"100"`
	Kinds        []string `json:"kinds" maxItems:"30"`
	Tags         []string `json:"tags" maxItems:"30"`
	Environments []string `json:"environments" maxItems:"5"`
	NamePattern  string   `json:"name_pattern" maxLength:"200" doc:"Matches names; * and ? work, plain text = contains"`
	OwnerUserID  string   `json:"owner_user_id,omitempty"`
	OwnerGroupID string   `json:"owner_group_id,omitempty"`
	DeputyUserID string   `json:"deputy_user_id,omitempty"`
	OwnerName    string   `json:"owner_name,omitempty" readOnly:"true"`
	GroupName    string   `json:"group_name,omitempty" readOnly:"true"`
	DeputyName   string   `json:"deputy_name,omitempty" readOnly:"true"`
}

type assetRuleList struct {
	Items []AssetOwnerRule `json:"items"`
}

// AssetSettings are a workspace's inventory settings.
type AssetSettings struct {
	AutoDiscover    bool       `json:"auto_discover" doc:"Look for unlisted assets on a schedule"`
	DiscoverHours   int        `json:"discover_hours" minimum:"1" maximum:"720"`
	RemindDays      []int      `json:"remind_days" maxItems:"6" doc:"Days before an expiry to send a reminder"`
	ChannelIDs      []string   `json:"channel_ids" maxItems:"20" doc:"Where reminders go; empty = the workspace's default channels"`
	NotifyOwners    bool       `json:"notify_owners" doc:"Also send alert rule notifications to the channels set on the asset"`
	LastDiscoveryAt *time.Time `json:"last_discovery_at,omitempty" readOnly:"true"`
}

func toAssetSettings(s sqlc.AssetSetting) AssetSettings {
	out := AssetSettings{AutoDiscover: s.AutoDiscover, DiscoverHours: int(s.DiscoverHours), RemindDays: []int{}, ChannelIDs: []string{}, NotifyOwners: s.NotifyOwners, LastDiscoveryAt: s.LastDiscoveryAt}
	for _, d := range s.RemindDays {
		out.RemindDays = append(out.RemindDays, int(d))
	}
	for _, c := range s.ChannelIds {
		out.ChannelIDs = append(out.ChannelIDs, c.String())
	}
	return out
}

func (h *assetHandler) settings(ctx context.Context, ws uuid.UUID) (sqlc.AssetSetting, error) {
	s, err := h.q.GetAssetSettings(ctx, ws)
	if isNotFound(err) {
		return sqlc.AssetSetting{WorkspaceID: ws, AutoDiscover: true, DiscoverHours: 24, RemindDays: []int32{30, 7, 1}, ChannelIds: []uuid.UUID{}, NotifyOwners: true}, nil
	}
	return s, err
}

// mayReview: the owner, their deputy, a member of the owning group, or an
// Operator on the workspace.
func (h *assetHandler) mayReview(ctx context.Context, p *principal, a Asset) bool {
	if p.Level >= auth.Operator {
		return true
	}
	me := p.User.ID.String()
	if a.Owner.UserID == me || a.Owner.DeputyID == me {
		return true
	}
	if a.Owner.GroupID != "" {
		ids, err := h.q.GroupMemberIDs(ctx, uuid.MustParse(a.Owner.GroupID))
		return err == nil && slices.Contains(ids, p.User.ID)
	}
	return false
}

func registerAssets(api huma.API, h *assetHandler) {
	tags := []string{"Assets"}

	huma.Register(api, huma.Operation{
		OperationID: "list-assets",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/assets",
		Summary:     "List the workspace's assets",
		Description: "Everything in the inventory: assets entered by hand plus one linked asset per server, database, storage, DNS server, proxy, site, Proxmox cluster, cloud account, web service, compose project and installed application, kept in step with Morche on every read.",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*struct{ Body assetList }, error) {
		ws := uuid.MustParse(in.ID)
		h.syncAssets(ctx, ws, false)
		rows, err := h.q.ListAssets(ctx, ws)
		if err != nil {
			return nil, internalError(err)
		}
		rules := h.rules(ctx, ws)
		counts := map[uuid.UUID]int{}
		if cs, err := h.q.CountAssetNotesByWorkspace(ctx, ws); err == nil {
			for _, c := range cs {
				counts[c.AssetID] = int(c.Notes)
			}
		}
		out := &struct{ Body assetList }{}
		out.Body.Items = make([]Asset, len(rows))
		for i, r := range rows {
			out.Body.Items[i] = toAsset(rowOfList(r), rules)
			out.Body.Items[i].NoteCount = counts[r.Asset.ID]
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-asset",
		Method:        http.MethodPost,
		Path:          "/workspaces/{id}/assets",
		Summary:       "Add an asset by hand",
		Description:   "Hardware, a licence, a domain, a subscription… Things Morche manages are added in their own section and show up here by themselves.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body AssetBody
	}) (*AssetOutput, error) {
		ws := uuid.MustParse(in.ID)
		if n, err := h.q.CountAssets(ctx, ws); err == nil && n >= 20000 {
			return nil, huma.Error409Conflict("This workspace already has 20,000 assets")
		}
		id, err := h.create(ctx, ws, in.Body)
		if err != nil {
			return nil, err
		}
		a, _, err := h.load(ctx, id.String())
		if err != nil {
			return nil, err
		}
		return &AssetOutput{a}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "import-assets",
		Method:      http.MethodPost,
		Path:        "/workspaces/{id}/assets/import",
		Summary:     "Add many assets at once",
		Description: "Each item is added like create-asset; rows that fail are listed and the rest are kept.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body struct {
			Items []AssetBody `json:"items" minItems:"1" maxItems:"1000"`
		}
	}) (*struct {
		Body struct {
			Created int                `json:"created"`
			Errors  []AssetImportError `json:"errors"`
		}
	}, error) {
		ws := uuid.MustParse(in.ID)
		out := &struct {
			Body struct {
				Created int                `json:"created"`
				Errors  []AssetImportError `json:"errors"`
			}
		}{}
		out.Body.Errors = []AssetImportError{}
		for i, b := range in.Body.Items {
			if _, err := h.create(ctx, ws, b); err != nil {
				out.Body.Errors = append(out.Body.Errors, AssetImportError{Row: i, Message: assetProblemText(err)})
				continue
			}
			out.Body.Created++
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "bulk-update-assets",
		Method:      http.MethodPost,
		Path:        "/workspaces/{id}/assets/bulk",
		Summary:     "Change several assets at once",
		Description: "Sets the owner, environment, criticality, classification, lifecycle or review period, or adds and removes tags, on every asset listed.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body AssetBulkBody
	}) (*struct {
		Body struct {
			Changed int `json:"changed"`
		}
	}, error) {
		ws := uuid.MustParse(in.ID)
		b := in.Body
		out := &struct {
			Body struct {
				Changed int `json:"changed"`
			}
		}{}
		for _, raw := range b.IDs {
			id, err := uuid.Parse(raw)
			if err != nil {
				return nil, fieldError("body.ids", "Not an asset id", raw)
			}
			old, stored, err := h.load(ctx, id.String())
			if err != nil || stored.WorkspaceID != ws {
				return nil, huma.Error404NotFound("asset not found")
			}
			nb := bodyOf(old)
			if b.OwnerUserID != nil {
				nb.OwnerUserID = *b.OwnerUserID
			}
			if b.OwnerGroupID != nil {
				nb.OwnerGroupID = *b.OwnerGroupID
			}
			if b.DeputyUserID != nil {
				nb.DeputyUserID = *b.DeputyUserID
			}
			if b.Environment != nil {
				nb.Environment = *b.Environment
			}
			if b.Criticality != nil {
				nb.Criticality = *b.Criticality
			}
			if b.Classification != nil {
				nb.Classification = *b.Classification
			}
			if b.Lifecycle != nil {
				nb.Lifecycle = *b.Lifecycle
			}
			if b.ReviewDays != nil {
				nb.ReviewDays = *b.ReviewDays
			}
			nb.Tags = append(slices.Clone(nb.Tags), b.AddTags...)
			nb.Tags = slices.DeleteFunc(nb.Tags, func(t string) bool { return slices.Contains(b.RemoveTags, t) })
			if _, err := h.saveAsset(ctx, old, stored, nb, "updated"); err != nil {
				return nil, err
			}
			out.Body.Changed++
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-asset",
		Method:      http.MethodGet,
		Path:        "/assets/{id}",
		Summary:     "Read an asset with its relations and history",
		Tags:        tags,
	}, func(ctx context.Context, in *AssetIDPath) (*struct{ Body AssetDetail }, error) {
		a, stored, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if stored.SourceKind != "" {
			h.syncAssets(ctx, stored.WorkspaceID, false)
			if a, stored, err = h.load(ctx, in.ID); err != nil {
				return nil, err
			}
		}
		out := &struct{ Body AssetDetail }{}
		if n, err := h.q.CountAssetNotes(ctx, stored.ID); err == nil {
			a.NoteCount = int(n)
		}
		out.Body.Asset = a
		out.Body.Relations = []AssetRelation{}
		out.Body.Related = []Asset{}
		out.Body.Events = []AssetEvent{}
		rels, err := h.q.ListWorkspaceAssetRelations(ctx, stored.WorkspaceID)
		if err != nil {
			return nil, internalError(err)
		}
		want := map[uuid.UUID]bool{}
		for _, r := range rels {
			if r.FromID == stored.ID || r.ToID == stored.ID {
				out.Body.Relations = append(out.Body.Relations, toAssetRelation(r))
				want[r.FromID], want[r.ToID] = true, true
			}
		}
		delete(want, stored.ID)
		if len(want) > 0 {
			rows, err := h.q.ListAssets(ctx, stored.WorkspaceID)
			if err != nil {
				return nil, internalError(err)
			}
			rules := h.rules(ctx, stored.WorkspaceID)
			for _, r := range rows {
				if want[r.Asset.ID] {
					out.Body.Related = append(out.Body.Related, toAsset(rowOfList(r), rules))
				}
			}
		}
		evs, err := h.q.ListAssetEvents(ctx, sqlc.ListAssetEventsParams{AssetID: stored.ID, Lim: 200})
		if err != nil {
			return nil, internalError(err)
		}
		for _, e := range evs {
			ev := AssetEvent{ID: e.ID.String(), At: e.At, ByName: e.ByName, Action: e.Action, Changes: []AssetChange{}}
			_ = json.Unmarshal(e.Changes, &ev.Changes)
			out.Body.Events = append(out.Body.Events, ev)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-asset",
		Method:      http.MethodPut,
		Path:        "/assets/{id}",
		Summary:     "Save changes to an asset",
		Description: "A linked asset keeps the kind and name of its source.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		AssetIDPath
		Body AssetBody
	}) (*AssetOutput, error) {
		old, stored, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if in.Body.Revision != nil && !in.Body.Revision.Equal(stored.UpdatedAt) {
			return nil, huma.Error409Conflict("Someone else saved this asset after you opened it.")
		}
		a, err := h.saveAsset(ctx, old, stored, in.Body, "updated")
		if err != nil {
			return nil, err
		}
		return &AssetOutput{a}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-asset",
		Method:        http.MethodDelete,
		Path:          "/assets/{id}",
		Summary:       "Delete an asset",
		Description:   "Only assets entered by hand, or linked ones whose source is gone; the rest go when removed from their section.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *AssetIDPath) (*struct{}, error) {
		_, stored, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if stored.SourceKind != "" && !stored.SourceGone {
			return nil, huma.Error409Conflict("This asset mirrors something Morche manages. Remove it in its own section, or mark it retired.")
		}
		if _, err := h.q.DeleteAsset(ctx, stored.ID); err != nil {
			return nil, internalError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "review-asset",
		Method:      http.MethodPost,
		Path:        "/assets/{id}/review",
		Summary:     "Confirm an asset is still owned and needed",
		Description: "For the owner, their deputy, a member of the owning group, or an Operator on the workspace.",
		Tags:        tags,
	}, func(ctx context.Context, in *AssetIDPath) (*AssetOutput, error) {
		a, stored, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		p := principalOf(ctx)
		if !h.mayReview(ctx, p, a) {
			return nil, huma.Error403Forbidden("You need Operator access, or to own this asset, to confirm it")
		}
		if err := h.q.ReviewAsset(ctx, sqlc.ReviewAssetParams{ID: stored.ID, ReviewedByName: byName(p)}); err != nil {
			return nil, internalError(err)
		}
		h.event(ctx, stored.ID, byName(p), "reviewed", nil)
		a, _, err = h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		return &AssetOutput{a}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-asset-license-key",
		Method:      http.MethodGet,
		Path:        "/assets/{id}/license-key",
		Summary:     "Show an asset's licence key",
		Description: "Owner on the workspace; each look is written to the asset's history.",
		Tags:        tags,
	}, func(ctx context.Context, in *AssetIDPath) (*struct {
		Body struct {
			Key string `json:"key"`
		}
	}, error) {
		raw, err := h.q.GetAssetLicenseKey(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Key string `json:"key"`
			}
		}{}
		if raw != nil {
			if out.Body.Key, err = h.box.Open(raw); err != nil {
				return nil, internalError(err)
			}
		}
		h.event(ctx, uuid.MustParse(in.ID), byName(principalOf(ctx)), "key-shown", nil)
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-asset-relations",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/asset-relations",
		Summary:     "List every relation between the workspace's assets",
		Description: "For the map and impact analysis.",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*struct {
		Body struct {
			Items []AssetRelation `json:"items"`
		}
	}, error) {
		ws := uuid.MustParse(in.ID)
		h.syncAssets(ctx, ws, false)
		rels, err := h.q.ListWorkspaceAssetRelations(ctx, ws)
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Items []AssetRelation `json:"items"`
			}
		}{}
		out.Body.Items = make([]AssetRelation, len(rels))
		for i, r := range rels {
			out.Body.Items[i] = toAssetRelation(r)
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "add-asset-relation",
		Method:        http.MethodPost,
		Path:          "/assets/{id}/relations",
		Summary:       "Relate an asset to another",
		Description:   "The asset in the path is the from side: it runs on, uses, depends on… the other.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		AssetIDPath
		Body struct {
			ToID string `json:"to_id" format:"uuid"`
			Kind string `json:"kind" enum:"runs_on,uses,depends_on,stored_in,backs_up_to,points_to,connects_to,part_of,licensed_for,assigned_to"`
			Note string `json:"note,omitempty" maxLength:"500"`
		}
	}) (*struct{ Body AssetRelation }, error) {
		_, stored, err := h.load(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		to := uuid.MustParse(in.Body.ToID)
		ws, err := h.q.GetAssetWorkspace(ctx, to)
		if err != nil || ws != stored.WorkspaceID {
			return nil, fieldError("body.to_id", "Pick an asset of this workspace", in.Body.ToID)
		}
		if to == stored.ID {
			return nil, fieldError("body.to_id", "An asset can't relate to itself", nil)
		}
		r, err := h.q.CreateAssetRelation(ctx, sqlc.CreateAssetRelationParams{
			WorkspaceID: ws, FromID: stored.ID, ToID: to, Kind: in.Body.Kind, Note: strings.TrimSpace(in.Body.Note),
		})
		if err != nil {
			return nil, internalError(err)
		}
		h.event(ctx, stored.ID, byName(principalOf(ctx)), "related", []AssetChange{{Field: in.Body.Kind, To: in.Body.ToID}})
		return &struct{ Body AssetRelation }{toAssetRelation(r)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-asset-relation",
		Method:        http.MethodDelete,
		Path:          "/assets/{id}/relations/{relation}",
		Summary:       "Remove a relation",
		Description:   "A discovered relation comes back while Morche still sees it.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, func(ctx context.Context, in *AssetRelationPath) (*struct{}, error) {
		id := uuid.MustParse(in.ID)
		r, err := h.q.GetAssetRelation(ctx, sqlc.GetAssetRelationParams{ID: uuid.MustParse(in.Relation), AssetID: id})
		if isNotFound(err) {
			return nil, huma.Error404NotFound("relation not found")
		}
		if err != nil {
			return nil, internalError(err)
		}
		if _, err := h.q.DeleteAssetRelation(ctx, sqlc.DeleteAssetRelationParams{ID: r.ID, AssetID: id}); err != nil {
			return nil, internalError(err)
		}
		h.event(ctx, id, byName(principalOf(ctx)), "unrelated", []AssetChange{{Field: r.Kind, From: r.ToID.String()}})
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-asset-people",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/asset-people",
		Summary:     "People and groups who can own assets",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*struct {
		Body struct {
			Users  []AssetPerson `json:"users"`
			Groups []AssetGroup  `json:"groups"`
		}
	}, error) {
		users, err := h.q.ListAssetPeople(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		groups, err := h.q.ListAssetGroups(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		out := &struct {
			Body struct {
				Users  []AssetPerson `json:"users"`
				Groups []AssetGroup  `json:"groups"`
			}
		}{}
		out.Body.Users = make([]AssetPerson, len(users))
		for i, u := range users {
			out.Body.Users[i] = AssetPerson{ID: u.ID.String(), Name: u.Name, Username: u.Username, Status: u.Status}
		}
		out.Body.Groups = make([]AssetGroup, len(groups))
		for i, g := range groups {
			out.Body.Groups[i] = AssetGroup{ID: g.ID.String(), Name: g.Name, Members: int(g.Members)}
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-asset-owner-rules",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/asset-owner-rules",
		Summary:     "List the owner rules",
		Description: "An asset with no owner of its own takes the first rule that matches it.",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*struct{ Body assetRuleList }, error) {
		rules := h.rules(ctx, uuid.MustParse(in.ID))
		out := &struct{ Body assetRuleList }{}
		out.Body.Items = make([]AssetOwnerRule, len(rules))
		for i, r := range rules {
			out.Body.Items[i] = AssetOwnerRule{
				ID: r.ID.String(), Name: r.Name, Kinds: r.Kinds, Tags: r.Tags, Environments: r.Environments,
				NamePattern: r.NamePattern, OwnerUserID: idString(r.OwnerUserID), OwnerGroupID: idString(r.OwnerGroupID),
				DeputyUserID: idString(r.DeputyUserID), OwnerName: r.OwnerUserName, GroupName: r.OwnerGroupName, DeputyName: r.DeputyUserName,
			}
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-asset-owner-rules",
		Method:      http.MethodPut,
		Path:        "/workspaces/{id}/asset-owner-rules",
		Summary:     "Replace the owner rules",
		Description: "In order: the first match wins.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body struct {
			Items []AssetOwnerRule `json:"items" maxItems:"100"`
		}
	}) (*struct{ Body assetRuleList }, error) {
		ws := uuid.MustParse(in.ID)
		type parsed struct {
			r                    AssetOwnerRule
			owner, group, deputy *uuid.UUID
		}
		var all []parsed
		for i, r := range in.Body.Items {
			var p parsed
			var err error
			at := func(f string) string { return fmt.Sprintf("items[%d].%s", i, f) }
			if p.owner, err = assetID(r.OwnerUserID, at("owner_user_id")); err != nil {
				return nil, err
			}
			if p.group, err = assetID(r.OwnerGroupID, at("owner_group_id")); err != nil {
				return nil, err
			}
			if p.deputy, err = assetID(r.DeputyUserID, at("deputy_user_id")); err != nil {
				return nil, err
			}
			if p.owner == nil && p.group == nil {
				return nil, fieldError("body."+at("owner_user_id"), "Pick an owner: a person or a group", nil)
			}
			if r.NamePattern != "" {
				if _, err := path.Match(strings.ToLower(r.NamePattern), ""); err != nil {
					return nil, fieldError("body."+at("name_pattern"), "That pattern isn't valid", r.NamePattern)
				}
			}
			for _, k := range r.Kinds {
				if !slices.Contains(linkedAssetKinds, k) && !slices.Contains(manualAssetKinds, k) {
					return nil, fieldError("body."+at("kinds"), "Unknown kind "+k, k)
				}
			}
			r.Kinds, r.Tags, r.Environments = nonNil(r.Kinds), nonNil(r.Tags), nonNil(r.Environments)
			p.r = r
			all = append(all, p)
		}
		tx, err := h.servers.db.Begin(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		defer tx.Rollback(ctx)
		q := h.q.WithTx(tx)
		if err := q.DeleteAssetOwnerRules(ctx, ws); err != nil {
			return nil, internalError(err)
		}
		for i, p := range all {
			err := q.CreateAssetOwnerRule(ctx, sqlc.CreateAssetOwnerRuleParams{
				WorkspaceID: ws, Position: int32(i), Name: strings.TrimSpace(p.r.Name), Kinds: p.r.Kinds, Tags: p.r.Tags,
				Environments: p.r.Environments, NamePattern: strings.TrimSpace(p.r.NamePattern),
				OwnerUserID: p.owner, OwnerGroupID: p.group, DeputyUserID: p.deputy,
			})
			if isForeignKeyViolation(err) {
				return nil, huma.Error422UnprocessableEntity("A person or group you picked no longer exists")
			}
			if err != nil {
				return nil, internalError(err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, internalError(err)
		}
		rules := h.rules(ctx, ws)
		out := &struct{ Body assetRuleList }{}
		out.Body.Items = make([]AssetOwnerRule, len(rules))
		for i, r := range rules {
			out.Body.Items[i] = AssetOwnerRule{
				ID: r.ID.String(), Name: r.Name, Kinds: r.Kinds, Tags: r.Tags, Environments: r.Environments,
				NamePattern: r.NamePattern, OwnerUserID: idString(r.OwnerUserID), OwnerGroupID: idString(r.OwnerGroupID),
				DeputyUserID: idString(r.DeputyUserID), OwnerName: r.OwnerUserName, GroupName: r.OwnerGroupName, DeputyName: r.DeputyUserName,
			}
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-asset-settings",
		Method:      http.MethodGet,
		Path:        "/workspaces/{id}/asset-settings",
		Summary:     "Read the inventory settings",
		Tags:        tags,
	}, func(ctx context.Context, in *WorkspacePath) (*struct{ Body AssetSettings }, error) {
		s, err := h.settings(ctx, uuid.MustParse(in.ID))
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body AssetSettings }{toAssetSettings(s)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-asset-settings",
		Method:      http.MethodPut,
		Path:        "/workspaces/{id}/asset-settings",
		Summary:     "Save the inventory settings",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		WorkspacePath
		Body AssetSettings
	}) (*struct{ Body AssetSettings }, error) {
		ws := uuid.MustParse(in.ID)
		b := in.Body
		days := []int32{}
		for _, d := range b.RemindDays {
			if d < 0 || d > 365 {
				return nil, fieldError("body.remind_days", "Between 0 and 365 days", d)
			}
			if !slices.Contains(days, int32(d)) {
				days = append(days, int32(d))
			}
		}
		chans := []uuid.UUID{}
		if len(b.ChannelIDs) > 0 {
			ids := []uuid.UUID{}
			for _, s := range b.ChannelIDs {
				id, err := uuid.Parse(s)
				if err != nil {
					return nil, fieldError("body.channel_ids", "Pick channels from the list", s)
				}
				ids = append(ids, id)
			}
			found, err := h.q.AssetReminderChannels(ctx, sqlc.AssetReminderChannelsParams{WorkspaceID: ws, Ids: ids})
			if err != nil {
				return nil, internalError(err)
			}
			for _, c := range found {
				chans = append(chans, c.ID)
			}
		}
		if b.DiscoverHours == 0 {
			b.DiscoverHours = 24
		}
		s, err := h.q.UpsertAssetSettings(ctx, sqlc.UpsertAssetSettingsParams{
			WorkspaceID: ws, AutoDiscover: b.AutoDiscover, DiscoverHours: int32(b.DiscoverHours),
			RemindDays: days, ChannelIds: chans, NotifyOwners: b.NotifyOwners,
		})
		if err != nil {
			return nil, internalError(err)
		}
		return &struct{ Body AssetSettings }{toAssetSettings(s)}, nil
	})

	registerAssetDiscovery(api, h)
	registerAssetNotes(api, h)
}
