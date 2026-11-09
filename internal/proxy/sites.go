package proxy

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// TypeStorage serves a bucket of an S3 storage (from the Storage section)
// as a public site. The proxy reads the files over the storage's own
// address, without keys: the bucket must let anyone download its files.
const TypeStorage = "storage"

// StorageSite is what a storage site serves.
type StorageSite struct {
	StorageID string `json:"storage_id" doc:"The S3 storage (from the Storage section) the files come from"`
	Bucket    string `json:"bucket" doc:"Bucket the site serves"`
	Folder    string `json:"folder,omitempty" doc:"Folder inside the bucket, like /site; empty = the whole bucket"`
	// Endpoint and PathStyle are filled in from the storage when the site is
	// saved: whatever is sent is replaced.
	Endpoint  string `json:"endpoint,omitempty" doc:"Filled in by the server: where the files are read from, like https://s3.example.com"`
	PathStyle bool   `json:"path_style,omitempty" doc:"Filled in by the server: the bucket goes in the path, not the host name"`
}

// Prefix is what goes before a file's path on the storage: the bucket in
// path style, and the folder.
func (s StorageSite) Prefix() string {
	p := ""
	if s.PathStyle {
		p = "/" + s.Bucket
	}
	return p + s.Folder
}

// Mirror sends a copy of requests to a test server (proxy sites). Its
// answers are thrown away; visitors only ever see the real upstream's.
type Mirror struct {
	To       string `json:"to,omitempty" doc:"Test server that gets a copy of requests, like http://10.0.0.9:8080; empty = off"`
	SkipBody bool   `json:"skip_body,omitempty" doc:"Leave request bodies out of the copies"`
	Percent  int    `json:"percent,omitempty" minimum:"0" maximum:"100" doc:"Share of requests copied; 0 = all"`
}

// On says whether requests are copied.
func (m Mirror) On() bool { return m.To != "" }

// A bucket name as S3 allows it (dots included, for older buckets).
var bucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$`)

// normalizeSites tidies the storage and mirror fields, and clears them for
// the types that don't use them.
func normalizeSites(h HostConfig) HostConfig {
	if h.Type != TypeStorage {
		h.Storage = StorageSite{}
	} else {
		s := &h.Storage
		s.StorageID, s.Bucket = strings.TrimSpace(s.StorageID), strings.TrimSpace(s.Bucket)
		s.Folder = strings.Trim(strings.TrimSpace(s.Folder), "/")
		if s.Folder != "" {
			s.Folder = "/" + s.Folder
		}
		s.Endpoint = strings.TrimRight(strings.TrimSpace(s.Endpoint), "/")
	}
	if h.Type != TypeProxy {
		h.Mirror = Mirror{}
	}
	h.Mirror.To = strings.TrimSpace(h.Mirror.To)
	if !h.Mirror.On() {
		h.Mirror = Mirror{}
	} else if h.Mirror.Percent >= 100 {
		h.Mirror.Percent = 0
	}
	return h
}

// validateSites checks the storage and mirror fields.
func validateSites(h HostConfig, add func(field, msg string, v any)) {
	if h.Type == TypeStorage {
		s := h.Storage
		if s.StorageID == "" {
			add("storage.storage_id", "Choose the storage the files come from.", nil)
		}
		switch {
		case s.Bucket == "":
			add("storage.bucket", "Choose a bucket.", nil)
		case !bucketRe.MatchString(s.Bucket) || strings.Contains(s.Bucket, ".."):
			add("storage.bucket", "Not a bucket name (lowercase letters, digits, . and -).", s.Bucket)
		}
		if s.Folder != "" && !safePath(s.Folder) {
			add("storage.folder", "Use letters, digits and . _ - / only.", s.Folder)
		}
		if s.StorageID != "" && s.Endpoint != "" {
			if msg := checkURL(s.Endpoint); msg != "" {
				add("storage.storage_id", "The storage's address can't be used: "+msg, s.Endpoint)
			} else if u, _ := url.Parse(s.Endpoint); strings.Trim(u.Path, "/") != "" || u.RawQuery != "" {
				add("storage.storage_id", "The storage's address has a path; serving it as a site needs a plain address.", s.Endpoint)
			}
		}
	}
	if m := h.Mirror; m.On() {
		if msg := checkURL(m.To); msg != "" {
			add("mirror.to", msg, m.To)
		} else if u, _ := url.Parse(m.To); strings.Trim(u.Path, "/") != "" || u.RawQuery != "" {
			add("mirror.to", "Only the address: the requested path is added on its own.", m.To)
		}
		if m.Percent < 0 || m.Percent > 100 {
			add("mirror.percent", fmt.Sprintf("Use 1 to 100 (got %d).", m.Percent), m.Percent)
		}
	}
}
