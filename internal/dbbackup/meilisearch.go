package dbbackup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/morche/backend/internal/dbmon"
)

// meiliPage is how many documents one fetch reads.
const meiliPage = 1000

// A batch of documents sent back in one task.
const (
	meiliBatchDocs  = 5000
	meiliBatchBytes = 10 << 20
)

type meiliIndexInfo struct {
	UID        string  `json:"uid"`
	PrimaryKey *string `json:"primaryKey"`
}

// meiliDump writes every index (name "") or the one named. Meilisearch has
// no snapshot to read from: documents added or removed while the export
// runs may or may not be in it. Fetching without a filter or sort walks the
// documents in their internal id order, so offsets stay put unless
// documents are removed meanwhile.
func meiliDump(ctx context.Context, h *dbmon.HTTPDB, name string, out io.Writer) error {
	var names []string
	if name != "" {
		names = []string{name}
	} else {
		for offset := 0; ; offset += meiliPage {
			var list struct {
				Results []meiliIndexInfo `json:"results"`
				Total   int              `json:"total"`
			}
			if err := h.JSON(ctx, http.MethodGet, fmt.Sprintf("/indexes?offset=%d&limit=%d", offset, meiliPage), nil, &list); err != nil {
				return fmt.Errorf("couldn't list the indexes: %w", err)
			}
			for _, ix := range list.Results {
				names = append(names, ix.UID)
			}
			if len(list.Results) == 0 || offset+len(list.Results) >= list.Total {
				break
			}
		}
	}
	var v struct {
		PkgVersion string `json:"pkgVersion"`
	}
	if err := h.JSON(ctx, http.MethodGet, "/version", nil, &v); err != nil {
		return err
	}
	w, err := NewNativeWriter(out, NativeHeader{Morche: MeiliNDJSON, Engine: dbmon.Meili, Source: strings.TrimSpace("Meilisearch " + v.PkgVersion)})
	if err != nil {
		return err
	}
	for _, uid := range names {
		if err := meiliDumpIndex(ctx, h, uid, w); err != nil {
			return fmt.Errorf("index %s: %w", uid, err)
		}
	}
	return w.Close()
}

func meiliDumpIndex(ctx context.Context, h *dbmon.HTTPDB, uid string, w *NativeWriter) error {
	var ix meiliIndexInfo
	if err := h.JSON(ctx, http.MethodGet, dbmon.Path("indexes", uid), nil, &ix); err != nil {
		if dbmon.HTTPStatus(err) == http.StatusNotFound {
			return fmt.Errorf("there's no index named %s", uid)
		}
		return err
	}
	settings, err := h.Raw(ctx, http.MethodGet, dbmon.Path("indexes", uid, "settings"), nil, 16<<20)
	if err != nil {
		return fmt.Errorf("couldn't read its settings: %w", err)
	}
	var stats struct {
		NumberOfDocuments int64 `json:"numberOfDocuments"`
	}
	if err := h.JSON(ctx, http.MethodGet, dbmon.Path("indexes", uid, "stats"), nil, &stats); err != nil {
		return err
	}
	line := NativeIndex{Name: uid, Settings: settings, Documents: &stats.NumberOfDocuments}
	if ix.PrimaryKey != nil {
		line.PrimaryKey = *ix.PrimaryKey
	}
	if err := w.Index(line); err != nil {
		return err
	}
	path := dbmon.Path("indexes", uid, "documents", "fetch")
	var buf bytes.Buffer
	for offset := int64(0); ; {
		if err := ctx.Err(); err != nil {
			return err
		}
		var page struct {
			Results []json.RawMessage `json:"results"`
			Total   int64             `json:"total"`
		}
		body := map[string]any{"offset": offset, "limit": meiliPage}
		if err := h.JSON(ctx, http.MethodPost, path, body, &page); err != nil {
			return fmt.Errorf("couldn't read documents from %d on: %w", offset, err)
		}
		for _, d := range page.Results {
			buf.Reset()
			if err := json.Compact(&buf, d); err != nil {
				return err
			}
			if err := w.Doc(bytes.Clone(buf.Bytes())); err != nil {
				return err
			}
		}
		offset += int64(len(page.Results))
		if len(page.Results) < meiliPage || offset >= page.Total {
			return nil
		}
	}
}

var meiliUID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// meiliCheckUID says what's wrong with an index name, if anything.
func meiliCheckUID(uid string) error {
	switch {
	case uid == "":
		return errors.New("Name the index to restore into.")
	case len(uid) > 400:
		return errors.New("A Meilisearch index name can be at most 400 characters long.")
	case !meiliUID.MatchString(uid):
		return fmt.Errorf("%q can't be a Meilisearch index name: use only letters, digits, - and _.", uid)
	}
	return nil
}

// meiliLoad restores one index of the file into name. With o.Replace and an
// index of that name, the file goes into a new index first, which then
// swaps places with the old one: the old one stays until the restore
// succeeded.
func meiliLoad(ctx context.Context, h *dbmon.HTTPDB, name string, o RestoreOptions, in io.Reader) error {
	if err := meiliCheckUID(name); err != nil {
		return err
	}
	r, err := NewNativeReader(in)
	if err != nil {
		return err
	}
	if r.Header.Morche != MeiliNDJSON {
		return errors.New("the file isn't a Meilisearch export")
	}
	exists, err := meiliExists(ctx, h, name)
	if err != nil {
		return err
	}
	if exists && !o.Replace {
		return fmt.Errorf("an index named %s already exists. Restore into a new name, or choose to replace it.", name)
	}
	target := name
	if exists {
		b := make([]byte, 6)
		_, _ = rand.Read(b)
		target = "morche_restore_" + hex.EncodeToString(b)
	}

	var (
		picked   *NativeIndex
		seen     []string
		created  bool
		sent     int64
		batch    bytes.Buffer
		batchN   int
		finished bool
	)
	// Whatever went wrong, a half-made index doesn't stay behind.
	defer func() {
		if created && !finished {
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
			defer cancel()
			if t, err := meiliTask(cctx, h, http.MethodDelete, dbmon.Path("indexes", target), nil, ""); err == nil {
				_ = meiliWaitTask(cctx, h, t)
			}
		}
	}()
	flush := func() error {
		if batchN == 0 {
			return nil
		}
		path := dbmon.Path("indexes", target, "documents")
		if picked.PrimaryKey != "" {
			path += "?primaryKey=" + url.QueryEscape(picked.PrimaryKey)
		}
		t, err := meiliTask(ctx, h, http.MethodPost, path, batch.Bytes(), "application/x-ndjson")
		if err != nil {
			return fmt.Errorf("couldn't send documents: %w", err)
		}
		if err := meiliWaitTask(ctx, h, t); err != nil {
			return fmt.Errorf("adding documents failed: %w", err)
		}
		sent += int64(batchN)
		batch.Reset()
		batchN = 0
		return nil
	}
	for {
		l, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		switch {
		case l.Index != nil:
			seen = append(seen, l.Index.Name)
			if picked != nil {
				if err := flush(); err != nil {
					return err
				}
				if o.Source == "" {
					return fmt.Errorf("the file holds more than one index (%s): pick the one to restore.", strings.Join(seen, ", "))
				}
				picked = nil
				// The one asked for is done; the rest of the file doesn't matter.
				finished = true
			}
			if finished || (o.Source != "" && l.Index.Name != o.Source) {
				continue
			}
			ix := *l.Index
			picked = &ix
			if err := meiliCreate(ctx, h, target, picked); err != nil {
				return err
			}
			created = true
		case l.Doc != nil:
			if picked == nil {
				continue
			}
			batch.Write(l.Doc)
			batch.WriteByte('\n')
			batchN++
			if batchN >= meiliBatchDocs || batch.Len() >= meiliBatchBytes {
				if err := flush(); err != nil {
					return err
				}
			}
		}
		if finished {
			break
		}
	}
	if !created {
		if o.Source != "" {
			return fmt.Errorf("the file has no index named %s (it holds: %s).", o.Source, strings.Join(seen, ", "))
		}
		return errors.New("the file holds no index")
	}
	if picked != nil {
		if err := flush(); err != nil {
			return err
		}
	}
	finished = false
	var stats struct {
		NumberOfDocuments int64 `json:"numberOfDocuments"`
	}
	if err := h.JSON(ctx, http.MethodGet, dbmon.Path("indexes", target, "stats"), nil, &stats); err != nil {
		return err
	}
	if stats.NumberOfDocuments != sent {
		return fmt.Errorf("the restored index holds %d documents, but the file had %d", stats.NumberOfDocuments, sent)
	}
	if target != name {
		swap := []map[string]any{{"indexes": []string{name, target}}}
		t, err := meiliTask(ctx, h, http.MethodPost, "/swap-indexes", swap, "")
		if err != nil {
			return fmt.Errorf("couldn't put the restored index in place: %w", err)
		}
		if err := meiliWaitTask(ctx, h, t); err != nil {
			return fmt.Errorf("couldn't put the restored index in place: %w", err)
		}
		// target now holds the old documents: the deferred clean-up removes
		// them.
		return nil
	}
	finished = true
	return nil
}

func meiliExists(ctx context.Context, h *dbmon.HTTPDB, uid string) (bool, error) {
	err := h.JSON(ctx, http.MethodGet, dbmon.Path("indexes", uid), nil, nil)
	switch {
	case err == nil:
		return true, nil
	case dbmon.HTTPStatus(err) == http.StatusNotFound:
		return false, nil
	}
	return false, err
}

// meiliCreate makes the index and gives it the file's settings. A setting
// the target's version doesn't know (a newer file into an older
// Meilisearch) is left out.
func meiliCreate(ctx context.Context, h *dbmon.HTTPDB, uid string, ix *NativeIndex) error {
	body := map[string]any{"uid": uid}
	if ix.PrimaryKey != "" {
		body["primaryKey"] = ix.PrimaryKey
	}
	t, err := meiliTask(ctx, h, http.MethodPost, "/indexes", body, "")
	if err != nil {
		return fmt.Errorf("couldn't create the index: %w", err)
	}
	if err := meiliWaitTask(ctx, h, t); err != nil {
		return fmt.Errorf("couldn't create the index: %w", err)
	}
	if len(ix.Settings) == 0 {
		return nil
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(ix.Settings, &settings); err != nil {
		return fmt.Errorf("the file's settings for %s aren't valid JSON: %w", ix.Name, err)
	}
	path := dbmon.Path("indexes", uid, "settings")
	for range 30 {
		t, err := meiliTask(ctx, h, http.MethodPatch, path, settings, "")
		if err != nil {
			if k := meiliUnknownField(err); k != "" {
				if _, ok := settings[k]; ok {
					delete(settings, k)
					continue
				}
			}
			return fmt.Errorf("couldn't apply the settings: %w", err)
		}
		if err := meiliWaitTask(ctx, h, t); err != nil {
			return fmt.Errorf("couldn't apply the settings: %w", err)
		}
		return nil
	}
	return errors.New("couldn't apply the settings: too many of them are unknown to this Meilisearch")
}

var meiliUnknown = regexp.MustCompile("Unknown field `([^`]+)`")

// meiliUnknownField is the setting a bad_request names as unknown.
func meiliUnknownField(err error) string {
	var he *dbmon.HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusBadRequest {
		return ""
	}
	if m := meiliUnknown.FindStringSubmatch(he.Message); m != nil {
		return m[1]
	}
	return ""
}

// meiliTask sends a request that answers with a task, and returns its uid.
func meiliTask(ctx context.Context, h *dbmon.HTTPDB, method, path string, body any, ctype string) (int64, error) {
	res, err := h.Do(ctx, method, path, body, ctype)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	var t struct {
		TaskUID *int64 `json:"taskUid"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&t); err != nil || t.TaskUID == nil {
		return 0, errors.New("Meilisearch didn't answer with a task")
	}
	return *t.TaskUID, nil
}

// meiliWaitTask waits for a task to end; a failed or canceled one is an
// error with Meilisearch's own message.
func meiliWaitTask(ctx context.Context, h *dbmon.HTTPDB, uid int64) error {
	wait := 50 * time.Millisecond
	path := "/tasks/" + strconv.FormatInt(uid, 10)
	for {
		var t struct {
			Status string `json:"status"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := h.JSON(ctx, http.MethodGet, path, nil, &t); err != nil {
			return err
		}
		switch t.Status {
		case "succeeded":
			return nil
		case "failed":
			if t.Error != nil && t.Error.Message != "" {
				return errors.New(t.Error.Message)
			}
			return fmt.Errorf("task %d failed", uid)
		case "canceled":
			return fmt.Errorf("task %d was canceled", uid)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		wait = min(wait*2, time.Second)
	}
}
