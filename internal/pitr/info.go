package pitr

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Backup is one backup in the repository.
type PitrBackup struct {
	Label string    `json:"label"`
	Type  string    `json:"type" enum:"full,diff,incr"`
	Start time.Time `json:"start"`
	Stop  time.Time `json:"stop"`
	// What the database took, and what the backup takes in the repository
	// (compressed; a diff/incr only its changes).
	Size       int64  `json:"size"`
	RepoSize   int64  `json:"repo_size"`
	Delta      int64  `json:"delta"`
	RepoDelta  int64  `json:"repo_delta"`
	Prior      string `json:"prior" doc:"The backup it builds on (diff/incr)"`
	WALStart   string `json:"wal_start"`
	WALStop    string `json:"wal_stop"`
	LSNStart   string `json:"lsn_start"`
	LSNStop    string `json:"lsn_stop"`
	Error      bool   `json:"error" doc:"pgBackRest found a problem in a file while backing up"`
	PGVersion  string `json:"pg_version"`
	Annotation string `json:"annotation,omitempty"`
}

// Archiver is PostgreSQL's pg_stat_archiver row.
type PitrArchiver struct {
	ArchivedCount    int64      `json:"archived_count"`
	LastArchivedWAL  string     `json:"last_archived_wal"`
	LastArchivedTime *time.Time `json:"last_archived_time"`
	FailedCount      int64      `json:"failed_count"`
	LastFailedWAL    string     `json:"last_failed_wal"`
	LastFailedTime   *time.Time `json:"last_failed_time"`
	StatsReset       *time.Time `json:"stats_reset"`
}

// Failing says the last archive attempt failed.
func (a PitrArchiver) Failing() bool {
	return a.LastFailedTime != nil && (a.LastArchivedTime == nil || a.LastFailedTime.After(*a.LastArchivedTime))
}

// Info is the repository and the archiver at one moment.
type Info struct {
	Status  string       `json:"status" doc:"pgBackRest's own word on the stanza (ok, …)"`
	Message string       `json:"message"`
	Backups []PitrBackup `json:"backups"`
	// The oldest and newest WAL file the repository holds.
	WALMin   string       `json:"wal_min"`
	WALMax   string       `json:"wal_max"`
	Archiver PitrArchiver `json:"archiver"`
	// The server's clock when it was read.
	At time.Time `json:"at"`
	// Encrypted repository.
	Cipher string `json:"cipher"`
}

// Window is how far back it can go: from the end of the oldest whole backup
// to the last WAL file archived. Zero times = nothing to restore yet.
func (i Info) Window() (from, to time.Time) {
	for _, b := range i.Backups {
		if b.Error {
			continue
		}
		if from.IsZero() || b.Stop.Before(from) {
			from = b.Stop
		}
	}
	if from.IsZero() {
		return
	}
	to = from
	for _, b := range i.Backups {
		if b.Stop.After(to) {
			to = b.Stop
		}
	}
	if a := i.Archiver.LastArchivedTime; a != nil && a.After(to) {
		to = *a
	}
	return
}

// Latest is the newest backup of the type, or of any type when kind is "".
func (i Info) Latest(kind string) *PitrBackup {
	var out *PitrBackup
	for k := range i.Backups {
		b := &i.Backups[k]
		if (kind == "" || b.Type == kind) && (out == nil || b.Stop.After(out.Stop)) {
			out = b
		}
	}
	return out
}

// RepoSize is everything the backups take in the repository (WAL aside).
func (i Info) RepoSize() int64 {
	var n int64
	for _, b := range i.Backups {
		n += b.RepoDelta
	}
	return n
}

type rawInfo struct {
	Name   string `json:"name"`
	Status struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"status"`
	Cipher  string `json:"cipher"`
	Archive []struct {
		Min string `json:"min"`
		Max string `json:"max"`
	} `json:"archive"`
	PitrBackup []struct {
		Label   string `json:"label"`
		Type    string `json:"type"`
		Prior   string `json:"prior"`
		Error   bool   `json:"error"`
		Archive struct {
			Start string `json:"start"`
			Stop  string `json:"stop"`
		} `json:"archive"`
		LSN struct {
			Start string `json:"start"`
			Stop  string `json:"stop"`
		} `json:"lsn"`
		Info struct {
			Size       int64 `json:"size"`
			Delta      int64 `json:"delta"`
			Repository struct {
				Size  int64 `json:"size"`
				Delta int64 `json:"delta"`
			} `json:"repository"`
		} `json:"info"`
		Timestamp struct {
			Start int64 `json:"start"`
			Stop  int64 `json:"stop"`
		} `json:"timestamp"`
		Annotation map[string]string `json:"annotation"`
		Database   struct {
			ID int `json:"id"`
		} `json:"database"`
	} `json:"backup"`
	DB []struct {
		ID      int    `json:"id"`
		Version string `json:"version"`
	} `json:"db"`
}

// pgTime reads a timestamptz as row_to_json writes it.
type pgTime struct{ time.Time }

func (t *pgTime) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "null" || s == "" {
		return nil
	}
	for _, layout := range []string{"2006-01-02T15:04:05.999999Z07:00", "2006-01-02T15:04:05.999999Z07", "2006-01-02 15:04:05.999999-07"} {
		if v, err := time.Parse(layout, s); err == nil {
			t.Time = v
			return nil
		}
	}
	return errors.New("pitr: unreadable time " + s)
}

func (t pgTime) ptr() *time.Time {
	if t.IsZero() {
		return nil
	}
	v := t.Time
	return &v
}

// ParseInfo reads InfoScript's output.
func ParseInfo(out string) (Info, error) {
	v := marks(out)
	var info Info
	var raws []rawInfo
	if err := json.Unmarshal([]byte(v["info"]), &raws); err != nil {
		return info, errors.New("pgBackRest's info couldn't be read: " + firstLine(out))
	}
	var raw *rawInfo
	for k := range raws {
		if raws[k].Name == Stanza {
			raw = &raws[k]
		}
	}
	if raw == nil {
		return info, errors.New("The repository has no stanza for this database yet.")
	}
	info.Status, info.Message, info.Cipher = statusWord(raw.Status.Code), raw.Status.Message, raw.Cipher
	if len(raw.Archive) > 0 {
		a := raw.Archive[len(raw.Archive)-1]
		info.WALMin, info.WALMax = raw.Archive[0].Min, a.Max
	}
	versions := map[int]string{}
	for _, d := range raw.DB {
		versions[d.ID] = d.Version
	}
	for _, r := range raw.PitrBackup {
		b := PitrBackup{
			Label: r.Label, Type: r.Type, Prior: r.Prior, Error: r.Error,
			Start: time.Unix(r.Timestamp.Start, 0).UTC(), Stop: time.Unix(r.Timestamp.Stop, 0).UTC(),
			Size: r.Info.Size, Delta: r.Info.Delta, RepoSize: r.Info.Repository.Size, RepoDelta: r.Info.Repository.Delta,
			WALStart: r.Archive.Start, WALStop: r.Archive.Stop, LSNStart: r.LSN.Start, LSNStop: r.LSN.Stop,
			PGVersion: versions[r.Database.ID],
		}
		if r.Annotation != nil {
			b.Annotation = r.Annotation["morche"]
		}
		info.Backups = append(info.Backups, b)
	}
	if s := v["archiver"]; s != "" {
		var a struct {
			ArchivedCount    int64  `json:"archived_count"`
			LastArchivedWAL  string `json:"last_archived_wal"`
			LastArchivedTime pgTime `json:"last_archived_time"`
			FailedCount      int64  `json:"failed_count"`
			LastFailedWAL    string `json:"last_failed_wal"`
			LastFailedTime   pgTime `json:"last_failed_time"`
			StatsReset       pgTime `json:"stats_reset"`
		}
		if err := json.Unmarshal([]byte(s), &a); err == nil {
			info.Archiver = PitrArchiver{
				ArchivedCount: a.ArchivedCount, LastArchivedWAL: a.LastArchivedWAL, LastArchivedTime: a.LastArchivedTime.ptr(),
				FailedCount: a.FailedCount, LastFailedWAL: a.LastFailedWAL, LastFailedTime: a.LastFailedTime.ptr(), StatsReset: a.StatsReset.ptr(),
			}
		}
	}
	if at, err := time.Parse(time.RFC3339Nano, v["now"]); err == nil {
		info.At = at
	}
	return info, nil
}

// statusWord turns pgBackRest's stanza status code into a word.
func statusWord(code int) string {
	switch code {
	case 0:
		return "ok"
	case 1:
		return "missing"
	case 2:
		return "no_backup"
	case 3:
		return "missing_data"
	case 4:
		return "different_cipher"
	case 99:
		return "other"
	}
	return "other"
}

func firstLine(s string) string {
	for line := range strings.SplitSeq(s, "\n") {
		if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(l, mark) {
			return l
		}
	}
	return ""
}
