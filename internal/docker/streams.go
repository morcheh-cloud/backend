package docker

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// LogLine is one line a container printed.
type LogLine struct {
	Stream string    // "stdout" or "stderr" ("stdout" for a TTY container)
	Time   time.Time // zero when the engine didn't stamp it
	Text   string
}

// LogQuery says which lines to read.
type LogQuery struct {
	Tail   int // last N lines; 0 = all
	Since  time.Time
	Until  time.Time
	Follow bool
}

// Logs reads a container's log and calls fn for each line until the log
// ends (or, following, until ctx is done). tty says the container runs with
// a terminal, so its output isn't split into stdout/stderr frames. fn
// returning false stops early.
func (c *Client) Logs(ctx context.Context, id string, tty bool, q LogQuery, fn func(LogLine) bool) error {
	v := url.Values{"stdout": {"1"}, "stderr": {"1"}, "timestamps": {"1"}}
	if q.Tail > 0 {
		v.Set("tail", strconv.Itoa(q.Tail))
	}
	if !q.Since.IsZero() {
		v.Set("since", unixNano(q.Since))
	}
	if !q.Until.IsZero() {
		v.Set("until", unixNano(q.Until))
	}
	if q.Follow {
		v.Set("follow", "1")
	}
	res, err := c.Stream(ctx, http.MethodGet, "/containers/"+PathEscape(id)+"/logs", v, nil)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	// A response that says it's a raw stream isn't framed even without tty.
	if ct := res.Header.Get("Content-Type"); ct == "application/vnd.docker.raw-stream" {
		tty = true
	}
	emit := func(stream string, line string) bool {
		l := LogLine{Stream: stream, Text: strings.TrimRight(line, "\r\n")}
		if ts, rest, ok := strings.Cut(l.Text, " "); ok {
			if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				l.Time, l.Text = t, rest
			}
		}
		return fn(l)
	}
	if tty {
		sc := bufio.NewScanner(res.Body)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			if !emit("stdout", sc.Text()) {
				return nil
			}
		}
		return quiet(ctx, sc.Err())
	}
	// Framed: 8-byte header (stream, 0, 0, 0, size) then the payload. A
	// payload can hold several lines, or half of one.
	br := bufio.NewReaderSize(res.Body, 64<<10)
	var hdr [8]byte
	partial := map[byte]string{}
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			for s, p := range partial {
				if p != "" {
					emit(streamName(s), p)
				}
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return quiet(ctx, err)
		}
		n := binary.BigEndian.Uint32(hdr[4:])
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return quiet(ctx, err)
		}
		text := partial[hdr[0]] + string(buf)
		for {
			i := strings.IndexByte(text, '\n')
			if i < 0 {
				break
			}
			if !emit(streamName(hdr[0]), text[:i]) {
				return nil
			}
			text = text[i+1:]
		}
		partial[hdr[0]] = text
	}
}

func streamName(b byte) string {
	if b == 2 {
		return "stderr"
	}
	return "stdout"
}

func unixNano(t time.Time) string {
	return fmt.Sprintf("%d.%09d", t.Unix(), t.Nanosecond())
}

// quiet drops the error a stream ends with because its ctx was canceled.
func quiet(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// Sample is one reading of a container's resource use, with rates worked
// out against the reading before it.
type Sample struct {
	Time        time.Time
	CPUPercent  float64 // of one CPU: 250 = two and a half CPUs busy
	CPUs        int
	MemoryUsed  int64 // without the page cache
	MemoryLimit int64
	NetRx       int64 // totals since the container started
	NetTx       int64
	BlockRead   int64
	BlockWrite  int64
	NetRxRate   float64 // bytes per second
	NetTxRate   float64
	ReadRate    float64
	WriteRate   float64
	Pids        int64
}

type rawStats struct {
	Read     time.Time `json:"read"`
	CPUStats struct {
		CPUUsage struct {
			TotalUsage  uint64   `json:"total_usage"`
			PercpuUsage []uint64 `json:"percpu_usage"`
		} `json:"cpu_usage"`
		SystemUsage uint64 `json:"system_cpu_usage"`
		OnlineCPUs  int    `json:"online_cpus"`
	} `json:"cpu_stats"`
	PreCPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemUsage uint64 `json:"system_cpu_usage"`
	} `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
	Networks map[string]struct {
		RxBytes uint64 `json:"rx_bytes"`
		TxBytes uint64 `json:"tx_bytes"`
	} `json:"networks"`
	BlkioStats struct {
		IOServiceBytesRecursive []struct {
			Op    string `json:"op"`
			Value uint64 `json:"value"`
		} `json:"io_service_bytes_recursive"`
	} `json:"blkio_stats"`
	PidsStats struct {
		Current uint64 `json:"current"`
	} `json:"pids_stats"`
}

func (r rawStats) sample() Sample {
	s := Sample{Time: r.Read, CPUs: r.CPUStats.OnlineCPUs}
	if s.CPUs == 0 {
		s.CPUs = len(r.CPUStats.CPUUsage.PercpuUsage)
	}
	cpu := float64(r.CPUStats.CPUUsage.TotalUsage) - float64(r.PreCPUStats.CPUUsage.TotalUsage)
	sys := float64(r.CPUStats.SystemUsage) - float64(r.PreCPUStats.SystemUsage)
	if cpu > 0 && sys > 0 && r.PreCPUStats.SystemUsage > 0 {
		s.CPUPercent = cpu / sys * float64(max(s.CPUs, 1)) * 100
	}
	used := r.MemoryStats.Usage
	// What docker stats shows: the page cache isn't the container's.
	cache := r.MemoryStats.Stats["inactive_file"] // cgroup v2
	if v, ok := r.MemoryStats.Stats["total_inactive_file"]; ok { // cgroup v1
		cache = v
	}
	if cache < used {
		used -= cache
	}
	s.MemoryUsed, s.MemoryLimit = int64(used), int64(r.MemoryStats.Limit)
	for _, n := range r.Networks {
		s.NetRx += int64(n.RxBytes)
		s.NetTx += int64(n.TxBytes)
	}
	for _, b := range r.BlkioStats.IOServiceBytesRecursive {
		switch strings.ToLower(b.Op) {
		case "read":
			s.BlockRead += int64(b.Value)
		case "write":
			s.BlockWrite += int64(b.Value)
		}
	}
	s.Pids = int64(r.PidsStats.Current)
	return s
}

// Stats streams a running container's resource use, about once a second,
// until ctx is done or the container stops. fn returning false stops.
func (c *Client) Stats(ctx context.Context, id string, fn func(Sample) bool) error {
	res, err := c.Stream(ctx, http.MethodGet, "/containers/"+PathEscape(id)+"/stats", url.Values{"stream": {"1"}}, nil)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	dec := json.NewDecoder(res.Body)
	var prev *Sample
	for {
		var r rawStats
		if err := dec.Decode(&r); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return quiet(ctx, err)
		}
		s := r.sample()
		if s.Time.IsZero() || s.Time.Year() < 2000 {
			s.Time = time.Now()
		}
		if prev != nil {
			if d := s.Time.Sub(prev.Time).Seconds(); d > 0 {
				rate := func(now, before int64) float64 { return max(float64(now-before), 0) / d }
				s.NetRxRate, s.NetTxRate = rate(s.NetRx, prev.NetRx), rate(s.NetTx, prev.NetTx)
				s.ReadRate, s.WriteRate = rate(s.BlockRead, prev.BlockRead), rate(s.BlockWrite, prev.BlockWrite)
			}
		}
		prev = &s
		if !fn(s) {
			return nil
		}
	}
}

// StatsOnce reads one sample without waiting for a second reading (CPU is
// then 0 unless the engine had a previous one).
func (c *Client) StatsOnce(ctx context.Context, id string) (Sample, error) {
	var r rawStats
	err := c.Get(ctx, "/containers/"+PathEscape(id)+"/stats", url.Values{"stream": {"0"}, "one-shot": {"1"}}, &r)
	return r.sample(), err
}

// PullEvent is one progress message of a pull.
type PullEvent struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Progress struct {
		Current int64 `json:"current"`
		Total   int64 `json:"total"`
	} `json:"progressDetail"`
	Error string `json:"error"`
}

// Pull pulls image (a reference with an optional tag or digest), calling fn
// for each progress message. auth is the X-Registry-Auth value ("" = none).
func (c *Client) Pull(ctx context.Context, image, platform, auth string, fn func(PullEvent)) error {
	q := url.Values{"fromImage": {image}}
	if platform != "" {
		q.Set("platform", platform)
	}
	req, err := c.request(ctx, http.MethodPost, "/images/create", q, nil)
	if err != nil {
		return err
	}
	if auth != "" {
		req.Header.Set("X-Registry-Auth", auth)
	}
	res, err := c.send(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	dec := json.NewDecoder(res.Body)
	for {
		var ev PullEvent
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if ev.Error != "" {
			return &Error{Status: http.StatusBadGateway, Message: ev.Error}
		}
		fn(ev)
	}
}
