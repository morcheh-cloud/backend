package nginx

import (
	"bufio"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/morche/backend/internal/proxy"
)

// trafficCap is the most read from one log per call: a first look, or a
// burst, never reads a whole log.
const trafficCap = 4 << 20

var hostIDRe = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// trafficAwk counts lines of nginx's combined format (and the stream format,
// which keeps its fields) per minute, time zone and status class. Split on
// quotes, $1 holds the time, $3 the status and bytes.
const trafficAwk = `awk -F'"' '{split($1,a,"["); t=substr(a[2],1,17); z=substr(a[2],22,5); split($3,b," "); c=substr(b[1],1,1); k=t" "z" "c; n[k]++; by[k]+=b[2]} END{for(k in n) print k,n[k],by[k]+0}'`

// fileTrafficAwk counts the same per-minute keys for logs another program
// wrote: nginx's combined format, or Nginx Proxy Manager's
// ("[time] … 200 - GET https host "/uri" [Client …] [Length 512] …").
const fileTrafficAwk = `awk '{i=index($0,"["); if(!i) next; t=substr($0,i+1,17); z=substr($0,i+22,5); c=""; by=0
  if (match($0, /" [0-9][0-9][0-9] [0-9]+/)) {split(substr($0,RSTART+2,RLENGTH-2),b," "); c=substr(b[1],1,1); by=b[2]}
  else if (match($0, / [0-9][0-9][0-9] - [A-Z]/)) {c=substr($0,RSTART+1,1); if (match($0, /\[Length [0-9]+\]/)) by=substr($0,RSTART+8,RLENGTH-9)}
  else next
  k=t" "z" "c; n[k]++; by2[k]+=by} END{for(k in n) print k,n[k],by2[k]+0}'`

// FileTrafficScript is TrafficScript for logs at the given paths (keyed
// like the marks), such as the ones a proxy manager writes. Paths that
// don't look like plain absolute files are left out.
func (Driver) FileTrafficScript(logs map[string]string, marks map[string]proxy.LogMark) string {
	var b strings.Builder
	b.WriteString(`count() {
  f=$4
  if [ ! -f "$f" ]; then echo "@@host $1 - 0"; return; fi
  set -- "$1" "$2" "$3" $(stat -c '%i %s' "$f")
  o=$3
  if [ "$4" != "$2" ] || [ "$5" -lt "$o" ]; then o=0; fi
  if [ $(($5 - o)) -gt ` + strconv.Itoa(trafficCap) + ` ]; then o=$(($5 - ` + strconv.Itoa(trafficCap) + `)); fi
  echo "@@host $1 $4 $5"
  if [ "$5" -gt "$o" ]; then tail -c +$((o + 1)) "$f" | head -c $(($5 - o)) | ` + fileTrafficAwk + `; fi
}
`)
	keys := make([]string, 0, len(logs))
	for k := range logs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		f := logs[k]
		if !hostIDRe.MatchString(k) || !logPathRe.MatchString(f) {
			continue
		}
		m := marks[k]
		inode := m.Inode
		if inode == "" {
			inode = "-"
		}
		fmt.Fprintf(&b, "count %s %s %d %s\n", k, inode, m.Size, shellQuote(f))
	}
	b.WriteString("exit 0\n")
	return b.String()
}

var logPathRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// TrafficScript reads what each host's access log gained since its mark. A
// new file (rotated) or a smaller one starts over from the top.
func (Driver) TrafficScript(hosts []string, marks map[string]proxy.LogMark) string {
	var b strings.Builder
	b.WriteString(`count() {
  f=` + logDir + `/morche-$1.access.log
  if [ ! -f "$f" ]; then echo "@@host $1 - 0"; return; fi
  set -- "$1" "$2" "$3" $(stat -c '%i %s' "$f")
  o=$3
  if [ "$4" != "$2" ] || [ "$5" -lt "$o" ]; then o=0; fi
  if [ $(($5 - o)) -gt ` + strconv.Itoa(trafficCap) + ` ]; then o=$(($5 - ` + strconv.Itoa(trafficCap) + `)); fi
  echo "@@host $1 $4 $5"
  if [ "$5" -gt "$o" ]; then tail -c +$((o + 1)) "$f" | head -c $(($5 - o)) | ` + trafficAwk + `; fi
}
`)
	for _, h := range hosts {
		if !hostIDRe.MatchString(h) {
			continue
		}
		m := marks[h]
		inode := m.Inode
		if inode == "" {
			inode = "-"
		}
		fmt.Fprintf(&b, "count %s %s %d\n", h, inode, m.Size)
	}
	b.WriteString("exit 0\n")
	return b.String()
}

// ParseTraffic reads TrafficScript's output.
func (Driver) ParseTraffic(out string) ([]proxy.Hit, map[string]proxy.LogMark) {
	var hits []proxy.Hit
	marks := map[string]proxy.LogMark{}
	host := ""
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 4 && f[0] == "@@host" {
			host = f[1]
			size, _ := strconv.ParseInt(f[3], 10, 64)
			marks[host] = proxy.LogMark{Inode: f[2], Size: size}
			continue
		}
		// 08/Nov/2026:10:15 +0330 2 14 5120
		if host == "" || len(f) != 5 {
			continue
		}
		minute, err := time.Parse("02/Jan/2006:15:04 -0700", f[0]+" "+f[1])
		if err != nil {
			continue
		}
		class, _ := strconv.Atoi(f[2])
		if class < 1 || class > 5 {
			class = 0
		}
		n, err1 := strconv.ParseInt(f[3], 10, 64)
		bytes, err2 := strconv.ParseInt(f[4], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		hits = append(hits, proxy.Hit{
			Host: host, Minute: minute.UTC(), Class: class,
			Requests: n, Bytes: bytes,
		})
	}
	return hits, marks
}
