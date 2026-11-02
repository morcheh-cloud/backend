package dbmon

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func engineAuthError(err error) bool {
	return engineAuthErrorPostgres(err) || engineAuthErrorMySQL(err) ||
		engineAuthErrorMSSQL(err)
}

// sortTables keeps the 20 largest tables across every database read.
func sortTables(s *DatabaseSnapshot) {
	sort.SliceStable(s.Tables, func(i, j int) bool { return s.Tables[i].SizeBytes > s.Tables[j].SizeBytes })
	if len(s.Tables) > 20 {
		s.Tables = s.Tables[:20]
	}
	sort.SliceStable(s.IDColumns, func(i, j int) bool { return s.IDColumns[i].Ratio > s.IDColumns[j].Ratio })
	if len(s.IDColumns) > 15 {
		s.IDColumns = s.IDColumns[:15]
	}
	sort.SliceStable(s.Indexes, func(i, j int) bool { return deref(s.Indexes[i].SizeBytes) > deref(s.Indexes[j].SizeBytes) })
	if len(s.Indexes) > 15 {
		s.Indexes = s.Indexes[:15]
	}
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func groupDigits(n int64) string {
	s := strconv.FormatInt(n, 10)
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func humanSeconds(v float64) string {
	switch {
	case v < 120:
		return fmt.Sprintf("%.0f s", v)
	case v < 7200:
		return fmt.Sprintf("%.0f min", v/60)
	case v < 172800:
		return fmt.Sprintf("%.1f h", v/3600)
	}
	return fmt.Sprintf("%.1f days", v/86400)
}
