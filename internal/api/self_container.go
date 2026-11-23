package api

import (
	"os"
	"regexp"
	"strings"
	"sync"
)

// selfContainer is the ID of the container this backend runs in; "" outside
// Docker. Docker mounts /etc/hostname (and friends) from
// /var/lib/docker/containers/<id>/, which mountinfo shows; the hostname is
// the short ID unless compose set another.
var selfContainer = sync.OnceValue(func() string {
	if b, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		if m := containerDirRe.FindSubmatch(b); m != nil {
			return string(m[1])
		}
	}
	if h, err := os.Hostname(); err == nil && shortIDRe.MatchString(h) {
		if _, err := os.Stat("/.dockerenv"); err == nil {
			return h
		}
	}
	return ""
})

var (
	containerDirRe = regexp.MustCompile(`/containers/([0-9a-f]{64})/`)
	shortIDRe      = regexp.MustCompile(`^[0-9a-f]{12}$`)
)

// holdsSelf reports whether one of these containers is this backend.
func holdsSelf(cs []DockerRef) bool {
	self := selfContainer()
	if self == "" {
		return false
	}
	for _, c := range cs {
		if c.ID != "" && (strings.HasPrefix(c.ID, self) || strings.HasPrefix(self, c.ID)) {
			return true
		}
	}
	return false
}
