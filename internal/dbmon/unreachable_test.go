package dbmon

import (
	"net/netip"
	"testing"
)

func TestUnreachable(t *testing.T) {
	for addr, want := range map[string]bool{
		"169.254.169.254":        true, // AWS/GCP/Azure metadata
		"fe80::1":                true,
		"100.100.100.200":        true, // Alibaba
		"fd00:ec2::254":          true, // AWS IPv6
		"::ffff:169.254.169.254": true,
		"64:ff9b::a9fe:a9fe":     true, // 169.254.169.254 behind NAT64
		"0.0.0.0":                true,
		"224.0.0.1":              true,
		"127.0.0.1":              false, // dev MinIO
		"10.0.0.5":               false, // in-house storage
		"192.168.1.10":           false,
		"8.8.8.8":                false,
	} {
		if got := Unreachable(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Unreachable(%s) = %v, want %v", addr, got, want)
		}
	}
	if err := RefuseUnreachable("tcp", "169.254.169.254:80", nil); err == nil {
		t.Error("metadata dial not refused")
	}
	if err := RefuseUnreachable("tcp", "127.0.0.1:9100", nil); err != nil {
		t.Errorf("loopback refused: %v", err)
	}
}
