package storage

import "testing"

func TestS3PartSizeFor(t *testing.T) {
	const mib, gib = 1 << 20, 1 << 30
	for _, c := range []struct {
		hint int64
		want uint64
	}{
		{0, 32 * mib},
		{-5, 32 * mib},
		{1 * gib, 32 * mib},              // a hint never shrinks it
		{150 * gib, 32 * mib},            // 300 GiB fits 32 MiB parts
		{200 * gib, 41 * mib},            // 400 GiB / 10000 parts, rounded up to a MiB
		{2 << 40, 420 * mib},             // 2 TiB
		{1 << 50, uint64(s3MaxPartSize)}, // capped
	} {
		got := s3PartSizeFor(c.hint)
		if got != c.want {
			t.Errorf("hint %d: %d MiB, want %d MiB", c.hint, got/mib, c.want/mib)
		}
		if c.hint > 0 && got < uint64(s3MaxPartSize) && int64(got)*s3MaxParts < c.hint*s3HintMargin {
			t.Errorf("hint %d: %d MiB parts can't hold twice the hint", c.hint, got/mib)
		}
	}
}
