package api

import "testing"

func TestBucketAccess(t *testing.T) {
	const b = "photos"
	keep := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::1:user/x"]},"Action":["s3:PutObject"],"Resource":["arn:aws:s3:::photos/*"]}]}`
	for _, access := range []string{"private", "download", "public"} {
		for _, base := range []string{"", keep} {
			p, err := withAccess(b, base, access)
			if err != nil {
				t.Fatal(err)
			}
			if got, write := classify(b, p); got != access || write {
				t.Errorf("%s on %q: got %s (write %v) from %s", access, base, got, write, p)
			}
			if access == "private" && base == "" && p != "" {
				t.Errorf("private without other statements should remove the policy, got %s", p)
			}
		}
	}
	open := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::photos/*"}]}`
	if got, write := classify(b, open); got != "custom" || !write {
		t.Errorf("s3:* for anyone: got %s write %v", got, write)
	}
	if got, _ := classify(b, "not json"); got != "custom" {
		t.Errorf("bad JSON: got %s", got)
	}
}
