package api

import "testing"

func TestParseSockets(t *testing.T) {
	text := `@proc 10
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 030012AC:B26E 020012AC:1538 01 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 20 4 30 10 -1
   0: 0000000000000000FFFF0000030012AC:0050 0000000000000000FFFF0000010012AC:D431 01 00000000:00000000 00:00000000 00000000 0 0 3
@ss 20
LISTEN 0      4096         0.0.0.0:5432      0.0.0.0:*
	 cubic cwnd:10
ESTAB  0      0      [::ffff:172.18.0.2]:5432 [::ffff:172.18.0.3]:45678
	 cubic wscale:7,7 bytes_sent:900 bytes_acked:800 bytes_received:1200 segs_out:3
`
	var s netScan
	s.byPid = map[int][]socket{}
	parseSockets(text, &s)
	p := s.byPid[10]
	if len(p) != 3 || p[0].state != "LISTEN" || p[0].local.port != 8080 {
		t.Fatalf("proc: %+v", p)
	}
	if p[1].local.ip != "172.18.0.3" || p[1].remote.ip != "172.18.0.2" || p[1].remote.port != 5432 {
		t.Fatalf("proc v4: %+v", p[1])
	}
	if p[2].local.ip != "172.18.0.3" || p[2].local.port != 80 || p[2].remote.ip != "172.18.0.1" {
		t.Fatalf("proc v6: %+v", p[2])
	}
	q := s.byPid[20]
	if !s.bytes || len(q) != 2 || q[1].local.ip != "172.18.0.2" || q[1].acked != 800 || q[1].recv != 1200 || q[1].remote.port != 45678 {
		t.Fatalf("ss: %+v", q)
	}
}
