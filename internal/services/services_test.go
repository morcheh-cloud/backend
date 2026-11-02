package services

import (
	"slices"
	"testing"
)

const show = `Id=nginx.service
Description=A high performance web server
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=enabled
UnitFilePreset=enabled
MainPID=812
MemoryCurrent=7340032
CPUUsageNSec=[not set]
TasksCurrent=18446744073709551615
StateChangeTimestamp=@1793586600
NRestarts=2
FragmentPath=/usr/lib/systemd/system/nginx.service
DropInPaths=/etc/systemd/system/nginx.service.d/override.conf
CanStart=yes
CanStop=yes
CanReload=yes
ExecStart={ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -g daemon on; master_process on; ; ignore_errors=no ; start_time=[n/a] }
Environment=A=1 "B=two words"
EnvironmentFiles=/etc/default/nginx (ignore_errors=yes)

Id=nginx.service
Description=duplicate alias

Id=gone.service
LoadState=not-found
ActiveState=inactive

Id=myapp.service
LoadState=loaded
ActiveState=failed
FragmentPath=/etc/systemd/system/myapp.service
`

func TestParseShow(t *testing.T) {
	blocks := ParseShow(show)
	if len(blocks) != 3 {
		t.Fatalf("blocks = %d, want 3", len(blocks))
	}
	list := List(blocks)
	if len(list) != 2 || list[0].Name != "nginx.service" || list[1].Name != "myapp.service" {
		t.Fatalf("list = %+v", list)
	}
	n := list[0]
	if n.MainPID != 812 || n.Restarts != 2 || n.Memory == nil || *n.Memory != 7340032 || n.CPUNs != nil || n.Tasks != nil {
		t.Errorf("counters = %+v", n)
	}
	if n.Since == nil || n.Since.Unix() != 1793586600 || n.Preset != "enabled" || !n.CanReload || n.Custom {
		t.Errorf("nginx = %+v", n)
	}
	if !list[1].Custom {
		t.Errorf("myapp should be custom")
	}
	d := DetailsFrom(blocks[0], "")
	if !slices.Equal(d.ExecStart, []string{"/usr/sbin/nginx -g daemon on; master_process on;"}) {
		t.Errorf("exec = %q", d.ExecStart)
	}
	if !slices.Equal(d.Environment, []string{"A=1", "B=two words"}) || !slices.Equal(d.EnvironmentFiles, []string{"/etc/default/nginx"}) {
		t.Errorf("env = %q %q", d.Environment, d.EnvironmentFiles)
	}
}

func TestParseCat(t *testing.T) {
	files := ParseCat("# /usr/lib/systemd/system/nginx.service\n[Unit]\nDescription=x\n\n# /etc/systemd/system/nginx.service.d/override.conf\n[Service]\nRestart=always\n")
	if len(files) != 2 || files[0].Content != "[Unit]\nDescription=x\n" || files[0].DropIn || !files[1].DropIn {
		t.Fatalf("files = %+v", files)
	}
	if Revision(files[1].Content) != Revision("[Service]\r\nRestart=always\n\n\n") {
		t.Errorf("revision should ignore line endings and trailing newlines")
	}
	if Normalize(" \n\n") != "" {
		t.Errorf("blank should normalize to empty")
	}
}

func TestParseJournalLine(t *testing.T) {
	e, ok := ParseJournalLine(`{"__CURSOR":"s=1","__REALTIME_TIMESTAMP":"1793586600000000","PRIORITY":"3","_PID":"812","SYSLOG_IDENTIFIER":"nginx","MESSAGE":[104,105]}`)
	if !ok || e.Message != "hi" || e.Priority != 3 || e.PID != 812 || e.Ident != "nginx" || e.Cursor != "s=1" || e.Time.Unix() != 1793586600 {
		t.Fatalf("entry = %+v %v", e, ok)
	}
	if _, ok := ParseJournalLine("not json"); ok {
		t.Error("garbage parsed")
	}
}

func TestOpenRC(t *testing.T) {
	list := OpenRC(OpenRCInput{
		Scripts: "sshd\tOpenBSD Secure Shell server\nnginx\t\ncrond\tcron daemon\n",
		Status:  "Runlevel: default\n sshd    [  started  ]\n crond   [  crashed  ]\n",
		Update:  "   sshd | boot default\n  nginx |\n  crond | default\n",
	})
	if len(list) != 3 {
		t.Fatalf("list = %+v", list)
	}
	byName := map[string]Service{}
	for _, s := range list {
		byName[s.Name] = s
	}
	if s := byName["sshd"]; s.Active != "active" || s.Enabled != "enabled" || !s.Protected {
		t.Errorf("sshd = %+v", s)
	}
	if s := byName["nginx"]; s.Active != "inactive" || s.Enabled != "disabled" {
		t.Errorf("nginx = %+v", s)
	}
	if s := byName["crond"]; s.Active != "failed" {
		t.Errorf("crond = %+v", s)
	}
}
