package ansible

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestNames(t *testing.T) {
	got := Names([]string{"web 01", "web-01", "Web 01", "", "localhost", "a/b"})
	want := []string{"web-01", "web-01-2", "Web-01-3", "server", "localhost-2", "a-b"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Names[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestGroupName(t *testing.T) {
	for in, want := range map[string]string{
		"Web Servers": "web_servers", "prod-1": "prod_1", "all": "tag_all", "ungrouped": "tag_ungrouped",
		"1st": "_1st", "---": "", "os_ubuntu": "os_ubuntu",
	} {
		if got := GroupName(in); got != want {
			t.Errorf("GroupName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLogReducer(t *testing.T) {
	l := NewLog()
	l.Apply(RunEvent{E: "play", ID: "p", Name: "Play", Hosts: "all"})
	l.Apply(RunEvent{E: "task", ID: "t", Play: "p", Name: "Task", Action: "ping"})
	l.Apply(RunEvent{E: "start", Task: "t", Host: "a"})
	l.Apply(RunEvent{E: "start", Task: "t", Host: "b"})
	l.Apply(RunEvent{E: "result", Task: "t", Host: "a", Status: "changed"})
	l.Close()
	task := l.Plays[0].Tasks[0]
	if task.Results["a"].Status != "changed" {
		t.Errorf("a = %s", task.Results["a"].Status)
	}
	if task.Results["b"].Status != "failed" {
		t.Errorf("b should be closed as failed, is %s", task.Results["b"].Status)
	}
	if s := l.Recap["a"]; s.Ok != 1 || s.Changed != 1 {
		t.Errorf("recap a = %+v", s)
	}
	if s := l.Recap["b"]; s.Failed != 1 {
		t.Errorf("recap b = %+v", s)
	}
}

func TestInventoryRefusesUnknownHostKey(t *testing.T) {
	err := writeInventory(t.TempDir(), []Host{{ServerID: "x", ServerName: "web", Name: "web"}})
	if err == nil || !strings.Contains(err.Error(), "Check it first") {
		t.Fatalf("err = %v", err)
	}
}

// liveHostKey asks the test server for its key; the test is skipped when the
// container isn't running.
func liveHostKey(t *testing.T) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "127.0.0.1:2222", time.Second)
	if err != nil {
		t.Skip("test-ssh isn't running")
	}
	defer conn.Close()
	var key string
	cfg := &ssh.ClientConfig{User: "x", Timeout: 3 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = string(ssh.MarshalAuthorizedKey(k))
			return nil
		}}
	c, _, _, _ := ssh.NewClientConn(conn, "127.0.0.1:2222", cfg)
	if c != nil {
		c.Close()
	}
	if key == "" {
		t.Skip("no host key from test-ssh")
	}
	return key
}

func runLive(t *testing.T, sandbox, playbook, hostKey string) (int, string, *Log) {
	t.Helper()
	cfg := Config{Playbook: "ansible-playbook", Sandbox: sandbox, Timeout: 2 * time.Minute}
	if _, err := os.Stat(os.ExpandEnv("$HOME/.local/bin/ansible-playbook")); err == nil {
		cfg.Playbook = os.ExpandEnv("$HOME/.local/bin/ansible-playbook")
	}
	st := Detect(context.Background(), cfg)
	if !st.Installed {
		t.Skip(st.Problem)
	}
	if st.Problem != "" {
		t.Fatal(st.Problem)
	}
	var out strings.Builder
	log := NewLog()
	code, err := Run(context.Background(), cfg, st, Spec{
		Playbook: playbook, Forks: 2,
		Hosts: []Host{{ServerID: "11111111-1111-1111-1111-111111111111", Name: "web-01", ServerName: "web 01",
			Address: "127.0.0.1", Port: 2222, User: "ant", Password: "colony", HostKey: hostKey, Groups: []string{"web"}}},
	}, Hook{Output: func(s string) { out.WriteString(s) }, Event: func(e RunEvent) { log.Apply(e) }})
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	log.Close()
	return code, out.String(), log
}

const livePlaybook = `- hosts: web
  gather_facts: false
  tasks:
    - name: Who
      command: id -un
    - name: Root
      become: true
      command: id -un
    - name: Secrets not here
      command: echo "{{ lookup('env', 'DATABASE_URL') }}|{{ lookup('env', 'SECRETS_KEY') }}|"
`

func TestLiveRun(t *testing.T) {
	key := liveHostKey(t)
	for _, sandbox := range []string{SandboxBwrap, SandboxOff} {
		t.Run(sandbox, func(t *testing.T) {
			code, out, log := runLive(t, sandbox, livePlaybook, key)
			if code != 0 {
				t.Fatalf("exit %d\n%s", code, out)
			}
			if len(log.Plays) != 1 || len(log.Plays[0].Tasks) != 3 {
				t.Fatalf("plays = %+v\n%s", log.Plays, out)
			}
			tasks := log.Plays[0].Tasks
			if got := tasks[0].Results["web-01"].Stdout; got != "ant" {
				t.Errorf("who = %q", got)
			}
			if got := tasks[1].Results["web-01"].Stdout; got != "root" {
				t.Errorf("become = %q", got)
			}
			if got := tasks[2].Results["web-01"].Stdout; got != "||" {
				t.Errorf("env leaked: %q", got)
			}
			if log.Recap["web-01"].Ok != 3 {
				t.Errorf("recap = %+v", log.Recap)
			}
		})
	}
}

// A wrong stored key must stop the connection, not get replaced.
func TestLiveRefusesChangedHostKey(t *testing.T) {
	liveHostKey(t)
	// Some other valid key.
	wrong := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"
	code, out, log := runLive(t, SandboxBwrap, livePlaybook, wrong)
	if code == 0 {
		t.Fatalf("connected despite a wrong host key\n%s", out)
	}
	if s := log.Recap["web-01"]; s.Unreachable+s.Failed == 0 || s.Ok > 0 {
		t.Errorf("recap = %+v\n%s", log.Recap, out)
	}
}

// The sandbox hides the host's files from a playbook's local tasks.
func TestLiveSandboxHidesHostFiles(t *testing.T) {
	key := liveHostKey(t)
	secret := filepath.Join(os.Getenv("HOME"), ".morcheh-ansible-test-secret")
	if err := os.WriteFile(secret, []byte("topsecret"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(secret)
	pb := `- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - shell: 'cat ` + secret + ` 2>&1 || true; ls /proc | grep -c "^[0-9]" || true'
`
	_, out, log := runLive(t, SandboxBwrap, pb, key)
	if strings.Contains(out, "topsecret") {
		t.Fatalf("the sandbox let a playbook read a host file\n%s", out)
	}
	if len(log.Plays) == 0 || len(log.Plays[0].Tasks) == 0 {
		t.Fatalf("nothing ran\n%s", out)
	}
	res := log.Plays[0].Tasks[0].Results["localhost"]
	if res == nil || res.Status == "failed" || strings.Contains(res.Stdout, "topsecret") {
		t.Fatalf("result = %+v\n%s", res, out)
	}
}

func TestFilterMasksAcrossChunks(t *testing.T) {
	f := NewFilter([]Host{{Password: "s3cr3t-pass"}, {Password: "abc"}, {Passphrase: `q"uote`}})
	got := f.Write([]byte("login s3cr")) + f.Write([]byte("3t-pass done abc ")) + f.Write([]byte(`{"p":"q\"uote"}`)) + f.Flush()
	if strings.Contains(got, "s3cr") || strings.Contains(got, `q\"uote`) {
		t.Errorf("leaked: %q", got)
	}
	if !strings.Contains(got, "login **** done abc ") {
		t.Errorf("got %q", got)
	}
}

func TestFilterKeepsSplitCharacters(t *testing.T) {
	f := NewFilter(nil)
	b := []byte("سلام\x00")
	got := ""
	for i := range b {
		got += f.Write(b[i : i+1])
	}
	if got += f.Flush(); got != "سلام" {
		t.Errorf("got %q", got)
	}
}

func TestOutputCap(t *testing.T) {
	var o Output
	o.Add("first\n")
	if o.Truncated() || o.String() != "first\n" {
		t.Fatalf("%q", o.String())
	}
	line := strings.Repeat("x", 1<<16) + "\n"
	for range 200 {
		o.Add(line)
	}
	o.Add("last\n")
	s := o.String()
	if !o.Truncated() || !strings.HasPrefix(s, "first\n") || !strings.HasSuffix(s, "last\n") || !strings.Contains(s, "dropped") {
		t.Errorf("truncated=%v len=%d", o.Truncated(), len(s))
	}
	if len(s) > outputHead+outputTail+200 {
		t.Errorf("too long: %d", len(s))
	}
}

func TestFilterEventMasksValuesOnly(t *testing.T) {
	f := NewFilter([]Host{{Password: "status"}, {Password: `pa"ss`}})
	ev, err := f.Event([]byte(`{"e":"result","status":"ok","msg":"status pa\"ss"}`))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != "ok" || ev.Msg != "**** ****" {
		t.Errorf("%+v", ev)
	}
}
