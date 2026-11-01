package sshprobe

import "testing"

func TestParseUnix(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want OS
	}{
		{
			name: "ubuntu",
			out: "Linux\n6.8.0-45-generic\nx86_64\nweb-01\n---\n" +
				"PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\n",
			want: OS{Family: "linux", ID: "ubuntu", Name: "Ubuntu", Version: "24.04", Kernel: "6.8.0-45-generic", Arch: "x86_64", Hostname: "web-01"},
		},
		{
			name: "debian long name is shortened",
			out:  "Linux\n6.1.0\naarch64\ndb\n---\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nID=debian\n",
			want: OS{Family: "linux", ID: "debian", Name: "Debian", Version: "12", Kernel: "6.1.0", Arch: "aarch64", Hostname: "db"},
		},
		{
			name: "macos",
			out:  "Darwin\n23.5.0\narm64\nmac-mini\n---\nProductName:\t\tmacOS\nProductVersion:\t\t14.5\nBuildVersion:\t\t23F79\n",
			want: OS{Family: "darwin", ID: "macos", Name: "macOS", Version: "14.5", Kernel: "23.5.0", Arch: "arm64", Hostname: "mac-mini"},
		},
		{
			name: "freebsd without os-release",
			out:  "FreeBSD\n14.1-RELEASE\namd64\nbsd\n---\n",
			want: OS{Family: "freebsd", ID: "freebsd", Name: "FreeBSD", Version: "14.1-RELEASE", Kernel: "14.1-RELEASE", Arch: "amd64", Hostname: "bsd"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseUnix(tt.out)
			if !ok || got != tt.want {
				t.Errorf("parseUnix() = %+v, %v; want %+v", got, ok, tt.want)
			}
		})
	}
}

func TestParseUnixRejectsCmdOutput(t *testing.T) {
	if _, ok := parseUnix("'uname' is not recognized as an internal or external command\r\n"); ok {
		t.Error("expected cmd.exe output to be rejected")
	}
}

func TestParseWindows(t *testing.T) {
	got := parseWindows("\r\nMicrosoft Windows [Version 10.0.20348.2340]\r\n")
	if got.ID != "windows" || got.Version != "10.0.20348.2340" {
		t.Errorf("parseWindows() = %+v", got)
	}
}
