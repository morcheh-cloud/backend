package ports

// Script collects everything Parse needs in one round trip. It is plain
// POSIX sh (busybox works) and only reads: listening sockets (ss, else
// netstat; as root when the login user is root or `sudo -n` works, so every
// socket's process is visible), each owning process's name, user, command
// line and cgroup (which names its systemd unit or container), those units'
// descriptions, and the running containers with their published ports.
//
// Output is line based: `@` lines are markers, the rest belong to the marker
// before them.
const Script = `S=
if [ "$(id -u)" = 0 ]; then echo "@priv 1"
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then S="sudo -n"; echo "@priv 1"
else echo "@priv 0"; fi

if command -v ss >/dev/null 2>&1; then
  echo "@tool ss"; out=$($S ss -tulpn 2>/dev/null || ss -tulpn 2>/dev/null)
elif command -v netstat >/dev/null 2>&1; then
  echo "@tool netstat"; out=$($S netstat -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null)
else
  echo "@tool none"; out=
fi
echo "@sockets"
printf '%s\n' "$out"

units=
for p in $(printf '%s\n' "$out" | grep -oE 'pid=[0-9]+| [0-9]+/' | tr -dc '0-9\n' | sort -un); do
  cg=$(tr '\n' ' ' < /proc/$p/cgroup 2>/dev/null)
  printf '@pid %s\t%s\t%s\t%s\t%s\n' "$p" \
    "$(cat /proc/$p/comm 2>/dev/null)" \
    "$(stat -c %U /proc/$p 2>/dev/null)" \
    "$(tr '\0\t\n' '   ' < /proc/$p/cmdline 2>/dev/null | cut -c1-400)" \
    "$cg"
  u=$(printf '%s' "$cg" | grep -oE '[^/ ]+\.service' | tail -n 1)
  [ -n "$u" ] && units="$units $u"
done
if [ -n "$units" ] && command -v systemctl >/dev/null 2>&1; then
  echo "@units"
  systemctl show -p Id -p Description $(printf '%s\n' $units | sort -u) 2>/dev/null
fi

F='{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Config.Image}},"state":{{json .State.Status}},"network":{{json .HostConfig.NetworkMode}},"labels":{{json .Config.Labels}},"ports":{{json .NetworkSettings.Ports}}}'
for b in docker podman; do
  command -v $b >/dev/null 2>&1 || continue
  if err=$($b ps -q 2>&1 >/dev/null); then D=$b
  elif [ -n "$S" ] && $S $b ps -q >/dev/null 2>&1; then D="$S $b"
  else echo "@docker error $b $(printf '%s\n' "$err" | head -n 1)"; break; fi
  echo "@docker ok $b"
  ids=$($D ps -q)
  [ -n "$ids" ] && $D inspect --format "$F" $ids 2>/dev/null
  break
done
exit 0
`
