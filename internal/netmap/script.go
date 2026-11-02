// Package netmap maps how a fleet of servers is networked: every server's
// interfaces and addresses, the subnets they share, and whether each server
// can reach the others (TCP to their SSH port, plus ping).
package netmap

// CollectScript reads one server's interfaces in a single round trip. Plain
// POSIX sh (busybox works). Output is line based: `@` lines are markers, the
// rest belong to the marker before them.
//
//   - @if: one line per interface from /sys (name, ARP type, DEVTYPE, bridge,
//     has a device, wireless, tun, operstate, MAC, MTU) so virtual ones can
//     be told apart, and so something shows without `ip`.
//   - @link / @addr: `ip -o` one-line output.
//   - @route: default routes (v4 and v6); @procroute (/proc/net/route) when
//     there is no `ip` (no addresses then: @noip).
//   - @docker: Docker/Podman network IDs and names, to name br-<id> bridges.
const CollectScript = `export LC_ALL=C
echo "@hostname $(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null)"
for d in /sys/class/net/*; do
  [ -e "$d" ] || continue
  n=${d##*/}
  t=$(cat "$d/type" 2>/dev/null)
  dt=$(grep -s '^DEVTYPE=' "$d/uevent" | cut -d= -f2)
  b=0; [ -d "$d/bridge" ] && b=1
  p=0; [ -e "$d/device" ] && p=1
  w=0; [ -d "$d/wireless" ] && w=1
  u=0; [ -e "$d/tun_flags" ] && u=1
  printf '@if %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$n" "${t:--}" "${dt:--}" "$b" "$p" "$w" "$u" \
    "$(cat "$d/operstate" 2>/dev/null)" "$(cat "$d/address" 2>/dev/null)" "$(cat "$d/mtu" 2>/dev/null)"
done
if command -v ip >/dev/null 2>&1; then
  echo @link; ip -o link show 2>/dev/null
  echo @addr; ip -o addr show 2>/dev/null
  echo @route; ip route show default 2>/dev/null; ip -6 route show default 2>/dev/null
else
  echo @noip
  echo @procroute; cat /proc/net/route 2>/dev/null
fi
S=
[ "$(id -u)" = 0 ] || { command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null && S="sudo -n"; }
for b in docker podman; do
  command -v $b >/dev/null 2>&1 || continue
  out=$($b network ls --no-trunc --format '{{.ID}}	{{.Name}}	{{.Driver}}' 2>/dev/null) ||
    { [ -n "$S" ] && out=$($S $b network ls --no-trunc --format '{{.ID}}	{{.Name}}	{{.Driver}}' 2>/dev/null); }
  [ -n "$out" ] && { echo "@docker $b"; printf '%s\n' "$out"; }
  break
done
exit 0
`

// ProbeScript tries every target it reads on stdin (`key<TAB>address<TAB>port`
// lines), all at once: a TCP connect to the port (bash /dev/tcp under
// timeout, else nc), one ping, and the route the kernel would take. Each
// result is one `@probe` line; addresses are passed as arguments, never
// spliced into a command.
const ProbeScript = `export LC_ALL=C
tcp() {
  if command -v bash >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
    timeout 2 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$1" "$2" 2>&1; return $?
  fi
  if command -v nc >/dev/null 2>&1; then
    nc -z -w 2 "$1" "$2" </dev/null 2>&1; return $?
  fi
  echo "no bash or nc"; return 127
}
pong() {
  command -v ping >/dev/null 2>&1 || { echo "-"; return; }
  out=$(ping -c 1 -W 1 "$1" 2>/dev/null) || { echo "x"; return; }
  printf '%s\n' "$out" | grep -o 'time[=<][0-9.]*' | head -n 1 | cut -c6-
}
while IFS='	' read -r key addr port; do
  [ -n "$addr" ] || continue
  (
    msg=$(tcp "$addr" "$port"); rc=$?
    msg=$(printf '%s\n' "$msg" | head -n 1 | tr '\t' ' ')
    rt=$(ip route get "$addr" 2>/dev/null | head -n 1)
    printf '@probe %s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$key" "$addr" "$port" "$rc" "$(pong "$addr")" "$rt" "$msg"
  ) &
done
wait
exit 0
`
