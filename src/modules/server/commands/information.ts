/** biome-ignore-all lint/suspicious/noUselessEscapeInString: <explanation> */
export const ListeningPortsCommand = `
ss -tulpenH | awk '
BEGIN {
  print "["
  first = 1
}
{
  split($5,a,":"); port=a[length(a)];

  # extract program name
  prog = $7
  sub(/^users:\(\("/, "", prog)
  sub(/".*/, "", prog)

  # extract pid
  pid = $7
  match(pid, /pid=([0-9]+)/, m)
  if (m[1] != "") pid = m[1]; else pid = ""

  if (!first) {
    print ","
  }
  first = 0

  printf "  {\"proto\":\"%s\",\"state\":\"%s\",\"local\":\"%s\",\"port\":%s,\"program\":\"%s\",\"pid\":%s}",
    $1, $2, $5, port, prog, pid
}
END {
  print "\n]"
}'
`
