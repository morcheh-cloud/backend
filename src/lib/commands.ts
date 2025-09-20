/** biome-ignore-all lint/suspicious/noUselessEscapeInString: <explanation> */
export type StorageInfoCommandResult = {
	size?: string
	used?: string
	avail?: string
	use_pct?: string
}

export const StorageInfoCommand = `df -h --total | awk '/^total/ {printf("{\"size\":\"%s\",\"used\":\"%s\",\"avail\":\"%s\",\"use_pct\":\"%s\"}\n",$2,$3,$4,$5)}'`
export const GetHostnameCommand = `hostname`
export const GetOSInfoCommand = `cat /etc/os-release`

// Get Memory information
export interface GetMemoryInfoCommandResult {
	total: string
	used: string
	free: string
	shared: string
	buff_cache: string
	available: string
}
export const GetMemoryInfoCommand = `free -h | awk '/^Mem/ {printf("{\"total\":\"%s\",\"used\":\"%s\",\"free\":\"%s\",\"shared\":\"%s\",\"buff_cache\":\"%s\",\"available\":\"%s\"}\n",$2,$3,$4,$5,$6,$7)}'`

// Get CPU information
export interface GetCpuInfoCommandResult {
	model: string
	sockets: number
	cores_per_socket: number
	threads_per_core: number
	total_cores: number
	total_threads: number
}

export const GetCpuInfoCommand = `lscpu | awk -F: '/Model name/ {gsub(/^ +| +$/, "", $2); model=$2} /Socket\(s\)/ {gsub(/^ +| +$/, "", $2); sockets=$2} /Core\(s\) per socket/ {gsub(/^ +| +$/, "", $2); cores=$2} /Thread\(s\) per core/ {gsub(/^ +| +$/, "", $2); threads=$2} END {printf("{\"model\":\"%s\",\"sockets\":%d,\"cores_per_socket\":%d,\"threads_per_core\":%d,\"total_cores\":%d,\"total_threads\":%d}\n", model, sockets, cores, threads, sockets*cores, sockets*cores*threads)}'
`
