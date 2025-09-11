import SSH2Promise from "ssh2-promise"
import SSHConfig from "ssh2-promise/lib/sshConfig"

export interface ISSHConnection {
	config: SSHConfig
	lastActivityAt: number
	connection: SSH2Promise
	status: "connected" | "disconnected" | "error"
	connectedAt?: number
	disconnectedAt?: number
}
