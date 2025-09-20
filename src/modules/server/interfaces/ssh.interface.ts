import SSH2Promise from "ssh2-promise"
import SSHConfig from "ssh2-promise/lib/sshConfig"

export interface IActiveSession {
	sessionId: string
	serverId: string
	config: SSHConfig
	connection: SSH2Promise
}
