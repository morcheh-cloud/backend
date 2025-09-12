import { Logger } from "@nestjs/common"
import { Client } from "ssh2"

interface ExecuteRemoteCommandOptions {
	host: string
	username: string
	password: string
	port?: number
	command: string

	sudoPassword?: string
	become?: boolean
}

interface RemoteCommandResult {
	stdout: string
	stderr: string
	code: number
}

const logger = new Logger("ssh")

export function executeRemoteCommand(arg: ExecuteRemoteCommandOptions): Promise<RemoteCommandResult> {
	const { host, username, password, port = 22, command, become } = arg

	const sudoPassword = arg.sudoPassword || arg.password

	return new Promise((resolve, reject) => {
		const conn = new Client()
		let stdout = ""
		let stderr = ""

		conn
			.on("ready", () => {
				logger.verbose(`connected to server`)
				// If become is true, wrap the command with sudo
				const execCommand = become ? `sudo -S bash -c '${command.replace(/'/g, `'\\''`)}'` : command

				conn.exec(execCommand, (err, stream) => {
					if (err) {
						conn.end()
						return reject(err)
					}

					if (become && sudoPassword) {
						// Feed password to sudo prompt
						stream.write(`${sudoPassword}\n`)
					}

					stream
						.on("close", (code: number) => {
							conn.end()
							resolve({
								code: code ?? -1,
								stderr: stderr.trim(),
								stdout: stdout.trim(),
							})
						})
						.on("data", (data: Buffer) => {
							stdout += data.toString()
						})

					stream.stderr.on("data", (data: Buffer) => {
						stderr += data.toString()
					})
				})
			})
			.on("error", reject)
			.on("close", () => {
				logger.verbose("closed")
			})
			.connect({
				host,
				password,
				port,
				username,
			})
	})
}

export interface ICommand {
	cmd: string
	args?: string[]
	sudo?: boolean
	cwd?: string
	env?: Record<string, string>
}

export function Command(params: ICommand): string {
	const { args = [], cmd, cwd, env, sudo } = params

	let finalCmd = cmd

	// add args
	if (args.length > 0) {
		finalCmd += ` ${args.map(a => `"${a}"`).join(" ")}`
	}

	// handle options
	if (sudo) {
		finalCmd = `sudo ${finalCmd}`
	}
	if (cwd) {
		finalCmd = `cd ${cwd} && ${finalCmd}`
	}
	if (env) {
		const envStr = Object.entries(env)
			.map(([k, v]) => `${k}="${v}"`)
			.join(" ")
		finalCmd = `${envStr} ${finalCmd}`
	}

	return finalCmd
}
