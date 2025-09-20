import { Injectable } from "@nestjs/common"
import { Command, ICommand } from "src/lib/ssh"
import { SessionService } from "src/modules/server/services/session.service"

@Injectable()
export class SSHService {
	constructor(private sessionService: SessionService) {}

	async execCommand(serverId: string, commandOptions: ICommand) {
		const client = await this.sessionService.getOrCreate(serverId)

		const cmd = Command(commandOptions)
		let stdout = ""
		let stderr = ""

		try {
			stdout = await client.connection.exec(cmd)
		} catch (e) {
			stderr = e as string
		}

		this.sessionService.logCommand(client.sessionId, cmd, stdout, stderr)

		await this.sessionService.close(client.sessionId)

		return { stderr, stdout }
	}

	async execManyCommand(serverId: string, commands: ICommand[]) {
		const client = await this.sessionService.getOrCreate(serverId)
		const results: { stderr: string; stdout: string }[] = []

		for (const commandOptions of commands) {
			const cmd = Command(commandOptions)
			let stdout = ""
			let stderr = ""

			try {
				stdout = await client.connection.exec(cmd)
			} catch (e) {
				stderr = e as string
			}

			this.sessionService.logCommand(client.sessionId, cmd, stdout, stderr)
			results.push({ stderr, stdout })
		}

		await this.sessionService.close(client.sessionId)

		return results
	}
}
