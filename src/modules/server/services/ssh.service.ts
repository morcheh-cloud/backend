import { Injectable } from "@nestjs/common"
import { Command, ICommand } from "src/lib/ssh"
import { SessionService } from "src/modules/server/services/session.service"

@Injectable()
export class SSHService {
	constructor(private sessionService: SessionService) {}

	async execCommand(serverId: string, commandOptions: ICommand) {
		const client = await this.sessionService.getOrCreate(serverId)

		const exp = Command(commandOptions)
		let stdout = ""
		let stderr = ""

		try {
			stdout = await client.connection.exec(exp)
		} catch (e) {
			stderr = e as string
		}

		const isError = !!stderr.length
		await this.sessionService.logOutput(client.sessionId, stdout, isError)

		await this.sessionService.close(client.sessionId)

		return { stderr, stdout }
	}
}
