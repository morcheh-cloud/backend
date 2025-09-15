import { Injectable } from "@nestjs/common"
import { SaveServerPayload } from "src/modules/server/DTOs/server.dto"
import { ServerProtocol } from "src/modules/server/entities/server.entity"
import { ServerRepository } from "src/modules/server/repositories/server.repository"
import { SSHService } from "src/modules/server/services/ssh.service"
import { CredentialService } from "src/modules/vault/services/vault.service"

@Injectable()
export class ServerService {
	constructor(
		private readonly serverRepository: ServerRepository,
		private credentialService: CredentialService,
		private sshService: SSHService,
	) {}

	async create(userId: string, workspaceId: string, payload: SaveServerPayload) {
		const credential = await this.credentialService.create(userId, workspaceId, {
			description: payload.description,
			password: payload.password,
			username: payload.username,
		})

		const server = await this.serverRepository.createAndSave({
			...payload,
			credential,
			protocol: ServerProtocol.SSH,
			user: { id: userId },
			workspace: { id: workspaceId },
		})

		return server
	}

	async serverHealthCheck(serverId: string) {
		const { stderr, stdout } = await this.sshService.execCommand(serverId, {
			cmd: `echo ping`,
		})

		return { stderr, stdout }
	}
}
