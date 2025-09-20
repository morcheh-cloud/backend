import { Injectable } from "@nestjs/common"
import { DirectoryService } from "src/modules/directory/services/directory.service"
import { SaveServerPayload } from "src/modules/server/DTOs/server.dto"
import { ServerProtocol } from "src/modules/server/entities/server.entity"
import { ServerRepository } from "src/modules/server/repositories/server.repository"
import { CredentialService } from "src/modules/vault/services/vault.service"

@Injectable()
export class ServerService {
	constructor(
		private readonly serverRepository: ServerRepository,
		private credentialService: CredentialService,
		private directoryService: DirectoryService,
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
			directory: { id: payload.directoryId },
			protocol: ServerProtocol.SSH,
			user: { id: userId },
			workspace: { id: workspaceId },
		})

		return server
	}

	async getTree(workspaceId: string) {
		return this.directoryService.getServerTree(workspaceId)
	}
}
