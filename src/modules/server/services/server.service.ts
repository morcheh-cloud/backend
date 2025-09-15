import { Injectable, OnModuleInit } from "@nestjs/common"
import { DirectoryService } from "src/modules/directory/services/directory.service"
import { SaveServerPayload } from "src/modules/server/DTOs/server.dto"
import { ServerProtocol } from "src/modules/server/entities/server.entity"
import { ServerRepository } from "src/modules/server/repositories/server.repository"
import { CredentialService } from "src/modules/vault/services/vault.service"

@Injectable()
export class ServerService implements OnModuleInit {
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
			protocol: ServerProtocol.SSH,
			user: { id: userId },
			workspace: { id: workspaceId },
		})

		return server
	}

	onModuleInit() {
		this.getTree("019942ff-edbb-7575-8418-c1de3bfa746b")
	}

	async getTree(workspaceId: string) {
		return this.directoryService.getServerTree(workspaceId)
	}
}
