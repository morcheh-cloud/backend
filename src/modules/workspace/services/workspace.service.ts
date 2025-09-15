import { Injectable } from "@nestjs/common"
import { User } from "src/modules/user/entities/user.entity"
import { CreateWorkSpacePayload } from "src/modules/workspace/DTOs/workspace.dto"
import { WorkspaceRepository } from "src/modules/workspace/repositories/workspace.repository"

@Injectable()
export class WorkspaceService {
	constructor(private workspaceRepository: WorkspaceRepository) {}

	async createWorkspace(payload: CreateWorkSpacePayload, user: User) {
		const workspace = await this.workspaceRepository.createAndSave({
			...payload,
			owner: user,
		})

		return {
			workspace,
		}
	}

	async delete(id: string, userId: string) {
		const isAllowed = await this.workspaceRepository.findOne({ where: { id, owner: { id: userId } } })
		if (!isAllowed) {
			throw new Error("You are not allowed to delete this workspace")
		}

		return await this.workspaceRepository.softDelete(id)
	}
}
