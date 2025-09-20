import { Body, Delete, Post } from "@nestjs/common"
import { SuccessModel } from "src/common/DTOs/std.dto"
import { BasicController } from "src/common/decorators/basicController.decorator"
import { GetUser } from "src/common/decorators/getUser.decorator"
import { GetWorkspace } from "src/common/decorators/getWorkspace.decorator"
import { StandardApi } from "src/common/decorators/standard-api.decorator"
import { DirectoryModel, SaveDirectoryPayload } from "src/modules/directory/DTOs/directory.dto"
import { DirectoryService } from "src/modules/directory/services/directory.service"
import { User } from "src/modules/user/entities/user.entity"
import { Workspace } from "src/modules/workspace/entities/workspace.entity"

@BasicController("directory")
export class DirectoryController {
	constructor(private readonly directoryService: DirectoryService) {}

	@StandardApi({ type: DirectoryModel })
	@Post()
	async create(
		@GetUser() user: User,
		@GetWorkspace() workspace: Workspace,
		@Body() body: SaveDirectoryPayload,
	) {
		const result = await this.directoryService.create(user.id, workspace.id, body)
		return result
	}

	@StandardApi({ type: SuccessModel })
	@Delete()
	async delete(@GetWorkspace() workspace: Workspace, @Body() body: { id: string }) {
		const result = await this.directoryService.delete(body.id, workspace.id)
		return result
	}
}
