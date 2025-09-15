import { Body, Delete, Post } from "@nestjs/common"
import { SuccessModel } from "src/common/DTOs/std.dto"
import { BasicController } from "src/common/decorators/basicController.decorator"
import { GetUser } from "src/common/decorators/getUser.decorator"
import { StandardApi } from "src/common/decorators/standard-api.decorator"
import { User } from "src/modules/user/entities/user.entity"
import { CreateWorkSpacePayload, DeleteWorkSpacePayload } from "src/modules/workspace/DTOs/workspace.dto"
import { WorkspaceService } from "src/modules/workspace/services/workspace.service"

@BasicController("workspace")
export class WorkspaceController {
	constructor(private workspaceService: WorkspaceService) {}

	@StandardApi()
	@Post()
	async create(@GetUser() user: User, @Body() body: CreateWorkSpacePayload) {
		const workspace = await this.workspaceService.createWorkspace(body, user)
		return workspace
	}

	@StandardApi({ type: SuccessModel })
	@Delete()
	async delete(@Body() body: DeleteWorkSpacePayload, @GetUser() user: User) {
		await this.workspaceService.delete(body.id, user.id)
		return new SuccessModel("Workspace deleted successfully")
	}
}
