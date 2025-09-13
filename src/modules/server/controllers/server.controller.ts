import { Body, Post } from "@nestjs/common";
import { BasicController } from "src/common/decorators/basicController.decorator";
import { GetUser } from "src/common/decorators/getUser.decorator";
import { GetWorkspace } from "src/common/decorators/getWorkspace.decorator";
import { ApiPermissions } from "src/common/decorators/permission.decorator";
import { StandardApi } from "src/common/decorators/standard-api.decorator";
import {
  SaveServerPayload,
  ServerModel,
} from "src/modules/server/DTOs/server.dto";
import { ServerService } from "src/modules/server/services/server.service";
import { User } from "src/modules/user/entities/user.entity";
import { Workspace } from "src/modules/workspace/entities/workspace.entity";

@BasicController("server")
export class ServerController {
  constructor(private serverService: ServerService) {}

  @ApiPermissions("ansible:create")
  @StandardApi({ type: ServerModel })
  @Post("create")
  async create(
    @GetUser() user: User,
    @GetWorkspace() workspace: Workspace,
    @Body() body: SaveServerPayload
  ) {
    const server = await this.serverService.create(user.id, workspace.id, body);
    return server;
  }
}
