// src/rbac/permissions.guard.ts
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { InjectDataSource } from "@nestjs/typeorm";
import { Request } from "express";
import { API_PERMISSION_METADATA_KEY } from "src/common/decorators/permission.decorator";
import { Permission } from "src/modules/auth/entities/permission.entity";
import { User } from "src/modules/user/entities/user.entity";
import { Workspace } from "src/modules/workspace/entities/workspace.entity";
import { DataSource, Repository } from "typeorm";

@Injectable()
export class PermissionsGuard implements CanActivate {
  private readonly workspaceRepository: Repository<Workspace>;
  private readonly permissionRepository: Repository<Permission>;

  constructor(
    private readonly reflector: Reflector,
    @InjectDataSource()
    private readonly dataSource: DataSource
  ) {
    this.workspaceRepository =
      this.dataSource.getRepository<Workspace>(Workspace);

    this.permissionRepository =
      this.dataSource.getRepository<Permission>(Permission);
  }

  async checkUserWorkspacePermission(
    workspaceId: string,
    userId: string,
    ability: string
  ) {
    const isOwner = await this.workspaceRepository
      .createQueryBuilder("workspace")
      .where("workspace.id = :workspaceId", { workspaceId })
      .andWhere("workspace.ownerId = :userId", { userId })
      .getCount();

    if (isOwner) {
      return true;
    }

    const isAllowed = await this.permissionRepository
      .createQueryBuilder("permission")
      .where("permission.workspaceId = :workspaceId", { workspaceId })
      .andWhere("permission.userId = :userId", { userId })
      .andWhere("permission.ability = :ability", { ability })
      .getCount();

    return isAllowed > 0;
  }

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const request = ctx.switchToHttp().getRequest<Request>();
    const user = (request as any)["user"] as User;

    const ability = this.reflector.getAllAndOverride<string>(
      API_PERMISSION_METADATA_KEY,
      [ctx.getHandler(), ctx.getClass()]
    );

    const workspaceId: string =
      (request.query["workspaceId"] as string) ||
      (request.query["workspaceid"] as string) ||
      (request.headers["workspaceId"] as string) ||
      (request.headers["workspaceid"] as string);

    if (!workspaceId) {
      throw new ForbiddenException("Workspace ID is required");
    }

    if (user.isAdmin) {
      return true;
    }

    const isAllowed = await this.checkUserWorkspacePermission(
      workspaceId,
      user.id,
      ability
    );

    if (isAllowed) {
      return true;
    }

    // access denied error
    throw new ForbiddenException(
      `User is not allowed to ${ability} on workspace ${workspaceId}`
    );
  }
}
