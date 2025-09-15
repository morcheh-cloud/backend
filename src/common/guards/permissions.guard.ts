// src/rbac/permissions.guard.ts
import {
	CanActivate,
	ExecutionContext,
	ForbiddenException,
	Injectable,
	InternalServerErrorException,
} from "@nestjs/common"
import { InjectDataSource } from "@nestjs/typeorm"
import { Request } from "express"
import { User } from "src/modules/user/entities/user.entity"
import { Workspace } from "src/modules/workspace/entities/workspace.entity"
import { WorkspaceMember, WorkspaceRole } from "src/modules/workspace/entities/workspaceMember.entity"
import { PermissionAction } from "src/permissions"
import { DataSource, Repository } from "typeorm"

@Injectable()
export class PermissionsGuard implements CanActivate {
	// private readonly workspaceRepository: Repository<Workspace>
	// private readonly permissionRepository: Repository<Permission>
	// private readonly teamRepository: Repository<Team>
	private readonly workspaceMemberRepository: Repository<WorkspaceMember>

	constructor(
		@InjectDataSource()
		private readonly dataSource: DataSource,
		// private readonly reflector: Reflector,
	) {
		// this.workspaceRepository = this.dataSource.getRepository<Workspace>(Workspace)
		// this.permissionRepository = this.dataSource.getRepository<Permission>(Permission)
		// this.teamRepository = this.dataSource.getRepository<Team>(Team)
		this.workspaceMemberRepository = this.dataSource.getRepository<WorkspaceMember>(WorkspaceMember)
	}

	private readonly rolePermissionsMap: Record<WorkspaceRole, PermissionAction[]> = {
		[WorkspaceRole.MANAGER]: [
			PermissionAction.READ,
			PermissionAction.CREATE,
			PermissionAction.UPDATE,
			PermissionAction.DELETE,
		],
		[WorkspaceRole.EDITOR]: [PermissionAction.CREATE, PermissionAction.READ, PermissionAction.UPDATE],
		[WorkspaceRole.VIEWER]: [PermissionAction.READ],
	}

	private readonly actionResolver: Record<string, PermissionAction> = {
		DELETE: PermissionAction.DELETE,
		GET: PermissionAction.READ,
		PATCH: PermissionAction.UPDATE,
		POST: PermissionAction.CREATE,
		PUT: PermissionAction.UPDATE,
	}

	private isActionAllowedForRole(action: PermissionAction, role: WorkspaceRole): boolean {
		const allowedActions = this.rolePermissionsMap[role]
		return allowedActions.includes(action)
	}

	private async validateUserAccess(user: User, workspace: Workspace, action: PermissionAction): Promise<boolean> {
		if (user.isAdmin) {
			return true
		}

		if (workspace.owner.id === user.id) {
			return true
		}

		const workspaceMembership = await this.workspaceMemberRepository.findOne({
			select: { expiredAt: true, id: true },
			where: { user: { id: user.id }, workspace: { id: workspace.id } },
		})

		if (workspaceMembership) {
			const isExpired = workspaceMembership.expiredAt && workspaceMembership.expiredAt < new Date()
			if (isExpired) {
				return false
			}

			const role = workspaceMembership.role
			const isAllowed = this.isActionAllowedForRole(action, role)
			if (isAllowed) {
				return true
			}
		}

		// const teamMemberships = await this.teamRepository.find({
		// 	where: {
		// 		users: { id: user.id },
		// 		workspace: { id: workspace.id },
		// 	},
		// })

		// for (const team of teamMemberships) {
		// }

		return false
	}

	async canActivate(ctx: ExecutionContext): Promise<boolean> {
		const request = ctx.switchToHttp().getRequest<Request>()
		const user = request.user
		const method = request.method
		const workspace = request.workspace

		// const workspaceIdRequired = this.reflector.getAllAndOverride<boolean>(WORKSPACE_ID_IS_REQUIRED_METADATA_KEY, [
		// 	ctx.getHandler(),
		// ])

		// if (!workspaceIdRequired) {
		// 	return true
		// }

		if (!user || !workspace) {
			throw new InternalServerErrorException("User or workspace not found in request")
		}

		// const ability = this.reflector.getAllAndOverride<string>(API_PERMISSION_METADATA_KEY, [
		// 	ctx.getHandler(),
		// 	ctx.getClass(),
		// ])

		const action = this.actionResolver[method]
		if (!action) {
			throw new ForbiddenException(`Unsupported method ${method}`)
		}

		const isAllowed = await this.validateUserAccess(user, workspace, action)
		if (isAllowed) {
			return true
		}

		// access denied error
		throw new ForbiddenException(`You don't have permission`)
	}
}
