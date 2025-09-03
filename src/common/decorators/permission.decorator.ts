import { SetMetadata, UseGuards } from "@nestjs/common"
import { ApiBearerAuth } from "@nestjs/swagger"
import { AuthGuard } from "src/common/guards/auth.guard"
// import { PermissionGuard } from '../guard/permission.guard';
// import { RolePermissionGuard } from '../guard/rolePermission.guard';
// import { OwnerGuard } from 'src/common/guard/owner.guard';

export const PermissionMetDataKey = "LevelPermissionMetDataKey"

interface ApiPermissionParam {
	autoFill?: boolean
	name?: string
	groupName?: string
}

export const ApiPermissionMetaDataKey = "ApiPermissionMetaDataKey"

export enum ApiAccessLevel {
	ADMIN = "admin",
	USER = "user",
	SUPPLIER = "reference",
	ALL = "all",
}

export function ApiPermission(
	level: ApiAccessLevel[] = [],
	option: ApiPermissionParam = {},
) {
	level = [...level, ApiAccessLevel.ADMIN]

	return (target: any, key: any, descriptor: any) => {
		const actionName = option?.name || key
		const groupName = option?.groupName || target.constructor.name

		const actionData: any = { group: { name: groupName }, name: actionName }

		Reflect.defineMetadata(ApiPermissionMetaDataKey, actionData, descriptor)

		ApiBearerAuth()(target, key, descriptor)
		SetMetadata("permission", level)(target, key, descriptor)
		SetMetadata(PermissionMetDataKey, level)(target, key, descriptor)
		UseGuards(AuthGuard)(target, key, descriptor)
	}
}
