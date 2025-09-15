import { SetMetadata, UseGuards } from "@nestjs/common"
import { ApiHeader } from "@nestjs/swagger"
import { PermissionsGuard } from "src/common/guards/permissions.guard"
import { PermissionSubject } from "src/permissions"

export const API_PERMISSION_METADATA_KEY = "ApiPermissionMetaDataKey"

// manage = all actions
// read = read-only access
// update = edit existing resources
// delete = remove resources
// create = add new resources
export type Action = "manage" | "read" | "update" | "delete" | "create"
export type Subject = keyof typeof PermissionSubject
type Ability = `${Subject}:${Action}` | "owner" | "admin"

export function ApiPermissions(ability?: Ability) {
	return (target: object, key: string, descriptor: object) => {
		SetMetadata(API_PERMISSION_METADATA_KEY, ability)(target, key, descriptor)
		UseGuards(PermissionsGuard)(target, key, descriptor)
		ApiHeader({
			description: "current selected workspace",
			name: "workspaceId",
			required: true,
		})(target, key, descriptor)
	}
}
