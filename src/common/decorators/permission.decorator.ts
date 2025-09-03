import { SetMetadata, UseGuards } from "@nestjs/common";
import { PermissionsGuard } from "src/common/guards/permissions.guard";

export const API_PERMISSION_METADATA_KEY = "ApiPermissionMetaDataKey";

export type Action = "manage" | "read" | "update" | "delete" | "create";
export type Subject = "article" | "s3" | "vod";
type Ability = `${Subject}:${Action}`;

export function ApiPermissions(ability: Ability) {
  return (target: object, key: string, descriptor: object) => {
    SetMetadata(API_PERMISSION_METADATA_KEY, ability)(target, key, descriptor);
    UseGuards(PermissionsGuard)(target, key, descriptor);
  };
}
