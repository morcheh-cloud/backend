import { SetMetadata } from "@nestjs/common";
import type { Role } from "src/modules/user/entities/user.entity";

export const ROLES_KEY = "roles";
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
