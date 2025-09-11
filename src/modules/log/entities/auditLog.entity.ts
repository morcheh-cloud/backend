import { BaseEntityWithoutSoftDelete } from "src/common/base/base.entity"
import { IsEnumField, IsStringField } from "src/common/decorators/validation.decorator"
import { Server } from "src/modules/server/entities/server.entity"
import { User } from "src/modules/user/entities/user.entity"
import { Workspace } from "src/modules/workspace/entities/workspace.entity"
import { Column, Entity, ManyToOne } from "typeorm"

export enum AudiLogType {
	REQUEST = "request",
}

export enum AuditLogLevel {
	INFO = "info",
	DEBUG = "debug",
	ERROR = "error",
}

@Entity()
export class AuditLog extends BaseEntityWithoutSoftDelete {
	@ManyToOne(() => User)
	user!: User

	@ManyToOne(() => Workspace)
	workspace!: Workspace

	@ManyToOne(() => Server)
	server!: Server

	@IsStringField()
	@Column()
	message!: string

	@IsStringField()
	@Column({ default: {}, type: "jsonb" })
	content!: object

	@IsEnumField(AuditLogLevel)
	@Column({ enum: AudiLogType, type: "enum" })
	log!: AudiLogType

	@IsEnumField(AudiLogType)
	@Column({ enum: AudiLogType, type: "enum" })
	type!: AudiLogType
}
