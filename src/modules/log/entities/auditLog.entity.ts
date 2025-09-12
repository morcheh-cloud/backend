import { BaseEntityWithoutSoftDelete } from "src/common/base/base.entity"
import { IsEnumField, IsStringField } from "src/common/decorators/validation.decorator"
import { ServerCommandExecLog, ServerLoginLog } from "src/modules/log/DTOs/log.dto"
import { Server } from "src/modules/server/entities/server.entity"
import { User } from "src/modules/user/entities/user.entity"
import { Workspace } from "src/modules/workspace/entities/workspace.entity"
import { Column, Entity, ManyToOne } from "typeorm"

export enum AudiLogType {
	REQUEST = "request",
	SERVER = "server",
}

export enum AuditLogLevel {
	INFO = "info",
	DEBUG = "debug",
	ERROR = "error",
}

type AudiLogDataType = ServerCommandExecLog | ServerLoginLog

@Entity()
export class AuditLog extends BaseEntityWithoutSoftDelete {
	@ManyToOne(() => User)
	user?: User

	@ManyToOne(() => Workspace)
	workspace?: Workspace

	@ManyToOne(() => Server)
	server?: Server

	@IsStringField()
	@Column()
	message!: string

	@IsStringField()
	@Column({ nullable: true })
	error?: string

	@IsStringField()
	@Column({ nullable: true })
	ip?: string

	@IsStringField()
	@Column({ default: {}, type: "jsonb" })
	data!: AudiLogDataType

	@IsEnumField(AuditLogLevel)
	@Column({ enum: AuditLogLevel, type: "enum" })
	level!: AuditLogLevel
}
