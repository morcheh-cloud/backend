import { BaseEntityWithoutSoftDelete } from "src/common/base/base.entity"
import { IsDateField, IsEnumField, IsStringField } from "src/common/decorators/validation.decorator"
import { Server } from "src/modules/server/entities/server.entity"
import { SessionLog } from "src/modules/server/entities/sessionLog.entity"
import { User } from "src/modules/user/entities/user.entity"
import { Column, Entity, ManyToOne, OneToMany } from "typeorm"

export enum SessionStatus {
	INITIALIZING = "initializing",
	CONNECTED = "connected",
	CONNECTING = "connecting",
	FAILED = "failed",
	CLOSED = "closed",
}

@Entity()
export class Session extends BaseEntityWithoutSoftDelete {
	@ManyToOne(() => Server, { nullable: false })
	server?: Server

	@OneToMany(
		() => SessionLog,
		c => c.session,
	)
	logs?: SessionLog[]

	@ManyToOne(() => User)
	user?: User

	@IsEnumField(SessionStatus)
	@Column({ enum: SessionStatus, type: "enum" })
	status?: SessionStatus

	@IsStringField()
	@Column({ nullable: true })
	message?: string

	@IsStringField()
	@Column({ nullable: true })
	stderr?: string

	@IsDateField()
	@Column({ nullable: true })
	startedAt?: Date

	@IsDateField()
	@Column({ nullable: true })
	finishedAt?: Date
}
