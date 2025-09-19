import { BaseEntityWithoutSoftDelete } from "src/common/base/base.entity"
import { IsDateField, IsEnumField, IsStringField } from "src/common/decorators/validation.decorator"
import { Server } from "src/modules/server/entities/server.entity"
import { SessionChunks } from "src/modules/server/entities/sessionChunk.entity"
import { User } from "src/modules/user/entities/user.entity"
import { Column, Entity, ManyToOne, OneToMany } from "typeorm"

export enum SessionStatus {
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
		() => SessionChunks,
		c => c.session,
	)
	chunks?: SessionChunks[]

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
