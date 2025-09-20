import { BaseEntityWithoutSoftDelete } from "src/common/base/base.entity"
import { IsNumberField, IsStringField } from "src/common/decorators/validation.decorator"
import { Session } from "src/modules/server/entities/session.entity"
import { Column, Entity, ManyToOne } from "typeorm"

@Entity()
export class SessionLog extends BaseEntityWithoutSoftDelete {
	@ManyToOne(() => Session, { nullable: false })
	session?: Session

	@IsStringField()
	@Column({ type: "text" })
	stdout?: string

	@IsStringField()
	@Column({ type: "text" })
	stderr?: string

	@IsNumberField()
	@Column({ default: 1 })
	version?: number
}
