import { BaseEntity } from "src/common/base/base.entity"
import {
	IsReferenceField,
	IsStringField,
} from "src/common/decorators/validation.decorator"
import { AuditLog } from "src/modules/user/entities/auditLog.entity"
import { User } from "src/modules/user/entities/user.entity"
import { Column, Entity, Index, OneToMany, OneToOne } from "typeorm"

class WorkSpaceConfig {
	@IsStringField()
	color?: string
}

@Index(["name"], {
	unique: true,
	where: "name IS NOT NULL",
})
@Entity()
export class Workspace extends BaseEntity {
	@OneToOne(() => User, { nullable: false })
	owner!: User

	@OneToMany(
		() => AuditLog,
		(auditLog) => auditLog.workspace,
	)
	auditLogs?: AuditLog[]

	@IsStringField()
	@Column()
	name!: string

	@IsStringField({ required: false })
	@Column({ nullable: true })
	descriptions?: string

	@IsReferenceField()
	@Column({ default: {}, type: "jsonb" })
	config!: WorkSpaceConfig
}
