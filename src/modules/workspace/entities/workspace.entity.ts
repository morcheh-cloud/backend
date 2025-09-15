import { BaseEntity } from "src/common/base/base.entity"
import { IsReferenceField, IsStringField } from "src/common/decorators/validation.decorator"
import { Permission } from "src/modules/auth/entities/permission.entity"
import { Directory } from "src/modules/directory/entities/directory.entity"
import { AuditLog } from "src/modules/log/entities/auditLog.entity"
import { User } from "src/modules/user/entities/user.entity"
import { WorkspaceMember } from "src/modules/workspace/entities/workspaceMember.entity"
import { Column, Entity, Index, JoinColumn, ManyToOne, OneToMany, OneToOne } from "typeorm"

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
	@ManyToOne(() => User, { nullable: false })
	@JoinColumn()
	owner!: User

	@OneToOne(
		() => Permission,
		permission => permission.workspace,
	)
	permission?: Permission

	@OneToMany(
		() => AuditLog,
		auditLog => auditLog.workspace,
	)
	auditLogs?: AuditLog[]

	@OneToMany(
		() => WorkspaceMember,
		member => member.workspace,
	)
	members?: WorkspaceMember[]

	@OneToMany(
		() => Directory,
		directory => directory.workspace,
	)
	directories?: Directory[]

	@IsStringField()
	@Column()
	name!: string

	@IsStringField({ required: false })
	@Column({ nullable: true })
	descriptions?: string

	@IsReferenceField()
	@Column({ default: {}, type: "jsonb" })
	config!: WorkSpaceConfig

	@IsStringField()
	@Column({ nullable: true })
	timezone?: string
}
