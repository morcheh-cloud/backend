import { BaseEntity } from "src/common/base/base.entity"
import { IsStringField } from "src/common/decorators/validation.decorator"
import { Permission } from "src/modules/auth/entities/permission.entity"
import { User } from "src/modules/user/entities/user.entity"
import { Workspace } from "src/modules/workspace/entities/workspace.entity"
import { Column, Entity, JoinTable, ManyToMany, ManyToOne, OneToMany } from "typeorm"

@Entity()
export class Team extends BaseEntity {
	@ManyToOne(() => Workspace, { nullable: false })
	workspace!: Workspace

	@ManyToMany(
		() => User,
		u => u.teams,
	)
	@JoinTable()
	users!: User[]

	@OneToMany(
		() => Permission,
		permission => permission.team,
	)
	permissions?: Permission[]

	@IsStringField()
	@Column()
	name!: string
}
