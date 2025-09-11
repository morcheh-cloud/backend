import { BaseEntityWithoutSoftDelete } from "src/common/base/base.entity"
import { IsStringField } from "src/common/decorators/validation.decorator"
import { Workspace } from "src/modules/workspace/entities/workspace.entity"
import { Column, Entity, ManyToOne, OneToMany } from "typeorm"

@Entity()
export class ServerDirectory extends BaseEntityWithoutSoftDelete {
	@ManyToOne(() => Workspace, { nullable: false })
	workspace!: Workspace

	@ManyToOne(
		() => ServerDirectory,
		directory => directory.children,
		{
			onDelete: "CASCADE",
		},
	)
	parent?: ServerDirectory

	@OneToMany(
		() => ServerDirectory,
		directory => directory.parent,
	)
	children?: ServerDirectory[]

	@IsStringField()
	@Column()
	name!: string

	@IsStringField()
	@Column({ nullable: true })
	icon?: string
}
