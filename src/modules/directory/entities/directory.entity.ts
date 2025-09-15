import { BaseEntity } from "src/common/base/base.entity"
import { IsBooleanField, IsEnumField, IsStringField } from "src/common/decorators/validation.decorator"
import { Server } from "src/modules/server/entities/server.entity"
import { Workspace } from "src/modules/workspace/entities/workspace.entity"
import { Column, Entity, Index, ManyToOne, OneToMany } from "typeorm"

export enum DirectoryType {
	SERVER = "server",
	PLAYBOOK = "playbook",
	ANSIBLE_MODULE = "ansible_module",
	SECRETE = "secrete",
	DATABASE = "database",
	DOCUMENT = "document",
}

@Index(["workspace", "name"], { unique: true })
@Entity()
export class Directory extends BaseEntity {
	@ManyToOne(
		() => Directory,
		d => d.children,
		{ onDelete: "CASCADE" },
	)
	parent?: Directory

	@OneToMany(
		() => Directory,
		directory => directory.parent,
		{
			onDelete: "CASCADE",
		},
	)
	children?: Directory[]

	@OneToMany(
		() => Server,
		server => server.directory,
	)
	servers?: Server[]

	@ManyToOne(() => Workspace)
	workspace!: Workspace

	@IsStringField()
	@Column()
	name!: string

	@IsEnumField(DirectoryType)
	@Column({ enum: DirectoryType, type: "enum" })
	type!: DirectoryType

	@IsBooleanField()
	@Column({ default: true })
	isDeletable!: boolean

	@IsBooleanField()
	@Column({ default: true })
	isEditable!: boolean

	@IsBooleanField()
	@Column({ default: false })
	isHidden!: boolean

	@IsBooleanField()
	@Column({ default: false })
	isLocked!: boolean

	@IsStringField()
	@Column({ nullable: true })
	icon?: string
}
