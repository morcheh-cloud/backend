import { BaseEntity } from "src/common/base/base.entity"
import { IsDateField, IsEnumField } from "src/common/decorators/validation.decorator"
import { User } from "src/modules/user/entities/user.entity"
import { Workspace } from "src/modules/workspace/entities/workspace.entity"
import { Column, Entity, JoinColumn, ManyToOne } from "typeorm"

export enum WorkspaceRole {
	MANAGER = "manager", // can manage members and settings
	EDITOR = "editor", // can create and edit resources
	VIEWER = "viewer", // can view resources
}

@Entity()
export class WorkspaceMember extends BaseEntity {
	@ManyToOne(() => Workspace, { nullable: false })
	@JoinColumn()
	workspace!: Workspace

	@ManyToOne(() => User, { nullable: false })
	@JoinColumn()
	user!: User

	@ManyToOne(() => User, { nullable: false })
	@JoinColumn()
	invitedBy!: User

	@IsEnumField(WorkspaceRole)
	@Column({
		default: WorkspaceRole.VIEWER,
		enum: WorkspaceRole,
		type: "enum",
	})
	role!: WorkspaceRole

	@IsDateField()
	@Column({ nullable: true })
	expiredAt?: Date
}
