import { BaseEntity } from "src/common/base/base.entity";
import { IsEnumField } from "src/common/decorators/validation.decorator";
import { User } from "src/modules/user/entities/user.entity";
import { Workspace } from "src/modules/workspace/entities/workspace.entity";
import { Column, Entity, JoinColumn, ManyToOne } from "typeorm";

export enum WorkspaceRole {
  OWNER = "owner",
  ADMIN = "admin",
  EDITOR = "editor",
  GUEST = "guest",
}

@Entity()
export class WorkspaceMember extends BaseEntity {
  @ManyToOne(() => Workspace, { nullable: false })
  @JoinColumn()
  workspace!: Workspace;

  @ManyToOne(() => User, { nullable: false })
  @JoinColumn()
  user!: User;

  @IsEnumField(WorkspaceRole)
  @Column({
    default: WorkspaceRole.GUEST,
    enum: WorkspaceRole,
    type: "enum",
  })
  role!: WorkspaceRole;
}
