import { BaseEntityWithoutSoftDelete } from "src/common/base/base.entity";
import { User } from "src/modules/user/entities/user.entity";
import { Team } from "src/modules/workspace/entities/team.entity";
import { Workspace } from "src/modules/workspace/entities/workspace.entity";
import { Column, Entity, Index, JoinColumn, ManyToOne } from "typeorm";

@Index(["user", "workspace", "ability"], { unique: true })
@Entity()
export class Permission extends BaseEntityWithoutSoftDelete {
  @ManyToOne(() => User, (u) => u.permissions)
  @JoinColumn()
  user!: User;

  @ManyToOne(() => Team, (t) => t.permissions)
  @JoinColumn()
  team!: Team;

  @ManyToOne(() => Workspace, { nullable: false })
  @JoinColumn()
  workspace!: Workspace;

  @Column()
  ability!: string;

  @Column({ nullable: true })
  expiredAt?: Date;
}
