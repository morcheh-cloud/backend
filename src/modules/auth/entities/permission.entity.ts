import { BaseEntityWithoutSoftDelete } from "src/common/base/base.entity";
import { User } from "src/modules/user/entities/user.entity";
import { Workspace } from "src/modules/workspace/entities/workspace.entity";
import { Column, Entity, Index, JoinColumn, ManyToOne } from "typeorm";

@Index(["user", "workspace", "ability"], { unique: true })
@Entity()
export class Permission extends BaseEntityWithoutSoftDelete {
  @ManyToOne(() => User, { nullable: false })
  @JoinColumn()
  user!: User;

  @ManyToOne(() => Workspace, { nullable: false })
  @JoinColumn()
  workspace!: Workspace;

  @Column()
  ability!: string;

  @Column({ nullable: true })
  expiredAt?: Date;
}
