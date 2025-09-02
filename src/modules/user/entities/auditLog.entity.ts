import { BaseEntityWithoutSoftDelete } from "src/common/base/base.entity";
import { IsStringField } from "src/common/decorators/validation.decorator";
import { User } from "src/modules/user/entities/user.entity";
import { Workspace } from "src/modules/workspace/entities/workspace.entity";
import { Column, Entity, ManyToOne } from "typeorm";

@Entity()
export class AuditLog extends BaseEntityWithoutSoftDelete {
  @ManyToOne(() => User, { nullable: false })
  user!: User;

  @ManyToOne(() => Workspace, { nullable: false })
  workspace!: Workspace;

  @IsStringField()
  @Column()
  message!: string;
}
