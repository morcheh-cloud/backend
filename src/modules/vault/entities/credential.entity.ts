import { BaseEntityWithoutSoftDelete } from "src/common/base/base.entity";
import { Account } from "src/modules/account/entities/account.entity";
import { Server } from "src/modules/server/entities/server.entity";
import { User } from "src/modules/user/entities/user.entity";
import { Workspace } from "src/modules/workspace/entities/workspace.entity";
import { Column, Entity, JoinColumn, ManyToOne, OneToOne } from "typeorm";

@Entity()
export class Credential extends BaseEntityWithoutSoftDelete {
  @ManyToOne(() => User, { nullable: false })
  @JoinColumn()
  user!: User;

  @ManyToOne(() => Workspace, { nullable: false })
  @JoinColumn()
  workspace!: Workspace;

  @OneToOne(() => Server, (s) => s.credential)
  @JoinColumn()
  server?: Server;

  @OneToOne(() => Account, (a) => a.credential)
  @JoinColumn()
  account?: Account;

  @Column({ nullable: true })
  username?: string; // encrypted

  @Column({ nullable: true })
  password?: string; // encrypted

  @Column({ nullable: true })
  description?: string; // encrypted

  @Column({ nullable: true })
  token?: string; // encrypted

  @Column({ nullable: true })
  expiredAt?: Date;

  @Column({ nullable: true, type: "varchar" })
  metadata?: Record<string, unknown>; // encrypted
}
