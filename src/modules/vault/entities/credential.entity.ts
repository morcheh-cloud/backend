import { BaseEntityWithoutSoftDelete } from "src/common/base/base.entity";
import { Account } from "src/modules/account/entities/account.entity";
import { Server } from "src/modules/server/entities/server.entity";
import { User } from "src/modules/user/entities/user.entity";
import { Column, Entity, ManyToOne, OneToOne } from "typeorm";

@Entity()
export class Credential extends BaseEntityWithoutSoftDelete {
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

  @ManyToOne(() => User, { nullable: false })
  createdBy!: User;

  @ManyToOne(() => Server)
  server?: Server;

  @OneToOne(() => Account)
  account?: Account;
}
