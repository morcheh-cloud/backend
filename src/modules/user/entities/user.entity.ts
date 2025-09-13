import { Exclude } from "class-transformer";
import { IsEmail } from "class-validator";
import { BaseEntity } from "src/common/base/base.entity";
import { IsStringField } from "src/common/decorators/validation.decorator";
import { Permission } from "src/modules/auth/entities/permission.entity";
import { AuditLog } from "src/modules/log/entities/auditLog.entity";
import { Team } from "src/modules/workspace/entities/team.entity";
import { Workspace } from "src/modules/workspace/entities/workspace.entity";
import { Column, Entity, ManyToMany, OneToMany } from "typeorm";

export enum UserRole {
  USER = "user",
  ADMIN = "admin",
}

@Entity()
export class User extends BaseEntity {
  @OneToMany(() => Workspace, (workspace) => workspace.owner)
  workspaces?: Workspace[];

  @ManyToMany(() => Team, (team) => team.users)
  teams?: Team[];

  @OneToMany(() => Permission, (permission) => permission.user)
  permissions?: Permission[];

  @OneToMany(() => AuditLog, (auditLog) => auditLog.user)
  auditLogs?: AuditLog[];

  @IsStringField()
  @Column()
  fullName!: string;

  @IsEmail()
  @IsStringField()
  @Column({ unique: true })
  email!: string;

  @Exclude()
  @Column()
  password!: string;

  // @Column({ enum: UserRole, type: "enum" })
  // role!: UserRole;

  @Column({ default: false })
  isAdmin!: boolean;
}
