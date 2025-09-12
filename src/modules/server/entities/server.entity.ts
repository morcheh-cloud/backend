import { BaseEntity } from "src/common/base/base.entity";
import {
  IsBooleanField,
  IsEnumField,
  IsNumberField,
  IsReferenceField,
  IsStringField,
} from "src/common/decorators/validation.decorator";
import { Directory } from "src/modules/directory/entities/directory.entity";
import { AuditLog } from "src/modules/log/entities/auditLog.entity";
import { User } from "src/modules/user/entities/user.entity";
import { Credential } from "src/modules/vault/entities/credential.entity";
import { Workspace } from "src/modules/workspace/entities/workspace.entity";
import { Column, Entity, ManyToOne, OneToMany, OneToOne } from "typeorm";

export class ServerMetadata {
  @IsStringField()
  icon?: string;
}

export enum ServerProtocol {
  SSH = "ssh",
  RDP = "rdp",
  SFTP = "sftp",
  VNC = "vnc",
}

export enum ServerOS {
  LINUX = "linux",
  WINDOWS = "windows",
  MACOS = "macos",
}

export enum ServerStatus {
  CONNECTED = "connected",
  UNKNOWN = "unknown",
}

@Entity()
export class Server extends BaseEntity {
  @ManyToOne(() => Workspace, { nullable: false })
  workspace!: Workspace;

  @ManyToOne(() => User, { nullable: false })
  user!: User;

  @ManyToOne(() => Directory, { nullable: false })
  directory!: Directory;

  @OneToOne(() => Credential, (c) => c.server, {
    eager: true,
    nullable: false,
    onDelete: "CASCADE",
  })
  credential!: Credential;

  @OneToMany(() => AuditLog, (a) => a.server)
  logs!: AuditLog[];

  @IsStringField()
  @Column()
  name!: string;

  @IsStringField()
  @Column({ nullable: true })
  description?: string;

  @IsStringField()
  @Column()
  address!: string;

  @IsNumberField()
  @Column()
  port!: number;

  @IsReferenceField()
  @Column({ default: {}, type: "jsonb" })
  metadata!: ServerMetadata;

  @IsEnumField(ServerProtocol)
  @Column({ enum: ServerProtocol, type: "enum" })
  protocol!: ServerProtocol;

  @IsEnumField(ServerOS)
  @Column({ enum: ServerOS, nullable: true, type: "enum" })
  os?: ServerOS; // fill automatic by OS detection

  @IsBooleanField()
  @Column({ default: false })
  keepAlive!: boolean;
}
