import { BaseEntity } from "src/common/base/base.entity"
import {
	IsEnumField,
	IsNumberField,
	IsReferenceField,
	IsStringField,
} from "src/common/decorators/validation.decorator"
import { ServerDirectory } from "src/modules/server/entities/serverDirectory.entity"
import { Credential } from "src/modules/vault/entities/credential.entity"
import { Workspace } from "src/modules/workspace/entities/workspace.entity"
import { Column, Entity, ManyToOne, OneToOne } from "typeorm"

export class ServerMetadata {
	@IsStringField()
	icon?: string
}

export enum Protocol {
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

@Entity()
export class Server extends BaseEntity {
	@ManyToOne(() => Workspace, { nullable: false })
	workspace!: Workspace

	@OneToOne(() => Credential, {
		eager: true,
		nullable: false,
		onDelete: "CASCADE",
	})
	credential!: Credential

	@ManyToOne(() => ServerDirectory)
	directory?: ServerDirectory

	@IsStringField()
	@Column()
	name!: string

	@IsStringField()
	@Column({ nullable: true })
	description?: string

	@IsStringField()
	@Column()
	address!: string

	@IsNumberField()
	@Column()
	port!: number

	@IsReferenceField()
	@Column({ default: {}, type: "jsonb" })
	metadata!: ServerMetadata

	@IsEnumField(Protocol)
	@Column({ enum: Protocol, type: "enum" })
	protocol!: Protocol

	@IsEnumField(ServerOS)
	@Column({ enum: ServerOS, nullable: true, type: "enum" })
	os?: ServerOS // fill automatic by OS detection
}
