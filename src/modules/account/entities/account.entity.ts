import { BaseEntityWithoutSoftDelete } from "src/common/base/base.entity"
import {
	IsReferenceField,
	IsStringField,
} from "src/common/decorators/validation.decorator"
import { Credential } from "src/modules/vault/entities/credential.entity"
import { Column, Entity, OneToOne } from "typeorm"

class AccountMetadata {
	@IsStringField()
	icon?: string
}

@Entity()
export class Account extends BaseEntityWithoutSoftDelete {
	@IsStringField()
	@Column()
	title!: string

	@IsStringField()
	@Column({ nullable: true })
	description?: string

	@IsStringField()
	@Column({ nullable: true })
	URI?: string

	@OneToOne(() => Credential, { nullable: false, onDelete: "CASCADE" })
	credential?: Credential

	@IsReferenceField()
	@Column({ default: {}, type: "json" })
	metadata?: AccountMetadata
}
