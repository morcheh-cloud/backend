import { BaseEntity } from "src/common/base/base.entity"
import {
	IsEnumField,
	IsJSONField,
	IsReferenceField,
	IsStringField,
} from "src/common/decorators/validation.decorator"
import type { IPlaybook } from "src/modules/ansible/interfaces/playbook.interface"
import { Column, Entity } from "typeorm"

export class Code {
	@IsStringField()
	content!: string
}

export enum PlayBookType {
	OFFICIAL = "official",
	COMMUNITY = "community",
	CUSTOM = "custom",
}

@Entity()
export class PlayBook extends BaseEntity {
	@Column({ unique: true })
	name!: string

	@Column()
	description!: string

	@IsReferenceField()
	@Column("jsonb", { default: {} })
	content!: Code

	@IsEnumField(PlayBookType)
	@Column({ enum: PlayBookType, type: "enum" })
	type!: PlayBookType

	@IsJSONField()
	@Column({ default: {}, type: "json" })
	schema!: Partial<IPlaybook>
}
