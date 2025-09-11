import { BaseEntity } from "src/common/base/base.entity"
import { IsEnumField, IsJSONField } from "src/common/decorators/validation.decorator"
import type { IPlaybook } from "src/modules/ansible/interfaces/playbook.interface"
import { Column, Entity } from "typeorm"

export enum ModuleType {
	OFFICIAL = "official",
	COMMUNITY = "community",
	CUSTOM = "custom",
}

@Entity()
export class Module extends BaseEntity {
	@Column({ unique: true })
	name!: string

	@Column()
	description!: string

	@IsEnumField(ModuleType)
	@Column({ enum: ModuleType, type: "enum" })
	type!: ModuleType

	@IsJSONField()
	@Column({ default: {}, type: "json" })
	schema!: Partial<IPlaybook>
}
