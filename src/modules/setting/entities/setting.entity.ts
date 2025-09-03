import { BaseEntityWithoutSoftDelete } from "src/common/base/base.entity"
import { Column, Entity } from "typeorm"

@Entity()
export class Setting extends BaseEntityWithoutSoftDelete {
	@Column()
	key!: string

	@Column({ type: "jsonb" })
	value!: Record<string, unknown>
}
