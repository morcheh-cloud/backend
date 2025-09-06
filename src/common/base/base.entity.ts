import { IsStringField } from "src/common/decorators/validation.decorator"
import { BeforeInsert, CreateDateColumn, DeleteDateColumn, PrimaryColumn, UpdateDateColumn } from "typeorm"
import { v7 as uuidv7 } from "uuid"

export class BaseEntityWithoutSoftDelete {
	@IsStringField()
	@PrimaryColumn()
	id!: string

	@CreateDateColumn()
	createdAt!: Date

	@UpdateDateColumn()
	updatedAt!: Date

	@BeforeInsert()
	generateId() {
		if (!this.id) {
			this.id = uuidv7()
		}
	}
}

export class BaseEntity extends BaseEntityWithoutSoftDelete {
	@DeleteDateColumn()
	deletedAt?: Date
}
