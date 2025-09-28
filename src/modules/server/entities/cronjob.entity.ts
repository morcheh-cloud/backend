import { BaseEntity } from "src/common/base/base.entity"
import { IsNumberField, IsObjectField, IsStringField } from "src/common/decorators/validation.decorator"
import { CronJobExecution } from "src/modules/server/entities/CronJobExecution.entity"
import { Server } from "src/modules/server/entities/server.entity"
import { Column, Entity, ManyToOne, OneToMany } from "typeorm"

export enum CronJobType {
	ANSIBLE = "ansible",
	SHELL = "shell",
	SSH = "ssh",
	PYTHON = "python",
	JAVASCRIPT = "javascript",
}

@Entity()
export class CronJob extends BaseEntity {
	@ManyToOne(() => Server)
	server?: Server

	@OneToMany(
		() => CronJobExecution,
		e => e.cronJob,
	)
	executions?: CronJobExecution[]

	@ManyToOne(() => CronJobExecution)
	lastExecution?: CronJobExecution

	@IsStringField()
	@Column()
	name?: string

	@IsStringField()
	@Column({ nullable: true })
	description?: string

	@IsStringField()
	@Column()
	cronTime?: string

	@IsStringField()
	@Column()
	command?: string

	@IsStringField()
	@Column()
	timezone?: string

	@IsObjectField()
	@Column({ default: false })
	isEnabled?: boolean

	@IsNumberField()
	@Column({
		default: 60, // in seconds
	})
	timeout?: number

	// @IsNumberField()
	// @Column({ default: 0 })
	// retryCount?: number

	// @IsNumberField()
	// @Column({ default: 0 })
	// maxRetries?: number
}
