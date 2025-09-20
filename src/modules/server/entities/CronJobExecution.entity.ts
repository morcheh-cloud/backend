import { BaseEntity } from "src/common/base/base.entity"
import { IsDateField, IsStringField } from "src/common/decorators/validation.decorator"
import { CronJob } from "src/modules/server/entities/cronjob.entity"
import { Session } from "src/modules/server/entities/session.entity"
import { Column, Entity, ManyToOne } from "typeorm"

export enum CronJobExecutionStatus {
	RUNNING = "running",
	SUCCESS = "success",
	FAILED = "failed",
	CANCELLED = "cancelled",
}

@Entity()
export class CronJobExecution extends BaseEntity {
	@ManyToOne(() => CronJob, { nullable: false })
	cronJob!: CronJob

	@ManyToOne(() => Session, { nullable: true })
	session?: Session

	@IsStringField()
	@Column()
	status!: string

	@IsDateField()
	@Column({ nullable: false })
	startedAt!: Date

	@IsDateField()
	@Column({ nullable: true })
	finishedAt?: Date
}
