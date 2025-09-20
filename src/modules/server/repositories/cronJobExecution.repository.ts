import { BaseRepository } from "src/common/base/base.repository"
import { EntityRepository } from "src/common/decorators/typeorm-ex.decorator"
import { CronJobExecution } from "src/modules/server/entities/CronJobExecution.entity"

@EntityRepository(CronJobExecution)
export class CronJobExecutionRepository extends BaseRepository<CronJobExecution> {}
