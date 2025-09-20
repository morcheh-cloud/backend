import { BaseRepository } from "src/common/base/base.repository"
import { EntityRepository } from "src/common/decorators/typeorm-ex.decorator"
import { CronJob } from "src/modules/server/entities/cronjob.entity"

@EntityRepository(CronJob)
export class CronJobRepository extends BaseRepository<CronJob> {}
