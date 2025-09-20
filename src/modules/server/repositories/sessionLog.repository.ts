import { BaseRepository } from "src/common/base/base.repository"
import { EntityRepository } from "src/common/decorators/typeorm-ex.decorator"
import { SessionLog } from "src/modules/server/entities/sessionLog.entity"

@EntityRepository(SessionLog)
export class sessionLogRepository extends BaseRepository<SessionLog> {}
