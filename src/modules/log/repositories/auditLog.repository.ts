import { BaseRepository } from "src/common/base/base.repository"
import { EntityRepository } from "src/common/decorators/typeorm-ex.decorator"
import { AuditLog } from "src/modules/log/entities/auditLog.entity"

@EntityRepository(AuditLog)
export class AuditLogRepository extends BaseRepository<AuditLog> {}
