import { Module } from "@nestjs/common"
import { TypeOrmExModule } from "src/common/typeorm-ex.module"
import { AuditLogRepository } from "src/modules/log/repositories/auditLog.repository"

@Module({
	imports: [TypeOrmExModule.forFeature([AuditLogRepository])],
})
export class LogModule {}
