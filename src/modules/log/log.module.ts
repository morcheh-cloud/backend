import { Global, Module } from "@nestjs/common"
import { TypeOrmExModule } from "src/common/typeorm-ex.module"
import { AuditLogRepository } from "src/modules/log/repositories/auditLog.repository"
import { AuditLogsService } from "src/modules/log/services/auditLogs.service"

@Global()
@Module({
	exports: [AuditLogsService],
	imports: [TypeOrmExModule.forFeature([AuditLogRepository])],
	providers: [AuditLogsService],
})
export class LogModule {}
