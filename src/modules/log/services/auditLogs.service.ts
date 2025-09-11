import { Injectable, Logger } from "@nestjs/common"
import { AuditLogRepository } from "src/modules/log/repositories/auditLog.repository"

@Injectable()
export class AuditLogsService {
	private logger = new Logger(AuditLogsService.name)

	constructor(private auditLogRepository: AuditLogRepository) {}

	async log() {
		await this.auditLogRepository.save({})
		this.logger.log("hi log")
	}
}
