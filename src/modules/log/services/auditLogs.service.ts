import { Injectable, Logger } from "@nestjs/common"
import { AuditLog, AuditLogLevel } from "src/modules/log/entities/auditLog.entity"
import { AuditLogRepository } from "src/modules/log/repositories/auditLog.repository"
import { DeepPartial } from "typeorm"

export interface SaveAuditLogType extends AuditLog {
	serverId?: string
	userId?: string
}

@Injectable()
export class AuditLogsService {
	private logger = new Logger(AuditLogsService.name)

	constructor(private auditLogRepository: AuditLogRepository) {}

	async info(payload: DeepPartial<SaveAuditLogType>) {
		await this.auditLogRepository.save({
			...payload,
			level: AuditLogLevel.INFO,
			server: payload.serverId ? { id: payload.serverId } : payload.server,
			user: payload.userId ? { id: payload.userId } : payload.user,
		})
		this.logger.log(payload.message)
	}

	async error(payload: DeepPartial<SaveAuditLogType>) {
		await this.auditLogRepository.save({
			...payload,
			level: AuditLogLevel.ERROR,
			server: payload.serverId ? { id: payload.serverId } : payload.server,
			user: payload.userId ? { id: payload.userId } : payload.user,
		})
		this.logger.error(payload.message)
	}

	async debug(payload: DeepPartial<SaveAuditLogType>) {
		await this.auditLogRepository.save({
			...payload,
			level: AuditLogLevel.DEBUG,
			server: payload.serverId ? { id: payload.serverId } : payload.server,
			user: payload.userId ? { id: payload.userId } : payload.user,
		})
		this.logger.debug(payload.message)
	}
}
