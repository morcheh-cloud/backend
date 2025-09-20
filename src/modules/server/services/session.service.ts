import { Injectable, Logger, OnApplicationShutdown, OnModuleInit } from "@nestjs/common"
import { AuditLogsService } from "src/modules/log/services/auditLogs.service"
import { SessionStatus } from "src/modules/server/entities/session.entity"
import { IActiveSession } from "src/modules/server/interfaces/ssh.interface"
import { ServerRepository } from "src/modules/server/repositories/server.repository"
import { SessionRepository } from "src/modules/server/repositories/session.repository"
import { sessionLogRepository } from "src/modules/server/repositories/sessionLog.repository"
import { CredentialService } from "src/modules/vault/services/vault.service"
import SSH2Promise from "ssh2-promise"
import SSHConfig from "ssh2-promise/lib/sshConfig"
import { IsNull } from "typeorm"

@Injectable()
export class SessionService implements OnModuleInit, OnApplicationShutdown {
	private activeSessions: Map<string, IActiveSession> = new Map()
	private readonly logger = new Logger(SessionService.name)

	constructor(
		private serverRepository: ServerRepository,
		private sessionRepository: SessionRepository,
		private credentialService: CredentialService,
		private auditLogsService: AuditLogsService,
		private sessionLogRepository: sessionLogRepository,
	) {}

	async onApplicationShutdown() {
		await this.closeAll()
	}

	onModuleInit() {
		this.closeAll()
	}

	getSession(serverId: string): IActiveSession | undefined {
		return this.activeSessions.get(serverId)
	}

	async getOrCreate(serverId: string): Promise<IActiveSession> {
		const existingSession = this.getSession(serverId)
		if (existingSession) {
			return existingSession
		}
		return this.create(serverId)
	}

	async create(serverId: string): Promise<IActiveSession> {
		const server = await this.serverRepository.findOneOrFail({
			relations: {
				credential: {},
			},
			where: { id: serverId },
		})

		const credential = this.credentialService.decryptCredentials(server.credential)

		const session = await this.sessionRepository.createAndSave({
			server,
			status: SessionStatus.INITIALIZING,
		})

		const config: SSHConfig = {
			host: server.address,
			keepaliveInterval: 1000 * 1,
			password: credential.password,
			port: server.port,
			readyTimeout: 10 * 1000,
			reconnect: true,
			reconnectDelay: 1000 * 3,
			uniqueId: session.id,
			username: credential.username,
		}

		const conn = new SSH2Promise(config)

		await this.sessionRepository.updateById(session.id, {
			startedAt: new Date(),
			status: SessionStatus.CONNECTING,
		})

		try {
			await conn.connect()
			this.logger.log(`SSH connection established for server ${serverId}`)

			this.auditLogsService.info({
				message: "SSH connection established for server",
				server,
			})

			await this.sessionRepository.updateById(session.id, {
				startedAt: new Date(),
				status: SessionStatus.CONNECTED,
			})

			//
		} catch (error) {
			this.auditLogsService.error({
				error: error as string,
				message: "Error establishing SSH connection for server",
				server,
			})

			await this.sessionRepository.updateById(session.id, {
				finishedAt: new Date(),
				message: error as string,
				status: SessionStatus.FAILED,
			})

			throw new Error(`Error connecting to SSH server ${serverId}: ${error}`)
		}

		conn.on("close", () => {
			this.close(serverId)
		})

		const client: IActiveSession = {
			config,
			connection: conn,
			serverId: server.id,
			sessionId: session.id,
		}

		this.activeSessions.set(serverId, client)

		return client
	}

	async close(id: string) {
		const client = this.activeSessions.get(id)

		const session = await this.sessionRepository.findOne({
			where: { server: { id } },
		})

		if (!session?.finishedAt) {
			await this.sessionRepository.updateById(id, {
				finishedAt: new Date(),
				status: SessionStatus.CLOSED,
			})
		}

		if (!client) {
			return
		}

		try {
			await client.connection.close()
			this.activeSessions.delete(id)
		} catch (error) {
			this.logger.error(`Error closing SSH connection for server ${id}`, error)
		}
	}

	async closeServerSessions(serverId: string) {
		const client = this.activeSessions.get(serverId)
		if (client) {
			await this.close(serverId)
		}
	}

	private async closeAll() {
		const activeSessions = await this.sessionRepository.find({
			where: {
				finishedAt: IsNull(),
			},
		})

		for (const session of activeSessions) {
			this.close(session.id)
		}
	}

	async logOutput(sessionId: string, output: string, isError = false) {
		const log = this.sessionLogRepository.create({
			session: { id: sessionId },
			stderr: isError ? output : undefined,
			stdout: isError ? undefined : output,
		})

		return await this.sessionLogRepository.save(log)
	}
}
