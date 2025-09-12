import { Injectable, Logger, OnApplicationShutdown } from "@nestjs/common"
import { Cron, CronExpression } from "@nestjs/schedule"
import { Command, ICommand } from "src/lib/ssh"
import { GenUUID } from "src/lib/utils"
import { AuditLogsService } from "src/modules/log/services/auditLogs.service"
import { ISSHConnection } from "src/modules/server/interfaces/ssh.interface"
import { ServerRepository } from "src/modules/server/repositories/server.repository"
import { CredentialService } from "src/modules/vault/services/vault.service"
import SSH2Promise from "ssh2-promise"
import SSHConfig from "ssh2-promise/lib/sshConfig"

@Injectable()
export class SSHService implements OnApplicationShutdown {
	private connections: Map<string, ISSHConnection> = new Map()
	private readonly logger = new Logger(SSHService.name)

	constructor(
		private serverRepository: ServerRepository,
		private credentialService: CredentialService,
		private auditLogsService: AuditLogsService,
	) {}

	async onApplicationShutdown(signal?: string) {
		this.logger.log(`SSHService onApplicationShutdown: ${signal}`)
		await this.closeAllConnections()
	}

	@Cron(CronExpression.EVERY_SECOND)
	async watcher() {
		const connections = Array.from(this.connections.entries())

		for (const [server_uuid, conn] of connections) {
			const now = Date.now()
			const idleTime = now - conn.lastActivityAt
			const maxIdleTime = 1000 * 60 * 5 // 5 minutes
			// const maxIdleTime = 1000 * 10 // 5 minutes
			const isIdleTimeExpired = idleTime > maxIdleTime

			if (isIdleTimeExpired) {
				this.logger.log(`Closing idle SSH connection for server ${server_uuid}`)
				await this.closeConnection(server_uuid)
			}
		}
	}

	private async closeAllConnections() {
		for (const [server_uuid, conn] of this.connections) {
			try {
				await conn.connection.close()
				this.logger.log(`Closed SSH connection for server ${server_uuid}`)
			} catch (error) {
				this.logger.error(`Error closing SSH connection for server ${server_uuid}`, error)
			}
		}
	}

	async initConnection(serverId: string) {
		const server = await this.serverRepository.findOneOrFail({
			relations: {
				credential: {},
			},
			where: { id: serverId },
		})

		const credential = this.credentialService.decryptCredentials(server.credential)
		const sessionUUID = GenUUID()

		const config: SSHConfig = {
			host: server.address,
			keepaliveInterval: 1000 * 1,
			password: credential.password,
			port: server.port,
			readyTimeout: 10 * 1000,
			reconnect: true,
			reconnectDelay: 1000 * 3,
			uniqueId: sessionUUID,
			username: credential.username,
		}

		const conn = new SSH2Promise(config)

		try {
			await conn.connect()
			this.logger.log(`SSH connection established for server ${serverId}`)

			this.auditLogsService.info({
				message: "SSH connection established for server",
				server,
			})

			//
		} catch (error) {
			this.auditLogsService.error({
				error: error as string,
				message: "Error establishing SSH connection for server",
				server,
			})

			return
		}

		// init events
		conn.on("close", () => {
			this.closeConnection(serverId)
		})

		const client: ISSHConnection = {
			config,
			connectedAt: Date.now(),
			connection: conn,
			lastActivityAt: Date.now(),
		}

		this.connections.set(serverId, client)

		return conn
	}

	private async closeConnection(id: string) {
		const client = this.connections.get(id)

		if (!client) {
			return
		}

		try {
			await client.connection.close()
			this.connections.delete(id)

			this.auditLogsService.info({
				message: "Closed SSH connection for server",
				serverId: id,
			})
		} catch (error) {
			this.logger.error(`Error closing SSH connection for server ${id}`, error)
		}
	}

	async reconnect(id: string) {
		await this.closeConnection(id)
		return this.initConnection(id)
	}

	async getOrCreateConnection(id: string) {
		const client = this.connections.get(id)

		if (client) {
			client.lastActivityAt = Date.now()
			return client.connection
		}

		return this.initConnection(id)
	}

	async execCommand(serverId: string, commandOptions: ICommand) {
		const client = this.connections.get(serverId)
		if (!client) {
			throw new Error(`No active SSH connection for server ${serverId}`)
		}

		const exp = Command(commandOptions)

		let stdout = ""
		let stderr = ""

		try {
			stdout = await client.connection.exec(exp)
		} catch (e) {
			stderr = e as string
		}

		client.lastActivityAt = Date.now()

		return { stderr, stdout }
	}

	// private async isConnected(id: string) {
	// 	const client = this.connections.get(id)

	// 	let isOK = false
	// 	if (!client) {
	// 		return false
	// 	}

	// 	try {
	// 		const res = await client.connection.exec("echo 'ping'")
	// 		if (res.trim() === "ping") {
	// 			isOK = true
	// 		}
	// 		return isOK
	// 	} catch (error) {
	// 		this.logger.error(`Error checking SSH connection for server ${id}`, error)
	// 		return false
	// 	}
	// }
}
