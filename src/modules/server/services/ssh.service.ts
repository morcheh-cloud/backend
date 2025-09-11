import { Injectable, Logger, OnApplicationShutdown } from "@nestjs/common"
import { Cron, CronExpression } from "@nestjs/schedule"
import { Command, CommandOptions } from "src/lib/ssh"
import { GenUUID } from "src/lib/utils"
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

	async initConnection(id: string) {
		const server = await this.serverRepository.findOneOrFail({
			relations: {
				credential: {},
			},
			where: { id },
		})

		const credential = this.credentialService.decryptCredentials(server.credential)
		const sessionUUID = GenUUID()

		const config: SSHConfig = {
			host: server.address,
			keepaliveInterval: 1000 * 1,
			password: credential.password || "",
			port: server.port,
			readyTimeout: 10 * 1000,
			reconnect: true,
			reconnectDelay: 1000 * 3,
			uniqueId: sessionUUID,
			username: credential.username || "",
		}

		const conn = new SSH2Promise(config)

		try {
			await conn.connect()
			this.logger.log(`SSH connection established for server ${id}`)
		} catch (error) {
			this.logger.error(`Error establishing SSH connection for server ${id}`, error)
			return
		}

		// init events
		conn.on("close", () => {
			this.closeConnection(id)
		})

		const client: ISSHConnection = {
			config,
			connectedAt: Date.now(),
			connection: conn,
			lastActivityAt: Date.now(),
			status: "connected",
		}

		this.connections.set(id, client)

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
			this.logger.log(`Closed SSH connection for server ${id}`)
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

		if (client && client.status === "connected") {
			client.lastActivityAt = Date.now()
			return client.connection
		}

		if (client && client.status !== "connected") {
			await this.closeConnection(id)
		}

		return this.initConnection(id)
	}

	async execCommand(id: string, cmd: string, args: string[], options: CommandOptions = {}) {
		const client = this.connections.get(id)
		if (!client) {
			throw new Error(`No active SSH connection for server ${id}`)
		}

		const exp = Command(cmd, args, options)

		let stdout = ""
		let stderr = ""
		try {
			stdout = await client.connection.exec(exp)
		} catch (e) {
			stderr = e as any
		}

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
