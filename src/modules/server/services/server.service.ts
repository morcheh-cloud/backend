import { Injectable, NotFoundException } from "@nestjs/common"
import {
	GetCpuInfoCommand,
	GetCpuInfoCommandResult,
	GetHostnameCommand,
	GetMemoryInfoCommand,
	GetMemoryInfoCommandResult,
	GetOSInfoCommand,
	StorageInfoCommand,
	StorageInfoCommandResult,
} from "src/lib/commands"
import { ParseKeyValueConfig } from "src/lib/parser/parseKeyValueConfig"
import { ParseJson } from "src/lib/utils"
import { DirectoryService } from "src/modules/directory/services/directory.service"
import { SaveServerPayload } from "src/modules/server/DTOs/server.dto"
import { ServerProtocol } from "src/modules/server/entities/server.entity"
import { ServerRepository } from "src/modules/server/repositories/server.repository"
import { SSHService } from "src/modules/server/services/ssh.service"
import { CredentialService } from "src/modules/vault/services/vault.service"

@Injectable()
export class ServerService {
	constructor(
		private readonly serverRepository: ServerRepository,
		private credentialService: CredentialService,
		private directoryService: DirectoryService,
		private sshService: SSHService,
	) {}

	async create(userId: string, workspaceId: string, payload: SaveServerPayload) {
		const credential = await this.credentialService.create(userId, workspaceId, {
			description: payload.description,
			password: payload.password,
			username: payload.username,
		})

		const server = await this.serverRepository.createAndSave({
			...payload,
			credential,
			directory: { id: payload.directoryId },
			protocol: ServerProtocol.SSH,
			user: { id: userId },
			workspace: { id: workspaceId },
		})

		return server
	}

	async getTree(workspaceId: string) {
		return this.directoryService.getServerTree(workspaceId)
	}

	async delete(serverId: string, workspaceId: string) {
		const res = await this.serverRepository.softDelete({
			id: serverId,
			workspace: { id: workspaceId },
		})

		if (!res.affected) {
			throw new NotFoundException("Server not found")
		}
	}

	async update(serverId: string, workspaceId: string, payload: SaveServerPayload) {
		const server = await this.serverRepository.findOneOrFail({
			where: {
				id: serverId,
				workspace: { id: workspaceId },
			},
		})

		return await this.serverRepository.updateById(server.id, payload)
	}

	async getServerStats(serverId: string) {
		const output = await this.sshService.execManyCommand(serverId, [
			{
				cmd: StorageInfoCommand,
			},
			{
				cmd: GetHostnameCommand,
			},
			{
				cmd: GetOSInfoCommand,
			},
			{
				cmd: GetCpuInfoCommand,
			},
			{
				cmd: GetMemoryInfoCommand,
			},
		])

		const storageInfo = ParseJson(output.at(0)?.stdout) as StorageInfoCommandResult
		const hostname = output.at(1)?.stdout
		const osInfo = ParseKeyValueConfig(output.at(2)?.stdout)
		const cpuInfo = ParseJson(output.at(3)?.stdout) as GetCpuInfoCommandResult
		const memoryInfo = ParseJson(output.at(4)?.stdout) as GetMemoryInfoCommandResult

		const server = await this.serverRepository.updateById(serverId, {
			info: {
				cpuCoreCount: cpuInfo?.total_cores?.toString(),
				diskAvail: storageInfo.avail,
				diskSize: storageInfo.size,
				diskUsed: storageInfo.used,
				hostname: hostname?.trim(),
				memoryAvailable: memoryInfo.available,
				memorySize: memoryInfo.total,
				memoryUsage: memoryInfo.used,
				OSPrettyName: osInfo["PRETTY_NAME"],
			},
		})
		console.log("🚀 ~ ServerService ~ getServerStats ~ server:", server)

		return server
	}
}
