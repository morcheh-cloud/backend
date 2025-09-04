import { Injectable, OnModuleInit } from "@nestjs/common"
import { SaveServerPayload } from "src/modules/server/DTOs/server.dto"
import { ServerRepository } from "src/modules/server/repositories/server.repository"
import { CredentialService } from "src/modules/vault/services/vault.service"

@Injectable()
export class ServerService implements OnModuleInit {
	constructor(
		private readonly serverRepository: ServerRepository,
		private credentialService: CredentialService,
	) {}

	async create(userId: number, workspaceId: number, payload: SaveServerPayload) {
		const credential = await this.credentialService.create(userId, workspaceId, payload)

		const server = await this.serverRepository.save({
			...payload,
			credential,
			user: { id: userId },
			workspace: { id: workspaceId },
		})

		return server
	}

	onModuleInit() {
		this.test()
	}

	async test() {
		// const res = await executeRemoteCommand({
		//   command: "ss -tulpenH",
		//   host: "94.182.91.38",
		//   password: "ZdFWBl8sjVBu0dNH",
		//   port: 22,
		//   username: "doctop",
		// });
		// const res2 = await executeRemoteCommand({
		//   become: true,
		//   command: "docker ps",
		//   host: "94.182.91.38",
		//   password: "ZdFWBl8sjVBu0dNH",
		//   port: 22,
		//   username: "doctop",
		// });
		// console.log(res2);
		// const lines = SplitToLines(res.stdout);
		// const parsed = lines.map((item) => {
		//   const splited = item.split(/\s+/);
		//   console.log("🚀 ~ ServerService ~ test ~ splited:", splited);
		//   const serviceName = splited
		//     .at(8)
		//     ?.split("/")
		//     .at(-1)
		//     ?.replace(".service", "");
		//   const port = splited.at(4)?.split(":").at(-1);
		//   return {
		//     port: Number(port),
		//     protocol: splited.at(0),
		//     serviceName,
		//     status: splited.at(1) === "LISTEN",
		//   };
		// });
		// const activePorts = parsed.filter((item) => !!item.status);
		// console.log("🚀 ~ ServerService ~ test ~ activePorts:", activePorts);
	}
}
