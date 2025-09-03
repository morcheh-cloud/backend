import { spawn } from "node:child_process"
import { randomUUID } from "node:crypto"
import { mkdirSync, unlinkSync, writeFileSync } from "node:fs"
import path from "node:path"
import { Injectable, Logger, OnModuleInit } from "@nestjs/common"
import { jsonToYaml } from "src/lib/utils"
import { AnsibleGateway } from "src/modules/ansible/gateways/ansible.gateway"
import { IHostEntry } from "src/modules/ansible/interfaces/ansible.interface"

export interface RunPlaybookOptions {
	/** Absolute or relative path to your playbook yml */
	playbookPath: string

	/** Optional inventory path (file or directory or inline like `inventory.ini`) */
	inventory?: string

	/** Extra vars object or JSON string. Will be passed via --extra-vars */
	extraVars?: Record<string, unknown> | string

	/** Additional args to append verbatim to ansible-playbook */
	args?: string[]

	/** Optional room/job id. If omitted, a UUID will be generated */
	jobId?: string

	/** Working directory (cwd) for the spawned process */
	cwd?: string
}

@Injectable()
export class AnsibleService implements OnModuleInit {
	private readonly logger = new Logger(AnsibleService.name)

	constructor(private readonly gateway: AnsibleGateway) {}

	private readonly inventoryFilePath = path.join(
		"/",
		"tmp",
		"morcheh",
		"ansible",
		"inventory",
	)
	// private readonly playbookPath = path.join(
	//   "/",
	//   "tmp",
	//   "morcheh",
	//   "ansible",
	//   "playbook"
	// );

	onModuleInit() {
		this.createInventory()
		// this.runPlaybook();
	}

	private createHostEntry(data: IHostEntry) {
		return {
			[data.hostname]: {
				ansible_host: data.addr,
				ansible_password: data.password,
				ansible_user: data.username,
			},
		}
	}

	private createInventoryFile(data: string) {
		const now = Date.now()
		const fileName = `inventory-${now}.yml`
		const filePath = path.join(this.inventoryFilePath, fileName)
		mkdirSync(this.inventoryFilePath, { recursive: true })
		writeFileSync(filePath, data, "utf8")
		return { fileName, filePath }
	}

	private async createInventory() {
		const hosts: IHostEntry[] = [
			{
				addr: "localhost",
				hostname: "localhost",
				password: "ansible",
				username: "ansible",
			},
		]

		const inventory = {
			all: {
				hosts: {
					...hosts.reduce((acc, host) => {
						return { ...acc, ...this.createHostEntry(host) }
					}, {}),
				},
			},
		}

		const inventoryYaml = jsonToYaml(inventory)
		const { filePath, fileName } = this.createInventoryFile(inventoryYaml)

		return { fileName, filePath }
	}

	clearInventory(fileName: string) {
		unlinkSync(path.join(this.inventoryFilePath, fileName))
	}

	async runPlaybook(opts?: RunPlaybookOptions) {
		const jobId = opts?.jobId ?? randomUUID()

		// const args: string[] = [];
		// if (opts.inventory) args.push("-i", opts.inventory);
		// args.push(opts.playbookPath);

		// // Handle --extra-vars
		// if (opts.extraVars) {
		//   const ev =
		//     typeof opts.extraVars === "string"
		//       ? opts.extraVars
		//       : JSON.stringify(opts.extraVars);
		//   args.push("--extra-vars", ev);
		// }

		// args.push("-v");

		// if (opts.args?.length) args.push(...opts.args);

		// Spawn ansible-playbook
		const child = spawn(
			"ansible-playbook",
			[
				"-i",
				"/home/ali/w/morcheh/backend/dev/inventory.yml",
				"/home/ali/w/morcheh/backend/dev/ls.yml",
			],
			{
				env: {
					ANSIBLE_FORCE_COLOR: "1",
					ANSIBLE_STDOUT_CALLBACK: "debug",
					PYTHONUNBUFFERED: "1",
				},
			},
		)

		child.stdout.on("data", (d) => {
			const content = d.toString("utf-8")
			const time = new Date().toISOString()
			console.log(`[${time.padEnd(10)}] ${content}`)
		})

		child.stderr.on("data", (d) => {
			const content = d.toString("utf-8")
			const time = new Date().toISOString()
			console.error(`[${time.padEnd(10)}] ${content}`)
		})

		child.on("close", (code, signal) => {
			this.gateway.emit(jobId, {
				code: code ?? -1,
				signal: signal ?? null,
				time: new Date().toISOString(),
				type: "exit",
			})

			this.logger.log(
				`ansible-playbook (job ${jobId}) exited with code ${code}, signal ${
					signal ?? "null"
				}`,
			)
		})

		child.on("error", (err) => {
			this.logger.error(
				`Failed to start ansible-playbook (job ${jobId}): ${err.message}`,
			)
			this.gateway.emit(jobId, {
				line: `Spawn error: ${err.message}`,
				time: new Date().toISOString(),
				type: "stderr",
			})
		})

		return jobId
	}

	/**
	 * Heuristically parse common Ansible lines into structured events.
	 * This works with standard text output. For richer, per-task JSON events,
	 * see the note below about callback plugins.
	 */
	parseLine(line: string): any | null {
		const ts = new Date().toISOString()

		// PLAY [something]
		const playMatch = line.match(/^\s*PLAY\s+\[(.+?)\]\s*$/)
		if (playMatch) {
			return { play: playMatch[1], time: ts, type: "play-start" }
		}

		// TASK [something]
		const taskMatch =
			line.match(/^\s*TASK\s+\[(.+?)\]\s*\*{3,}\s*$/) ||
			line.match(/^\s*TASK\s+\[(.+?)\]\s*$/)
		if (taskMatch) {
			return { task: taskMatch[1], time: ts, type: "task-start" }
		}

		// ok|changed|failed|skipped|unreachable: [host] ...
		const resultMatch = line.match(
			/^\s*(ok|changed|failed|skipped|unreachable):\s*\[(.+?)\](.*)$/i,
		)
		if (resultMatch) {
			const status = resultMatch?.at(1)?.toLowerCase() as any
			// const status = resultMatch[1].toLowerCase() as any as AnsibleEvent["type"];
			const host = resultMatch[2]
			const summary = resultMatch[3]?.trim() || undefined
			const normalized =
				status === "ok" ||
				status === "changed" ||
				status === "failed" ||
				status === "skipped" ||
				status === "unreachable"
					? (status as "ok" | "changed" | "failed" | "skipped" | "unreachable")
					: "ok"
			return {
				host,
				status: normalized,
				summary,
				time: ts,
				type: "host-result",
			}
		}

		return null
	}
}
