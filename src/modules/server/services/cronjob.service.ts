import { Injectable, OnApplicationShutdown, OnModuleInit } from "@nestjs/common"
import { CronJob as CJ } from "cron"
import { CronJobRepository } from "src/modules/server/repositories/cronjob.repository"

@Injectable()
export class CronJobService implements OnModuleInit, OnApplicationShutdown {
	private jobs: Map<string, CJ> = new Map()

	constructor(private cronJobRepository: CronJobRepository) {}

	async onApplicationShutdown() {
		await this.stopAll()
	}

	onModuleInit() {}

	async load() {
		const cronJobs = await this.cronJobRepository.find({
			where: {},
		})

		for (const item of cronJobs) {
			const job = this.jobs.get(item.id)

			if (job) {
				await job.stop()
				this.jobs.delete(item.id)
			}

			const newJob = CJ.from({
				cronTime: item.cronTime as string,
				onTick: async () => {
					return await this.executeCronJobById(item.id)
				},
				start: !!item.isEnabled,
				timeZone: item.timezone,
			})

			this.jobs.set(item.id, newJob)
		}
	}

	async stopAll() {}

	private async executeCronJobById(id: string) {
		console.log(id)
	}

	// async runShellMode(cron: CronJob) {}
	// async runSSHMode(cron: CronJob) {}
	// async runPythonMode(crom)
}
