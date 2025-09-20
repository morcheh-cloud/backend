import { Injectable, OnApplicationShutdown, OnModuleInit } from "@nestjs/common"

@Injectable()
export class CronJobService implements OnModuleInit, OnApplicationShutdown {
	onApplicationShutdown(signal?: string) {
		console.log(`Application shutdown initiated. Signal: ${signal}`)
	}

	onModuleInit() {}
}
