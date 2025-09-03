import { Injectable, OnModuleInit } from "@nestjs/common"

@Injectable()
export class SettingService implements OnModuleInit {
	onModuleInit() {
		this.initSettings()
	}

	async initSettings() {
		// Initialization logic here
	}
}
