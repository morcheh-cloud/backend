import { Get, Post } from "@nestjs/common"
import { BasicController } from "src/common/decorators/basicController.decorator"
import { StandardApi } from "src/common/decorators/standard-api.decorator"
import { PlaybookModel } from "src/modules/ansible/DTOs/playbook.dto"
import { PlaybookService } from "src/modules/ansible/services/playbook.service"

@BasicController("playbooks")
export class AnsibleController {
	constructor(private ansibleService: PlaybookService) {}

	@Post("sync")
	async syncAnsible() {
		await this.ansibleService.sync()
		return {
			success: true,
		}
	}

	@StandardApi({ type: PlaybookModel })
	@Get()
	async find() {
		return this.ansibleService.find()
	}
}
