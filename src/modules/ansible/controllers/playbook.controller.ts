import { Controller, Post } from "@nestjs/common";
import { PlaybookService } from "src/modules/ansible/services/playbook.service";

@Controller("ansible")
export class AnsibleController {
  constructor(private ansibleService: PlaybookService) {}

  @Post("sync")
  async syncAnsible() {
    await this.ansibleService.sync();
    return {
      success: true,
    };
  }
}
